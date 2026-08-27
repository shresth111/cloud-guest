"""Celery Beat task: the every-five-minutes hub reconciliation sweep.

Follows this codebase's established sweep shape exactly -- a plain,
synchronous ``@celery_app.task`` body delegating to a module-level ``async
def`` via ``run_celery_task``, which opens a fresh ``AsyncSession``
(``SessionLocal``, never FastAPI's ``Depends`` machinery, which has no
meaning inside a worker), builds the real services by hand, does the work,
commits, and returns a plain JSON-serializable result. See
``app.domains.router.tasks`` for the precedent this mirrors, and
``app.domains.provisioning_engine.tasks`` for the Redis overlap-lock idiom.

## What this task is for

Divergence between what the platform believes about a router and what the
hub is actually doing is, by construction, invisible to everything else.
When a router's WireGuard identity and its FreeRADIUS ``client{}`` stanza
disagree, FreeRADIUS drops that router's Access-Requests without replying:
no error, no log line, no degraded mode -- the venue is simply down. It was
found, on 2026-08-27, by someone at the venue complaining.

It also recurred that same night, after the fix was written and before it
was deployed: a factory reset moved the router to ``10.20.0.10``, the peer
row followed it, and ``radius_nas_clients`` was left holding ``10.20.0.6``
from an earlier manual repair. Same silent failure, third distinct cause in
one day. That is the case for a timer rather than an endpoint: the repair
is only useful if it happens without anyone deciding to run it.

## Why the service tree is NOT hand-constructed here

The obvious reading of the precedent above says to replicate
``get_hub_reconciliation_service``'s whole graph by hand. That would mean
assembling ``GuestService`` (OTP, voucher, captive-portal, monitoring,
guest-access, queue, policy, MAC-authorization and Redis collaborators),
``RouterService``, ``LocationService`` and a NAS-code counter, in order to
reach two methods that read none of them.

Nine services built to be unused is not thoroughness, it is nine chances to
be subtly wrong in a way nothing on this path would ever surface --
precisely the "runs, logs success, silently does nothing" failure this task
exists to prevent. So the dependency is narrowed instead: see
``service.NasBindingStore``, the two-method Protocol
``HubReconciliationService`` actually requires. ``_NoCollaborator`` below
makes the unused constructor arguments loudly unusable rather than
plausibly wrong.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.database.redis import create_redis_client
from app.database.session import SessionLocal
from app.domains.guest.repository import GuestRepository
from app.domains.guest.service import RadiusService
from app.domains.rbac.repository import RBACRepository
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService
from app.domains.wireguard.dependencies import (
    hub_capabilities_from_settings,
    make_hub_peer_deregistrar,
    make_hub_peer_lister,
)
from app.domains.wireguard.exceptions import WireGuardError
from app.domains.wireguard.repository import WireGuardRepository
from app.domains.wireguard.service import WireGuardService

from .constants import (
    HUB_RECONCILIATION_SWEEP_ADOPTS,
    HUB_RECONCILIATION_SWEEP_LOCK_REDIS_KEY,
    HUB_RECONCILIATION_SWEEP_LOCK_TTL_SECONDS,
    TASK_RUN_HUB_RECONCILIATION_SWEEP,
)
from .service import HubReconciliationService

logger = logging.getLogger(__name__)


class _NoCollaborator:
    """Stands in for a ``RadiusService`` collaborator this task's code path
    provably never touches, and fails loudly if that ever stops being true.

    ``None`` was the obvious choice and is the wrong one. A ``None`` that is
    unexpectedly dereferenced raises ``AttributeError: 'NoneType' object has
    no attribute 'get_router'`` several frames from the cause, and -- worse
    -- a ``None`` passed where a value is merely *checked* for truthiness
    can silently change behaviour without raising at all. This raises on any
    attribute access whatsoever, naming itself and the reason, so a future
    change that makes the reconciliation path reach one of these fails
    immediately and legibly instead of at 3am in a venue.

    The two methods used (``list_nas_clients``, ``record_hub_client_sync``,
    and ``get_nas_client`` beneath the latter) read only ``repository`` and
    the pure ``_enforce_nas_tenant_scope`` -- see ``service.NasBindingStore``
    for the full contract this is narrowing to.
    """

    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attribute: str) -> Any:
        raise RuntimeError(
            f"The hub reconciliation sweep touched RadiusService.{self._name}"
            f".{attribute}, which it was built without. This code path is "
            "documented as needing only list_nas_clients and "
            "record_hub_client_sync (see hub_reconciliation.service"
            ".NasBindingStore). Either narrow the call back, or construct a "
            "real collaborator here -- do not pass None."
        )


def _build_services(session) -> HubReconciliationService:  # noqa: ANN001
    """Constructs the same pair ``dependencies.get_hub_reconciliation_service``
    builds for a request, including re-tying the ``peer_address_listener``
    knot between them.

    That knot is the part worth being careful about: without it, an adoption
    corrects the WireGuard identity and never tells the RADIUS side, which
    is exactly half a repair and looks like a whole one in the logs. It is
    reproduced here rather than shared with the dependency module because
    the two differ in how ``RadiusService`` is obtained -- see this module's
    docstring.
    """
    from app.core.config import get_settings

    settings = get_settings()

    wireguard_service = WireGuardService(
        WireGuardRepository(session),
        RouterService(
            RouterRepository(session),
            _NoCollaborator("location_lookup"),
            _NoCollaborator("organization_lookup"),
        ),
        audit_writer=RBACRepository(session),
        handshake_stale_after_minutes=(
            settings.wireguard_handshake_stale_after_minutes
        ),
        hub_peer_deregistrar=make_hub_peer_deregistrar(settings),
        hub_peer_lister=make_hub_peer_lister(settings),
        hub_capabilities=hub_capabilities_from_settings(settings),
    )
    radius_service = RadiusService(
        GuestRepository(session),
        _NoCollaborator("guest_service"),
        _NoCollaborator("router_lookup"),
        _NoCollaborator("location_lookup"),
        _NoCollaborator("nas_code_counter_repository"),
        audit_writer=RBACRepository(session),
    )
    reconciliation = HubReconciliationService(wireguard_service, radius_service)

    async def _on_peer_address_changed(
        *, router_id, previous_tunnel_ip_address: str, tunnel_ip_address: str
    ) -> None:
        await reconciliation.rebind_nas_for_router(
            router_id=router_id, tunnel_ip_address=tunnel_ip_address
        )

    wireguard_service.peer_address_listener = _on_peer_address_changed
    return reconciliation


async def _run_hub_reconciliation_sweep_async(*, adopt: bool) -> dict[str, Any]:
    """Acquire the overlap lock, run one pass, commit.

    A fresh Redis client per invocation -- never the shared module-level
    singleton -- for the identical "a fresh event loop every tick" reason
    ``provisioning_engine.tasks`` documents for its own coordinator.
    """
    redis = create_redis_client()
    try:
        acquired = await redis.set(
            HUB_RECONCILIATION_SWEEP_LOCK_REDIS_KEY,
            "1",
            nx=True,
            ex=HUB_RECONCILIATION_SWEEP_LOCK_TTL_SECONDS,
        )
        if not acquired:
            # WARNING, not INFO: at 300s spacing this should not happen, and
            # if it happens repeatedly the pass is running longer than its
            # own interval -- which is a real capacity signal, not routine.
            logger.warning(
                "hub_reconciliation_sweep_skipped_locked",
                extra={"lock_key": HUB_RECONCILIATION_SWEEP_LOCK_REDIS_KEY},
            )
            return {"skipped_locked": True}
        try:
            async with SessionLocal() as session:
                try:
                    report = await _build_services(session).reconcile(adopt=adopt)
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise
            pushed = [r for r in report.nas_rebinds if r.pushed]
            failed = [r for r in report.nas_rebinds if not r.pushed]
            return {
                "skipped_locked": False,
                "hub_unreachable": False,
                "peers_seen": sum(report.summary.values()),
                "adopted": len(report.adopted_public_keys),
                "rebound": len(pushed),
                "rebind_failed": len(failed),
                "rebinds_deferred": report.rebinds_deferred,
                "needs_operator": len(report.drift_public_keys),
                "orphaned": report.summary.get("known_orphan", 0),
                "unchanged": max(
                    sum(report.summary.values())
                    - len(report.adopted_public_keys)
                    - len(pushed),
                    0,
                ),
            }
        finally:
            # Explicit release the moment the pass finishes -- the ``ex``
            # above is purely the crash-safety backstop, not the normal
            # release path.
            await redis.delete(HUB_RECONCILIATION_SWEEP_LOCK_REDIS_KEY)
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_RUN_HUB_RECONCILIATION_SWEEP)
def run_hub_reconciliation_sweep(
    adopt: bool = HUB_RECONCILIATION_SWEEP_ADOPTS,
) -> dict[str, Any]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.HUB_RECONCILIATION_SWEEP_INTERVAL_SECONDS``).

    ``adopt`` defaults to ``constants.HUB_RECONCILIATION_SWEEP_ADOPTS``
    (True -- see that constant for the full justification) and is exposed as
    a parameter so an operator can run a report-only pass by hand without a
    deploy.

    A hub that cannot be reached is reported, not raised. It is a real,
    expected operational state (the bridge is plain HTTP on a private
    address, and the whole point of this task is that it runs unattended),
    and letting it propagate would bury a one-line cause under a Celery
    traceback and a retry storm. Anything unexpected still propagates.
    """
    try:
        result = run_celery_task(_run_hub_reconciliation_sweep_async(adopt=adopt))
    except WireGuardError as exc:
        # HubPeerListerNotConfiguredError / HubBridgeUnavailableError and
        # their siblings. ERROR, because a hub this task cannot read means
        # no reconciliation is happening at all -- the silent state it
        # exists to end.
        result = {
            "skipped_locked": False,
            "hub_unreachable": True,
            "error": str(exc),
        }
        logger.error(
            "hub_reconciliation_task_sweep_hub_unreachable", extra=result
        )
        return result
    # Logged at INFO on EVERY run, including one that changes nothing --
    # the identical reasoning ``run_stale_heartbeat_sweep`` documents for
    # its own: a sweep that silently stops running looks exactly like a
    # fleet that is entirely healthy, and that is the failure this whole
    # task exists to stop being invisible. It applies with more force here,
    # because nothing else on the platform can see this divergence at all.
    logger.info("hub_reconciliation_task_sweep_completed", extra=result)
    return result


__all__ = ["run_hub_reconciliation_sweep"]
