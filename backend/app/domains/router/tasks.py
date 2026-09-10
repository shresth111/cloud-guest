"""Celery Beat task for the Router domain's enrollment-token expiry cleanup
sweep.

``RouterProvisioningToken`` (``models.py``) has always carried
``expires_at``/``used_at``, and ``RouterService.check_in`` has always
honestly rejected an expired or already-used token
(``ProvisioningTokenExpiredError``/``ProvisioningTokenAlreadyUsedError``) --
but nothing has ever actually swept and soft-deleted the expired-but-unused
rows themselves, so they simply accumulated forever. This module closes
that gap the exact same way every other Beat-scheduled sweep in this
codebase does: a plain, synchronous ``@celery_app.task`` body delegating to
a module-level ``async def`` via ``asyncio.run``, which opens a fresh
``AsyncSession`` (``app.database.session.SessionLocal``, never the FastAPI
``Depends`` machinery, which has no meaning inside a Celery worker), builds
a real ``RouterService`` by hand, does the actual work
(``RouterService.sweep_expired_provisioning_tokens`` -- see that method's
own docstring for the per-token failure-isolation contract), commits, and
returns a plain, JSON-serializable result.

``_build_router_service`` manually replicates
``app.domains.router.dependencies.get_router_service``'s own construction --
the identical ``app.domains.isp.tasks._build_router_service``/
``app.domains.connected_devices.tasks._build_router_service`` precedent for
composing a multi-dependency service by hand inside a Celery task, since
FastAPI's DI machinery cannot run outside a request.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.database.redis import create_redis_client
from app.database.session import SessionLocal
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.location.service import LocationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.rbac.repository import RBACRepository
from app.domains.wireguard.dependencies import make_hub_peer_lister
from app.domains.wireguard.repository import WireGuardRepository

from .constants import (
    TASK_RUN_PROVISIONING_TOKEN_CLEANUP_SWEEP,
    TASK_RUN_ROUTER_REACHABILITY_SWEEP,
    TASK_RUN_STALE_HEARTBEAT_SWEEP,
)
from .repository import RouterRepository
from .service import RouterService

logger = logging.getLogger(__name__)


def _build_router_service(session) -> RouterService:  # noqa: ANN001
    organization_service = OrganizationService(OrganizationRepository(session))
    location_service = LocationService(
        LocationRepository(session),
        organization_service,
        location_code_counter=LocationCodeCounterRepository(session),
    )
    return RouterService(
        RouterRepository(session),
        location_service,
        organization_service,
        audit_writer=RBACRepository(session),
    )


async def _run_provisioning_token_cleanup_sweep_async() -> int:
    async with SessionLocal() as session:
        try:
            router_service = _build_router_service(session)
            cleaned = await router_service.sweep_expired_provisioning_tokens()
            await session.commit()
            return cleaned
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_PROVISIONING_TOKEN_CLEANUP_SWEEP)
def run_provisioning_token_cleanup_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.PROVISIONING_TOKEN_CLEANUP_SWEEP_INTERVAL_SECONDS``)."""
    cleaned = run_celery_task(_run_provisioning_token_cleanup_sweep_async())
    result = {"cleaned": cleaned}
    logger.info(
        "router_task_run_provisioning_token_cleanup_sweep_completed", extra=result
    )
    return result


async def _run_stale_heartbeat_sweep_async() -> dict[str, int]:
    async with SessionLocal() as session:
        try:
            router_service = _build_router_service(session)
            result = await router_service.sweep_stale_heartbeats()
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_STALE_HEARTBEAT_SWEEP)
def run_stale_heartbeat_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.STALE_HEARTBEAT_SWEEP_INTERVAL_SECONDS``).

    The only writer of ``ONLINE -> OFFLINE`` on the platform. Before this
    existed, ``heartbeat()`` wrote ``ONLINE`` and nothing ever wrote it back,
    so a router that stopped answering read as online indefinitely."""
    result = run_celery_task(_run_stale_heartbeat_sweep_async())
    # Logged at INFO every minute even when it marks nothing, on purpose: a
    # sweep that silently stops running looks exactly like a fleet that is
    # entirely healthy, and that is the failure this whole task exists to
    # stop being invisible.
    logger.info("router_task_run_stale_heartbeat_sweep_completed", extra=result)
    return result


# How fresh a WireGuard handshake has to be for the hub's live
# ``wg show wg0 dump`` to count as "this tunnel is demonstrably alive".
#
# Every peer this platform provisions carries
# ``persistent-keepalive=25s`` (see
# ``app.domains.network_config.renderers``), and WireGuard renegotiates
# roughly every two minutes while anything is flowing -- so a working
# tunnel's ``latest_handshake`` age sits comfortably under two minutes and
# spikes no higher than about three. Three minutes is therefore the point
# below which "alive" is a safe claim.
#
# Note the asymmetry, which is deliberate: this threshold can only ever
# SUPPRESS an alert, never raise one. An over-generous window makes the
# probe withhold an alert it should have allowed (we stay quiet on a real
# outage for one more 30s cycle); a mean one makes it withhold nothing,
# which is simply the no-probe behaviour. Neither can invent an outage.
TUNNEL_HANDSHAKE_ALIVE_WITHIN_SECONDS = 180

# Redis key holding the moment this sweep last completed a real evaluation
# pass. Read back on the next tick as ``previous_sweep_at`` to answer "were
# we awake for the window we are about to judge?" -- see
# ``RouterService.sweep_router_reachability``'s awake-window guard. Redis
# rather than a table because the value is worth exactly one sweep interval
# and losing it fails SAFE: a missing key reads as "we were not awake",
# which skips one pass rather than alerting on one.
ROUTER_REACHABILITY_LAST_SWEEP_REDIS_KEY = "router:reachability_sweep:last_run_at"

# Generous relative to the 30s cadence so a couple of missed ticks (a
# worker restart, a slow pass) do not silently expire the key and make
# every subsequent pass think it just woke up.
ROUTER_REACHABILITY_LAST_SWEEP_TTL_SECONDS = 3600


def _make_tunnel_probe(session, settings):  # noqa: ANN001, ANN202
    """Builds the ``TunnelLivenessProbe`` the reachability sweep uses to
    confirm that a silent router's tunnel is gone too.

    One HTTP call to the hub's ``GET /wg/peers`` answers for the entire
    fleet at once -- it is the hub's own ``wg show wg0 dump``, read live --
    so this costs one request per sweep no matter how many routers went
    quiet, and never opens a connection to a router. That is the whole
    reason the confirmation is affordable at a 30-second cadence: the
    cheapest platform-to-router probe this codebase has is a full
    librouteros login on 8728 with a ten-second timeout, which at fleet
    scale could not fit inside the latency budget.

    Returns ``None`` (the no-probe behaviour) when the hub bridge is not
    configured, rather than a probe that would fail on every call.
    """
    if not settings.hub_wg_agent_peers_url or not settings.hub_wg_agent_secret:
        return None

    lister = make_hub_peer_lister(settings)
    repository = WireGuardRepository(session)

    async def _probe(routers) -> dict:  # noqa: ANN001
        peers = await lister()
        by_key: dict[str, dict] = {
            str(peer.get("public_key")): peer
            for peer in peers
            if peer.get("public_key")
        }
        now_epoch = datetime.now(UTC).timestamp()
        verdicts: dict = {}
        for router in routers:
            peer_row = await repository.get_peer_by_router_id(router.id)
            if peer_row is None:
                # No tunnel on record -- nothing to confirm with. Absence
                # alone decides, which is the same answer as no probe.
                verdicts[router.id] = None
                continue
            live = by_key.get(peer_row.public_key)
            if live is None:
                verdicts[router.id] = False
                continue
            epoch = live.get("latest_handshake_epoch") or 0
            if not epoch:
                verdicts[router.id] = False
                continue
            verdicts[router.id] = (
                now_epoch - float(epoch)
            ) <= TUNNEL_HANDSHAKE_ALIVE_WITHIN_SECONDS
        return verdicts

    return _probe


async def _run_router_reachability_sweep_async() -> dict[str, int]:
    settings = get_settings()
    redis = create_redis_client()
    try:
        previous_raw = await redis.get(ROUTER_REACHABILITY_LAST_SWEEP_REDIS_KEY)
        previous_sweep_at = None
        if previous_raw:
            raw = (
                previous_raw.decode()
                if isinstance(previous_raw, bytes)
                else str(previous_raw)
            )
            try:
                previous_sweep_at = datetime.fromisoformat(raw)
            except ValueError:
                previous_sweep_at = None
        async with SessionLocal() as session:
            try:
                router_service = _build_router_service(session)
                result = await router_service.sweep_router_reachability(
                    previous_sweep_at=previous_sweep_at,
                    tunnel_probe=_make_tunnel_probe(session, settings),
                )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
        # Written only after a pass that actually completed. A run that
        # crashed leaves the old value in place, so the next tick sees a
        # gap and correctly refuses to judge a window nobody was awake for.
        await redis.set(
            ROUTER_REACHABILITY_LAST_SWEEP_REDIS_KEY,
            datetime.now(UTC).isoformat(),
            ex=ROUTER_REACHABILITY_LAST_SWEEP_TTL_SECONDS,
        )
        return result
    finally:
        # A fresh client per invocation, closed here -- never the shared
        # module-level ``redis_client`` singleton. Its pool binds to
        # whichever event loop first used it, and every ``run_celery_task``
        # call is a new ``asyncio.run`` loop; reusing the singleton across
        # them has already produced real cross-loop RuntimeErrors elsewhere
        # in this codebase.
        await redis.aclose()


@celery_app.task(name=TASK_RUN_ROUTER_REACHABILITY_SWEEP)
def run_router_reachability_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (every
    ``ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS`` = 30s) -- the fast half
    of "a venue went down and nobody was told".

    Distinct from ``run_stale_heartbeat_sweep`` above and deliberately so:
    that one owns ``Router.status`` at the shared 15-minute definition of
    offline every screen agrees on, this one owns a separate,
    alert-only ``reachability_state`` sized to a two-minute email. See
    ``RouterService.sweep_router_reachability`` for the guards that keep
    absence from becoming a false alarm."""
    result = run_celery_task(_run_router_reachability_sweep_async())
    # INFO on every pass, like the stale-heartbeat sweep above and for the
    # same reason: a sweep that has silently stopped running is
    # indistinguishable, from the outside, from a fleet that is entirely
    # healthy -- and that is the exact failure this whole feature exists to
    # stop being invisible.
    logger.info("router_task_run_router_reachability_sweep_completed", extra=result)
    return result


__all__ = [
    "run_provisioning_token_cleanup_sweep",
    "run_stale_heartbeat_sweep",
    "run_router_reachability_sweep",
]
