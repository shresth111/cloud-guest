"""Celery tasks for the DHCP domain: the scheduled rogue-DHCP detector.

## What this closes

``wyfy_device_gateway.mikrotik_adapter.read_rogue_dhcp_alerts`` -- the read
that answers "is this router actually watching for a DHCP server that isn't
ours" -- was implemented, documented, and had **zero callers anywhere in
``app/``**. The writer was wired on both config paths
(``DhcpService.push_pool_to_device`` asks for the alert the moment a pool
lands on a device); the reader was not. The asymmetry mattered: a router
that is *not* being watched has no alert row, produces no error, and
appears nowhere. It is invisible precisely because it is unguarded. This
module is the caller.

## Detector writes, surface reads

The device read deliberately does not hang off the readiness checklist.
``app.domains.readiness.service.ReadinessService.get_checklist`` calls
``_run_auto_detection`` on **every** GET, so a RouterOS round trip wired in
there would put a device timeout behind an ordinary dashboard page load.
Nor does the detector raise an ``Alert`` directly:
``app.domains.monitoring.models.Alert.rule_id`` is a non-nullable FK to
``alert_rules`` (an alert with no rule cannot be written at all), and
``app.domains.monitoring.tasks``'s own module docstring commits the alert
engine to reading already-persisted state and never performing per-device
I/O of its own. So this task writes ``models.RouterRogueDhcpStatus`` rows,
and the readiness checklist's ``ROGUE_DHCP_GUARD`` item reads only those
rows -- honouring readiness's documented zero-new-device-I/O rule, because
the device read already happened, here, off the request path.

## Coordinator + per-router fan-out, on the device-I/O queue

Modelled on ``app.domains.provisioning_engine.tasks
.run_router_health_poll_sweep``/``poll_single_router_health``, whose own
docstrings carry the full write-up: the Beat-scheduled coordinator takes a
Redis overlap-prevention lock, lists the routers due a check, and dispatches
one real Celery task per router rather than looping over them in-process.
One router's timeout then only ever delays its own leaf task. The leaf is
routed to ``app.core.celery_app.DEVICE_IO_QUEUE_NAME`` for the same reason
every other real per-router round trip is: so it cannot starve the pure-DB
sweeps sharing the default queue.

## Why this is not folded into ``poll_single_router_health``

That task already visits every router on a 10-minute cadence, so folding
this read into it looks like a free ride. It is not one. The gateway opens
a **fresh API connection per method** --
``mikrotik_adapter._read_rogue_dhcp_alerts_sync`` calls ``_connect_api``
itself and closes it in a ``finally`` -- so there is no connection to share
and nothing saved by co-location. What co-location would cost is real:
the health poll, which runs 24 times more often than this needs to, would
get slower on every router, and would gain a new way to fail on a read
that has nothing to do with health. A separate task on a much slower
cadence keeps the existing poll exactly as fast and exactly as reliable as
it is today.

## Deliberately out of scope: an alert-engine target

The obvious next step is an ``ALERT_TARGET_ROGUE_DHCP_GUARD`` alongside
``app.domains.monitoring.constants``'s existing ``ALERT_TARGET_ROUTER``/
``ALERT_TARGET_ISP_LINK``/``ALERT_TARGET_MONITORED_HARDWARE``, so an
unguarded interface could page someone instead of only appearing on a
checklist. It composes cleanly with what this change builds -- the alert
engine reads already-persisted state, and ``RouterRogueDhcpStatus`` is
exactly that -- and it is the natural follow-up.

It is not built here. ``Alert.rule_id`` is a non-nullable FK to
``alert_rules``, so no ``Alert`` can exist until an ``AlertRule`` for this
target does; that means a rule type, its seeding, its evaluation branch and
the customer-facing surface to configure it. That is materially more
product than a detector, and bolting it on would have made this change a
notification feature wearing a detector's name. The persisted rows are the
seam it will need when someone picks it up.

## Per-router failure isolation

One router raising must never stop the rest of the fleet being checked --
and with fan-out it structurally cannot, since each router is its own task.
Within a single router's task, every device failure is caught in
``DhcpService.run_rogue_dhcp_detection_for_router`` and recorded as
``RogueDhcpAlertState.UNKNOWN`` rather than raised: an unreachable router
is an unanswered question, not a finding, and never a task failure.
"""

from __future__ import annotations

import uuid

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.logging import get_logger
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
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService

from .constants import (
    ROGUE_DHCP_DETECTION_SWEEP_LOCK_REDIS_KEY,
    ROGUE_DHCP_DETECTION_SWEEP_LOCK_TTL_SECONDS,
    TASK_DETECT_ROGUE_DHCP_FOR_ROUTER,
    TASK_RUN_ROGUE_DHCP_DETECTION_SWEEP,
)
from .repository import DhcpRepository
from .service import DhcpService, RogueDhcpDetectionSummary

logger = get_logger(__name__)


def _build_dhcp_service(session) -> DhcpService:  # noqa: ANN001
    """The narrow graph the detector actually needs: a real ``DhcpService``
    over a real ``DhcpRepository``, and the real ``RouterService`` it
    composes for router resolution and API-credential decryption.

    ``RouterService`` requires ``LocationService``/``OrganizationService``
    as its own non-optional constructor dependencies, so they are built
    here for the same reason ``app.domains.provisioning_engine.tasks
    ._build_router_and_provisioning_services`` builds its own: the real
    service graph, not a special-case constructor path invented for a task.

    ``audit_writer`` is left at its real default of ``None``. This task
    performs no operator-initiated action -- it observes and records -- and
    an audit entry per router per tick would be noise, not a trail.
    """
    audit_repository = RBACRepository(session)
    organization_service = OrganizationService(
        OrganizationRepository(session), audit_writer=audit_repository
    )
    location_service = LocationService(
        LocationRepository(session),
        organization_service,
        location_code_counter=LocationCodeCounterRepository(session),
        audit_writer=audit_repository,
    )
    router_service = RouterService(
        RouterRepository(session),
        location_service,
        organization_service,
        audit_writer=audit_repository,
    )
    return DhcpService(DhcpRepository(session), router_service)


async def _dispatch_rogue_dhcp_detection_sweep_async() -> dict[str, object]:
    """The coordinator's real work: take the overlap lock, list every router
    serving DHCP, and fan out one leaf task per router.

    A fresh Redis client per invocation, never the shared module-level
    ``app.database.redis.redis_client`` singleton -- the identical "a fresh
    ``asyncio.run`` event loop every tick" discipline
    ``app.domains.provisioning_engine.tasks._drain_provision_queue_async``'s
    own docstring documents in full (a client's connection pool binds to
    whichever loop first used it; reusing it from a later invocation's new
    loop previously raised real cross-loop ``RuntimeError``s here).

    No device I/O of its own -- one DB query plus N in-memory ``.delay()``
    calls -- so this task stays on the default queue and only the leaf is
    routed to ``DEVICE_IO_QUEUE_NAME``.
    """
    redis = create_redis_client()
    try:
        acquired = await redis.set(
            ROGUE_DHCP_DETECTION_SWEEP_LOCK_REDIS_KEY,
            "1",
            nx=True,
            ex=ROGUE_DHCP_DETECTION_SWEEP_LOCK_TTL_SECONDS,
        )
        if not acquired:
            logger.warning(
                "dhcp_rogue_detection_sweep_skipped_locked",
                extra={"lock_key": ROGUE_DHCP_DETECTION_SWEEP_LOCK_REDIS_KEY},
            )
            return {"dispatched": 0, "skipped_locked": True}
        try:
            async with SessionLocal() as session:
                repository = DhcpRepository(session)
                router_ids = await repository.list_router_ids_serving_dhcp()
            for router_id in router_ids:
                detect_rogue_dhcp_for_router.delay(str(router_id))
            return {"dispatched": len(router_ids), "skipped_locked": False}
        finally:
            # Explicit release the moment dispatch finishes -- the ``ex``
            # above is purely a crash-safety backstop, not the normal
            # release path. See the constants module.
            await redis.delete(ROGUE_DHCP_DETECTION_SWEEP_LOCK_REDIS_KEY)
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_RUN_ROGUE_DHCP_DETECTION_SWEEP)
def run_rogue_dhcp_detection_sweep() -> dict[str, object]:
    """Beat-scheduled coordinator (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.ROGUE_DHCP_DETECTION_SWEEP_INTERVAL_SECONDS``, six hours).

    Its return value is a dispatch count, not a detection summary: the
    outcomes are only known once each leaf task completes, independently,
    on whichever worker slot picks it up.
    """
    result = run_celery_task(_dispatch_rogue_dhcp_detection_sweep_async())
    logger.info("dhcp_rogue_detection_sweep_dispatched", extra=result)
    return result


async def _detect_rogue_dhcp_for_router_async(
    router_id: uuid.UUID,
) -> RogueDhcpDetectionSummary:
    """The leaf task's async body -- a fresh session per invocation (this
    runs once per router, potentially many times concurrently across worker
    slots), mirroring every other sweep task's identical per-run discipline.

    No Redis client is built here, unlike
    ``provisioning_engine.tasks._poll_single_router_health_async``: that
    task's service graph needs one for its queue dispatcher, and this one's
    does not. Constructing a client this task never uses would be one more
    connection per router per tick for nothing.
    """
    async with SessionLocal() as session:
        try:
            service = _build_dhcp_service(session)
            summary = await service.run_rogue_dhcp_detection_for_router(router_id)
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_DETECT_ROGUE_DHCP_FOR_ROUTER)
def detect_rogue_dhcp_for_router(router_id: str) -> dict[str, int]:
    """The real per-router fan-out leaf task, one dispatched per router
    serving DHCP. This -- not a loop inside the coordinator -- is what keeps
    one unreachable router from delaying every other router's check.

    Routed to ``app.core.celery_app.DEVICE_IO_QUEUE_NAME``: it is a real
    RouterOS API round trip, and belongs off the default queue the cheap
    pure-DB sweeps share.

    ``unknown`` is reported as its own count, never folded into
    ``unguarded`` -- see ``service.RogueDhcpDetectionSummary``.
    """
    summary = run_celery_task(_detect_rogue_dhcp_for_router_async(uuid.UUID(router_id)))
    result = {
        "interfaces": summary.interfaces,
        "guarded": summary.guarded,
        "unguarded": summary.unguarded,
        "unknown": summary.unknown,
    }
    logger.info(
        "dhcp_rogue_detection_router_completed",
        extra={"router_id": router_id, **result},
    )
    return result


__all__ = ["run_rogue_dhcp_detection_sweep", "detect_rogue_dhcp_for_router"]
