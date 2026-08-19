"""Celery Beat tasks for the Connected Device Management domain's
platform-wide device-sync sweep.

## Coordinator + real per-router fan-out, not one sequential loop

``run_connected_device_sync_sweep`` (Beat-scheduled) is a *coordinator*: it
acquires a Redis overlap-prevention lock, lists every router due a sync via
``ConnectedDeviceRepository.list_routers_for_sync``, and dispatches one real
Celery task (``sync_single_router_devices``) per router -- never itself
performing the real per-router RouterOS DHCP-lease/ARP/wireless-
registration-table discovery call. Each dispatched leaf task then does the
identical fresh-``AsyncSession``-per-invocation bridge every other Celery
task in this codebase uses (see ``app.domains.isp.tasks
.run_isp_health_check_sweep`` for the original single-process precedent
this domain's sweep used to follow directly, before fan-out): a fresh
``AsyncSession`` (via ``app.database.session.SessionLocal``, never the
FastAPI ``Depends`` machinery, which has no meaning inside a Celery
worker), the real repository/service objects built by hand, the actual
per-router sync awaited via ``asyncio.run``, then committed -- exactly as
if this were a one-shot async script, just now scoped to one router per
task invocation instead of every router in one process. See
``_dispatch_connected_device_sync_sweep_async``'s and
``sync_single_router_devices``'s own docstrings for the full scale-
readiness write-up (mirrors
``app.domains.provisioning_engine.tasks``'s identical coordinator/fan-out
shape for its own router-health-poll sweep).

``_build_router_service`` manually replicates
``app.domains.router.dependencies.get_router_service``'s own
construction, mirroring ``app.domains.isp.tasks``'s identical precedent
for composing a multi-dependency service by hand inside a Celery task.
"""

from __future__ import annotations

import logging
import uuid

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.database.redis import create_redis_client
from app.database.session import SessionLocal
from app.domains.guest.repository import GuestRepository
from app.domains.guest_access.repository import GuestAccessRepository
from app.domains.guest_access.service import GuestAccessService
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.location.service import LocationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.rbac.repository import RBACRepository
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService

from .constants import (
    CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY,
    CONNECTED_DEVICE_SYNC_SWEEP_LOCK_TTL_SECONDS,
    TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP,
    TASK_SYNC_SINGLE_ROUTER_DEVICES,
)
from .device_adapters import get_connected_device_adapter
from .repository import ConnectedDeviceRepository
from .service import DeviceSyncSweepSummary, run_device_sync_sweep

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


async def _dispatch_connected_device_sync_sweep_async() -> dict[str, object]:
    """The Beat-scheduled coordinator's real work: acquire the overlap-
    prevention lock, list every router due a device sync, and fan out one
    real Celery task (``sync_single_router_devices``) per router instead of
    syncing them sequentially, in this same process, the way the original
    implementation did -- mirrors
    ``app.domains.provisioning_engine.tasks
    ._dispatch_router_health_poll_sweep_async``'s identical coordinator
    shape (see that function's own docstring, and ``constants
    .CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY``'s, for exactly what the
    lock does and does not protect against).

    A fresh Redis client per invocation -- never the shared module-level
    singleton -- for this codebase's standard "a fresh ``asyncio.run``
    event loop every tick" reason (see
    ``app.domains.provisioning_engine.tasks
    ._drain_provision_queue_async``'s own docstring for the full write-up)."""
    redis = create_redis_client()
    try:
        acquired = await redis.set(
            CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY,
            "1",
            nx=True,
            ex=CONNECTED_DEVICE_SYNC_SWEEP_LOCK_TTL_SECONDS,
        )
        if not acquired:
            logger.warning(
                "connected_device_task_sync_sweep_skipped_locked",
                extra={"lock_key": CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY},
            )
            return {"dispatched": 0, "skipped_locked": True}
        try:
            async with SessionLocal() as session:
                repository = ConnectedDeviceRepository(session)
                routers = await repository.list_routers_for_sync()
            for router in routers:
                sync_single_router_devices.delay(str(router.id))
            return {"dispatched": len(routers), "skipped_locked": False}
        finally:
            # Explicit release the moment dispatch finishes -- the lock's
            # own ``ex`` above is purely a crash-safety backstop, not the
            # normal release path. See constants module docstring.
            await redis.delete(CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY)
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP)
def run_connected_device_sync_sweep() -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS``). This is
    now purely a *coordinator*: it lists due routers and fans out one real
    ``sync_single_router_devices`` Celery task per router (see that task's
    own docstring for why) rather than syncing every router sequentially,
    in-process, itself. Its own return value is therefore a dispatch
    count, not a sync-outcome summary -- those outcomes are only known once
    each dispatched leaf task actually completes, asynchronously and
    independently, on whichever worker slot picks it up."""
    result = run_celery_task(_dispatch_connected_device_sync_sweep_async())
    logger.info("connected_device_task_run_sync_sweep_dispatched", extra=result)
    return result


async def _sync_single_router_devices_async(
    router_id: uuid.UUID,
) -> DeviceSyncSweepSummary:
    """The real per-router fan-out leaf task's own async body -- a fresh
    session per invocation (this task runs once per router, potentially
    many times concurrently across worker slots). Loads exactly the one
    router this invocation was dispatched for, then reuses
    ``service.run_device_sync_sweep``'s exact same per-router sync logic
    (via its ``routers=`` override) for that single-element list -- no
    duplicated discovery/reconciliation logic between the old sequential
    sweep and this new fan-out leaf task.

    A missing/deleted router (raced with the coordinator's own listing
    query) is an honest no-op, not a task failure -- mirrors
    ``app.domains.provisioning_engine.tasks
    ._poll_single_router_health_async``'s identical race handling."""
    async with SessionLocal() as session:
        try:
            repository = ConnectedDeviceRepository(session)
            router_service = _build_router_service(session)
            guest_access_service = GuestAccessService(
                GuestAccessRepository(session), audit_writer=RBACRepository(session)
            )
            guest_repository = GuestRepository(session)
            try:
                router = await router_service.get_router(router_id)
            except RouterNotFoundError:
                return DeviceSyncSweepSummary(
                    routers_synced=0,
                    routers_failed=0,
                    discovered=0,
                    updated=0,
                    disconnected=0,
                )
            summary = await run_device_sync_sweep(
                repository,
                router_service,
                guest_access_service,
                guest_repository,
                audit_writer=RBACRepository(session),
                device_adapter_resolver=get_connected_device_adapter,
                routers=[router],
            )
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_SYNC_SINGLE_ROUTER_DEVICES)
def sync_single_router_devices(router_id: str) -> dict[str, int]:
    """The real fan-out leaf task ``run_connected_device_sync_sweep`` (the
    Beat-scheduled coordinator, above) dispatches one of per router that
    still needs a device sync -- this, not one giant sequential loop inside
    the coordinator itself, is the actual scale fix: N routers means N
    independent, real Celery tasks each worker slot picks up and runs
    concurrently (up to worker pool capacity), rather than one task
    blocking on N sequential, potentially-expensive real RouterOS
    DHCP-lease/ARP/wireless-registration-table discovery calls. One
    router's own connection failure/timeout only ever fails/delays this
    one task -- it can never block or slow down any other router's own
    sync."""
    summary = run_celery_task(_sync_single_router_devices_async(uuid.UUID(router_id)))
    result = {
        "routers_synced": summary.routers_synced,
        "routers_failed": summary.routers_failed,
        "discovered": summary.discovered,
        "updated": summary.updated,
        "disconnected": summary.disconnected,
    }
    logger.info(
        "connected_device_task_sync_single_router_devices_completed",
        extra={"router_id": router_id, **result},
    )
    return result


__all__ = ["run_connected_device_sync_sweep", "sync_single_router_devices"]
