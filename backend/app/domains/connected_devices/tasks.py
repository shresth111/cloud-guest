"""Celery Beat task for the Connected Device Management domain's
platform-wide device-sync sweep.

Bridges the async ``service.run_device_sync_sweep`` into a sync Celery
task body exactly the way ``app.domains.isp.tasks
.run_isp_health_check_sweep`` does: a fresh ``AsyncSession`` (via
``app.database.session.SessionLocal``, never the FastAPI ``Depends``
machinery, which has no meaning inside a Celery worker), the real
repository/service objects built by hand, the actual async sweep awaited
via ``asyncio.run``, then committed -- exactly as if this were a
one-shot async script.

``_build_router_service`` manually replicates
``app.domains.router.dependencies.get_router_service``'s own
construction, mirroring ``app.domains.isp.tasks``'s identical precedent
for composing a multi-dependency service by hand inside a Celery task.
"""

from __future__ import annotations

import asyncio
import logging

from app.core.celery_app import celery_app
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
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService

from .constants import TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP
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


async def _run_connected_device_sync_sweep_async() -> DeviceSyncSweepSummary:
    async with SessionLocal() as session:
        try:
            repository = ConnectedDeviceRepository(session)
            router_service = _build_router_service(session)
            guest_access_service = GuestAccessService(
                GuestAccessRepository(session), audit_writer=RBACRepository(session)
            )
            guest_repository = GuestRepository(session)
            summary = await run_device_sync_sweep(
                repository,
                router_service,
                guest_access_service,
                guest_repository,
                audit_writer=RBACRepository(session),
                device_adapter_resolver=get_connected_device_adapter,
            )
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP)
def run_connected_device_sync_sweep() -> dict[str, int]:
    summary = asyncio.run(_run_connected_device_sync_sweep_async())
    result = {
        "routers_synced": summary.routers_synced,
        "routers_failed": summary.routers_failed,
        "discovered": summary.discovered,
        "updated": summary.updated,
        "disconnected": summary.disconnected,
    }
    logger.info("connected_device_task_run_sync_sweep_completed", extra=result)
    return result


__all__ = ["run_connected_device_sync_sweep"]
