"""Celery Beat task for the ISP Management domain's health-check sweep.

Bridges the async ``service.run_health_check_sweep`` into a sync Celery
task body exactly the way ``app.domains.guest.tasks
.run_session_timeout_sweep``/``run_fup_time_accrual_sweep`` do: a fresh
``AsyncSession`` (via ``app.database.session.SessionLocal``, never the
FastAPI ``Depends`` machinery, which has no meaning inside a Celery
worker), the real repository/service objects built by hand, the actual
async sweep awaited via ``asyncio.run``, then committed -- exactly as if
this were a one-shot async script. ``asyncio.run`` is safe here for the
same reason it is in every other task in this codebase: a Celery worker
task body never itself already runs inside an event loop.

``_build_router_service`` manually replicates
``app.domains.router.dependencies.get_router_service``'s own construction
(``RouterRepository`` + ``LocationService`` + ``OrganizationService`` +
RBAC's ``RBACRepository`` as its audit writer) since FastAPI's DI
machinery cannot run outside a request -- the identical
``app.domains.guest.tasks._build_policy_service`` precedent for composing
a multi-dependency service by hand inside a Celery task.
"""

from __future__ import annotations

import logging

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
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

from .constants import TASK_RUN_ISP_HEALTH_CHECK_SWEEP
from .device_adapters import get_isp_health_adapter
from .repository import IspRepository
from .service import HealthCheckSweepSummary, run_health_check_sweep

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


async def _run_isp_health_check_sweep_async() -> HealthCheckSweepSummary:
    async with SessionLocal() as session:
        try:
            repository = IspRepository(session)
            router_service = _build_router_service(session)
            audit_writer = RBACRepository(session)
            summary = await run_health_check_sweep(
                repository,
                router_service,
                audit_writer=audit_writer,
                device_adapter_resolver=get_isp_health_adapter,
            )
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_ISP_HEALTH_CHECK_SWEEP)
def run_isp_health_check_sweep() -> dict[str, int]:
    summary = run_celery_task(_run_isp_health_check_sweep_async())
    result = {
        "checked": summary.checked,
        "failovers": summary.failovers,
        "failbacks": summary.failbacks,
        "skipped": summary.skipped,
        "errors": summary.errors,
    }
    logger.info("isp_task_run_health_check_sweep_completed", extra=result)
    return result


__all__ = ["run_isp_health_check_sweep"]
