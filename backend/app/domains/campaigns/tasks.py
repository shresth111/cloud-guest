"""Celery task definitions for the Campaigns domain.

``sweep_campaign_status_transitions`` is the Beat-scheduled task (see
``app.core.celery_app``'s own ``beat_schedule``) that keeps the *stored*
``Campaign.status`` reasonably fresh for admin dashboards -- see
``service.CampaignsService.sweep_status_transitions``'s own docstring and
``app.domains.campaigns``'s module docstring for why the guest-facing
serving path never trusts this stored value alone regardless of this
sweep's cadence.

## The async bridge, concretely

Mirrors ``app.domains.queue_management.tasks``'s identical bridge
pattern: a plain, synchronous ``@celery_app.task`` body delegating
immediately to a module-level ``async def`` via ``asyncio.run``, which
opens a fresh ``AsyncSession``, builds the real repository/service graph,
does the actual work, commits, and returns a plain, JSON-serializable
result.
"""

from __future__ import annotations

import asyncio

from app.core.celery_app import celery_app
from app.core.logging import get_logger
from app.database.session import SessionLocal
from app.domains.guest.repository import GuestRepository
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

from .constants import TASK_SWEEP_CAMPAIGN_STATUS_TRANSITIONS
from .repository import CampaignsRepository
from .service import CampaignsService

logger = get_logger(__name__)


async def _sweep_campaign_status_transitions_async() -> dict[str, int]:
    """The actual async work behind ``sweep_campaign_status_transitions``
    -- a fresh session per task run, never shared across separate task
    invocations/worker ticks, mirroring ``queue_management.tasks``'s
    identical per-run session discipline."""
    async with SessionLocal() as session:
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
        service = CampaignsService(
            CampaignsRepository(session),
            organization_service,
            location_service,
            router_service,
            GuestRepository(session),
            audit_writer=audit_repository,
        )
        transitioned = await service.sweep_status_transitions()
        await session.commit()
        return {"transitioned": transitioned}


@celery_app.task(name=TASK_SWEEP_CAMPAIGN_STATUS_TRANSITIONS)
def sweep_campaign_status_transitions() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.CAMPAIGN_STATUS_SWEEP_INTERVAL_SECONDS``)."""
    result = asyncio.run(_sweep_campaign_status_transitions_async())
    logger.info("campaigns_task_sweep_status_transitions_completed", extra=result)
    return result


__all__ = ["sweep_campaign_status_transitions"]
