"""Celery task definitions for the Queue Management Engine domain.

``sweep_schedule_transitions`` is the Beat-scheduled task (see
``app.core.celery_app``'s own ``beat_schedule``) that closes the real
background half of the module brief's own "Automatically change assigned
queues based on time" requirement -- ``QueueManagementService
.sweep_schedule_transitions`` (see that method's own docstring) only ever
runs when *something* calls it; this is the real, periodic caller.

## The async bridge, concretely

Mirrors ``app.domains.provisioning_engine.tasks``'s identical bridge
pattern: a plain, synchronous ``@celery_app.task`` body delegating
immediately to a module-level ``async def`` via ``asyncio.run``, which
opens a fresh ``AsyncSession``, builds the real repository/service graph,
does the actual work, commits, and returns a plain, JSON-serializable
result. The graph here is much lighter than ``provisioning_engine.tasks``'s
own -- ``QueueManagementService`` composes only ``RouterService``/
``PolicyService`` (see ``service.py``'s own module docstring), not the
full guest/OTP/voucher/captive-portal graph that domain's own
``RadiusService`` composition drags in.
"""

from __future__ import annotations

import uuid

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.session import SessionLocal
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.location.service import LocationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.policy.repository import PolicyRepository
from app.domains.policy.service import PolicyService
from app.domains.rbac.repository import RBACRepository
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService

from .constants import (
    TASK_REAPPLY_POLICY_ASSIGNMENTS,
    TASK_SWEEP_SCHEDULE_TRANSITIONS,
)
from .repository import QueueManagementRepository
from .service import QueueManagementService

logger = get_logger(__name__)


async def _reapply_policy_assignments_async(
    policy_id: str, version_id: str
) -> dict[str, int]:
    """The actual async work behind ``reapply_policy_assignments`` -- a
    fresh session per task run, mirroring
    ``_sweep_schedule_transitions_async``'s identical discipline.

    Resolves which locations the just-published policy is actively mapped
    to (its ``LOCATION``-scoped, active ``PolicyAssignment`` rows), then
    asks ``QueueManagementService`` to re-resolve every live SESSION queue
    assignment in each of those locations against the location's now-
    published policy -- the "a venue just raised their speeds, guests who
    are already connected should get them" hook.
    """
    settings = get_settings()
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
            provisioning_token_ttl_hours=settings.router_provisioning_token_expire_hours,
        )
        policy_service = PolicyService(
            PolicyRepository(session),
            organization_service,
            location_service,
            audit_writer=audit_repository,
        )
        service = QueueManagementService(
            QueueManagementRepository(session),
            router_service,
            policy_service,
            audit_writer=audit_repository,
        )
        policy_repository = PolicyRepository(session)
        policy = await policy_repository.get_policy_by_id(uuid.UUID(policy_id))
        if policy is None:
            return {"reapplied": 0, "failed": 0, "locations": 0}
        assignments = await policy_repository.list_assignments_for_policy(
            uuid.UUID(policy_id)
        )
        location_ids = {
            a.scope_id
            for a in assignments
            if a.is_active
            and a.scope_type == "location"
            and a.scope_id is not None
        }
        total_reapplied = 0
        total_failed = 0
        for location_id in location_ids:
            result = await service.reapply_active_sessions_for_location(
                location_id=location_id,
                requesting_organization_id=policy.organization_id,
            )
            total_reapplied += result["reapplied"]
            total_failed += result["failed"]
        await session.commit()
        return {
            "reapplied": total_reapplied,
            "failed": total_failed,
            "locations": len(location_ids),
        }


@celery_app.task(
    name=TASK_REAPPLY_POLICY_ASSIGNMENTS,
    bind=True,
    max_retries=3,
)
def reapply_policy_assignments(
    self, *, policy_id: str, version_id: str
) -> dict[str, int]:
    """Fired by the Policy router after a bandwidth-policy publish. Re-runs
    every live (ACTIVE) session queue assignment in the policy's mapped
    locations through the same resolution a fresh login uses, so a speed
    change reaches guests already connected. Retries on transient worker/
    router failures; a permanently unreachable router is recorded per
    assignment (see ``reapply_active_sessions_for_location``'s own
    per-item isolation) and does not fail the task."""
    try:
        result = run_celery_task(
            _reapply_policy_assignments_async(policy_id, version_id)
        )
        logger.info(
            "queue_management_task_reapply_policy_assignments_completed",
            extra=result,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "queue_management_task_reapply_policy_assignments_failed",
            extra={"policy_id": policy_id, "error": str(exc)},
        )
        raise self.retry(exc=exc, countdown=30) from exc


async def _sweep_schedule_transitions_async() -> dict[str, int]:
    """The actual async work behind ``sweep_schedule_transitions`` -- a
    fresh session per task run, never shared across separate task
    invocations/worker ticks, mirroring ``provisioning_engine.tasks``'s
    identical per-run session discipline."""
    settings = get_settings()
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
            provisioning_token_ttl_hours=settings.router_provisioning_token_expire_hours,
        )
        policy_service = PolicyService(
            PolicyRepository(session),
            organization_service,
            location_service,
            audit_writer=audit_repository,
        )
        service = QueueManagementService(
            QueueManagementRepository(session),
            router_service,
            policy_service,
            audit_writer=audit_repository,
        )
        result = await service.sweep_schedule_transitions()
        await session.commit()
        return result


@celery_app.task(name=TASK_SWEEP_SCHEDULE_TRANSITIONS)
def sweep_schedule_transitions() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.SCHEDULE_SWEEP_INTERVAL_SECONDS``)."""
    result = run_celery_task(_sweep_schedule_transitions_async())
    logger.info(
        "queue_management_task_sweep_schedule_transitions_completed", extra=result
    )
    return result


__all__ = ["sweep_schedule_transitions", "reapply_policy_assignments"]
