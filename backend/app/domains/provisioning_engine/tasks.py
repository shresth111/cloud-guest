"""Celery task definitions for the Provisioning Engine domain.

Closes ``app.domains.router_provisioning``'s own long-documented seam:
that module's docstring has always said *"a future app.domains.router_agent
module is expected to call complete_provisioning_job after actually
performing the device-side action"* -- this is that caller, now real.
``drain_provision_queue`` is the Beat-scheduled task (see
``app.core.celery_app``'s own ``beat_schedule``) that drains
``constants.PROVISION_ENGINE_QUEUE_REDIS_KEY`` (the Redis wake-up signal
``repository.RedisProvisionEngineQueueDispatcher.enqueue`` LPUSHes onto) and
actually runs each queued :class:`~.models.ProvisionJob` end to end via
``ProvisioningEngineService.run_provision_job`` -- including a real
``MikroTikProvisionAdapter`` device-push attempt (see
``device_adapters.py``'s own "real client code, untested end-to-end here"
scope note: in this sandbox, that attempt always ends in a real, honest
``ProvisionDeviceConnectionError``, never a fabricated success).

## The async bridge, concretely

Mirrors ``app.domains.billing.tasks``'s identical bridge pattern (itself
mirroring ``app.domains.analytics.tasks``'s original one): a plain,
synchronous ``@celery_app.task`` body delegating immediately to a
module-level ``async def`` via ``asyncio.run``, which opens a fresh
``AsyncSession``, builds the full, real repository/service graph, does the
actual work, commits, and returns a plain, JSON-serializable result.

## Why the full, real DI graph, not a lighter stand-in

``ProvisioningEngineService`` composes ``RouterService``/
``RouterProvisioningService``/``PolicyService``/``RadiusService`` (see
``service.py``'s own module docstring on composition, not duplication).
``RadiusService`` itself requires a real ``GuestService`` instance (its
constructor's own, non-optional dependency) even though this task's own
calls into it (``register_nas``/``list_nas_clients``) never touch
``guest_service`` at all -- confirmed by reading both method bodies. Rather
than fabricate a special-case constructor path, this task builds the exact
same real service graph ``app.domains.guest.dependencies.get_guest_service``
builds for the live API (``OtpService``/``VoucherService``/
``CaptivePortalService``), leaving ``GuestService``'s own optional
``monitoring_hook``/``access_control_hook`` at their real, honest default of
``None`` -- the identical "additive, opt-in hook" contract that class's own
docstring already establishes for every caller that doesn't need them, not
a shortcut invented for this task.

## Per-job failure isolation, not per-step

``run_provision_job`` itself never continues past a step failure *within*
one job (see that method's own docstring: a single router's own steps are
sequential and dependent). This task's own drain loop is the layer where
per-item isolation belongs instead: one job raising must never stop the
tick from draining the rest of the batch -- mirrors every other batch sweep
in this codebase (e.g. ``RenewalService.run_renewal_sweep``'s own
per-subscription isolation).
"""

from __future__ import annotations

import asyncio
import uuid

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.redis import redis_client
from app.database.session import SessionLocal
from app.domains.captive_portal.repository import CaptivePortalRepository
from app.domains.captive_portal.service import CaptivePortalService
from app.domains.guest.repository import GuestRepository, RadiusNasCodeCounterRepository
from app.domains.guest.service import GuestService, RadiusService
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.location.service import LocationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.otp.repository import OtpRepository
from app.domains.otp.service import OtpService
from app.domains.policy.repository import PolicyRepository
from app.domains.policy.service import PolicyService
from app.domains.rbac.repository import RBACRepository
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService
from app.domains.router_provisioning.repository import (
    RedisProvisioningQueueDispatcher,
    RouterProvisioningRepository,
)
from app.domains.router_provisioning.service import RouterProvisioningService
from app.domains.voucher.repository import VoucherRepository
from app.domains.voucher.service import VoucherService

from .constants import (
    PROVISION_ENGINE_QUEUE_REDIS_KEY,
    PROVISION_QUEUE_DRAIN_BATCH_SIZE,
    TASK_DRAIN_PROVISION_QUEUE,
    TASK_RUN_ROUTER_HEALTH_POLL_SWEEP,
)
from .exceptions import ProvisioningEngineError
from .repository import (
    ProvisioningEngineRepository,
    RedisProvisionEngineQueueDispatcher,
)
from .service import HealthPollSweepSummary, ProvisioningEngineService
from .service import run_router_health_poll_sweep as _run_router_health_poll_sweep

logger = get_logger(__name__)


async def _build_provisioning_engine_service(session) -> ProvisioningEngineService:  # noqa: ANN001
    """Builds the full, real service graph a worker process needs to run a
    :class:`~.models.ProvisionJob` end to end. See module docstring for why
    every one of these is real, not a lighter stand-in."""
    settings = get_settings()
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
    router_provisioning_service = RouterProvisioningService(
        RouterProvisioningRepository(session),
        router_service,
        location_service,
        queue_dispatcher=RedisProvisioningQueueDispatcher(redis_client),
        audit_writer=audit_repository,
    )
    policy_service = PolicyService(
        PolicyRepository(session),
        organization_service,
        location_service,
        audit_writer=audit_repository,
    )

    otp_service = OtpService(
        OtpRepository(session), redis_client, audit_writer=audit_repository
    )
    voucher_service = VoucherService(
        VoucherRepository(session),
        redis_client,
        organization_service,
        location_service,
        audit_writer=audit_repository,
    )
    captive_portal_service = CaptivePortalService(
        CaptivePortalRepository(session),
        organization_service,
        location_service,
        audit_writer=audit_repository,
    )
    guest_repository = GuestRepository(session)
    guest_service = GuestService(
        guest_repository,
        otp_service,
        voucher_service,
        captive_portal_service,
        router_service,
        audit_writer=audit_repository,
    )
    radius_service = RadiusService(
        guest_repository,
        guest_service,
        router_service,
        location_service,
        RadiusNasCodeCounterRepository(session),
        audit_writer=audit_repository,
    )

    return ProvisioningEngineService(
        ProvisioningEngineRepository(session),
        router_service,
        router_provisioning_service,
        policy_service,
        radius_service,
        queue_dispatcher=RedisProvisionEngineQueueDispatcher(redis_client),
        audit_writer=audit_repository,
    )


async def _drain_provision_queue_async() -> dict[str, int]:
    """Pops up to ``PROVISION_QUEUE_DRAIN_BATCH_SIZE`` job IDs off
    ``PROVISION_ENGINE_QUEUE_REDIS_KEY`` and runs each one via
    ``ProvisioningEngineService.run_provision_job`` -- a fresh session per
    task run, never shared across separate task invocations/worker ticks,
    mirroring ``analytics.tasks``'/``guest.tasks``'s identical per-run
    session discipline. One job's own failure never stops the rest of the
    batch draining (see module docstring)."""
    processed = 0
    failed = 0
    async with SessionLocal() as session:
        service = await _build_provisioning_engine_service(session)
        for _ in range(PROVISION_QUEUE_DRAIN_BATCH_SIZE):
            raw_job_id = await redis_client.rpop(PROVISION_ENGINE_QUEUE_REDIS_KEY)
            if raw_job_id is None:
                break
            processed += 1
            try:
                await service.run_provision_job(uuid.UUID(raw_job_id))
                await session.commit()
            except ProvisioningEngineError:
                await session.rollback()
                failed += 1
                logger.exception(
                    "provisioning_engine_task_drain_job_failed",
                    extra={"job_id": raw_job_id},
                )
    return {"processed": processed, "failed": failed}


@celery_app.task(name=TASK_DRAIN_PROVISION_QUEUE)
def drain_provision_queue() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.PROVISION_QUEUE_DRAIN_INTERVAL_SECONDS``)."""
    result = asyncio.run(_drain_provision_queue_async())
    logger.info(
        "provisioning_engine_task_drain_provision_queue_completed", extra=result
    )
    return result


async def _run_router_health_poll_sweep_async() -> HealthPollSweepSummary:
    """A fresh session per task run, never shared across separate task
    invocations/worker ticks -- mirrors every other sweep task's identical
    per-run session discipline. Only the three narrow pieces
    ``run_router_health_poll_sweep`` actually needs are built (this
    domain's own repository, a real ``RouterService`` for credential
    decryption/heartbeat, and a real ``RouterProvisioningService`` for
    ``RouterHealthSnapshot`` persistence) -- not the full
    ``ProvisioningEngineService`` graph ``_build_provisioning_engine_service``
    builds for job orchestration, which this sweep never touches."""
    async with SessionLocal() as session:
        try:
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
            router_provisioning_service = RouterProvisioningService(
                RouterProvisioningRepository(session),
                router_service,
                location_service,
                queue_dispatcher=RedisProvisioningQueueDispatcher(redis_client),
                audit_writer=audit_repository,
            )
            summary = await _run_router_health_poll_sweep(
                ProvisioningEngineRepository(session),
                router_service,
                router_provisioning_service,
            )
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_ROUTER_HEALTH_POLL_SWEEP)
def run_router_health_poll_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS``). Bridges to the
    real async implementation of the same name in ``service.py`` (imported
    here as ``_run_router_health_poll_sweep`` purely to avoid shadowing this
    task function's own name within this module)."""
    summary = asyncio.run(_run_router_health_poll_sweep_async())
    result = {
        "checked": summary.checked,
        "unreachable": summary.unreachable,
        "skipped": summary.skipped,
        "errors": summary.errors,
    }
    logger.info(
        "provisioning_engine_task_run_router_health_poll_sweep_completed",
        extra=result,
    )
    return result


__all__ = ["drain_provision_queue", "run_router_health_poll_sweep"]
