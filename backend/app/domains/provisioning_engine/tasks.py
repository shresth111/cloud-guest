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

## Router health poll: coordinator + real per-router fan-out, not one
## sequential loop

``run_router_health_poll_sweep`` (Beat-scheduled) is a *coordinator*: it
acquires a Redis overlap-prevention lock, lists every router due a health
poll via ``ProvisioningEngineRepository.list_routers_for_health_poll``, and
dispatches one real Celery task (``poll_single_router_health``) per router
-- never itself performing the real per-router RouterOS API health-check
call. This replaces the original design, which polled every router
sequentially inside one process with a real ~10s timeout per router (a
single sweep run could exceed its own scheduling interval once the router
fleet was large enough, causing overlapping/queued coordinator runs
forever). See ``_dispatch_router_health_poll_sweep_async``'s and
``poll_single_router_health``'s own docstrings for the full write-up, and
``constants.ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY``'s for exactly what
the lock does and does not protect against.
"""

from __future__ import annotations

import uuid

from redis.asyncio import Redis

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.redis import create_redis_client
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
from app.domains.router.exceptions import RouterNotFoundError
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
    ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY,
    ROUTER_HEALTH_POLL_SWEEP_LOCK_TTL_SECONDS,
    TASK_DRAIN_PROVISION_QUEUE,
    TASK_POLL_SINGLE_ROUTER_HEALTH,
    TASK_RUN_ROUTER_HEALTH_POLL_SWEEP,
    TASK_RUN_ROUTER_SNMP_METRICS_POLL_SWEEP,
)
from .exceptions import ProvisioningEngineError
from .repository import (
    ProvisioningEngineRepository,
    RedisProvisionEngineQueueDispatcher,
)
from .service import (
    HealthPollSweepSummary,
    ProvisioningEngineService,
    SnmpMetricsPollSweepSummary,
)
from .service import run_router_health_poll_sweep as _run_router_health_poll_sweep
from .service import (
    run_router_snmp_metrics_poll_sweep as _run_router_snmp_metrics_poll_sweep,
)

logger = get_logger(__name__)


async def _build_provisioning_engine_service(
    session,  # noqa: ANN001
    redis: Redis,
) -> ProvisioningEngineService:
    """Builds the full, real service graph a worker process needs to run a
    :class:`~.models.ProvisionJob` end to end. See module docstring for why
    every one of these is real, not a lighter stand-in.

    ``redis`` is always a fresh client constructed by the calling
    ``asyncio.run``-bridged async function for this one task invocation
    (never the shared ``app.database.redis.redis_client`` module-level
    singleton) -- see module docstring's "fresh Redis client per task run"
    section for why sharing that singleton across separate
    ``asyncio.run`` calls is a real, previously-observed crash, not a
    theoretical one."""
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
        queue_dispatcher=RedisProvisioningQueueDispatcher(redis),
        audit_writer=audit_repository,
    )
    policy_service = PolicyService(
        PolicyRepository(session),
        organization_service,
        location_service,
        audit_writer=audit_repository,
    )

    otp_service = OtpService(
        OtpRepository(session), redis, audit_writer=audit_repository
    )
    voucher_service = VoucherService(
        VoucherRepository(session),
        redis,
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
        queue_dispatcher=RedisProvisionEngineQueueDispatcher(redis),
        audit_writer=audit_repository,
    )


async def _drain_provision_queue_async() -> dict[str, int]:
    """Pops up to ``PROVISION_QUEUE_DRAIN_BATCH_SIZE`` job IDs off
    ``PROVISION_ENGINE_QUEUE_REDIS_KEY`` and runs each one via
    ``ProvisioningEngineService.run_provision_job`` -- a fresh session *and*
    a fresh Redis client per task run, never shared across separate task
    invocations/worker ticks, mirroring ``analytics.tasks``'/
    ``guest.tasks``'s identical per-run session discipline and
    ``analytics.report_tasks._run_scheduled_reports_async``'s identical
    per-run Redis-client discipline.

    Deliberately never the shared ``app.database.redis.redis_client``
    module-level singleton: this task body is a synchronous
    ``@celery_app.task`` bridging to this async function via
    ``asyncio.run(...)`` (see ``drain_provision_queue`` below), which opens
    a **brand-new** event loop on every single invocation. A ``redis.asyncio
    .Redis`` client's underlying connection pool binds its sockets/
    ``asyncio.Future`` objects to whichever event loop was running the
    first time it was actually used -- reusing that same client object from
    a later invocation's new loop previously raised exactly
    ``RuntimeError: ... Future ... attached to a different loop``, followed
    by ``RuntimeError: Event loop is closed`` when the stale connection
    tried to tear itself down. Constructing a fresh client here and closing
    it in ``finally`` below (before this function -- and therefore this
    invocation's event loop -- returns) avoids that entirely."""
    processed = 0
    failed = 0
    redis = create_redis_client()
    try:
        async with SessionLocal() as session:
            service = await _build_provisioning_engine_service(session, redis)
            for _ in range(PROVISION_QUEUE_DRAIN_BATCH_SIZE):
                raw_job_id = await redis.rpop(PROVISION_ENGINE_QUEUE_REDIS_KEY)
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
    finally:
        await redis.aclose()
    return {"processed": processed, "failed": failed}


@celery_app.task(name=TASK_DRAIN_PROVISION_QUEUE)
def drain_provision_queue() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.PROVISION_QUEUE_DRAIN_INTERVAL_SECONDS``)."""
    result = run_celery_task(_drain_provision_queue_async())
    logger.info(
        "provisioning_engine_task_drain_provision_queue_completed", extra=result
    )
    return result


def _build_router_and_provisioning_services(
    session,  # noqa: ANN001
    redis: Redis,
) -> tuple[RouterService, RouterProvisioningService]:
    """The narrow pair ``run_router_health_poll_sweep`` actually needs
    (a real ``RouterService`` for credential decryption/heartbeat, and a
    real ``RouterProvisioningService`` for ``RouterHealthSnapshot``
    persistence) -- not the full ``ProvisioningEngineService`` graph
    ``_build_provisioning_engine_service`` builds for job orchestration,
    which this sweep never touches. Shared by both the coordinator (below)
    and ``poll_single_router_health``'s own leaf-task body so the two never
    drift."""
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
        queue_dispatcher=RedisProvisioningQueueDispatcher(redis),
        audit_writer=audit_repository,
    )
    return router_service, router_provisioning_service


async def _dispatch_router_health_poll_sweep_async() -> dict[str, object]:
    """The Beat-scheduled coordinator's real work: acquire the overlap-
    prevention lock, list every router due a health poll, and fan out one
    real Celery task (``poll_single_router_health``) per router instead of
    polling them sequentially, in this same process, the way the original
    implementation did. See ``constants
    .ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY``'s own docstring for exactly
    what this lock does and does not protect against, and
    ``poll_single_router_health``'s own docstring for the leaf task each
    dispatched job runs.

    A fresh Redis client per invocation -- never the shared module-level
    singleton -- for the identical "a fresh ``asyncio.run`` event loop every
    tick" reason ``_drain_provision_queue_async``'s own docstring documents
    in full."""
    redis = create_redis_client()
    try:
        acquired = await redis.set(
            ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY,
            "1",
            nx=True,
            ex=ROUTER_HEALTH_POLL_SWEEP_LOCK_TTL_SECONDS,
        )
        if not acquired:
            logger.warning(
                "provisioning_engine_task_router_health_poll_sweep_skipped_locked",
                extra={"lock_key": ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY},
            )
            return {"dispatched": 0, "skipped_locked": True}
        try:
            async with SessionLocal() as session:
                repository = ProvisioningEngineRepository(session)
                routers = await repository.list_routers_for_health_poll()
            for router in routers:
                poll_single_router_health.delay(str(router.id))
            return {"dispatched": len(routers), "skipped_locked": False}
        finally:
            # Explicit release the moment dispatch finishes -- the lock's
            # own ``ex`` above is purely a crash-safety backstop, not the
            # normal release path. See constants module docstring.
            await redis.delete(ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY)
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_RUN_ROUTER_HEALTH_POLL_SWEEP)
def run_router_health_poll_sweep() -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS``). This is now
    purely a *coordinator*: it lists due routers and fans out one real
    ``poll_single_router_health`` Celery task per router (see that task's
    own docstring for why) rather than polling every router sequentially,
    in-process, itself. Its own return value is therefore a dispatch count,
    not a health-check-outcome summary -- those outcomes are only known
    once each dispatched leaf task actually completes, asynchronously and
    independently, on whichever worker slot picks it up."""
    result = run_celery_task(_dispatch_router_health_poll_sweep_async())
    logger.info(
        "provisioning_engine_task_run_router_health_poll_sweep_dispatched",
        extra=result,
    )
    return result


async def _poll_single_router_health_async(
    router_id: uuid.UUID,
) -> HealthPollSweepSummary:
    """The real per-router fan-out leaf task's own async body -- a fresh
    session *and* a fresh Redis client per invocation (this task runs once
    per router, potentially many times concurrently across worker slots),
    mirroring every other sweep task's identical per-run discipline. Loads
    exactly the one router this invocation was dispatched for, then reuses
    ``service.run_router_health_poll_sweep``'s exact same per-router polling
    logic (via its ``routers=`` override) for that single-element list --
    no duplicated health-check/recording logic between the old sequential
    sweep and this new fan-out leaf task.

    A missing/deleted router (raced with the coordinator's own listing
    query -- e.g. deleted between dispatch and this task actually running)
    is treated as an honest no-op, not a task failure: there is nothing
    left to poll."""
    redis = create_redis_client()
    try:
        async with SessionLocal() as session:
            try:
                router_service, router_provisioning_service = (
                    _build_router_and_provisioning_services(session, redis)
                )
                try:
                    router = await router_service.get_router(router_id)
                except RouterNotFoundError:
                    return HealthPollSweepSummary(
                        checked=0, unreachable=0, skipped=1, errors=0
                    )
                summary = await _run_router_health_poll_sweep(
                    ProvisioningEngineRepository(session),
                    router_service,
                    router_provisioning_service,
                    routers=[router],
                )
                await session.commit()
                return summary
            except Exception:
                await session.rollback()
                raise
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_POLL_SINGLE_ROUTER_HEALTH)
def poll_single_router_health(router_id: str) -> dict[str, int]:
    """The real fan-out leaf task ``run_router_health_poll_sweep`` (the
    Beat-scheduled coordinator, above) dispatches one of per router that
    still needs a health poll -- this, not one giant sequential loop inside
    the coordinator itself, is the actual scale fix: N routers means N
    independent, real Celery tasks each worker slot picks up and runs
    concurrently (up to worker pool capacity), rather than one task
    blocking on N sequential ~10s-timeout RouterOS round trips. One
    router's own connection failure/timeout only ever fails/delays this one
    task -- it can never block or slow down any other router's own poll,
    which the original single-process sequential loop could not say."""
    summary = run_celery_task(_poll_single_router_health_async(uuid.UUID(router_id)))
    result = {
        "checked": summary.checked,
        "unreachable": summary.unreachable,
        "skipped": summary.skipped,
        "errors": summary.errors,
    }
    logger.info(
        "provisioning_engine_task_poll_single_router_health_completed",
        extra={"router_id": router_id, **result},
    )
    return result


async def _run_router_snmp_metrics_poll_sweep_async() -> SnmpMetricsPollSweepSummary:
    """Beat-scheduled, single sequential sweep -- see
    ``constants.TASK_RUN_ROUTER_SNMP_METRICS_POLL_SWEEP``'s own docstring
    for why this is deliberately not fanned out the way
    ``run_router_health_poll_sweep``/``poll_single_router_health`` are (a
    real, deliberate choice at today's real scale, not an oversight).
    Reuses ``_build_router_and_provisioning_services`` -- the identical
    real ``RouterService``/``RouterProvisioningService`` pair the
    RouterOS-API sweep above already builds by hand, since this sweep
    needs the exact same two things (per-router SNMP-credential
    resolution via ``RouterService.get_decrypted_snmp_community``, and
    ``RouterHealthSnapshot`` persistence via
    ``RouterProvisioningService.record_health_snapshot``/
    ``record_failed_health_check``)."""
    redis = create_redis_client()
    try:
        async with SessionLocal() as session:
            try:
                router_service, router_provisioning_service = (
                    _build_router_and_provisioning_services(session, redis)
                )
                summary = await _run_router_snmp_metrics_poll_sweep(
                    ProvisioningEngineRepository(session),
                    router_service,
                    router_provisioning_service,
                )
                await session.commit()
                return summary
            except Exception:
                await session.rollback()
                raise
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_RUN_ROUTER_SNMP_METRICS_POLL_SWEEP)
def run_router_snmp_metrics_poll_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.ROUTER_SNMP_METRICS_POLL_SWEEP_INTERVAL_SECONDS``). Real,
    standards-based SNMP polling of every ``Router.snmp_enabled`` router,
    supplementing (never replacing) ``run_router_health_poll_sweep``'s own
    RouterOS-API-based sweep above -- see
    ``service.run_router_snmp_metrics_poll_sweep``'s own docstring for the
    full "why both sweeps exist" write-up."""
    summary = run_celery_task(_run_router_snmp_metrics_poll_sweep_async())
    result = {
        "checked": summary.checked,
        "unreachable": summary.unreachable,
        "skipped": summary.skipped,
        "errors": summary.errors,
    }
    logger.info(
        "provisioning_engine_task_run_router_snmp_metrics_poll_sweep_completed",
        extra=result,
    )
    return result


__all__ = [
    "drain_provision_queue",
    "run_router_health_poll_sweep",
    "poll_single_router_health",
    "run_router_snmp_metrics_poll_sweep",
]
