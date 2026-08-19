"""Celery task definitions for the Guest domain (Guest Session Engine,
Phase 1).

Wraps ``service.enforce_session_timeouts`` -- a status-transition sweep that
already existed (as ``GuestService.enforce_timeouts``) and was already
tested, but was never actually invoked by anything before this module. See
``app.core.celery_app``'s module docstring for why: this codebase's
``GuestSession``/timeout detection was, until now, a callable mechanism
with no scheduler wired to call it periodically -- the exact same "real
logic, missing the cron" gap this file closes.

Also defines the two FUP (Fair Usage Policy) quota Beat sweeps added for
Phase 1 BhaiFi-parity: ``run_fup_time_accrual_sweep`` (accrues guest-level
connected-time usage and expires sessions that just crossed a configured
time cap) and ``run_quota_reset_sweep`` (proactively rolls every
``GuestQuotaUsage`` row over once its own organization's local calendar
day/week/month boundary passes). See ``service.py``'s "FUP quota tracking"
module docstring section for the full design write-up shared by both.

## The async bridge, concretely

Mirrors ``app.domains.analytics.tasks``'s identical bridge pattern:
``run_session_timeout_sweep`` is a plain, synchronous function (what
Celery's worker expects), which delegates immediately to a module-level
**async** function (``_run_session_timeout_sweep_async``) via
``asyncio.run(...)``. That async function opens a fresh ``AsyncSession``
(``app.database.session.SessionLocal``), builds a real ``GuestRepository``,
and calls the module-level ``enforce_session_timeouts`` function directly --
**not** a full ``GuestService`` (which would additionally require real
``OtpService``/``VoucherService``/``CaptivePortalService``/``RouterService``
instances this task never needs, since the sweep only ever reads/writes
``GuestSession`` rows through the repository). See ``service
.enforce_session_timeouts``'s own docstring for why that function was
pulled out to module scope specifically to make this possible.

Keeping the async bridge function at module scope (rather than inlining it
into the ``@celery_app.task`` body) is what keeps this file testable
without a running Celery worker or broker -- the same "monkeypatch the
bridge, call the plain task function directly" contract
``tests/unit/test_guest.py``'s task-bridge test uses, mirroring
``tests/unit/test_analytics.py``'s identical pattern for
``analytics.tasks``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
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
from app.domains.queue_management.constants import QueueTargetType

from .constants import (
    ASSIGN_GUEST_QUEUE_MAX_RETRIES,
    ASSIGN_GUEST_QUEUE_RETRY_BACKOFF_SECONDS,
    TASK_ASSIGN_GUEST_QUEUE,
    TASK_RUN_FUP_TIME_ACCRUAL_SWEEP,
    TASK_RUN_QUOTA_RESET_SWEEP,
    TASK_RUN_SESSION_TIMEOUT_SWEEP,
)
from .repository import GuestRepository
from .service import enforce_session_timeouts, run_fup_time_accrual, run_quota_reset

logger = get_logger(__name__)


def _build_policy_service(session: AsyncSession) -> PolicyService:
    """Constructs a real ``PolicyService`` from scratch, the way
    ``app.domains.policy.dependencies.get_policy_service`` would via
    FastAPI's ``Depends`` chain -- there is no request/DI container inside
    a Celery task, so this bridges the same real
    ``OrganizationService``/``LocationService`` composition by hand.
    Neither the accrual sweep below nor ``PolicyService
    .resolve_effective_policy`` (the only method either sweep task calls)
    ever exercises ``organization_lookup``/``location_lookup`` -- those are
    only used by ``PolicyService.create_policy``/assignment-scope
    validation -- but the constructor requires real instances regardless,
    so this builds them for real rather than passing a hollow stand-in."""
    organization_service = OrganizationService(OrganizationRepository(session))
    location_service = LocationService(
        LocationRepository(session),
        organization_service,
        location_code_counter=LocationCodeCounterRepository(session),
    )
    return PolicyService(
        PolicyRepository(session), organization_service, location_service
    )


async def _run_session_timeout_sweep_async() -> int:
    """The actual async work behind ``run_session_timeout_sweep`` -- a
    fresh session per task run (never a session shared across separate task
    invocations/worker ticks, mirroring ``analytics.tasks``'s identical
    per-run session discipline). Returns the number of sessions flipped to
    ``EXPIRED``."""
    async with SessionLocal() as session:
        try:
            repository = GuestRepository(session)
            expired = await enforce_session_timeouts(repository)
            await session.commit()
            return len(expired)
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_SESSION_TIMEOUT_SWEEP)
def run_session_timeout_sweep() -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS``). Flips every
    ``ACTIVE`` ``GuestSession`` whose inactivity has exceeded its own
    ``session_timeout_minutes`` to ``EXPIRED``, exactly what
    ``GuestService.enforce_timeouts`` has always computed -- this task is
    what makes that computation actually run on a schedule instead of only
    ever being reachable by an explicit caller (e.g. a test, or a future
    manual admin trigger)."""
    expired_count = run_celery_task(_run_session_timeout_sweep_async())
    logger.info(
        "guest_task_run_session_timeout_sweep_completed",
        extra={"expired_count": expired_count},
    )
    return {"expired_count": expired_count}


async def _run_fup_time_accrual_sweep_async() -> dict[str, int]:
    """The actual async work behind ``run_fup_time_accrual_sweep`` -- a
    fresh session per task run, mirroring
    ``_run_session_timeout_sweep_async``'s identical per-run session
    discipline. Delegates the real logic to ``service.run_fup_time_accrual``
    (see that function's own docstring), against a real ``GuestRepository``
    and a real ``PolicyService`` built by ``_build_policy_service``."""
    async with SessionLocal() as session:
        try:
            repository = GuestRepository(session)
            policy_service = _build_policy_service(session)
            result = await run_fup_time_accrual(
                repository, policy_service, now=datetime.now(UTC)
            )
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_FUP_TIME_ACCRUAL_SWEEP)
def run_fup_time_accrual_sweep() -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.FUP_TIME_ACCRUAL_SWEEP_INTERVAL_SECONDS``). Accrues
    guest-level connected-time usage for every guest with at least one
    ``ACTIVE`` session and a configured ``PolicyType.FUP`` time limit, and
    expires any session whose guest has just crossed one -- see
    ``service.py``'s "FUP quota tracking" module docstring section for the
    full design write-up."""
    result = run_celery_task(_run_fup_time_accrual_sweep_async())
    logger.info("guest_task_run_fup_time_accrual_sweep_completed", extra=result)
    return result


async def _run_quota_reset_sweep_async() -> dict[str, int]:
    """The actual async work behind ``run_quota_reset_sweep`` -- a fresh
    session per task run, mirroring ``_run_session_timeout_sweep_async``'s
    identical per-run session discipline. Delegates the real logic to
    ``service.run_quota_reset`` (see that function's own docstring),
    against a real ``GuestRepository``."""
    async with SessionLocal() as session:
        try:
            repository = GuestRepository(session)
            result = await run_quota_reset(repository, now=datetime.now(UTC))
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_QUOTA_RESET_SWEEP)
def run_quota_reset_sweep() -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.QUOTA_RESET_SWEEP_INTERVAL_SECONDS``). Proactively rolls
    every ``GuestQuotaUsage`` row over to a fresh, zeroed period the moment
    its own organization's local calendar day/week/month boundary passes --
    see ``service.py``'s "FUP quota tracking" module docstring section."""
    result = run_celery_task(_run_quota_reset_sweep_async())
    logger.info("guest_task_run_quota_reset_sweep_completed", extra=result)
    return result


# ============================================================================
# Dynamic bandwidth-queue assignment, off the login request path (§5 S9)
# ============================================================================


def _build_queue_management_service(session: AsyncSession):
    """Constructs a real ``QueueManagementService`` the way
    ``app.domains.queue_management.dependencies.get_queue_management_service``
    would via FastAPI's ``Depends`` chain -- there is no request/DI
    container inside a Celery task, so this composes the same real
    ``RouterService``/``PolicyService`` graph by hand, mirroring
    ``_build_policy_service`` above.

    Imported inside the function rather than at module scope: the router
    domain pulls in a large dependency graph, and this task module is
    imported by the API process too (``GuestService`` enqueues through
    it), where none of that is needed."""
    from app.domains.queue_management.repository import QueueManagementRepository
    from app.domains.queue_management.service import QueueManagementService
    from app.domains.rbac.repository import RBACRepository
    from app.domains.router.repository import RouterRepository
    from app.domains.router.service import RouterService

    organization_service = OrganizationService(OrganizationRepository(session))
    location_service = LocationService(
        LocationRepository(session),
        organization_service,
        location_code_counter=LocationCodeCounterRepository(session),
    )
    router_service = RouterService(
        RouterRepository(session), organization_service, location_service
    )
    return QueueManagementService(
        QueueManagementRepository(session),
        router_service,
        _build_policy_service(session),
        audit_writer=RBACRepository(session),
    )


async def _assign_guest_queue_async(
    *,
    organization_id: str | None,
    location_id: str,
    router_id: str,
    session_id: str,
    device_target: str,
    guest_id: str | None,
) -> None:
    """The actual async work behind ``assign_guest_queue`` -- a fresh
    ``AsyncSession`` per task run, mirroring every other task in this
    module.

    Every value it needs arrives as an argument. Nothing is re-read from
    ``guest_sessions``, which is what makes this free of a read-your-own-
    write race against the request that enqueued it: the API request's own
    commit may not have landed when the worker picks this up, and
    ``QueueAssignment.target_id`` is deliberately not a foreign key (see
    ``queue_management.models``' own docstring), so the assignment does
    not need the session row to exist yet."""
    async with SessionLocal() as session:
        try:
            service = _build_queue_management_service(session)
            await service.resolve_and_assign_queue(
                requesting_organization_id=(
                    uuid.UUID(organization_id) if organization_id else None
                ),
                location_id=uuid.UUID(location_id),
                router_id=uuid.UUID(router_id),
                target_type=QueueTargetType.SESSION,
                target_id=uuid.UUID(session_id),
                device_target=device_target,
                guest_id=uuid.UUID(guest_id) if guest_id else None,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@celery_app.task(
    name=TASK_ASSIGN_GUEST_QUEUE,
    bind=True,
    max_retries=ASSIGN_GUEST_QUEUE_MAX_RETRIES,
)
def assign_guest_queue(
    self,
    *,
    organization_id: str | None,
    location_id: str,
    router_id: str,
    session_id: str,
    device_target: str,
    guest_id: str | None = None,
) -> dict[str, object]:
    """Applies a guest session's policy-resolved bandwidth queue to the
    venue's router. Enqueued per login by
    ``GuestService._assign_guest_queue``; never Beat-scheduled.

    Arguments are strings, not UUIDs -- ``app.core.celery_app`` configures
    JSON-only serialization (never pickle), so a UUID would not survive
    the broker.

    Retries on failure, unlike the inline call this replaces, which could
    only swallow. That is a real behavioural gain and not just a
    relocation: a router that was rebooting during a login used to lose
    that guest's queue permanently."""
    try:
        run_celery_task(
            _assign_guest_queue_async(
                organization_id=organization_id,
                location_id=location_id,
                router_id=router_id,
                session_id=session_id,
                device_target=device_target,
                guest_id=guest_id,
            )
        )
    except Exception as exc:
        logger.warning(
            "guest_task_assign_guest_queue_failed",
            extra={"session_id": session_id, "error": str(exc)},
        )
        raise self.retry(
            exc=exc, countdown=ASSIGN_GUEST_QUEUE_RETRY_BACKOFF_SECONDS
        ) from exc
    logger.info(
        "guest_task_assign_guest_queue_completed",
        extra={"session_id": session_id},
    )
    return {"session_id": session_id}


async def enqueue_guest_queue_assignment(
    *,
    organization_id: uuid.UUID | None,
    location_id: uuid.UUID,
    router_id: uuid.UUID,
    session_id: uuid.UUID,
    device_target: str,
    guest_id: uuid.UUID | None,
) -> None:
    """The dispatcher ``GuestService`` is wired with -- publishes the task
    and returns, so the guest's login response no longer waits on a router.

    ``.delay()`` is Kombu's *synchronous* broker publish. It is a single
    Redis command, but calling it directly from an async request handler
    would block the event loop, so it is pushed to a thread. That is the
    difference between "the router connect is off the request path" and
    "the request path now blocks on a broker instead".

    Never raises: queueing is a quality-of-service concern, and a broker
    hiccup must not fail a login that has otherwise succeeded -- the
    identical best-effort posture ``_assign_guest_queue`` has always had.
    """
    from asyncio import to_thread

    def _publish() -> None:
        assign_guest_queue.delay(
            organization_id=str(organization_id) if organization_id else None,
            location_id=str(location_id),
            router_id=str(router_id),
            session_id=str(session_id),
            device_target=device_target,
            guest_id=str(guest_id) if guest_id else None,
        )

    try:
        await to_thread(_publish)
    except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
        logger.warning(
            "guest_queue_assignment_enqueue_failed",
            extra={"session_id": str(session_id), "error": str(exc)},
        )


__all__ = [
    "run_session_timeout_sweep",
    "run_fup_time_accrual_sweep",
    "run_quota_reset_sweep",
    "assign_guest_queue",
    "enqueue_guest_queue_assignment",
]
