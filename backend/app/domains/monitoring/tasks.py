"""Celery Beat task for the Monitoring domain's Alert Engine evaluation
sweep.

``constants.ALERT_EVENT_LOOKBACK_MINUTES``'s own docstring documented, back
when it was written, that this module had no recurring scheduler: no Celery
deployment existed anywhere in this codebase yet, so
``AlertService.evaluate_alert_rules`` could only ever run on-demand (an
operator's ``POST /alerts/evaluate`` action). That constraint no longer
holds -- ``app.core.celery_app`` is real, running infrastructure now (see
its own module docstring) -- so this module closes that exact gap:
``run_alert_rule_evaluation_sweep`` is the Beat-scheduled task (see
``app.core.celery_app``'s ``beat_schedule``) that actually calls
``evaluate_alert_rules`` on a real cadence, the one piece that turns the
Alert Engine from a fully-built-but-dormant capability (a customer can
configure an ``AlertRule``, but nothing ever evaluates it) into a real,
running one.

## The async bridge, concretely

Mirrors ``app.domains.isp.tasks``/``app.domains.notification.tasks``'s
identical bridge pattern: a plain, synchronous ``@celery_app.task`` body
delegating to a module-level ``async def`` via
``app.core.async_task_bridge.run_celery_task``, which opens a fresh
``AsyncSession``, builds the real repository/service graph, does the actual
work, commits, and returns a plain, JSON-serializable result.

## No fan-out, no Redis overlap-prevention lock

Unlike ``app.domains.provisioning_engine.tasks.run_router_health_poll_sweep``
(a *coordinator* that fans out one real per-router RouterOS API round trip
per leaf task, the actual scale risk that pattern exists to close),
``evaluate_alert_rules`` never performs any per-device I/O of its own -- it
only reads already-persisted state (``ServiceHealth``, ``Router
.health_status``, ``RouterHealthSnapshot``, ``IspLink.health_status``,
``PlatformEvent``) and writes ``Alert`` rows, dispatching outbound
notifications through ``NotificationService`` (a handful of webhook/email/
SMS calls per newly-triggered/resolved alert, not one per rule or per
router). This is the same risk profile ``app.domains.isp.tasks
.run_isp_health_check_sweep`` documents for its own still-sequential (not
yet fanned-out) sweep -- a single Beat-scheduled task, run to completion
well within this task's own 15-minute cadence, is the right shape here, not
fan-out infrastructure this task's own workload does not need.

## Fresh Redis client and HTTP client per invocation

A fresh ``redis.asyncio.Redis`` client (never the shared module-level
``app.database.redis.redis_client`` singleton) and a fresh
``httpx.AsyncClient`` are constructed inside the async function and closed
before it returns -- the identical "a fresh ``asyncio.run`` event loop
every tick" discipline ``app.domains.provisioning_engine.tasks``'s own
module docstring documents in full for its own fresh-Redis-client-per-run
requirement. Both clients' underlying connection pools bind to whichever
event loop was running the first time they are actually used; reusing
either across separate ``asyncio.run`` invocations previously caused real
cross-loop ``RuntimeError``s elsewhere in this codebase.
"""

from __future__ import annotations

import httpx

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.redis import create_redis_client
from app.database.session import SessionLocal
from app.domains.auth.repository import AuthRepository
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.location.service import LocationService
from app.domains.monitored_hardware.repository import MonitoredHardwareRepository
from app.domains.monitored_hardware.service import MonitoredHardwareService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.otp.service import (
    get_configured_email_provider,
    get_configured_sms_provider,
)
from app.domains.rbac.repository import RBACRepository
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService
from app.domains.wireguard.dependencies import (
    make_hub_peer_deregistrar,
    make_hub_peer_lister,
)
from app.domains.wireguard.repository import WireGuardRepository
from app.domains.wireguard.service import WireGuardService

from .constants import (
    TASK_RUN_ALERT_RULE_EVALUATION_SWEEP,
    TASK_RUN_HEALTH_CHECK_SWEEP,
)
from .repository import MonitoringRepository
from .service import (
    AlertEvaluationResult,
    AlertService,
    MonitoringService,
    NotificationService,
)

logger = get_logger(__name__)


async def _run_alert_rule_evaluation_sweep_async() -> AlertEvaluationResult:
    settings = get_settings()
    redis = create_redis_client()
    try:
        async with httpx.AsyncClient() as http_client, SessionLocal() as session:
            repository = MonitoringRepository(session)
            notification_service = NotificationService(
                repository,
                http_client,
                sms_provider=get_configured_sms_provider(settings),
                email_provider=get_configured_email_provider(settings),
            )
            # Real composition chain for ALERT_TARGET_MONITORED_HARDWARE
            # evaluation (access points/printers/cameras down), same
            # "construct real services here, not fake shortcuts" approach
            # this task already takes for NotificationService above.
            # location_lookup/router_lookup are never actually exercised on
            # the read-only list_all_devices_with_status path this sweep
            # calls, but MonitoredHardwareService's own constructor requires
            # real ones, not stand-ins.
            org_service = OrganizationService(OrganizationRepository(session))
            location_service = LocationService(
                LocationRepository(session),
                org_service,
                location_code_counter=LocationCodeCounterRepository(session),
            )
            router_service = RouterService(
                RouterRepository(session), location_service, org_service
            )
            monitored_hardware_service = MonitoredHardwareService(
                MonitoredHardwareRepository(session), location_service, router_service
            )
            alert_service = AlertService(
                repository,
                notification_service=notification_service,
                redis_client=redis,
                monitored_hardware_service=monitored_hardware_service,
            )
            try:
                result = await alert_service.evaluate_alert_rules()
                await session.commit()
                return result
            except Exception:
                await session.rollback()
                raise
    finally:
        await redis.aclose()


async def _run_health_check_sweep_async() -> list[str]:
    """Runs every Health Engine check once and persists the results.

    The WireGuard and auth checks are given their **real** collaborators
    rather than left as ``None``. ``MonitoringService`` treats a missing
    collaborator as ``HealthStatus.UNKNOWN``, which is the right answer for
    infrastructure that does not exist -- but here it would mean a
    scheduled sweep overwriting a component that is genuinely healthy with
    "we did not look", every five minutes, on the strength of how this task
    happened to be constructed. Same "construct real services here, not
    fake shortcuts" posture ``_run_alert_rule_evaluation_sweep_async``
    already takes.
    """
    settings = get_settings()
    redis = create_redis_client()
    try:
        async with SessionLocal() as session:
            repository = MonitoringRepository(session)
            org_service = OrganizationService(OrganizationRepository(session))
            location_service = LocationService(
                LocationRepository(session),
                org_service,
                location_code_counter=LocationCodeCounterRepository(session),
            )
            router_service = RouterService(
                RouterRepository(session), location_service, org_service
            )
            service = MonitoringService(
                repository,
                redis,
                settings,
                auth_repository=AuthRepository(session),
                wireguard_service=WireGuardService(
                    WireGuardRepository(session),
                    router_service,
                    audit_writer=RBACRepository(session),
                    handshake_stale_after_minutes=(
                        settings.wireguard_handshake_stale_after_minutes
                    ),
                    hub_peer_deregistrar=make_hub_peer_deregistrar(settings),
                    hub_peer_lister=make_hub_peer_lister(settings),
                ),
            )
            try:
                results = await service.run_all_health_checks()
                await session.commit()
                return [f"{r.component.value}={r.status.value}" for r in results]
            except Exception:
                await session.rollback()
                raise
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_RUN_HEALTH_CHECK_SWEEP)
def run_health_check_sweep() -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.HEALTH_CHECK_SWEEP_INTERVAL_SECONDS``).

    Before this existed, the only thing that ever wrote a ``HealthCheck``
    row was the Master console's own "Run health checks now" button, so the
    System Health page's timestamps were exactly as old as the last time a
    human clicked it -- two days, when this was found.
    """
    outcomes = run_celery_task(_run_health_check_sweep_async())
    logger.info(
        "monitoring_task_health_check_sweep_completed",
        extra={"components": len(outcomes), "outcomes": outcomes},
    )
    return {"components": len(outcomes), "outcomes": outcomes}


@celery_app.task(name=TASK_RUN_ALERT_RULE_EVALUATION_SWEEP)
def run_alert_rule_evaluation_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.ALERT_RULE_EVALUATION_SWEEP_INTERVAL_SECONDS``)."""
    result = run_celery_task(_run_alert_rule_evaluation_sweep_async())
    summary = {
        "triggered": len(result.triggered),
        "resolved": len(result.resolved),
    }
    logger.info("monitoring_task_alert_rule_evaluation_sweep_completed", extra=summary)
    return summary


__all__ = ["run_alert_rule_evaluation_sweep"]
