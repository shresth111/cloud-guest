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
    TASK_APPLY_ARUBA_HYBRID_QUEUE,
    TASK_REAPPLY_POLICY_ASSIGNMENTS,
    TASK_RECONCILE_ARUBA_HYBRID_QUEUES,
    TASK_RELEASE_ARUBA_HYBRID_QUEUE,
    TASK_SWEEP_SCHEDULE_TRANSITIONS,
)
from .repository import QueueManagementRepository
from .service import QueueManagementService

logger = get_logger(__name__)


#: Why both task factories below pass ``controller_speed_hook``.
#:
#: A Celery task has no ``Depends`` chain, so each of these composes the
#: service by hand -- and "by hand" is where a composition silently drifts
#: from the dependency it claims to mirror. Both of these did: the FastAPI
#: dependency passes the hook and neither of these did, so every
#: controller-managed venue was refused by *background* work while the same
#: venue succeeded through a request. The policy-publish reapply is the one
#: that mattered: it is how a venue's edited speed reaches guests who are
#: already online, and at a controller venue it reached none of them.
#:
#: ``build_controller_speed_hook`` is imported inside each factory rather
#: than at module scope, mirroring every other cross-domain import here:
#: ``network_integration.dependencies`` imports ``guest.dependencies``, so a
#: module-scope import would pull that whole graph into any process that
#: merely imports this task module.


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
    from app.domains.network_integration.client_hooks import (  # noqa: PLC0415
        build_controller_speed_hook,
    )

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
            # The same hook ``dependencies.get_queue_management_service``
            # passes. Without it this task refuses every controller-managed
            # venue -- see the module-level note above.
            controller_speed_hook=build_controller_speed_hook(session),
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
    from app.domains.network_integration.client_hooks import (  # noqa: PLC0415
        build_controller_speed_hook,
    )

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
            # The same hook ``dependencies.get_queue_management_service``
            # passes. Without it this task refuses every controller-managed
            # venue -- see the module-level note above.
            controller_speed_hook=build_controller_speed_hook(session),
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


# ============================================================================
# Aruba AP + MikroTik gateway hybrid (see speed_gateway.py)
# ============================================================================


def _build_speed_gateway_service(session):  # noqa: ANN001, ANN202
    """``SpeedGatewayService`` over the same hand-built ``QueueManagementService``
    graph the two tasks above compose (controller hook included, so the
    composition does not drift from the FastAPI dependency's)."""
    from app.domains.network_integration.client_hooks import (  # noqa: PLC0415
        build_controller_speed_hook,
    )

    from .speed_gateway import SpeedGatewayRepository, SpeedGatewayService

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
    policy_service = PolicyService(
        PolicyRepository(session),
        organization_service,
        location_service,
        audit_writer=audit_repository,
    )
    queue_service = QueueManagementService(
        QueueManagementRepository(session),
        router_service,
        policy_service,
        audit_writer=audit_repository,
        controller_speed_hook=build_controller_speed_hook(session),
    )
    return SpeedGatewayService(
        SpeedGatewayRepository(session),
        router_service,
        queue_service=queue_service,
        enabled=settings.aruba_hybrid_speed_gateway_enabled,
    )


async def _run_hybrid(work) -> dict[str, object]:  # noqa: ANN001
    async with SessionLocal() as session:
        try:
            service = _build_speed_gateway_service(session)
            result = await work(service)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return result.as_dict() if hasattr(result, "as_dict") else result


@celery_app.task(name=TASK_APPLY_ARUBA_HYBRID_QUEUE)
def apply_aruba_hybrid_queue(
    *,
    session_id: str,
    nas_router_id: str,
    framed_ip: str | None = None,
    verify: bool = False,
) -> dict[str, object]:
    """Put this guest's per-device queue on the venue's gateway MikroTik.
    Never retried here: the next Interim-Update (~5 min) re-runs it, and a
    failure must not pile retries onto an unreachable router."""
    try:
        result = run_celery_task(
            _run_hybrid(
                lambda service: service.apply_for_session(
                    session_id=uuid.UUID(session_id),
                    nas_router_id=uuid.UUID(nas_router_id),
                    framed_ip=framed_ip,
                    verify=verify,
                )
            )
        )
    except Exception as exc:  # noqa: BLE001 -- logged; next interim retries
        logger.warning(
            "aruba_hybrid_apply_failed",
            extra={"session_id": session_id, "error": str(exc)},
        )
        return {"action": "failed", "reason": str(exc)}
    return result


@celery_app.task(name=TASK_RELEASE_ARUBA_HYBRID_QUEUE)
def release_aruba_hybrid_queue(*, session_id: str) -> dict[str, object]:
    """Take an ended guest's queue off the gateway (Accounting-Stop). A
    failure leaves the assignment ACTIVE for the reconcile sweep."""
    try:
        return run_celery_task(
            _run_hybrid(
                lambda service: service.release_for_session(
                    session_id=uuid.UUID(session_id)
                )
            )
        )
    except Exception as exc:  # noqa: BLE001 -- the sweep retries
        logger.warning(
            "aruba_hybrid_release_failed",
            extra={"session_id": session_id, "error": str(exc)},
        )
        return {"action": "failed", "reason": str(exc)}


@celery_app.task(name=TASK_RECONCILE_ARUBA_HYBRID_QUEUES)
def reconcile_aruba_hybrid_queues() -> dict[str, object]:
    """Beat: release gateway queues whose session has ended and whose AP-side
    cut-off has passed. Does nothing unless
    CLOUDGUEST_ARUBA_HYBRID_SPEED_GATEWAY_ENABLED is true."""
    if not get_settings().aruba_hybrid_speed_gateway_enabled:
        return {"checked": 0, "released": 0, "failed": 0, "kept": 0}
    result = run_celery_task(_run_hybrid(lambda service: service.reconcile()))
    logger.info("aruba_hybrid_reconcile_completed", extra=result)
    return result


async def enqueue_aruba_hybrid_apply(
    *,
    session_id: uuid.UUID,
    nas_router_id: uuid.UUID,
    framed_ip: str | None,
    verify: bool,
) -> None:
    """Publish from the RADIUS request path without blocking the event loop.
    Never raises (an accounting packet must never fail on a broker hiccup)."""
    from asyncio import to_thread  # noqa: PLC0415

    def _publish() -> None:
        apply_aruba_hybrid_queue.delay(
            session_id=str(session_id),
            nas_router_id=str(nas_router_id),
            framed_ip=framed_ip,
            verify=verify,
        )

    try:
        await to_thread(_publish)
    except Exception as exc:  # noqa: BLE001 -- see docstring
        logger.warning(
            "aruba_hybrid_apply_enqueue_failed",
            extra={"session_id": str(session_id), "error": str(exc)},
        )


async def enqueue_aruba_hybrid_release(*, session_id: uuid.UUID) -> None:
    """See ``enqueue_aruba_hybrid_apply``."""
    from asyncio import to_thread  # noqa: PLC0415

    def _publish() -> None:
        release_aruba_hybrid_queue.delay(session_id=str(session_id))

    try:
        await to_thread(_publish)
    except Exception as exc:  # noqa: BLE001 -- see docstring
        logger.warning(
            "aruba_hybrid_release_enqueue_failed",
            extra={"session_id": str(session_id), "error": str(exc)},
        )


__all__ = [
    "sweep_schedule_transitions",
    "reapply_policy_assignments",
    "apply_aruba_hybrid_queue",
    "release_aruba_hybrid_queue",
    "reconcile_aruba_hybrid_queues",
    "enqueue_aruba_hybrid_apply",
    "enqueue_aruba_hybrid_release",
]
