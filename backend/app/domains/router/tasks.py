"""Celery Beat task for the Router domain's enrollment-token expiry cleanup
sweep.

``RouterProvisioningToken`` (``models.py``) has always carried
``expires_at``/``used_at``, and ``RouterService.check_in`` has always
honestly rejected an expired or already-used token
(``ProvisioningTokenExpiredError``/``ProvisioningTokenAlreadyUsedError``) --
but nothing has ever actually swept and soft-deleted the expired-but-unused
rows themselves, so they simply accumulated forever. This module closes
that gap the exact same way every other Beat-scheduled sweep in this
codebase does: a plain, synchronous ``@celery_app.task`` body delegating to
a module-level ``async def`` via ``asyncio.run``, which opens a fresh
``AsyncSession`` (``app.database.session.SessionLocal``, never the FastAPI
``Depends`` machinery, which has no meaning inside a Celery worker), builds
a real ``RouterService`` by hand, does the actual work
(``RouterService.sweep_expired_provisioning_tokens`` -- see that method's
own docstring for the per-token failure-isolation contract), commits, and
returns a plain, JSON-serializable result.

``_build_router_service`` manually replicates
``app.domains.router.dependencies.get_router_service``'s own construction --
the identical ``app.domains.isp.tasks._build_router_service``/
``app.domains.connected_devices.tasks._build_router_service`` precedent for
composing a multi-dependency service by hand inside a Celery task, since
FastAPI's DI machinery cannot run outside a request.
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

from .constants import TASK_RUN_PROVISIONING_TOKEN_CLEANUP_SWEEP
from .repository import RouterRepository
from .service import RouterService

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


async def _run_provisioning_token_cleanup_sweep_async() -> int:
    async with SessionLocal() as session:
        try:
            router_service = _build_router_service(session)
            cleaned = await router_service.sweep_expired_provisioning_tokens()
            await session.commit()
            return cleaned
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_PROVISIONING_TOKEN_CLEANUP_SWEEP)
def run_provisioning_token_cleanup_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.PROVISIONING_TOKEN_CLEANUP_SWEEP_INTERVAL_SECONDS``)."""
    cleaned = run_celery_task(_run_provisioning_token_cleanup_sweep_async())
    result = {"cleaned": cleaned}
    logger.info(
        "router_task_run_provisioning_token_cleanup_sweep_completed", extra=result
    )
    return result


__all__ = ["run_provisioning_token_cleanup_sweep"]
