"""Data access layer for the Provisioning Engine domain.

Mirrors ``app.domains.router_provisioning.repository``'s shape: a
``Protocol`` describing every operation the service layer needs
(``ProvisioningEngineRepositoryProtocol``), a concrete, ``GenericRepository``-
backed implementation (``ProvisioningEngineRepository``) bundling all four
of this module's tables behind one repository object, and the identical
Redis queue-dispatch seam (``QueueDispatcherProtocol``/
``RedisProvisionEngineQueueDispatcher``) -- a structurally identical
"Postgres row + Redis wake-up signal" split, given its own, distinct Redis
key since :class:`~.models.ProvisionJob` is a different row shape than
``router_provisioning``'s own ``ProvisioningJob``.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router

from .constants import PROVISION_ENGINE_QUEUE_REDIS_KEY
from .models import ProvisionJob, ProvisionLog, ProvisionStep, ProvisionTemplate

# ============================================================================
# Queue dispatch (Redis transport)
# ============================================================================


class QueueDispatcherProtocol(Protocol):
    """The minimal surface ``ProvisioningEngineService`` needs to push a
    freshly-queued job onto the dispatch transport -- one method, so tests
    can substitute an in-memory fake with zero Redis dependency."""

    async def enqueue(self, job_id: uuid.UUID) -> None: ...


class RedisProvisionEngineQueueDispatcher:
    """Concrete, Redis-backed implementation of ``QueueDispatcherProtocol``.

    ``LPUSH`` onto a single list key
    (``constants.PROVISION_ENGINE_QUEUE_REDIS_KEY``) -- purely a wake-up
    signal for ``app.domains.provisioning_engine.tasks``'s real Celery
    worker task to ``BRPOP``/``RPOP`` and drain. Nothing here is ever read
    back by this module; ``provision_jobs`` (Postgres) is the only place job
    state is actually queried from.
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def enqueue(self, job_id: uuid.UUID) -> None:
        await self.redis.lpush(PROVISION_ENGINE_QUEUE_REDIS_KEY, str(job_id))


# ============================================================================
# Repository protocol
# ============================================================================


class ProvisioningEngineRepositoryProtocol(Protocol):
    # -- jobs ----------------------------------------------------------------
    async def create_job(self, **fields: object) -> ProvisionJob: ...

    async def get_job_by_id(
        self, job_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ProvisionJob | None: ...

    async def update_job(
        self, job: ProvisionJob, data: dict[str, object]
    ) -> ProvisionJob: ...

    async def list_jobs(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ProvisionJob], PaginationMeta]: ...

    # -- steps --------------------------------------------------------------
    async def create_step(self, **fields: object) -> ProvisionStep: ...

    async def get_step_by_id(self, step_id: uuid.UUID) -> ProvisionStep | None: ...

    async def update_step(
        self, step: ProvisionStep, data: dict[str, object]
    ) -> ProvisionStep: ...

    async def list_steps_for_job(self, job_id: uuid.UUID) -> list[ProvisionStep]: ...

    # -- logs ---------------------------------------------------------------
    async def create_log(self, **fields: object) -> ProvisionLog: ...

    async def list_logs_for_job(self, job_id: uuid.UUID) -> list[ProvisionLog]: ...

    # -- templates ------------------------------------------------------------
    async def create_template(self, **fields: object) -> ProvisionTemplate: ...

    async def get_template_by_id(
        self, template_id: uuid.UUID
    ) -> ProvisionTemplate | None: ...

    async def update_template(
        self, template: ProvisionTemplate, data: dict[str, object]
    ) -> ProvisionTemplate: ...

    async def list_templates(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
    ) -> tuple[list[ProvisionTemplate], PaginationMeta]: ...

    # -- routers (cross-domain, read-only) -----------------------------------
    async def list_routers_for_health_poll(self) -> list[Router]: ...


class ProvisioningEngineRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ProvisioningEngineRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.jobs = GenericRepository(ProvisionJob, session)
        self.steps = GenericRepository(ProvisionStep, session)
        self.logs = GenericRepository(ProvisionLog, session)
        self.templates = GenericRepository(ProvisionTemplate, session)

    # -- jobs ----------------------------------------------------------------

    async def create_job(self, **fields: object) -> ProvisionJob:
        return await self.jobs.create(fields)

    async def get_job_by_id(
        self, job_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ProvisionJob | None:
        return await self.jobs.get_by_id(job_id, include_deleted=include_deleted)

    async def update_job(
        self, job: ProvisionJob, data: dict[str, object]
    ) -> ProvisionJob:
        return await self.jobs.update(job, data)

    async def list_jobs(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ProvisionJob], PaginationMeta]:
        return await self.jobs.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    # -- steps --------------------------------------------------------------

    async def create_step(self, **fields: object) -> ProvisionStep:
        return await self.steps.create(fields)

    async def get_step_by_id(self, step_id: uuid.UUID) -> ProvisionStep | None:
        return await self.steps.get_by_id(step_id)

    async def update_step(
        self, step: ProvisionStep, data: dict[str, object]
    ) -> ProvisionStep:
        return await self.steps.update(step, data)

    async def list_steps_for_job(self, job_id: uuid.UUID) -> list[ProvisionStep]:
        return await self.steps.get_all(
            filters={"job_id": job_id},
            sort_by="sequence_number",
            sort_order=SortOrder.ASC,
        )

    # -- logs ---------------------------------------------------------------

    async def create_log(self, **fields: object) -> ProvisionLog:
        return await self.logs.create(fields)

    async def list_logs_for_job(self, job_id: uuid.UUID) -> list[ProvisionLog]:
        return await self.logs.get_all(
            filters={"job_id": job_id}, sort_by="logged_at", sort_order=SortOrder.ASC
        )

    # -- templates ------------------------------------------------------------

    async def create_template(self, **fields: object) -> ProvisionTemplate:
        return await self.templates.create(fields)

    async def get_template_by_id(
        self, template_id: uuid.UUID
    ) -> ProvisionTemplate | None:
        return await self.templates.get_by_id(template_id)

    async def update_template(
        self, template: ProvisionTemplate, data: dict[str, object]
    ) -> ProvisionTemplate:
        return await self.templates.update(template, data)

    async def list_templates(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
    ) -> tuple[list[ProvisionTemplate], PaginationMeta]:
        return await self.templates.paginate(
            page=page, page_size=page_size, filters=filters
        )

    # -- routers (cross-domain, read-only) -----------------------------------

    async def list_routers_for_health_poll(self) -> list[Router]:
        """Every non-deleted, already-provisioned router (``ONLINE`` or
        ``OFFLINE`` -- excludes ``PENDING_PROVISIONING``/``PROVISIONING``,
        which never have working device credentials yet, and
        ``SUSPENDED``/``DECOMMISSIONED``, which are administratively out of
        service) -- platform-wide, for ``service.run_router_health_poll_sweep``.
        Mirrors ``app.domains.connected_devices.repository
        .ConnectedDeviceRepository.list_routers_for_sync``'s/
        ``app.domains.monitoring.repository.MonitoringRepository
        .list_routers``'s identical "a domain owning its own read-only
        cross-domain router query, not delegating to ``app.domains.router``
        itself" precedent -- there is no platform-wide "list every router"
        method on ``RouterRepository`` itself to delegate to. ``OFFLINE`` is
        deliberately included (not just ``ONLINE``): a router the platform
        currently believes is offline is exactly the one this poll needs to
        keep trying, so it can flip back to a real, honest ``ONLINE`` the
        moment it actually answers again."""
        statement = select(Router).where(
            Router.is_deleted.is_(False),
            Router.status.in_([RouterStatus.ONLINE.value, RouterStatus.OFFLINE.value]),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())


__all__ = [
    "QueueDispatcherProtocol",
    "RedisProvisionEngineQueueDispatcher",
    "ProvisioningEngineRepositoryProtocol",
    "ProvisioningEngineRepository",
]
