"""Data access layer for the Router Provisioning domain.

Mirrors ``app.domains.rbac.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs
(``RouterProvisioningRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``RouterProvisioningRepository``) bundling all eight of this module's
small, tightly-coupled tables behind one repository object -- the same
reasoning ``RBACRepository`` uses for bundling ``roles``/``role_permissions``/
``user_roles``/... rather than one repository class per table. Hand-written
queries are used only where ``GenericRepository``'s equality/IN filters
can't express the need (sequential version numbering, "the current applied
version," scope-filtered variable resolution, active-job lookups).

Also defines the Redis queue-dispatch seam: ``QueueDispatcherProtocol`` (a
single-method narrow protocol, ``enqueue``) and its concrete
``RedisProvisioningQueueDispatcher`` implementation. This lives here, not in
``service.py``, because it is infrastructure/data-access (a thin wrapper
around ``redis.asyncio.Redis.lpush``), not business logic -- see
``docs/router_provisioning/FLOW.md`` for the full Redis-transport/
Postgres-source-of-truth split this mirrors from ``ProvisioningJob``'s own
module docstring.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .constants import PROVISIONING_QUEUE_REDIS_KEY, ProvisioningJobStatus
from .models import (
    ConfigProfile,
    ConfigTemplate,
    ConfigVariable,
    ConfigVersion,
    ProvisioningJob,
    RouterEnrollmentRequest,
    RouterEvent,
    RouterHealthSnapshot,
)

# ============================================================================
# Queue dispatch (Redis transport)
# ============================================================================


class QueueDispatcherProtocol(Protocol):
    """The minimal surface ``RouterProvisioningService`` needs to push a
    freshly-created job onto the dispatch transport -- deliberately just one
    method, so tests can substitute an in-memory fake with zero Redis
    dependency (mirrors every other narrow, duck-typed protocol in this
    codebase)."""

    async def enqueue(self, job_id: uuid.UUID) -> None: ...


class RedisProvisioningQueueDispatcher:
    """Concrete, Redis-backed implementation of ``QueueDispatcherProtocol``.

    ``LPUSH`` onto a single list key (``PROVISIONING_QUEUE_REDIS_KEY``) --
    purely a wake-up signal for a future worker (``app.domains.router_agent``)
    to ``BRPOP``/``RPOP`` and drain. Nothing here is ever read back by this
    module; ``provisioning_jobs`` (Postgres) is the only place job state is
    actually queried from.
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def enqueue(self, job_id: uuid.UUID) -> None:
        await self.redis.lpush(PROVISIONING_QUEUE_REDIS_KEY, str(job_id))


# ============================================================================
# Repository protocol
# ============================================================================


class RouterProvisioningRepositoryProtocol(Protocol):
    # -- templates -----------------------------------------------------------
    async def get_template(
        self, template_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ConfigTemplate | None: ...

    async def create_template(self, **fields: object) -> ConfigTemplate: ...

    async def update_template(
        self, template: ConfigTemplate, data: dict[str, object]
    ) -> ConfigTemplate: ...

    async def soft_delete_template(
        self, template: ConfigTemplate
    ) -> ConfigTemplate: ...

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ConfigTemplate], PaginationMeta]: ...

    # -- variables -------------------------------------------------------------
    async def get_variable(self, variable_id: uuid.UUID) -> ConfigVariable | None: ...

    async def find_variable(
        self,
        *,
        scope_type: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
        key: str,
    ) -> ConfigVariable | None: ...

    async def create_variable(self, **fields: object) -> ConfigVariable: ...

    async def update_variable(
        self, variable: ConfigVariable, data: dict[str, object]
    ) -> ConfigVariable: ...

    async def soft_delete_variable(
        self, variable: ConfigVariable
    ) -> ConfigVariable: ...

    async def list_global_variables(self) -> list[ConfigVariable]: ...

    async def list_organization_variables(
        self, organization_id: uuid.UUID
    ) -> list[ConfigVariable]: ...

    async def list_location_variables(
        self, location_id: uuid.UUID
    ) -> list[ConfigVariable]: ...

    async def list_router_variables(
        self, router_id: uuid.UUID
    ) -> list[ConfigVariable]: ...

    async def list_variables(
        self,
        *,
        scope_type: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ConfigVariable], PaginationMeta]: ...

    # -- profiles --------------------------------------------------------------
    async def get_profile(self, profile_id: uuid.UUID) -> ConfigProfile | None: ...

    async def get_profile_for_router(
        self, router_id: uuid.UUID
    ) -> ConfigProfile | None: ...

    async def create_profile(self, **fields: object) -> ConfigProfile: ...

    async def update_profile(
        self, profile: ConfigProfile, data: dict[str, object]
    ) -> ConfigProfile: ...

    # -- versions --------------------------------------------------------------
    async def get_version(self, version_id: uuid.UUID) -> ConfigVersion | None: ...

    async def create_version(self, **fields: object) -> ConfigVersion: ...

    async def update_version(
        self, version: ConfigVersion, data: dict[str, object]
    ) -> ConfigVersion: ...

    async def get_next_version_number(self, router_id: uuid.UUID) -> int: ...

    async def get_latest_applied_version(
        self, router_id: uuid.UUID, *, exclude_version_id: uuid.UUID | None = None
    ) -> ConfigVersion | None: ...

    async def get_latest_version_for_router(
        self, router_id: uuid.UUID
    ) -> ConfigVersion | None: ...

    async def list_versions_for_router(
        self, router_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[ConfigVersion], PaginationMeta]: ...

    # -- enrollment --------------------------------------------------------------
    async def get_enrollment(
        self, enrollment_id: uuid.UUID
    ) -> RouterEnrollmentRequest | None: ...

    async def create_enrollment(self, **fields: object) -> RouterEnrollmentRequest: ...

    async def update_enrollment(
        self, enrollment: RouterEnrollmentRequest, data: dict[str, object]
    ) -> RouterEnrollmentRequest: ...

    async def find_pending_enrollment(
        self, *, serial_number: str, mac_address: str
    ) -> RouterEnrollmentRequest | None: ...

    async def list_pending_enrollments(
        self, *, page: int, page_size: int
    ) -> tuple[list[RouterEnrollmentRequest], PaginationMeta]: ...

    # -- provisioning jobs -------------------------------------------------------
    async def get_job(self, job_id: uuid.UUID) -> ProvisioningJob | None: ...

    async def create_job(self, **fields: object) -> ProvisioningJob: ...

    async def update_job(
        self, job: ProvisioningJob, data: dict[str, object]
    ) -> ProvisioningJob: ...

    async def list_jobs_for_router(
        self, router_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[ProvisioningJob], PaginationMeta]: ...

    async def list_active_jobs_for_router(
        self, router_id: uuid.UUID
    ) -> list[ProvisioningJob]: ...

    # -- health / events ---------------------------------------------------------
    async def create_health_snapshot(
        self, **fields: object
    ) -> RouterHealthSnapshot: ...

    async def list_health_snapshots_for_router(
        self, router_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[RouterHealthSnapshot], PaginationMeta]: ...

    async def create_event(self, **fields: object) -> RouterEvent: ...

    async def list_events_for_router(
        self, router_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[RouterEvent], PaginationMeta]: ...


# ============================================================================
# Concrete implementation
# ============================================================================


class RouterProvisioningRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``RouterProvisioningRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.templates = GenericRepository(ConfigTemplate, session)
        self.variables = GenericRepository(ConfigVariable, session)
        self.profiles = GenericRepository(ConfigProfile, session)
        self.versions = GenericRepository(ConfigVersion, session)
        self.enrollments = GenericRepository(RouterEnrollmentRequest, session)
        self.jobs = GenericRepository(ProvisioningJob, session)
        self.health_snapshots = GenericRepository(RouterHealthSnapshot, session)
        self.events = GenericRepository(RouterEvent, session)

    # -- templates -----------------------------------------------------------

    async def get_template(
        self, template_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ConfigTemplate | None:
        return await self.templates.get_by_id(
            template_id, include_deleted=include_deleted
        )

    async def create_template(self, **fields: object) -> ConfigTemplate:
        return await self.templates.create(fields)

    async def update_template(
        self, template: ConfigTemplate, data: dict[str, object]
    ) -> ConfigTemplate:
        return await self.templates.update(template, data)

    async def soft_delete_template(self, template: ConfigTemplate) -> ConfigTemplate:
        return await self.templates.soft_delete(template)

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ConfigTemplate], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        conditions = [ConfigTemplate.is_deleted.is_(False)]
        if requesting_organization_id is not None:
            conditions.append(
                (ConfigTemplate.organization_id == requesting_organization_id)
                | (ConfigTemplate.organization_id.is_(None))
            )

        count_statement = (
            select(func.count()).select_from(ConfigTemplate).where(*conditions)
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = (
            select(ConfigTemplate)
            .where(*conditions)
            .order_by(ConfigTemplate.created_at.desc())
        )
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    # -- variables -------------------------------------------------------------

    async def get_variable(self, variable_id: uuid.UUID) -> ConfigVariable | None:
        return await self.variables.get_by_id(variable_id)

    async def find_variable(
        self,
        *,
        scope_type: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
        key: str,
    ) -> ConfigVariable | None:
        statement = select(ConfigVariable).where(
            ConfigVariable.is_deleted.is_(False),
            ConfigVariable.scope_type == scope_type,
            ConfigVariable.organization_id == organization_id
            if organization_id is not None
            else ConfigVariable.organization_id.is_(None),
            ConfigVariable.location_id == location_id
            if location_id is not None
            else ConfigVariable.location_id.is_(None),
            ConfigVariable.router_id == router_id
            if router_id is not None
            else ConfigVariable.router_id.is_(None),
            ConfigVariable.key == key,
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def create_variable(self, **fields: object) -> ConfigVariable:
        return await self.variables.create(fields)

    async def update_variable(
        self, variable: ConfigVariable, data: dict[str, object]
    ) -> ConfigVariable:
        return await self.variables.update(variable, data)

    async def soft_delete_variable(self, variable: ConfigVariable) -> ConfigVariable:
        return await self.variables.soft_delete(variable)

    async def list_global_variables(self) -> list[ConfigVariable]:
        statement = select(ConfigVariable).where(
            ConfigVariable.is_deleted.is_(False),
            ConfigVariable.scope_type == "organization",
            ConfigVariable.organization_id.is_(None),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_organization_variables(
        self, organization_id: uuid.UUID
    ) -> list[ConfigVariable]:
        return await self.variables.get_all(
            filters={"scope_type": "organization", "organization_id": organization_id}
        )

    async def list_location_variables(
        self, location_id: uuid.UUID
    ) -> list[ConfigVariable]:
        return await self.variables.get_all(
            filters={"scope_type": "location", "location_id": location_id}
        )

    async def list_router_variables(self, router_id: uuid.UUID) -> list[ConfigVariable]:
        return await self.variables.get_all(
            filters={"scope_type": "router", "router_id": router_id}
        )

    async def list_variables(
        self,
        *,
        scope_type: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ConfigVariable], PaginationMeta]:
        return await self.variables.paginate(
            page=page,
            page_size=page_size,
            filters={"scope_type": scope_type} if scope_type else None,
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    # -- profiles --------------------------------------------------------------

    async def get_profile(self, profile_id: uuid.UUID) -> ConfigProfile | None:
        return await self.profiles.get_by_id(profile_id)

    async def get_profile_for_router(
        self, router_id: uuid.UUID
    ) -> ConfigProfile | None:
        results = await self.profiles.get_all(filters={"router_id": router_id}, limit=1)
        return results[0] if results else None

    async def create_profile(self, **fields: object) -> ConfigProfile:
        return await self.profiles.create(fields)

    async def update_profile(
        self, profile: ConfigProfile, data: dict[str, object]
    ) -> ConfigProfile:
        return await self.profiles.update(profile, data)

    # -- versions --------------------------------------------------------------

    async def get_version(self, version_id: uuid.UUID) -> ConfigVersion | None:
        return await self.versions.get_by_id(version_id)

    async def create_version(self, **fields: object) -> ConfigVersion:
        return await self.versions.create(fields)

    async def update_version(
        self, version: ConfigVersion, data: dict[str, object]
    ) -> ConfigVersion:
        return await self.versions.update(version, data)

    async def get_next_version_number(self, router_id: uuid.UUID) -> int:
        statement = select(func.max(ConfigVersion.version_number)).where(
            ConfigVersion.router_id == router_id
        )
        result = await self.session.execute(statement)
        current_max = result.scalar_one_or_none()
        return (current_max or 0) + 1

    async def get_latest_applied_version(
        self, router_id: uuid.UUID, *, exclude_version_id: uuid.UUID | None = None
    ) -> ConfigVersion | None:
        conditions = [
            ConfigVersion.router_id == router_id,
            ConfigVersion.is_deleted.is_(False),
            ConfigVersion.is_backup.is_(False),
            ConfigVersion.status == "applied",
        ]
        if exclude_version_id is not None:
            conditions.append(ConfigVersion.id != exclude_version_id)
        statement = (
            select(ConfigVersion)
            .where(*conditions)
            .order_by(ConfigVersion.version_number.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_latest_version_for_router(
        self, router_id: uuid.UUID
    ) -> ConfigVersion | None:
        statement = (
            select(ConfigVersion)
            .where(
                ConfigVersion.router_id == router_id,
                ConfigVersion.is_deleted.is_(False),
            )
            .order_by(ConfigVersion.version_number.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def list_versions_for_router(
        self, router_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[ConfigVersion], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        conditions = [
            ConfigVersion.router_id == router_id,
            ConfigVersion.is_deleted.is_(False),
        ]
        count_statement = (
            select(func.count()).select_from(ConfigVersion).where(*conditions)
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = (
            select(ConfigVersion)
            .where(*conditions)
            .order_by(ConfigVersion.version_number.desc())
        )
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    # -- enrollment --------------------------------------------------------------

    async def get_enrollment(
        self, enrollment_id: uuid.UUID
    ) -> RouterEnrollmentRequest | None:
        return await self.enrollments.get_by_id(enrollment_id)

    async def create_enrollment(self, **fields: object) -> RouterEnrollmentRequest:
        return await self.enrollments.create(fields)

    async def update_enrollment(
        self, enrollment: RouterEnrollmentRequest, data: dict[str, object]
    ) -> RouterEnrollmentRequest:
        return await self.enrollments.update(enrollment, data)

    async def find_pending_enrollment(
        self, *, serial_number: str, mac_address: str
    ) -> RouterEnrollmentRequest | None:
        statement = select(RouterEnrollmentRequest).where(
            RouterEnrollmentRequest.is_deleted.is_(False),
            RouterEnrollmentRequest.status == "pending",
            (RouterEnrollmentRequest.serial_number == serial_number)
            | (RouterEnrollmentRequest.mac_address == mac_address),
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def list_pending_enrollments(
        self, *, page: int, page_size: int
    ) -> tuple[list[RouterEnrollmentRequest], PaginationMeta]:
        return await self.enrollments.paginate(
            page=page,
            page_size=page_size,
            filters={"status": "pending"},
            sort_by="requested_at",
            sort_order=SortOrder.ASC,
        )

    # -- provisioning jobs -------------------------------------------------------

    async def get_job(self, job_id: uuid.UUID) -> ProvisioningJob | None:
        return await self.jobs.get_by_id(job_id)

    async def create_job(self, **fields: object) -> ProvisioningJob:
        return await self.jobs.create(fields)

    async def update_job(
        self, job: ProvisioningJob, data: dict[str, object]
    ) -> ProvisioningJob:
        return await self.jobs.update(job, data)

    async def list_jobs_for_router(
        self, router_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[ProvisioningJob], PaginationMeta]:
        return await self.jobs.paginate(
            page=page,
            page_size=page_size,
            filters={"router_id": router_id},
            sort_by="scheduled_at",
            sort_order=SortOrder.DESC,
        )

    async def list_active_jobs_for_router(
        self, router_id: uuid.UUID
    ) -> list[ProvisioningJob]:
        statement = select(ProvisioningJob).where(
            ProvisioningJob.router_id == router_id,
            ProvisioningJob.is_deleted.is_(False),
            ProvisioningJob.status.in_(
                [
                    ProvisioningJobStatus.QUEUED.value,
                    ProvisioningJobStatus.RUNNING.value,
                ]
            ),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- health / events ---------------------------------------------------------

    async def create_health_snapshot(self, **fields: object) -> RouterHealthSnapshot:
        return await self.health_snapshots.create(fields)

    async def list_health_snapshots_for_router(
        self, router_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[RouterHealthSnapshot], PaginationMeta]:
        return await self.health_snapshots.paginate(
            page=page,
            page_size=page_size,
            filters={"router_id": router_id},
            sort_by="recorded_at",
            sort_order=SortOrder.DESC,
        )

    async def create_event(self, **fields: object) -> RouterEvent:
        return await self.events.create(fields)

    async def list_events_for_router(
        self, router_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[RouterEvent], PaginationMeta]:
        return await self.events.paginate(
            page=page,
            page_size=page_size,
            filters={"router_id": router_id},
            sort_by="occurred_at",
            sort_order=SortOrder.DESC,
        )
