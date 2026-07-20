"""Data access layer for the Queue Management Engine domain.

Mirrors ``app.domains.provisioning_engine.repository``'s shape: a
``Protocol`` describing every operation the service layer needs
(``QueueManagementRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``QueueManagementRepository``) bundling all four of this module's tables
behind one repository object. Unlike ``provisioning_engine``/
``router_provisioning``, this domain has no Redis-backed queue dispatcher --
``apply_queue``/``remove_queue`` are synchronous, single-device-connection
operations (see ``service.py``'s own module docstring), not a durable,
retryable background job.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, select

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import QueueAssignment, QueueProfile, QueueSchedule, QueueTemplate


class QueueManagementRepositoryProtocol(Protocol):
    # -- profiles --------------------------------------------------------------
    async def create_profile(self, **fields: object) -> QueueProfile: ...

    async def get_profile_by_id(
        self, profile_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QueueProfile | None: ...

    async def update_profile(
        self, profile: QueueProfile, data: dict[str, object]
    ) -> QueueProfile: ...

    async def soft_delete_profile(self, profile: QueueProfile) -> QueueProfile: ...

    async def list_profiles(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[QueueProfile], PaginationMeta]: ...

    # -- schedules -------------------------------------------------------------
    async def create_schedule(self, **fields: object) -> QueueSchedule: ...

    async def get_schedule_by_id(
        self, schedule_id: uuid.UUID
    ) -> QueueSchedule | None: ...

    async def update_schedule(
        self, schedule: QueueSchedule, data: dict[str, object]
    ) -> QueueSchedule: ...

    async def list_schedules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[QueueSchedule], PaginationMeta]: ...

    # -- templates ---------------------------------------------------------------
    async def create_template(self, **fields: object) -> QueueTemplate: ...

    async def get_template_by_id(
        self, template_id: uuid.UUID
    ) -> QueueTemplate | None: ...

    async def update_template(
        self, template: QueueTemplate, data: dict[str, object]
    ) -> QueueTemplate: ...

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[QueueTemplate], PaginationMeta]: ...

    # -- assignments -----------------------------------------------------------
    async def create_assignment(self, **fields: object) -> QueueAssignment: ...

    async def get_assignment_by_id(
        self, assignment_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QueueAssignment | None: ...

    async def update_assignment(
        self, assignment: QueueAssignment, data: dict[str, object]
    ) -> QueueAssignment: ...

    async def list_assignments(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[QueueAssignment], PaginationMeta]: ...

    async def get_active_assignment_for_target(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> QueueAssignment | None: ...


async def _paginate_org_or_system(
    session,  # noqa: ANN001
    model: type,
    requesting_organization_id: uuid.UUID | None,
    page: int,
    page_size: int,
) -> tuple[list, PaginationMeta]:
    """Shared "this org's own rows, plus every platform-wide (``
    organization_id IS NULL``) system row" query -- mirrors
    ``app.domains.router_provisioning.repository.RouterProvisioningRepository
    .list_templates``'s own identical real-SQL pattern (an ``OR`` condition
    the generic ``GenericRepository.paginate``'s exact-match ``filters``
    dict cannot express). Shared across ``QueueProfile``/``QueueSchedule``/
    ``QueueTemplate`` since all three use the identical nullable
    ``organization_id`` convention."""
    params = PageParams(page=page, page_size=page_size)
    conditions = [model.is_deleted.is_(False)]
    if requesting_organization_id is not None:
        conditions.append(
            (model.organization_id == requesting_organization_id)
            | (model.organization_id.is_(None))
        )

    count_statement = select(func.count()).select_from(model).where(*conditions)
    total_result = await session.execute(count_statement)
    total_items = int(total_result.scalar_one())

    statement = select(model).where(*conditions).order_by(model.created_at.desc())
    result = await session.execute(paginate(statement, params))
    rows = list(result.scalars().all())
    return rows, PaginationMeta.from_total(params, total_items)


class QueueManagementRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``QueueManagementRepositoryProtocol``."""

    def __init__(self, session) -> None:  # noqa: ANN001
        self.session = session
        self.profiles = GenericRepository(QueueProfile, session)
        self.schedules = GenericRepository(QueueSchedule, session)
        self.templates = GenericRepository(QueueTemplate, session)
        self.assignments = GenericRepository(QueueAssignment, session)

    # -- profiles --------------------------------------------------------------

    async def create_profile(self, **fields: object) -> QueueProfile:
        return await self.profiles.create(fields)

    async def get_profile_by_id(
        self, profile_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QueueProfile | None:
        return await self.profiles.get_by_id(
            profile_id, include_deleted=include_deleted
        )

    async def update_profile(
        self, profile: QueueProfile, data: dict[str, object]
    ) -> QueueProfile:
        return await self.profiles.update(profile, data)

    async def soft_delete_profile(self, profile: QueueProfile) -> QueueProfile:
        return await self.profiles.soft_delete(profile)

    async def list_profiles(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[QueueProfile], PaginationMeta]:
        return await _paginate_org_or_system(
            self.session, QueueProfile, requesting_organization_id, page, page_size
        )

    # -- schedules -------------------------------------------------------------

    async def create_schedule(self, **fields: object) -> QueueSchedule:
        return await self.schedules.create(fields)

    async def get_schedule_by_id(self, schedule_id: uuid.UUID) -> QueueSchedule | None:
        return await self.schedules.get_by_id(schedule_id)

    async def update_schedule(
        self, schedule: QueueSchedule, data: dict[str, object]
    ) -> QueueSchedule:
        return await self.schedules.update(schedule, data)

    async def list_schedules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[QueueSchedule], PaginationMeta]:
        return await _paginate_org_or_system(
            self.session, QueueSchedule, requesting_organization_id, page, page_size
        )

    # -- templates ---------------------------------------------------------------

    async def create_template(self, **fields: object) -> QueueTemplate:
        return await self.templates.create(fields)

    async def get_template_by_id(self, template_id: uuid.UUID) -> QueueTemplate | None:
        return await self.templates.get_by_id(template_id)

    async def update_template(
        self, template: QueueTemplate, data: dict[str, object]
    ) -> QueueTemplate:
        return await self.templates.update(template, data)

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[QueueTemplate], PaginationMeta]:
        return await _paginate_org_or_system(
            self.session, QueueTemplate, requesting_organization_id, page, page_size
        )

    # -- assignments -------------------------------------------------------------

    async def create_assignment(self, **fields: object) -> QueueAssignment:
        return await self.assignments.create(fields)

    async def get_assignment_by_id(
        self, assignment_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QueueAssignment | None:
        return await self.assignments.get_by_id(
            assignment_id, include_deleted=include_deleted
        )

    async def update_assignment(
        self, assignment: QueueAssignment, data: dict[str, object]
    ) -> QueueAssignment:
        return await self.assignments.update(assignment, data)

    async def list_assignments(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[QueueAssignment], PaginationMeta]:
        return await self.assignments.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def get_active_assignment_for_target(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> QueueAssignment | None:
        """The current (non-superseded, non-expired) assignment for one
        target -- what ``move_queue``/dynamic resolution consults to decide
        "is there already a live assignment here to supersede?"."""
        candidates = await self.assignments.get_all(
            filters={"target_type": target_type, "target_id": target_id}
        )
        active = [c for c in candidates if c.status != "expired" and not c.is_deleted]
        if not active:
            return None
        return max(active, key=lambda a: a.created_at)


__all__ = ["QueueManagementRepositoryProtocol", "QueueManagementRepository"]
