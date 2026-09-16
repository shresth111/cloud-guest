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
import zlib
from typing import Protocol

from sqlalchemy import func, select, text

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .constants import QueueStatus
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

    async def list_assignments_by_status(
        self, *, status: str
    ) -> list[QueueAssignment]: ...

    async def get_active_assignment_for_target(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> QueueAssignment | None: ...

    async def list_assignments_for_target(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> list[QueueAssignment]: ...

    async def list_assignments_for_device_target(
        self, *, router_id: uuid.UUID, device_target: str
    ) -> list[QueueAssignment]: ...

    async def list_system_profiles_by_rates(
        self, *, download_rate_kbps: int, upload_rate_kbps: int
    ) -> list[QueueProfile]: ...

    async def acquire_assignment_target_lock(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> None: ...

    async def acquire_profile_rate_lock(
        self, *, download_rate_kbps: int, upload_rate_kbps: int
    ) -> None: ...


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


async def _acquire_advisory_lock(
    session,  # noqa: ANN001
    *,
    namespace: bytes,
    key: str,
) -> None:
    """Transaction-scoped Postgres advisory lock on one logical key.

    ``resolve_and_assign_queue`` is a read-then-write: it asks "is there
    already a live assignment for this target?" and, when the answer is no,
    creates one. Two callers that ask that question at the same time both
    get "no" and both create -- which is exactly the duplicate this lock
    exists to stop (see that method's own docstring). The row is committed
    inside the same transaction the lock is held in, so the second waiter
    sees the first caller's row the moment it acquires the lock.

    ``pg_advisory_xact_lock(int4, int4)`` is used rather than the
    ``text``-keyed overload because the two-integer form is the documented
    one, and both halves are computed here with ``crc32`` rather than
    handed to Postgres' undocumented internal ``hashtext``. The locks are
    released by the surrounding COMMIT/ROLLBACK, never explicitly.
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:first, :second)"),
        {
            "first": zlib.crc32(namespace) & 0x7FFFFFFF,
            "second": zlib.crc32(key.encode()) & 0x7FFFFFFF,
        },
    )


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

    async def list_assignments_for_target(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> list[QueueAssignment]:
        """Every live (non-``EXPIRED``, non-deleted) assignment for one
        target, **newest first** -- the whole set, not just the newest.

        ``get_active_assignment_for_target`` below deliberately collapses
        this to one row, which is correct for "is there a live assignment
        here to supersede?" but hides a duplicate: two rows created for one
        target (see ``acquire_assignment_target_lock``'s own docstring for
        how that happened) both own their own ``/queue simple`` entry on the
        device, and RouterOS applies the *first matching* one. Returning the
        full set is what lets the service see and retire the others."""
        candidates = await self.assignments.get_all(
            filters={"target_type": target_type, "target_id": target_id}
        )
        live = [
            c
            for c in candidates
            if c.status != QueueStatus.EXPIRED.value and not c.is_deleted
        ]
        return sorted(live, key=lambda a: a.created_at, reverse=True)

    async def list_assignments_for_device_target(
        self, *, router_id: uuid.UUID, device_target: str
    ) -> list[QueueAssignment]:
        """Every live assignment on one router naming this exact
        ``device_target`` (the RouterOS ``target`` -- one concrete IP).

        Only one guest can hold an IP at a time, but several assignments can
        name it: the previous holder's, left behind when their session
        ended, and the current holder's. A ``/queue simple`` matches on one
        IP and RouterOS applies the first match in list order, so the stale
        entry silently wins and the new guest inherits a rate nobody
        configured for them. This is the lookup that makes those visible."""
        candidates = await self.assignments.get_all(
            filters={"router_id": router_id, "device_target": device_target}
        )
        return [
            c
            for c in candidates
            if c.status != QueueStatus.EXPIRED.value and not c.is_deleted
        ]

    async def list_system_profiles_by_rates(
        self, *, download_rate_kbps: int, upload_rate_kbps: int
    ) -> list[QueueProfile]:
        """Platform-wide (``organization_id IS NULL``) system profiles
        carrying exactly these rates. Replaces the ``page=1,
        page_size=100`` scan ``_get_or_create_system_profile`` used to do,
        which silently stopped finding an existing profile once the system
        kept more than a page of them -- and then quietly created another
        one on every call."""
        return await self.profiles.get_all(
            filters={
                "is_system_profile": True,
                "download_rate_kbps": download_rate_kbps,
                "upload_rate_kbps": upload_rate_kbps,
            }
        )

    async def acquire_assignment_target_lock(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> None:
        """Serializes ``resolve_and_assign_queue`` per target -- see
        ``_acquire_advisory_lock``."""
        await _acquire_advisory_lock(
            self.session,
            namespace=b"queue_assignment",
            key=f"{target_type}:{target_id}",
        )

    async def acquire_profile_rate_lock(
        self, *, download_rate_kbps: int, upload_rate_kbps: int
    ) -> None:
        """Serializes ``_get_or_create_system_profile`` per rate pair --
        see ``_acquire_advisory_lock``."""
        await _acquire_advisory_lock(
            self.session,
            namespace=b"queue_profile",
            key=f"{download_rate_kbps}:{upload_rate_kbps}",
        )

    async def get_active_assignment_for_target(
        self, *, target_type: str, target_id: uuid.UUID | None
    ) -> QueueAssignment | None:
        """The current (non-superseded, non-expired) assignment for one
        target -- what ``move_queue``/dynamic resolution consults to decide
        "is there already a live assignment here to supersede?"."""
        live = await self.list_assignments_for_target(
            target_type=target_type, target_id=target_id
        )
        return live[0] if live else None

    async def list_assignments_by_status(
        self, *, status: str
    ) -> list[QueueAssignment]:
        """Every non-deleted assignment with this exact status, platform-
        wide, **unpaginated** -- for
        ``QueueManagementService.sweep_schedule_transitions``, which must
        re-evaluate every ACTIVE/SUSPENDED assignment on each tick, not
        just the first page (``GenericRepository.get_all`` with no
        ``limit`` returns the full matching set in one query). Mirrors
        ``app.domains.provisioning_engine.repository
        .ProvisioningEngineRepository.list_routers_for_health_poll``'s/
        ``app.domains.connected_devices.repository.ConnectedDeviceRepository
        .list_routers_for_sync``'s identical "a platform-wide sweep needs
        the full table, not one page of it" precedent -- a ``page=1,
        page_size=1000`` call here silently dropped every assignment past
        the first 1000, a real, growing correctness bug as assignment
        count increases, independent of scale."""
        return await self.assignments.get_all(filters={"status": status})


__all__ = ["QueueManagementRepositoryProtocol", "QueueManagementRepository"]
