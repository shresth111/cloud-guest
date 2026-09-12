"""Data access layer for the Network Diagnostics domain.

Mirrors ``app.domains.device_sync.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``NetworkDiagnosticsRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``NetworkDiagnosticsRepository``). ``DiagnosticRun`` remains
create-and-read only for every request-path caller (see ``models.py``'s
own module docstring) -- the one write that is not a create is
:meth:`NetworkDiagnosticsRepository.delete_runs_older_than`, which exists
solely for the retention sweep in ``tasks.py`` and is a hard ``DELETE``
for the reason ``constants.py``'s retention section gives.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import DiagnosticRun


class NetworkDiagnosticsRepositoryProtocol(Protocol):
    async def create_run(self, **fields: object) -> DiagnosticRun: ...

    async def get_run_by_id(self, run_id: uuid.UUID) -> DiagnosticRun | None: ...

    async def list_runs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[DiagnosticRun], PaginationMeta]: ...

    async def delete_runs_older_than(
        self, cutoff: datetime, *, batch_size: int
    ) -> int: ...


class NetworkDiagnosticsRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``NetworkDiagnosticsRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.runs = GenericRepository(DiagnosticRun, session)

    async def create_run(self, **fields: object) -> DiagnosticRun:
        return await self.runs.create(fields)

    async def get_run_by_id(self, run_id: uuid.UUID) -> DiagnosticRun | None:
        return await self.runs.get_by_id(run_id)

    async def list_runs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[DiagnosticRun], PaginationMeta]:
        """``location_id`` narrows the history to one site.

        ``DiagnosticRun.location_id`` has been written on every row since
        the table shipped and was, until now, never read by anything: the
        column existed, the index existed, and no query used either. That
        is what made ``GET /runs`` an organization-wide read for a
        location-scoped caller -- see ``service.list_runs`` for who now
        supplies this.
        """
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        if location_id is not None:
            filters["location_id"] = location_id
        return await self.runs.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    async def delete_runs_older_than(self, cutoff: datetime, *, batch_size: int) -> int:
        """Hard-deletes up to ``batch_size`` runs created before ``cutoff``
        and returns how many rows actually went.

        One bounded batch per call, by ``id`` drawn from a ``LIMIT``ed
        subquery, so the caller (``tasks.run_diagnostic_run_retention_sweep``)
        decides how many batches one sweep does rather than this method
        holding one unbounded ``DELETE`` -- and its transaction, and its
        locks -- over a table live requests are inserting into. A returned
        count below ``batch_size`` means the backlog is drained.

        Not a soft delete: ``constants.DIAGNOSTIC_RUN_RETENTION_DAYS``
        explains why a sweep whose entire purpose is to bound table growth
        cannot leave the rows in the table.
        """
        doomed = (
            select(DiagnosticRun.id)
            .where(DiagnosticRun.created_at < cutoff)
            .limit(batch_size)
        )
        result = await self.session.execute(
            delete(DiagnosticRun).where(DiagnosticRun.id.in_(doomed))
        )
        return int(result.rowcount or 0)


__all__ = ["NetworkDiagnosticsRepositoryProtocol", "NetworkDiagnosticsRepository"]
