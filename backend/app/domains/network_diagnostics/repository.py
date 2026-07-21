"""Data access layer for the Network Diagnostics domain.

Mirrors ``app.domains.device_sync.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``NetworkDiagnosticsRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``NetworkDiagnosticsRepository``). No ``update``/``soft_delete``
methods exist at all -- ``DiagnosticRun`` is create-and-read only (see
``models.py``'s own module docstring).
"""

from __future__ import annotations

import uuid
from typing import Protocol

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
        page: int,
        page_size: int,
    ) -> tuple[list[DiagnosticRun], PaginationMeta]: ...


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
        page: int,
        page_size: int,
    ) -> tuple[list[DiagnosticRun], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.runs.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )


__all__ = ["NetworkDiagnosticsRepositoryProtocol", "NetworkDiagnosticsRepository"]
