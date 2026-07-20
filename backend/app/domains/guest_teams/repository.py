"""Data access layer for the Guest Teams domain.

Mirrors ``app.domains.voucher.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``GuestTeamRepositoryProtocol``), and a concrete, ``GenericRepository``-
backed implementation (``GuestTeamRepository``) wrapping two
``GenericRepository`` instances (one per table), plus a small number of
hand-written queries for the lookups ``GenericRepository``'s plain
equality/IN-filter support cannot express on its own (a batch existing-codes
check, an active-membership count/lookup).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import GuestTeam, GuestTeamMember


class GuestTeamRepositoryProtocol(Protocol):
    # -- teams -------------------------------------------------------------
    async def create_team(self, **fields: object) -> GuestTeam: ...

    async def get_team_by_id(
        self, team_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestTeam | None: ...

    async def get_team_by_code(self, team_code: str) -> GuestTeam | None: ...

    async def update_team(
        self, team: GuestTeam, data: dict[str, object]
    ) -> GuestTeam: ...

    async def list_teams(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[GuestTeam], PaginationMeta]: ...

    async def find_existing_codes(self, codes: Sequence[str]) -> list[str]: ...

    # -- members -------------------------------------------------------------
    async def create_member(self, **fields: object) -> GuestTeamMember: ...

    async def get_active_membership(
        self, team_id: uuid.UUID, guest_id: uuid.UUID
    ) -> GuestTeamMember | None: ...

    async def update_member(
        self, member: GuestTeamMember, data: dict[str, object]
    ) -> GuestTeamMember: ...

    async def count_active_members(self, team_id: uuid.UUID) -> int: ...

    async def list_active_members(
        self, team_id: uuid.UUID
    ) -> list[GuestTeamMember]: ...


class GuestTeamRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``GuestTeamRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.teams = GenericRepository(GuestTeam, session)
        self.members = GenericRepository(GuestTeamMember, session)

    # -- teams -------------------------------------------------------------

    async def create_team(self, **fields: object) -> GuestTeam:
        return await self.teams.create(fields)

    async def get_team_by_id(
        self, team_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestTeam | None:
        return await self.teams.get_by_id(team_id, include_deleted=include_deleted)

    async def get_team_by_code(self, team_code: str) -> GuestTeam | None:
        results = await self.teams.get_all(filters={"team_code": team_code}, limit=1)
        return results[0] if results else None

    async def update_team(self, team: GuestTeam, data: dict[str, object]) -> GuestTeam:
        return await self.teams.update(team, data)

    async def list_teams(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[GuestTeam], PaginationMeta]:
        return await self.teams.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def find_existing_codes(self, codes: Sequence[str]) -> list[str]:
        """Mirrors ``app.domains.voucher.repository.VoucherRepository
        .find_existing_codes`` exactly -- same in-clause existence-check
        shape, reused for this module's own join-code collision retry."""
        if not codes:
            return []
        results = await self.teams.get_all(
            filters={"team_code": list(codes)}, include_deleted=True
        )
        return [row.team_code for row in results]

    # -- members -------------------------------------------------------------

    async def create_member(self, **fields: object) -> GuestTeamMember:
        return await self.members.create(fields)

    async def get_active_membership(
        self, team_id: uuid.UUID, guest_id: uuid.UUID
    ) -> GuestTeamMember | None:
        results = await self.members.get_all(
            filters={"team_id": team_id, "guest_id": guest_id, "is_active": True},
            limit=1,
        )
        return results[0] if results else None

    async def update_member(
        self, member: GuestTeamMember, data: dict[str, object]
    ) -> GuestTeamMember:
        return await self.members.update(member, data)

    async def count_active_members(self, team_id: uuid.UUID) -> int:
        return await self.members.count(filters={"team_id": team_id, "is_active": True})

    async def list_active_members(self, team_id: uuid.UUID) -> list[GuestTeamMember]:
        return await self.members.get_all(
            filters={"team_id": team_id, "is_active": True},
            sort_by="joined_at",
            sort_order=SortOrder.ASC,
        )


__all__ = ["GuestTeamRepositoryProtocol", "GuestTeamRepository"]
