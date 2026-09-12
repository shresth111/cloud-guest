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

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .constants import GuestTeamStatus
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

    async def list_active_teams_for_portal(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> list[GuestTeam]: ...

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

    async def list_active_memberships_for_guest(
        self, guest_id: uuid.UUID
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

    async def list_active_teams_for_portal(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> list[GuestTeam]:
        """Every non-deleted, active team a guest at ``location_id`` could
        join: teams scoped to exactly that location, PLUS the organization's
        location-wide teams (``location_id IS NULL`` -- an org-wide team is
        joinable from any of its locations' portals). Hand-written: a plain
        equality filter cannot express "this location OR null", the same
        reason the admin list's own location filter cannot -- see
        ``app.domains.captive_portal.repository``'s module docstring on
        GenericRepository's None-filter skip."""
        statement = (
            select(GuestTeam)
            .where(
                GuestTeam.organization_id == organization_id,
                GuestTeam.status == GuestTeamStatus.ACTIVE.value,
                GuestTeam.is_deleted.is_(False),
                or_(
                    GuestTeam.location_id == location_id,
                    GuestTeam.location_id.is_(None),
                ),
            )
            .order_by(GuestTeam.name.asc())
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

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

    async def list_active_memberships_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[GuestTeamMember]:
        """The reverse of ``list_active_members``: which teams is this guest
        currently in? Needed to enforce a team's shared data limit at the
        moment one of its members logs in, which is the only place the guest
        domain knows a guest id but not a team id."""
        return await self.members.get_all(
            filters={"guest_id": guest_id, "is_active": True},
        )


__all__ = ["GuestTeamRepositoryProtocol", "GuestTeamRepository"]
