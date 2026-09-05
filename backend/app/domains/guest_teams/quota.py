"""Shared-quota enforcement for guest teams.

``GuestTeamService.check_shared_quota`` has computed a team's pooled usage
correctly since it shipped, and had **no caller anywhere in the application** --
`git grep check_shared_quota` returned its own definition and its own
docstring, nothing else. The service says so itself: "it is deliberately only
the check, not the mechanism that would cut a guest's network access
mid-session ... a future gate could call this method". So a team with a 5 GB
shared limit could use 50 GB and nothing anywhere noticed.

That matters because "one shared data limit" is the defining sentence of the
Guest Groups feature on /features and the co-working story on /how-it-works.

## Why this is a separate object rather than a call into ``GuestTeamService``

``GuestTeamService`` composes the concrete ``GuestService`` (see its own module
docstring for why). The enforcement point is *inside* ``GuestService``'s login
path, so wiring ``GuestTeamService`` into ``GuestService`` would close a
dependency cycle -- and in FastAPI's DI graph, ``get_guest_service ->
get_guest_team_service -> get_guest_service`` recurses forever rather than
failing loudly.

So this resolver takes the two **repositories** it actually needs and no
service at all. It is the same narrow-hook shape ``GuestService`` already uses
for ``policy_lookup``, ``access_control_hook`` and ``mac_authorization_hook``.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from app.domains.guest.constants import BYTES_PER_MB, GuestSessionStatus

from .repository import GuestTeamRepositoryProtocol


class _GuestSessionSource(Protocol):
    """The one thing this resolver needs from the guest domain's repository."""

    async def list_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list: ...


class SharedQuotaResolver:
    """Answers "has any team this guest belongs to burned through its shared
    data limit?" -- the gate ``check_shared_quota`` was always missing."""

    def __init__(
        self,
        team_repository: GuestTeamRepositoryProtocol,
        guest_repository: _GuestSessionSource,
    ) -> None:
        self.team_repository = team_repository
        self.guest_repository = guest_repository

    async def is_over_shared_quota(self, guest_id: uuid.UUID) -> bool:
        """``True`` when this guest belongs to at least one active team whose
        pooled usage has reached its ``shared_data_limit_mb``.

        A guest in no team, or in teams that set no shared limit, is never
        over quota -- so this is a no-op for every venue that does not use the
        feature, which is the same "costs nothing when unconfigured" posture
        the other login-path hooks take.
        """
        memberships = await self.team_repository.list_active_memberships_for_guest(
            guest_id
        )
        for membership in memberships:
            team = await self.team_repository.get_team_by_id(membership.team_id)
            if team is None or team.shared_data_limit_mb is None:
                continue
            if await self._team_usage_bytes(team.id) >= (
                team.shared_data_limit_mb * BYTES_PER_MB
            ):
                return True
        return False

    async def _team_usage_bytes(self, team_id: uuid.UUID) -> int:
        """Pooled bytes across every active member's active sessions --
        the same sum ``GuestTeamService.check_shared_quota`` computes."""
        total = 0
        for member in await self.team_repository.list_active_members(team_id):
            sessions = await self.guest_repository.list_sessions_for_guest(
                member.guest_id
            )
            for session in sessions:
                if session.status == GuestSessionStatus.ACTIVE.value:
                    total += session.total_bytes()
        return total
