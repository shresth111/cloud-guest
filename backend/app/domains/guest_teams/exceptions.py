"""Guest Teams domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

This module never re-raises ``app.domains.guest``'s own exceptions under a
different name -- a caller composing ``GuestService.terminate_session``/
``get_guest_sessions``/``get_or_create_device`` sees exactly the same
exceptions those methods already raise (composition, not translation). The
exceptions defined here cover only what is genuinely new at this module's
own layer: team lifecycle, membership, tenant isolation, and join-code
generation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "GuestTeamError",
    "GuestTeamNotFoundError",
    "CrossOrganizationGuestTeamAccessError",
    "InvalidGuestTeamStatusTransitionError",
    "GuestTeamNotActiveError",
    "GuestTeamMemberCapExceededError",
    "GuestTeamMemberNotFoundError",
    "GuestTeamCodeGenerationExhaustedError",
    "InvalidMaxMembersError",
    "InvalidSharedDataLimitError",
    "InvalidGuestTeamExpiryError",
]


class GuestTeamError(CloudGuestError):
    """Base exception for Guest Teams domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class GuestTeamNotFoundError(GuestTeamError):
    def __init__(self, team_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Guest team not found: {team_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationGuestTeamAccessError(GuestTeamError):
    """A caller acting within organization A attempted to read/mutate a
    guest team belonging to organization B -- mirrors
    ``app.domains.guest.exceptions.CrossOrganizationGuestAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a guest team belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidGuestTeamStatusTransitionError(GuestTeamError):
    """Raised when a requested status change is not a legal edge in
    ``app.domains.guest_teams.constants.GUEST_TEAM_STATUS_TRANSITIONS``."""

    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition guest team from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class GuestTeamNotActiveError(GuestTeamError):
    """A guest attempted to ``join_team`` a team that is not (or no longer)
    ``ACTIVE`` -- covers a team that has expired or been revoked."""

    def __init__(self, team_status: str) -> None:
        super().__init__(
            "This guest team is not currently active and cannot be joined",
            status_code=status.HTTP_409_CONFLICT,
            data={"team_status": team_status},
        )


class GuestTeamMemberCapExceededError(GuestTeamError):
    """The team's ``max_members`` cap has already been reached -- a real
    count check against currently-active ``GuestTeamMember`` rows, not a
    stale/cached counter."""

    def __init__(self, team_id: uuid.UUID | str, max_members: int) -> None:
        super().__init__(
            f"Guest team {team_id} has reached its member cap ({max_members})",
            status_code=status.HTTP_409_CONFLICT,
            data={"max_members": max_members},
        )


class GuestTeamMemberNotFoundError(GuestTeamError):
    """No currently-active ``GuestTeamMember`` row exists for this
    (team, guest) pair -- either this guest never joined this team, or has
    already been removed."""

    def __init__(self, team_id: uuid.UUID | str, guest_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Guest {guest_id} is not an active member of guest team {team_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class GuestTeamCodeGenerationExhaustedError(GuestTeamError):
    """Could not generate a unique team join code within
    ``constants.TEAM_CODE_GENERATION_MAX_ROUNDS`` rounds -- a defensive
    backstop, not expected in practice given the alphabet/length's
    combinatorial space."""

    def __init__(self) -> None:
        super().__init__(
            "Could not generate a unique guest team join code",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidMaxMembersError(GuestTeamError):
    def __init__(self, max_members: int) -> None:
        super().__init__(
            f"max_members must be a positive integer, got {max_members}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidSharedDataLimitError(GuestTeamError):
    def __init__(self, shared_data_limit_mb: int) -> None:
        super().__init__(
            "shared_data_limit_mb must be a positive integer, got "
            f"{shared_data_limit_mb}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidGuestTeamExpiryError(GuestTeamError):
    def __init__(self) -> None:
        super().__init__(
            "expires_at must be in the future", status_code=status.HTTP_400_BAD_REQUEST
        )
