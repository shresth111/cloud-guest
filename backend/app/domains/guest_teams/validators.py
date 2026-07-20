"""Pure, side-effect-free validation for the Guest Teams domain.

Mirrors ``app.domains.guest.validators``/``app.domains.voucher
.validators``'s identical discipline: no I/O, just "is this a legal input
or transition" checks the service layer calls before touching the database.

``normalize_identifier`` is a deliberate, small duplication of
``app.domains.guest.validators.normalize_identifier``'s own one-line body
(strip whitespace), not an import of it: that function lives in
``app.domains.guest``'s own internal ``validators.py``, which is not part of
the public composition surface this module is scoped to reuse (``service.py``
/``router.py``/``schemas.py``/the exported exceptions) -- see this module's
own ``service.py`` docstring for the full "what this module composes vs.
reimplements" write-up. A one-line ``.strip()`` carries no real logic to
duplicate incorrectly.
"""

from __future__ import annotations

from datetime import datetime

from .constants import GUEST_TEAM_STATUS_TRANSITIONS, GuestTeamStatus
from .exceptions import (
    InvalidGuestTeamExpiryError,
    InvalidGuestTeamStatusTransitionError,
    InvalidMaxMembersError,
    InvalidSharedDataLimitError,
)


def normalize_identifier(identifier: str) -> str:
    """Strips surrounding whitespace -- see module docstring."""
    return identifier.strip()


def validate_max_members(max_members: int | None) -> None:
    """``None`` means unlimited membership; anything else must be a positive
    integer."""
    if max_members is not None and max_members < 1:
        raise InvalidMaxMembersError(max_members)


def validate_shared_data_limit(shared_data_limit_mb: int | None) -> None:
    """``None`` means no team-level pooled quota; anything else must be a
    positive integer."""
    if shared_data_limit_mb is not None and shared_data_limit_mb < 1:
        raise InvalidSharedDataLimitError(shared_data_limit_mb)


def validate_team_expiry(expires_at: datetime | None, *, now: datetime) -> None:
    """``None`` means the team never expires; anything else must be in the
    future at creation time."""
    if expires_at is not None and expires_at <= now:
        raise InvalidGuestTeamExpiryError()


def validate_team_status_transition(
    *, current: GuestTeamStatus, target: GuestTeamStatus
) -> None:
    """Consults the exhaustive ``GUEST_TEAM_STATUS_TRANSITIONS`` graph.

    Deliberately has no "same status is a no-op" shortcut -- e.g. revoking an
    already-``REVOKED`` team must raise (every non-``ACTIVE`` status has no
    outgoing edges at all, including to itself), mirroring
    ``app.domains.guest.validators.validate_session_status_transition``'s
    identical discipline."""
    legal_targets = GUEST_TEAM_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidGuestTeamStatusTransitionError(current.value, target.value)


__all__ = [
    "normalize_identifier",
    "validate_max_members",
    "validate_shared_data_limit",
    "validate_team_expiry",
    "validate_team_status_transition",
]
