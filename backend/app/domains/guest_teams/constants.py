"""Enumerations and small constants for the Guest Teams domain.

Stored as plain ``String`` columns on the ORM models (``GuestTeam.status``),
never a native PostgreSQL enum type -- the same reason every other domain in
this codebase documents (``app.domains.guest.constants``,
``app.domains.voucher.constants``, ``app.domains.rbac.enums``): adding a new
status value never requires an ``ALTER TYPE`` migration, only a new additive
``StrEnum`` member.

**No new ``Settings`` fields.** Like ``app.domains.voucher``/
``app.domains.guest``, this module adds no fields to
``app.core.config.Settings`` -- every tunable knob (join-code length,
generation retry bound) lives here instead, as plain module-level constants.

**Team join code: the exact same alphabet/generation approach as vouchers,
reused, not re-derived.** ``TEAM_CODE_ALPHABET`` is imported directly from
``app.domains.voucher.constants.VOUCHER_CODE_ALPHABET`` (not copied as a new
string literal) so the two can never silently drift -- a voucher code and a
team join code solve the identical problem (a short, print-friendly,
verbally-communicable code a person types into a captive-portal-style form)
and this module's own join code is, like a voucher code, a physical/
verbally-communicated artifact (announced to a delegation, printed on a
welcome card), so the same "exclude every character a person could misread"
reasoning applies unchanged. See ``app.domains.voucher.constants``'s own
docstring for the full alphabet derivation write-up.
"""

from __future__ import annotations

from enum import StrEnum

from app.domains.voucher.constants import VOUCHER_CODE_ALPHABET

# Reused verbatim -- see module docstring.
TEAM_CODE_ALPHABET = VOUCHER_CODE_ALPHABET

# Fixed length for a generated team join code. Unlike vouchers (whose
# ``code_length`` is a per-batch, admin-configurable field, because a batch
# may print thousands of codes and needs a combinatorial space sized to that
# volume), a guest team has exactly one join code shared by every member --
# there is no per-team volume pressure that would ever justify a
# configurable length, so this is a fixed platform constant. 8 symbols from a
# 30-character alphabet (``30**8`` ~= 6.5e11) is comfortably large for a
# single code with negligible collision risk.
TEAM_CODE_LENGTH = 8

# Bound on how many (in-memory-generate, then DB-existence-check) rounds
# ``GuestTeamService._generate_team_code`` will attempt before giving up and
# raising ``GuestTeamCodeGenerationExhaustedError`` -- a defensive backstop,
# mirroring ``app.domains.voucher.constants.CODE_GENERATION_MAX_ROUNDS``'s
# identical purpose, never expected to be hit in practice (one code at a
# time, from a combinatorial space this large).
TEAM_CODE_GENERATION_MAX_ROUNDS = 20


class GuestTeamStatus(StrEnum):
    """Lifecycle status of a :class:`~.models.GuestTeam`.

    * ``ACTIVE`` -- the only status a team is ever created in. Guests may
      join (subject to ``max_members``) and the team's own shared quota/
      expiry are in effect.
    * ``EXPIRED`` -- ``expires_at`` has passed. Reached lazily (on the next
      read of an ``ACTIVE`` team past its expiry), not by a background
      sweep -- mirrors ``app.domains.voucher.models.VoucherBatch``'s own
      ``batch_expires_at``/``is_batch_expired`` "checked on read" posture
      exactly (see ``VoucherService._refresh_batch_expiry``, whose
      ``GuestTeamService._refresh_team_expiry`` counterpart is a structural
      copy of the same idea, adapted to this module's own status graph).
    * ``REVOKED`` -- administratively cancelled at any point before
      ``EXPIRED`` via ``GuestTeamService.revoke_team`` -- the whole team's
      access grant is cancelled at once, and every currently-active member's
      active session(s) are terminated (see ``service.py``'s module
      docstring for the full write-up).

    Both ``EXPIRED`` and ``REVOKED`` are terminal: once reached, a
    ``GuestTeam`` row's status never changes again -- mirrors
    ``app.domains.guest.constants.GuestSessionStatus``'s and
    ``app.domains.voucher.constants.VoucherBatchStatus``'s identical
    "terminal states have no outgoing edges, not even to themselves"
    discipline (attempting to revoke an already-revoked or already-expired
    team is rejected, not silently accepted as a no-op).
    """

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


# The explicit, exhaustive legal-transition graph for GuestTeam.status -- any
# transition not listed here is rejected by
# ``validators.validate_team_status_transition`` with
# ``InvalidGuestTeamStatusTransitionError``. Mirrors
# ``app.domains.guest.constants.GUEST_SESSION_STATUS_TRANSITIONS``'s/
# ``app.domains.voucher.constants.VOUCHER_BATCH_STATUS_TRANSITIONS``'s
# identical dict-of-frozenset shape.
GUEST_TEAM_STATUS_TRANSITIONS: dict[GuestTeamStatus, frozenset[GuestTeamStatus]] = {
    GuestTeamStatus.ACTIVE: frozenset(
        {GuestTeamStatus.EXPIRED, GuestTeamStatus.REVOKED}
    ),
    GuestTeamStatus.EXPIRED: frozenset(),
    GuestTeamStatus.REVOKED: frozenset(),
}

__all__ = [
    "TEAM_CODE_ALPHABET",
    "TEAM_CODE_LENGTH",
    "TEAM_CODE_GENERATION_MAX_ROUNDS",
    "GuestTeamStatus",
    "GUEST_TEAM_STATUS_TRANSITIONS",
]
