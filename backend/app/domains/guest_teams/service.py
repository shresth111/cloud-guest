"""Guest Teams business logic: team lifecycle (create/revoke), a shareable
join code, membership (join/remove), and read-only team summary/shared-quota
checks.

This module's entire value is composing ``app.domains.guest``'s already-real
guest identity/session machinery, never reimplementing any part of it -- the
same "compose the real domain, add only what is genuinely new" discipline
every prior BE-010+ module in this codebase follows for its own cross-domain
dependencies.

## Composing ``GuestService._get_or_create_guest`` -- a deliberate, narrow
## exception to this codebase's own "depend on a Protocol" convention

Every other cross-domain composition in this codebase (``VoucherService``'s
``OrganizationLookupProtocol``/``LocationLookupProtocol``,
``GuestService``'s own ``OtpVerifyProtocol``/``VoucherRedeemProtocol``/etc.)
depends on a narrow, duck-typed ``Protocol`` describing only the *public*
surface it needs, never the concrete class. This module's ``join_team``
breaks that convention in exactly one place, deliberately: it calls
``GuestService._get_or_create_guest`` directly -- a leading-underscore
"private" method on the concrete class -- because the module brief for this
feature explicitly requires reusing *that exact method* for guest identity
resolution rather than reimplementing "look up an existing guest by
identifier, or create one" a second time (the two implementations would
inevitably drift on edge cases like ``total_visit_count``/``first_seen_at``
initialization). A ``Protocol`` cannot honestly describe "depends on this
private implementation detail" as a loosely-coupled shape -- doing so would
just be theater around a tight coupling that already exists by design
mandate -- so ``GuestTeamService`` instead depends on the concrete
``GuestService`` class directly for this one composition, documented here
rather than hidden behind a misleading Protocol. Every *other* composition
with ``GuestService`` in this module (``get_guest_sessions``,
``terminate_session``, ``get_or_create_device``) uses only its ordinary
public API, exactly like every other domain's own compositions do.

``_get_or_create_guest`` itself only decides "is there already a ``Guest``
row for this identifier, or do we create one" -- it does not perform the
identifier lookup itself (that is ``GuestRepositoryProtocol
.get_guest_by_identifier``, called by this module through
``guest_service.repository`` -- a public attribute of ``GuestService``,
exposing its already-public ``GuestRepositoryProtocol`` -- exactly the same
lookup ``GuestService.login_via_otp``/``login_via_voucher`` themselves
perform before calling ``_get_or_create_guest``). Composing both together is
therefore not a partial reimplementation of guest identity resolution: it is
the *exact same two calls*, in the *exact same order*, that ``GuestService``
already makes internally for its own login flows.

## Team status graph

``GuestTeamStatus`` is ``ACTIVE`` -> ``EXPIRED``/``REVOKED``, both terminal
-- a real, explicit, exhaustively-validated transition graph
(``constants.GUEST_TEAM_STATUS_TRANSITIONS``), the same structural rigor
``VoucherBatchStatus``/``GuestSessionStatus`` already established in their
own sibling domains, deliberately *not* copying ``VoucherBatch``'s much
richer draft/pending-approval/approved workflow: a guest team has no
analogous approval gate in this feature's scope (an admin creating a team
is, by itself, the full authorization event -- there is no print-vendor-
style "vouchers get approved before going live" step for a team roster), so
a team is simply created ``ACTIVE`` and stays that way until it expires
(lazily, on read -- see ``_refresh_team_expiry``, a structural copy of
``VoucherService._refresh_batch_expiry``) or is explicitly revoked.

## Join-code join semantics: idempotent re-join while active, re-join creates
## a new row after removal

``join_team`` is idempotent for a guest who is *already* an active member of
the team (calling it again returns the existing membership unchanged, no
new row, no re-application of the ``max_members`` cap) -- mirrors
``GuestService.reconnect``'s own "already connected, no duplicate" posture.
For a guest who was previously a member and was **removed**
(``remove_team_member``), rejoining creates a **new** ``GuestTeamMember``
row rather than reactivating the old one -- see ``models.py``'s own
docstring for the full reasoning (append-only-per-membership-stint, mirroring
``GuestSession``'s own "reconnect creates a new row" convention). This is a
real, deliberate design choice: rejoining is allowed at all (there is no
"once removed, permanently barred" rule in this feature's scope -- a team
roster is expected to change as real groups do, e.g. someone stepped out and
is now back), and every join/leave cycle keeps its own permanent history
rather than one mutable row silently overwriting its own past.

## Removal ends the member's current session(s) too

``remove_team_member`` does not just stop counting a guest towards the
team's roster/shared quota going forward -- it also calls
``GuestService.terminate_session`` (the real, existing, audited, punitive
session-kill) for every currently-``ACTIVE`` session that guest has. This is
a real, defensible design decision, not the only one this brief allowed
(see the module brief's own "make a real, defensible choice" instruction),
argued here rather than merely asserted:

* This feature's own premise is that a team's members are "tracked/managed
  together as a unit" through their team membership. A guest's continued
  network access, once removed from that unit, is no longer sanctioned by
  the grant that (at least in intent) brought them onto the network as part
  of this group -- silently letting their session continue would undermine
  the entire "manage as a unit" value proposition this domain exists to
  provide, in favor of a purely cosmetic roster change.
* It mirrors this same codebase's own precedent one layer up:
  ``GuestService.block_guest`` (an admin-driven access restriction) and
  ``revoke_batch`` -> ``bulk_revoke_vouchers_for_batch`` (an admin revoking a
  *group* grant) are both real access-ending events, not just
  bookkeeping -- ``remove_team_member`` is the individual-member analogue of
  exactly that pattern, one level down from ``revoke_team``'s whole-team
  version of the same idea.
* ``terminate_session`` (not the gentler ``disconnect_session``) is used
  specifically because ``remove_team_member`` is always admin-initiated
  (mirrors ``GuestService.terminate_session``'s own "admin-driven, punitive"
  characterization) -- the resulting reconnect cooldown
  (``TERMINATION_RECONNECT_COOLDOWN_MINUTES``) is an intended consequence,
  not a side effect to work around: an ejected member should not be able to
  trivially reconnect via the low-friction ``reconnect`` flow moments later;
  they would need to present fresh credentials (a new OTP/voucher) to regain
  network access on their own, independent of team membership.
* Failure isolation matters here too, for the same reason it matters for
  ``revoke_team`` below: a session-termination failure for this one guest
  must never prevent the membership-removal itself from succeeding (the
  roster change is the primary, always-honored effect; ending the session is
  a best-effort follow-up), so it is wrapped in its own try/except and only
  ever logged, never re-raised.

## Revocation: real per-member failure isolation, composing
## ``GuestService.terminate_session`` verbatim

``revoke_team`` transitions the team to ``REVOKED`` and then, for **every**
currently-active member, looks up that guest's sessions via
``GuestService.get_guest_sessions`` and calls ``GuestService
.terminate_session`` (the real method -- never a hand-rolled bulk
``UPDATE ... SET status = 'terminated'`` that would bypass its own audit
entry, event, and reconnect-cooldown side effects) for each currently-
``ACTIVE`` one. Each member's lookup+termination work is wrapped in its own
try/except: one member's failure (a stale/already-terminal session, a
transient repository error) is logged and that member is recorded in
``failed_member_ids``, but the loop always continues to the next member --
mirrors the exact per-item failure-isolation shape this codebase already
established for its own batch operations (``app.domains.analytics``'s daily
aggregation sweep, ``app.domains.billing.renewal_service.RenewalService``'s
renewal sweep): one bad row must never abort the whole batch. The team
itself is *always* transitioned to ``REVOKED`` regardless of any member-level
failures -- the team's own status change is unconditional and happens before
any per-member work begins, so a caller can always trust that a successful
``revoke_team`` call means the team is revoked, with ``failed_member_ids``
surfacing (not swallowing) any member whose session(s) may still need manual
follow-up.

## Shared quota: a real check, not the enforcement point

``check_shared_quota`` is a real, callable check -- sums every currently-
active member's *currently-active* session's own ``bytes_uploaded +
bytes_downloaded`` (via ``GuestSession.total_bytes()``, the model's own
existing helper, never a re-derived formula) and compares it against
``shared_data_limit_mb`` -- but, like
``app.domains.billing.service.UsageService.validate_usage_against_license``,
it is deliberately *only* the check, not the mechanism that would cut a
guest's network access mid-session. There is no live RADIUS daemon in this
sandbox to issue a CoA-Disconnect once a team's pooled quota is exceeded
(the identical honest limitation ``app.domains.guest.service.GuestService
.enforce_timeouts``'s own docstring already documents for individual-session
quota/timeout detection) -- a future gate (e.g. a scheduled sweep, or a hook
inside RADIUS accounting) could call this method to decide whether to reject
further usage, exactly as a future caller of ``validate_usage_against_license``
would decide whether to block a billing action.

``check_shared_quota`` deliberately sums only *currently-active* sessions
(a live, "how much is the team using right now" snapshot), while
``get_team_summary``'s own ``total_bandwidth_bytes`` deliberately sums
*every* session (all statuses, all-time) for a "how much has this team ever
consumed" cumulative figure -- two different, both real, questions. Neither
reuses ``app.domains.guest.service.GuestAnalyticsService``'s own aggregate
methods: those are organization/location- and date-range-scoped SQL
aggregates over *every* guest in scope, not "sum bandwidth for this specific
list of member guest ids" -- a genuinely different query shape that
``GuestAnalyticsService``/``GuestRepository`` do not expose (and this
module's own directory boundary forbids adding a new method to either just
for this). Composing ``GuestService.get_guest_sessions`` per member (already
a real, public, tenant-scope-enforcing method) and summing via
``GuestSession.total_bytes()`` is the honest, available alternative: it
reuses the guest domain's own real session-listing capability and the
model's own existing per-session byte-total helper, rather than re-deriving
either the SQL aggregate logic ``GuestAnalyticsService`` already owns or the
``bytes_uploaded + bytes_downloaded`` formula a second, subtly-different way.

## Audit-volume judgment call

``create_team``/``remove_team_member``/``revoke_team`` are always admin-
initiated, moderate-volume, human-attributable actions -- audited
(``AuditAction.GUEST_TEAM_CREATED``/``GUEST_TEAM_MEMBER_REMOVED``/
``GUEST_TEAM_REVOKED``), the same profile every other domain's own lifecycle
events already meet. ``join_team`` is deliberately **not** audited at all --
it is guest-facing, high-volume, unauthenticated traffic (the identical
profile ``app.domains.guest.service.GuestService.login_via_otp``/
``login_via_voucher``'s own audit-volume judgment call already establishes
for guest logins), and unlike those two methods, this module has no
purpose-built high-volume history table of its own to record every attempt
into either (a guest team's whole roster, including every historical
membership stint, is already fully visible via ``GuestTeamMember`` itself --
see ``models.py``'s own "append-only-per-stint" write-up -- so there is no
analogous gap to a dedicated ``GuestLoginHistory``-style table here). Every
join is still logged via the structured logger and as a domain event
(``events.GuestMemberJoined``) for observability, exactly mirroring how
``GuestLoggedIn`` is logged without being audited.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from secrets import choice as secrets_choice
from typing import Protocol

from app.common.exceptions import CloudGuestError
from app.domains.guest.constants import BYTES_PER_MB, GuestSessionStatus
from app.domains.guest.exceptions import GuestBlockedError
from app.domains.guest.service import GuestService
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction

from .constants import (
    TEAM_CODE_ALPHABET,
    TEAM_CODE_GENERATION_MAX_ROUNDS,
    TEAM_CODE_LENGTH,
    GuestTeamStatus,
)
from .events import (
    GuestMemberJoined,
    GuestMemberRemoved,
    GuestTeamCreated,
    GuestTeamRevoked,
)
from .exceptions import (
    CrossOrganizationGuestTeamAccessError,
    GuestTeamCodeGenerationExhaustedError,
    GuestTeamMemberCapExceededError,
    GuestTeamMemberNotFoundError,
    GuestTeamNotActiveError,
    GuestTeamNotFoundError,
)
from .models import GuestTeam, GuestTeamMember
from .repository import GuestTeamRepositoryProtocol
from .validators import (
    normalize_identifier,
    validate_max_members,
    validate_shared_data_limit,
    validate_team_expiry,
    validate_team_status_transition,
)

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.guest.service._event_extra``/
    ``app.domains.voucher.service._event_extra``."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class OrganizationLookupProtocol(Protocol):
    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Read models
# ============================================================================


@dataclass(frozen=True, slots=True)
class GuestTeamJoinResult:
    team: GuestTeam
    membership: GuestTeamMember
    guest_id: uuid.UUID
    identifier: str
    is_new_guest: bool
    is_new_membership: bool


@dataclass(frozen=True, slots=True)
class GuestTeamMemberRemovalResult:
    team: GuestTeam
    membership: GuestTeamMember
    terminated_session_ids: list[uuid.UUID]


@dataclass(frozen=True, slots=True)
class GuestTeamRevocationResult:
    team: GuestTeam
    member_count: int
    terminated_session_ids: list[uuid.UUID]
    failed_member_ids: list[uuid.UUID]


@dataclass(frozen=True, slots=True)
class GuestTeamSummary:
    team_id: uuid.UUID
    member_count: int
    active_session_count: int
    total_bandwidth_bytes: int
    shared_data_limit_mb: int | None
    remaining_shared_quota_mb: float | None
    quota_exceeded: bool


@dataclass(frozen=True, slots=True)
class SharedQuotaCheckResult:
    team_id: uuid.UUID
    shared_data_limit_mb: int | None
    current_usage_bytes: int
    exceeded: bool


# ============================================================================
# Service
# ============================================================================


class GuestTeamService:
    """Core Guest Teams business logic -- see module docstring for the full
    design write-up."""

    def __init__(
        self,
        repository: GuestTeamRepositoryProtocol,
        organization_lookup: OrganizationLookupProtocol,
        location_lookup: LocationLookupProtocol,
        guest_service: GuestService,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup
        self.guest_service = guest_service
        self.audit_writer = audit_writer

    # ========================================================================
    # Team lifecycle
    # ========================================================================

    async def create_team(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        name: str,
        max_members: int | None,
        shared_data_limit_mb: int | None,
        expires_at: datetime | None,
    ) -> GuestTeam:
        validate_max_members(max_members)
        validate_shared_data_limit(shared_data_limit_mb)
        now = datetime.now(UTC)
        validate_team_expiry(expires_at, now=now)

        organization = await self.organization_lookup.get_organization(organization_id)
        if (
            requesting_organization_id is not None
            and organization.id != requesting_organization_id
        ):
            raise CrossOrganizationGuestTeamAccessError()
        if location_id is not None:
            await self.location_lookup.get_location(
                location_id, requesting_organization_id=organization.id
            )

        team_code = await self._generate_team_code()
        team = await self.repository.create_team(
            organization_id=organization.id,
            location_id=location_id,
            name=name,
            team_code=team_code,
            status=GuestTeamStatus.ACTIVE.value,
            max_members=max_members,
            shared_data_limit_mb=shared_data_limit_mb,
            expires_at=expires_at,
            created_by_user_id=actor_user_id,
            revoked_at=None,
            revoked_reason=None,
            created_by=actor_user_id,
        )
        event = GuestTeamCreated(
            team_id=team.id, organization_id=organization.id, team_code=team.team_code
        )
        logger.info("guest_team_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_TEAM_CREATED,
            team,
            f"Guest team '{team.name}' created (code={team.team_code})",
        )
        return team

    async def get_team(
        self,
        team_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> GuestTeam:
        team = await self.repository.get_team_by_id(team_id)
        if team is None:
            raise GuestTeamNotFoundError(team_id)
        self._enforce_tenant_scope(team.organization_id, requesting_organization_id)
        return await self._refresh_team_expiry(team)

    async def list_teams(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        status: GuestTeamStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[GuestTeam], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if status is not None:
            filters["status"] = status.value
        teams, meta = await self.repository.list_teams(
            page=page, page_size=page_size, filters=filters or None
        )
        refreshed = [await self._refresh_team_expiry(team) for team in teams]
        return refreshed, meta

    async def revoke_team(
        self,
        *,
        team_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        reason: str | None,
    ) -> GuestTeamRevocationResult:
        team = await self.get_team(
            team_id, requesting_organization_id=requesting_organization_id
        )
        current = GuestTeamStatus(team.status)
        validate_team_status_transition(current=current, target=GuestTeamStatus.REVOKED)

        now = datetime.now(UTC)
        updated_team = await self.repository.update_team(
            team,
            {
                "status": GuestTeamStatus.REVOKED.value,
                "revoked_at": now,
                "revoked_reason": reason,
                "updated_by": actor_user_id,
            },
        )

        members = await self.repository.list_active_members(team.id)
        terminated_session_ids: list[uuid.UUID] = []
        failed_member_ids: list[uuid.UUID] = []
        for member in members:
            try:
                sessions = await self.guest_service.get_guest_sessions(
                    member.guest_id, requesting_organization_id=team.organization_id
                )
                member_failed = False
                for session in sessions:
                    if session.status != GuestSessionStatus.ACTIVE.value:
                        continue
                    try:
                        await self.guest_service.terminate_session(
                            session_id=session.id,
                            actor_user_id=actor_user_id,
                            requesting_organization_id=team.organization_id,
                            reason=reason or "guest_team_revoked",
                        )
                        terminated_session_ids.append(session.id)
                    except CloudGuestError as exc:
                        member_failed = True
                        logger.warning(
                            "guest_team_revocation_session_termination_failed",
                            extra={
                                "team_id": str(team.id),
                                "guest_id": str(member.guest_id),
                                "session_id": str(session.id),
                                "error": str(exc),
                            },
                        )
                if member_failed:
                    failed_member_ids.append(member.guest_id)
            except CloudGuestError as exc:
                logger.warning(
                    "guest_team_revocation_member_lookup_failed",
                    extra={
                        "team_id": str(team.id),
                        "guest_id": str(member.guest_id),
                        "error": str(exc),
                    },
                )
                failed_member_ids.append(member.guest_id)

        event = GuestTeamRevoked(
            team_id=updated_team.id,
            reason=reason,
            member_count=len(members),
            terminated_session_count=len(terminated_session_ids),
            failed_member_count=len(failed_member_ids),
        )
        logger.info("guest_team_revoked", extra=_event_extra(event))
        description = f"Guest team '{updated_team.name}' revoked"
        if reason:
            description += f": {reason}"
        await self._audit(
            actor_user_id, AuditAction.GUEST_TEAM_REVOKED, updated_team, description
        )
        return GuestTeamRevocationResult(
            team=updated_team,
            member_count=len(members),
            terminated_session_ids=terminated_session_ids,
            failed_member_ids=failed_member_ids,
        )

    # ========================================================================
    # Membership
    # ========================================================================

    async def join_team(
        self,
        *,
        team_code: str,
        identifier: str,
        device_mac: str | None = None,
        device_name: str | None = None,
    ) -> GuestTeamJoinResult:
        team = await self.repository.get_team_by_code(team_code)
        if team is None:
            raise GuestTeamNotFoundError(team_code)
        team = await self._refresh_team_expiry(team)
        if GuestTeamStatus(team.status) != GuestTeamStatus.ACTIVE:
            raise GuestTeamNotActiveError(team.status)

        identifier = normalize_identifier(identifier)

        # See module docstring's "Composing GuestService._get_or_create_guest"
        # write-up for why this reuses the exact private method (plus the
        # exact repository lookup GuestService's own login flows perform
        # first) rather than reimplementing guest identity resolution.
        existing_guest = await self.guest_service.repository.get_guest_by_identifier(
            team.organization_id, identifier
        )
        if existing_guest is not None and existing_guest.is_blocked:
            raise GuestBlockedError(existing_guest.blocked_reason)

        guest, is_new_guest = await self.guest_service._get_or_create_guest(  # noqa: SLF001
            existing_guest,
            organization_id=team.organization_id,
            location_id=team.location_id,
            identifier=identifier,
        )

        if device_mac:
            await self.guest_service.get_or_create_device(
                guest_id=guest.id, mac_address=device_mac, device_name=device_name
            )

        existing_membership = await self.repository.get_active_membership(
            team.id, guest.id
        )
        if existing_membership is not None:
            # Idempotent -- already an active member, see module docstring.
            return GuestTeamJoinResult(
                team=team,
                membership=existing_membership,
                guest_id=guest.id,
                identifier=identifier,
                is_new_guest=is_new_guest,
                is_new_membership=False,
            )

        if team.max_members is not None:
            active_count = await self.repository.count_active_members(team.id)
            if active_count >= team.max_members:
                raise GuestTeamMemberCapExceededError(team.id, team.max_members)

        now = datetime.now(UTC)
        membership = await self.repository.create_member(
            team_id=team.id,
            guest_id=guest.id,
            joined_at=now,
            is_active=True,
            left_at=None,
            removal_reason=None,
        )
        event = GuestMemberJoined(
            team_id=team.id,
            guest_id=guest.id,
            is_new_guest=is_new_guest,
            is_new_membership=True,
        )
        logger.info("guest_team_member_joined", extra=_event_extra(event))
        return GuestTeamJoinResult(
            team=team,
            membership=membership,
            guest_id=guest.id,
            identifier=identifier,
            is_new_guest=is_new_guest,
            is_new_membership=True,
        )

    async def remove_team_member(
        self,
        *,
        team_id: uuid.UUID,
        guest_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        reason: str | None,
    ) -> GuestTeamMemberRemovalResult:
        team = await self.get_team(
            team_id, requesting_organization_id=requesting_organization_id
        )
        membership = await self.repository.get_active_membership(team.id, guest_id)
        if membership is None:
            raise GuestTeamMemberNotFoundError(team.id, guest_id)

        now = datetime.now(UTC)
        updated_membership = await self.repository.update_member(
            membership,
            {
                "is_active": False,
                "left_at": now,
                "removal_reason": reason,
                "updated_by": actor_user_id,
            },
        )

        # See module docstring's "Removal ends the member's current
        # session(s) too" write-up for the full reasoning, and its own
        # failure-isolation argument.
        terminated_session_ids: list[uuid.UUID] = []
        try:
            sessions = await self.guest_service.get_guest_sessions(
                guest_id, requesting_organization_id=team.organization_id
            )
            for session in sessions:
                if session.status != GuestSessionStatus.ACTIVE.value:
                    continue
                try:
                    await self.guest_service.terminate_session(
                        session_id=session.id,
                        actor_user_id=actor_user_id,
                        requesting_organization_id=team.organization_id,
                        reason=reason or "removed_from_guest_team",
                    )
                    terminated_session_ids.append(session.id)
                except CloudGuestError as exc:
                    logger.warning(
                        "guest_team_member_removal_session_termination_failed",
                        extra={
                            "team_id": str(team.id),
                            "guest_id": str(guest_id),
                            "session_id": str(session.id),
                            "error": str(exc),
                        },
                    )
        except CloudGuestError as exc:
            logger.warning(
                "guest_team_member_removal_session_lookup_failed",
                extra={
                    "team_id": str(team.id),
                    "guest_id": str(guest_id),
                    "error": str(exc),
                },
            )

        event = GuestMemberRemoved(
            team_id=team.id,
            guest_id=guest_id,
            reason=reason,
            terminated_session_count=len(terminated_session_ids),
        )
        logger.info("guest_team_member_removed", extra=_event_extra(event))
        description = f"Guest {guest_id} removed from guest team '{team.name}'"
        if reason:
            description += f": {reason}"
        await self._audit(
            actor_user_id, AuditAction.GUEST_TEAM_MEMBER_REMOVED, team, description
        )
        return GuestTeamMemberRemovalResult(
            team=team,
            membership=updated_membership,
            terminated_session_ids=terminated_session_ids,
        )

    # ========================================================================
    # Summary / shared quota
    # ========================================================================

    async def get_team_summary(
        self,
        team_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> GuestTeamSummary:
        team = await self.get_team(
            team_id, requesting_organization_id=requesting_organization_id
        )
        members = await self.repository.list_active_members(team.id)

        total_bandwidth_bytes = 0
        active_session_count = 0
        for member in members:
            sessions = await self.guest_service.get_guest_sessions(
                member.guest_id, requesting_organization_id=team.organization_id
            )
            for session in sessions:
                total_bandwidth_bytes += session.total_bytes()
                if session.status == GuestSessionStatus.ACTIVE.value:
                    active_session_count += 1

        remaining_shared_quota_mb: float | None = None
        quota_exceeded = False
        if team.shared_data_limit_mb is not None:
            used_mb = total_bandwidth_bytes / BYTES_PER_MB
            remaining_shared_quota_mb = max(team.shared_data_limit_mb - used_mb, 0.0)
            quota_exceeded = used_mb >= team.shared_data_limit_mb

        return GuestTeamSummary(
            team_id=team.id,
            member_count=len(members),
            active_session_count=active_session_count,
            total_bandwidth_bytes=total_bandwidth_bytes,
            shared_data_limit_mb=team.shared_data_limit_mb,
            remaining_shared_quota_mb=remaining_shared_quota_mb,
            quota_exceeded=quota_exceeded,
        )

    async def check_shared_quota(
        self,
        team_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> SharedQuotaCheckResult:
        """See module docstring's "Shared quota: a real check, not the
        enforcement point" write-up."""
        team = await self.get_team(
            team_id, requesting_organization_id=requesting_organization_id
        )
        if team.shared_data_limit_mb is None:
            return SharedQuotaCheckResult(
                team_id=team.id,
                shared_data_limit_mb=None,
                current_usage_bytes=0,
                exceeded=False,
            )

        members = await self.repository.list_active_members(team.id)
        current_usage_bytes = 0
        for member in members:
            sessions = await self.guest_service.get_guest_sessions(
                member.guest_id, requesting_organization_id=team.organization_id
            )
            for session in sessions:
                if session.status == GuestSessionStatus.ACTIVE.value:
                    current_usage_bytes += session.total_bytes()

        exceeded = current_usage_bytes >= team.shared_data_limit_mb * BYTES_PER_MB
        return SharedQuotaCheckResult(
            team_id=team.id,
            shared_data_limit_mb=team.shared_data_limit_mb,
            current_usage_bytes=current_usage_bytes,
            exceeded=exceeded,
        )

    # ========================================================================
    # Internal helpers
    # ========================================================================

    @staticmethod
    def _random_team_code() -> str:
        return "".join(
            secrets_choice(TEAM_CODE_ALPHABET) for _ in range(TEAM_CODE_LENGTH)
        )

    async def _generate_team_code(self) -> str:
        """Generates a single, collision-checked join code -- mirrors
        ``app.domains.voucher.service.VoucherService._generate_codes``'s
        in-memory-generate-then-DB-existence-check retry loop, adapted to
        one code at a time (a team has exactly one join code, never a bulk
        batch of them)."""
        for _ in range(TEAM_CODE_GENERATION_MAX_ROUNDS):
            candidate = self._random_team_code()
            existing = await self.repository.find_existing_codes([candidate])
            if not existing:
                return candidate
        raise GuestTeamCodeGenerationExhaustedError()

    async def _refresh_team_expiry(self, team: GuestTeam) -> GuestTeam:
        """Lazily flips ``ACTIVE -> EXPIRED`` once ``expires_at`` has
        passed -- checked on every read, not swept by a background job,
        mirroring ``app.domains.voucher.service.VoucherService
        ._refresh_batch_expiry``'s identical "checked on read" posture."""
        now = datetime.now(UTC)
        if GuestTeamStatus(
            team.status
        ) == GuestTeamStatus.ACTIVE and team.is_team_expired(now=now):
            return await self.repository.update_team(
                team, {"status": GuestTeamStatus.EXPIRED.value}
            )
        return team

    def _enforce_tenant_scope(
        self,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if (
            requesting_organization_id is not None
            and organization_id != requesting_organization_id
        ):
            raise CrossOrganizationGuestTeamAccessError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        team: GuestTeam,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="guest_team",
            entity_id=team.id,
            description=description,
            event_metadata={"team_status": team.status},
            organization_id=team.organization_id,
            location_id=team.location_id,
        )


__all__ = [
    "GuestTeamService",
    "OrganizationLookupProtocol",
    "LocationLookupProtocol",
    "AuditLogWriter",
    "GuestTeamJoinResult",
    "GuestTeamMemberRemovalResult",
    "GuestTeamRevocationResult",
    "GuestTeamSummary",
    "SharedQuotaCheckResult",
]
