"""Guest Access Control business logic: rule CRUD
(``GuestAccessService``) and the pure precedence resolution that decides
whether a given identifier/MAC is allowed to connect
(``AccessDecisionResolver``).

## Composition, not duplication, with ``app.domains.guest``

This module never reimplements guest identity or session lifecycle -- it
knows nothing about ``Guest``/``GuestSession`` rows at all (see
``models.py``'s module docstring for why both rule tables are
identifier/MAC-keyed, not foreign-keyed to ``guest``'s own tables).
Enforcement at login time is composed the other direction: ``GuestService``
(in ``app.domains.guest``) optionally calls this module's
``AccessDecisionResolver`` through a narrow ``AccessDecisionProtocol`` --
the identical "optional, additive, ``None``-by-default hook" pattern
``GuestService``'s own ``monitoring_hook`` already established (see that
class's docstring in ``app.domains.guest.service``). This module has zero
import-time dependency on ``app.domains.guest`` -- the dependency runs
guest -> guest_access, never the reverse, keeping the module graph acyclic
exactly as the Architecture Design Document's dependency graph (§4/§21)
specifies.

## Blocking is not a database insert

``create_guest_rule`` used to write a row, audit it, and stop -- while the
customer dashboard's Blocked Guests form promised, verbatim, *"Takes
effect immediately, ending any session these users currently have."* It
did not. The blocked guest stayed online.

Signing in *again* was already handled: ``GuestService
._enforce_access_control`` consults ``check_access`` before every OTP,
voucher, password and MAC-whitelist login. What was missing is the session
the guest is already in -- which is the only part the copy promises.

A ``BLOCKLIST`` rule now runs through ``enforcement.BlocklistEnforcer``,
which removes the guest from the router's own ``/ip hotspot active`` table
over the port-8728 API and then moves their ``GuestSession`` rows to a
terminal status. Both halves are required: leaving the row ``ACTIVE`` is a
standing re-admission ticket for the next RADIUS re-authorization, and
ending only the row is a record that says "over" while the device keeps
forwarding -- the same class of lie as the original bug.

The outcome is recorded on the rule
(``enforcement_status``/``enforcement_error``/``enforced_at``/
``sessions_ended``, mirroring ``Vlan.device_push_*``) and, when the device
cannot be made to agree, raised as a typed non-2xx rather than returned as
a success envelope. The block itself is committed *first*, so a guest
whose live session could not be cut is still barred from signing in again
and an operator can retry the device half alone -- ``enforce_guest_rule``,
the same "retry the push without re-submitting the form" separation
``VlanService.push_vlan_to_device`` makes.

## Default-allow, not deny-by-default

This module does **not** turn the platform into a whitelist-only ("deny
unless explicitly allowed") system. A guest with zero matching rules is
allowed, exactly as before this module existed. ``WHITELIST`` rules exist
to *guarantee* precedence over some other rule (see
``constants.AccessRuleType.WHITELIST``'s docstring), not to gate access by
themselves. Introducing true deny-by-default would be a platform-wide
behavioral change far outside a single Phase 1 module's scope -- see the
Architecture Design Document §13 for why that kind of default belongs to
the Phase 2 Policy Engine's ``AccessPolicy`` type, not here.
"""

from __future__ import annotations

import csv
import io
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from app.common.spreadsheet_safety import sanitize_spreadsheet_cell
from app.database.utils.pagination import PaginationMeta
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import (
    LocationScope,
    enforce_entity_location,
)

from .constants import (
    ACCESS_RULE_TYPE_PRECEDENCE,
    IMPORTABLE_RULE_TYPES,
    AccessRuleType,
    BlockEnforcementStatus,
    GuestRuleImportRejectionCode,
)
from .enforcement import BlockEnforcementReport
from .events import (
    AccessRuleCreated,
    AccessRuleDeactivated,
    AccessRuleDeleted,
    AccessRulesImported,
    GuestAccessDenied,
)
from .exceptions import (
    AccessRuleNotFoundError,
    CountryCodeRequiredError,
    CrossLocationAccessRuleError,
    CrossOrganizationAccessRuleError,
    GuestAccessError,
    InvalidGuestIdentifierError,
    InvalidImportCellError,
    InvalidRuleExpiryError,
    OrganizationRequiredError,
    RuleTypeNotImportableError,
    TemporaryRuleRequiresExpiryError,
)
from .models import DeviceAccessRule, GuestAccessRule
from .repository import GuestAccessRepositoryProtocol
from .validators import (
    canonicalize_rule_identifier,
    normalize_identifier,
    normalize_mac_address,
    validate_identifier_shape,
    validate_rule_expiry,
)

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    import dataclasses

    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


# ============================================================================
# Narrow cross-domain protocol (composition, not duplication) -- what
# app.domains.guest.service.GuestService composes with, if wired.
# ============================================================================


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Pure decision resolution
# ============================================================================


@dataclass(frozen=True, slots=True)
class AccessDecision:
    """The resolved outcome of ``AccessDecisionResolver.resolve`` -- never
    persisted, only returned. ``allowed`` is the only field callers
    strictly need; ``rule_type``/``matched_rule_id``/``reason`` explain
    *why*, for logging/audit and for surfacing a specific reason to an
    admin or (via ``GuestAccessDeniedError``) a denied caller."""

    allowed: bool
    rule_type: AccessRuleType | None
    matched_rule_id: uuid.UUID | None
    reason: str | None


_DEFAULT_ALLOW = AccessDecision(
    allowed=True, rule_type=None, matched_rule_id=None, reason=None
)


class AccessDecisionResolver:
    """Pure precedence resolution over already-fetched rule rows -- no I/O
    of its own. ``GuestAccessService.check_access`` is what actually
    queries the repository and hands the results here.

    Precedence, highest first (``constants.ACCESS_RULE_TYPE_PRECEDENCE``):
    ``VIP`` > ``TEMPORARY`` > ``BLOCKLIST`` > ``WHITELIST`` > default-allow.
    A ``VIP`` rule for either the identifier or the device overrides even an
    active ``BLOCKLIST`` rule for the other -- e.g. a VIP guest's own
    blocklisted personal device still connects, and a non-VIP guest on a
    device someone else VIP-tagged still connects. Guest-level and
    device-level rules are resolved together as one combined candidate set;
    neither takes blanket priority over the other -- only ``rule_type``
    ordering matters.
    """

    def resolve(
        self,
        *,
        guest_rules: list[GuestAccessRule],
        device_rules: list[DeviceAccessRule],
    ) -> AccessDecision:
        candidates: list[tuple[AccessRuleType, uuid.UUID, str | None]] = [
            (AccessRuleType(rule.rule_type), rule.id, rule.reason)
            for rule in (*guest_rules, *device_rules)
        ]
        for rule_type in ACCESS_RULE_TYPE_PRECEDENCE:
            for candidate_type, rule_id, reason in candidates:
                if candidate_type != rule_type:
                    continue
                allowed = rule_type != AccessRuleType.BLOCKLIST
                return AccessDecision(
                    allowed=allowed,
                    rule_type=rule_type,
                    matched_rule_id=rule_id,
                    reason=reason,
                )
        return _DEFAULT_ALLOW


# ============================================================================
# Application service
# ============================================================================


@dataclass
class AccessRuleListResult:
    items: list[GuestAccessRule]
    meta: PaginationMeta


@dataclass
class DeviceRuleListResult:
    items: list[DeviceAccessRule]
    meta: PaginationMeta


@dataclass(frozen=True, slots=True)
class RejectedGuestRuleImportRow:
    """One row of a bulk import that was not written, and why.

    Mirrors ``app.domains.mac_authorization.service.RejectedImportRow``'s
    shape (the identifier that failed, plus a reason) and adds two fields
    that a 200-row hotel upload actually needs:

    * ``row_number`` -- 1-based position in the submitted batch. Without it
      an operator holding a spreadsheet and a list of three bad numbers has
      to find them by eye.
    * ``code`` -- a stable machine-readable
      ``constants.GuestRuleImportRejectionCode``, so the upload screen can
      collapse forty identical failures into one instruction instead of
      forty lines. See that enum's own docstring.
    """

    row_number: int
    identifier: str
    code: GuestRuleImportRejectionCode
    reason: str


@dataclass(frozen=True, slots=True)
class GuestRuleImportResult:
    """The outcome of one bulk import.

    Created and updated rows are counted separately rather than summed into
    one "written" number, because the difference is the whole answer to the
    question a nightly re-uploading hotel asks: 20 created and 180 updated
    means the list landed and twenty guests are new; 200 created means the
    match key is wrong and the table is being duplicated nightly.
    """

    imported_count: int
    updated_count: int
    imported_ids: list[uuid.UUID] = field(default_factory=list)
    updated_ids: list[uuid.UUID] = field(default_factory=list)
    rejected: list[RejectedGuestRuleImportRow] = field(default_factory=list)


# Exception -> stable rejection code. A dict rather than an if/elif chain so
# that adding an exception without giving it a code is a visible ``KeyError``
# in review rather than a row silently falling into a generic bucket.
_IMPORT_REJECTION_CODES: dict[type[Exception], GuestRuleImportRejectionCode] = {
    InvalidGuestIdentifierError: GuestRuleImportRejectionCode.MALFORMED_IDENTIFIER,
    CountryCodeRequiredError: GuestRuleImportRejectionCode.COUNTRY_CODE_REQUIRED,
    RuleTypeNotImportableError: (GuestRuleImportRejectionCode.RULE_TYPE_NOT_IMPORTABLE),
    TemporaryRuleRequiresExpiryError: GuestRuleImportRejectionCode.INVALID_EXPIRY,
    InvalidRuleExpiryError: GuestRuleImportRejectionCode.INVALID_EXPIRY,
    CrossLocationAccessRuleError: (GuestRuleImportRejectionCode.LOCATION_OUT_OF_SCOPE),
}

# ``InvalidImportCellError`` is one exception covering several columns, so
# its code comes from the column it names rather than from its type.
_IMPORT_CELL_CODES: dict[str, GuestRuleImportRejectionCode] = {
    "location_id": GuestRuleImportRejectionCode.INVALID_LOCATION_ID,
    "expires_at": GuestRuleImportRejectionCode.INVALID_EXPIRY,
    "email": GuestRuleImportRejectionCode.INVALID_CONTACT_EMAIL,
}


# ``GuestAccessRule.identifier`` is ``String(255)``.
_IDENTIFIER_MAX_LENGTH = 255

# Deliberately the same loose shape ``validators`` accepts for an
# identifier-shaped email, reused rather than tightened: this column is a
# contact annotation, not the match key, and a stricter parser here would
# refuse rows over an address the platform never sends anything to.
_CONTACT_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _parse_location_id(value: object) -> uuid.UUID | None:
    """A row's ``location_id``, which arrives as a string from a CSV."""
    if value is None or isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise InvalidImportCellError("location_id", value) from None


def _parse_expires_at(value: object) -> datetime | None:
    """A row's ``expires_at``, which arrives as an ISO-8601 string from a
    CSV -- the same form this domain's own export writes, so a downloaded
    file re-imports without a human reformatting dates.

    A naive value is read as UTC for the reason ``schemas
    ._assume_utc_if_naive`` documents: comparing it against
    ``datetime.now(UTC)`` would otherwise raise ``TypeError`` and take the
    whole request down as an unhandled 500.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            raise InvalidImportCellError("expires_at", value) from None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _blank_to_none(value: object) -> str | None:
    """An empty spreadsheet cell is not a value. Stored as ``""`` it would
    read as "someone deliberately wrote nothing here", which is not what a
    blank column means."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_contact_email(value: object) -> str | None:
    """A row's optional contact ``email``. Refused rather than silently
    dropped when malformed -- quietly discarding an email somebody typed is
    the exact defect ``GuestAccessRule.email`` was added to fix."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if not _CONTACT_EMAIL_RE.match(text):
        raise InvalidImportCellError("email", text)
    return text


def _import_rejection_code(exc: Exception) -> GuestRuleImportRejectionCode:
    """The code for a per-row failure. A plain ``ValueError`` can only come
    from ``AccessRuleType(...)`` rejecting a string that is not a rule type
    at all -- see ``GuestAccessService._resolve_import_rule_type``."""
    if isinstance(exc, InvalidImportCellError):
        return _IMPORT_CELL_CODES[exc.column]
    return _IMPORT_REJECTION_CODES.get(
        type(exc), GuestRuleImportRejectionCode.UNKNOWN_RULE_TYPE
    )


class BlockEnforcerProtocol(Protocol):
    """What this service needs to make a ``BLOCKLIST`` rule true on the
    device -- satisfied by ``enforcement.BlocklistEnforcer``.

    Declared as a Protocol rather than imported concretely so this module
    keeps no dependency on the device-I/O layer, exactly as
    ``AccessDecisionProtocol`` does for the reverse direction in
    ``app.domains.guest.service``.
    """

    async def enforce(
        self,
        *,
        organization_id: uuid.UUID,
        identifier: str,
        reason: str | None,
        actor_user_id: uuid.UUID | None,
    ) -> BlockEnforcementReport: ...


class GuestAccessService:
    """CRUD over both rule tables, plus ``check_access`` (the read path
    ``GuestService``'s optional hook, and this module's own
    ``POST .../check`` endpoint, both call) and the device-side
    enforcement that makes a ``BLOCKLIST`` rule true (see the module
    docstring)."""

    def __init__(
        self,
        repository: GuestAccessRepositoryProtocol,
        *,
        block_enforcer: BlockEnforcerProtocol | None,
        audit_writer: AuditLogWriter | None = None,
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        # Constructor-injected -- see `app.domains.rbac.location_scope`.
        self.caller_location_scope = caller_location_scope
        # Keyword-only and **without a default**, deliberately. A default
        # of ``None`` is how the original defect would come back: a
        # mis-wired construction would silently create blocks that end no
        # sessions, and look exactly like a correct one. Passing ``None``
        # is still allowed -- a Celery sweep that only expires rules has
        # no router stack to build -- but it has to be written down at the
        # call site, and a BLOCKLIST rule created that way records
        # ``BlockEnforcementStatus.UNENFORCED`` rather than pretending.
        self.block_enforcer = block_enforcer
        self.audit_writer = audit_writer
        self.resolver = AccessDecisionResolver()

    # -- guest (identifier-keyed) rules --------------------------------------

    async def create_guest_rule(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        identifier: str,
        rule_type: AccessRuleType,
        reason: str | None,
        email: str | None = None,
        expires_at: datetime | None,
        actor_user_id: uuid.UUID | None,
    ) -> GuestAccessRule:
        self._enforce_tenant_scope(organization_id, requesting_organization_id)
        # Canonicalize before validating, and store what was validated --
        # this is the write half of the 2026-09 "Always Allowed matches
        # nobody" fix. A phone number lands in the table as E.164 or does
        # not land at all; ``validators.canonicalize_rule_identifier`` and
        # ``exceptions.CountryCodeRequiredError`` carry the reasoning.
        identifier = canonicalize_rule_identifier(identifier)
        validate_identifier_shape(identifier)
        now = datetime.now(UTC)
        validate_rule_expiry(rule_type=rule_type, expires_at=expires_at, now=now)
        rule = await self.repository.create_guest_rule(
            organization_id=organization_id,
            location_id=location_id,
            identifier=identifier,
            rule_type=rule_type.value,
            reason=reason,
            email=email,
            expires_at=expires_at,
            is_active=True,
            enforcement_status=self._initial_enforcement_status(rule_type).value,
            created_by=actor_user_id,
            updated_by=actor_user_id,
        )
        event = AccessRuleCreated(
            rule_id=rule.id, organization_id=organization_id, rule_type=rule_type.value
        )
        logger.info("guest_access_rule_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_ACCESS_RULE_CREATED,
            entity_type="guest_access_rule",
            entity_id=rule.id,
            description=(
                f"Guest access rule created for '{identifier}' ({rule_type.value})"
            ),
            organization_id=organization_id,
            location_id=location_id,
        )
        if rule_type is not AccessRuleType.BLOCKLIST or self.block_enforcer is None:
            return rule
        # The block is committed BEFORE the device is touched, and that
        # ordering is not incidental. ``GenericRepository.create`` only
        # ``flush()``es and ``get_db_session`` rolls back on any exception,
        # so without this commit a device failure would discard the rule
        # itself -- and the customer, who asked for this person to be
        # blocked, would end up with neither the block nor the
        # disconnection. Barring a future sign-in is the half this platform
        # can always deliver; it should not be forfeited because a router
        # was unreachable.
        await self.repository.commit()
        return await self._enforce_block(rule, actor_user_id=actor_user_id)

    def _initial_enforcement_status(
        self, rule_type: AccessRuleType
    ) -> BlockEnforcementStatus:
        """The value written at insert time, before any device work.

        Three distinct values, and the distinctions are the point (see
        ``constants.BlockEnforcementStatus``): "this rule type has nothing
        to enforce", "nobody was wired up to enforce it", and "enforcement
        is under way" are three different facts, and collapsing any two of
        them is how a block that ends no sessions goes unnoticed. In
        particular this never writes ``ENFORCED`` optimistically -- a row
        may only claim that after a router has confirmed it.
        """
        if rule_type is not AccessRuleType.BLOCKLIST:
            return BlockEnforcementStatus.NOT_APPLICABLE
        if self.block_enforcer is None:
            return BlockEnforcementStatus.UNENFORCED
        return BlockEnforcementStatus.PENDING

    async def enforce_guest_rule(
        self,
        *,
        rule_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> GuestAccessRule:
        """Re-runs device-side enforcement for an existing ``BLOCKLIST``
        rule.

        **Separate from create, deliberately** -- the same separation
        ``VlanService.push_vlan_to_device`` makes and for the same reason:
        an operator whose block failed on an unreachable router must be
        able to retry the device half without re-submitting the form and
        without creating a second, duplicate rule.

        Idempotent all the way down: a guest who is already offline
        matches nothing on the router, removes nothing, and records
        ``ENFORCED`` with ``sessions_ended=0``.
        """
        rule = await self.get_guest_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        rule_type = AccessRuleType(rule.rule_type)
        if rule_type is not AccessRuleType.BLOCKLIST or self.block_enforcer is None:
            # A whitelist/VIP/temporary rule grants access -- there is no
            # session to end, and no enforcer means there is nobody to end
            # it. Both are recorded as what they are rather than silently
            # returning a row that still reads ``pending`` forever.
            return await self.repository.update_guest_rule(
                rule,
                {
                    "enforcement_status": self._initial_enforcement_status(
                        rule_type
                    ).value
                },
            )
        return await self._enforce_block(rule, actor_user_id=actor_user_id)

    async def _enforce_block(
        self, rule: GuestAccessRule, *, actor_user_id: uuid.UUID | None
    ) -> GuestAccessRule:
        """Ends the blocked guest's live sessions, and records what
        happened either way.

        **A failure is recorded, committed, and then re-raised.**
        ``GenericRepository.update`` only ``flush()``es, and
        ``get_db_session`` rolls the session back on any exception -- so a
        failure record written just before a re-raise is discarded, and the
        row would still read as though the block had reached the device.
        Committing explicitly, before raising, is what makes the record
        survive to be read. (``VlanService.push_vlan_to_device`` documents
        the same fix; ``qos.push_rule_to_device`` was the last domain still
        missing it.)

        The exception then propagates as a real non-2xx. It must not become
        a ``200 {"success": false}``: the frontend's response interceptor
        unwraps ``data`` and never reads ``success``, so such a response is
        indistinguishable from success to every caller in the app -- which
        is exactly the failure mode this whole path exists to remove.
        """
        assert self.block_enforcer is not None  # noqa: S101 -- guarded by callers
        try:
            report = await self.block_enforcer.enforce(
                organization_id=rule.organization_id,
                identifier=rule.identifier,
                reason=rule.reason,
                actor_user_id=actor_user_id,
            )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_guest_rule(
                rule,
                {
                    "enforcement_status": BlockEnforcementStatus.FAILED.value,
                    "enforcement_error": str(exc),
                    "enforced_at": datetime.now(UTC),
                    "sessions_ended": 0,
                },
            )
            await self.repository.commit()
            logger.warning(
                "guest_access_block_enforcement_failed",
                extra={
                    "event_rule_id": str(rule.id),
                    "event_identifier": rule.identifier,
                    "event_error": str(exc),
                },
            )
            raise
        updated = await self.repository.update_guest_rule(
            rule,
            {
                "enforcement_status": BlockEnforcementStatus.ENFORCED.value,
                "enforcement_error": None,
                "enforced_at": datetime.now(UTC),
                "sessions_ended": report.sessions_ended,
            },
        )
        await self.repository.commit()
        return updated

    async def get_guest_rule(
        self,
        rule_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> GuestAccessRule:
        rule = await self.repository.get_guest_rule_by_id(rule_id)
        if rule is None:
            raise AccessRuleNotFoundError(rule_id)
        self._enforce_tenant_scope(rule.organization_id, requesting_organization_id)
        # Two entities in this domain, both reached by their own id, so
        # both getters enforce -- confining one and not the other would
        # be the `voucher` mistake.
        enforce_entity_location(
            entity_location_id=getattr(rule, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationAccessRuleError(),
        )
        return rule

    async def list_guest_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        identifier: str | None = None,
        rule_type: AccessRuleType | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> AccessRuleListResult:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if identifier is not None:
            # Strip-only, deliberately: this is a dashboard list filter,
            # not an access decision. ``canonicalize_rule_identifier``
            # would refuse a bare number outright (see
            # ``CountryCodeRequiredError``), turning "search for
            # 9876543210" into a 400 -- and a search for exactly the
            # legacy rows an admin most needs to find and rewrite. The
            # filter stays an exact ``==``; the widened matching in
            # ``check_access`` is what has to be right.
            filters["identifier"] = normalize_identifier(identifier)
        if rule_type is not None:
            filters["rule_type"] = rule_type.value
        items, meta = await self.repository.list_guest_rules(
            page=page, page_size=page_size, filters=filters or None
        )
        return AccessRuleListResult(items=items, meta=meta)

    async def deactivate_guest_rule(
        self,
        *,
        rule_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> GuestAccessRule:
        rule = await self.get_guest_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_guest_rule(
            rule, {"is_active": False, "updated_by": actor_user_id}
        )
        event = AccessRuleDeactivated(rule_id=updated.id)
        logger.info("guest_access_rule_deactivated", extra=_event_extra(event))
        return updated

    async def delete_guest_rule(
        self,
        *,
        rule_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> None:
        rule = await self.get_guest_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        await self.repository.delete_guest_rule(rule)
        event = AccessRuleDeleted(rule_id=rule.id)
        logger.info("guest_access_rule_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_ACCESS_RULE_DELETED,
            entity_type="guest_access_rule",
            entity_id=rule.id,
            description=f"Guest access rule for '{rule.identifier}' deleted",
            organization_id=rule.organization_id,
            location_id=rule.location_id,
        )

    # -- bulk import / export (identifier-keyed rules) -----------------------
    #
    # Why this exists at all: a per-property whitelist-only mode turns the
    # Always Allowed list from a convenience into the entire guest
    # population of the venue. A 200-room hotel cannot type that in one
    # number at a time, and the bulk plumbing that already existed
    # (``app.domains.mac_authorization``) is keyed by MAC address -- which
    # modern phones randomise per SSID, so a MAC-keyed guest list decays
    # within days. Hotels whitelist *guests*, by the phone number they
    # booked with, and that is this table.

    async def import_guest_rules(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        default_location_id: uuid.UUID | None,
        default_rule_type: AccessRuleType,
        default_expires_at: datetime | None,
        rows: list[dict[str, object]],
        actor_user_id: uuid.UUID | None,
    ) -> GuestRuleImportResult:
        """Bulk-load identifier-keyed access rules, one bounded batch per
        request, rejecting rows individually rather than the whole batch.

        Modelled on ``app.domains.mac_authorization.service
        .MacAuthorizationService.import_entries`` -- same bounded batch,
        same "accepted rows are written, refused rows come back with a
        reason, never all-or-nothing" contract. A 200-row list with three
        bad numbers imports 197 and reports the three; one malformed row
        must not cost a hotel its other 199.

        ## Batch defaults, per-row overrides

        ``location_id``/``rule_type``/``expires_at`` are supplied once for
        the batch and may be overridden per row. Both halves earn their
        place: a nightly hotel list is one property, one rule type and (for
        most venues) one checkout time, so requiring 200 rows to repeat
        them is 200 chances for a paste error to scatter half a list to
        another site; but a PMS export legitimately carries a different
        checkout date per guest, and the CSV this domain *exports* writes
        all three per row -- so without per-row overrides a venue could not
        round-trip its own list, which is the point of having an export.

        ## What a repeat row means

        A row matching an existing rule on the whole of
        (organization, location, identifier, rule type) **updates that
        rule** rather than inserting a second one or refusing. The workflow
        this endpoint exists for is a hotel re-uploading the same list
        nightly with twenty rows changed, and the other two options both
        fail it: refusing repeats reports 180 failures a night until the
        operator stops reading the report and misses the twenty real ones,
        and inserting repeats grows the table by a full list per night, so
        ``list_matching_guest_rules`` returns N copies of every rule at
        every guest login. Skipping repeats is subtler and worse -- the
        twenty *changed* rows are exactly the ones a skip would drop.

        An existing row that has already **expired** takes the same path:
        its ``expires_at`` is overwritten and it comes back to life. A
        guest who checked out on Tuesday and checks in again on Friday is
        the same person; reporting them as "already exists" would leave
        them locked out of the network behind a green success message.

        An existing row that was **deactivated** is likewise reactivated:
        an upload that names someone is a statement that they are allowed
        now. (A deactivated WHITELIST grants nothing, so this reverses no
        block -- and it could not reverse one anyway, see below.)

        A **soft-deleted** row is not matched at all, so a fresh rule is
        written. Deleted means gone.

        A row already in the table under its **pre-E.164 spelling** -- a
        bare national number, which is what every rule written before the
        2026-09 fix is -- counts as the same rule and is rewritten in
        E.164. Without that, the very first upload after this ships would
        file a canonical row beside every dead one, and the venue would
        hold two rows per guest with only one of them reachable from the
        list screen. The import is the one moment a human supplies the
        country code that no migration could invent; taking it here is what
        eventually makes ``identifier_match_terms``' widened comparison
        inert again. Only "+"-less rows are treated this way -- see
        ``repository.find_guest_rule_for_import`` for why a write must
        match more narrowly than a read.

        The same applies *within* one batch: a CSV listing the same guest
        twice (a real thing a two-sheet spreadsheet produces) writes one
        row and updates it, because the repository lookup sees the row the
        earlier iteration flushed. Last occurrence wins.

        ## What this never does

        It cannot override a block. ``WHITELIST`` sits *below* ``BLOCKLIST``
        in ``constants.ACCESS_RULE_TYPE_PRECEDENCE``, so a blocked guest
        whose number appears in an uploaded list stays blocked -- correct,
        and not something a bulk endpoint should be able to undo by
        accident. It also refuses to *write* BLOCKLIST rows at all; see
        ``constants.IMPORTABLE_RULE_TYPES``.

        ## The one thing that *is* all-or-nothing

        "Per-row" is a statement about **validation**. There is no explicit
        commit here -- ``get_db_session`` commits the request -- so the
        whole batch is one transaction, and an unexpected database error
        rolls all of it back. That is the right split: a row this code can
        judge is reported and skipped, while a failure it cannot explain
        must not leave a venue's list half-written with no record of where
        it stopped. Same shape as
        ``MacAuthorizationService.import_entries``, for the same reason.

        Note also that ``guest_access_rules`` carries **no unique index**
        on (organization, location, identifier, rule type) -- see
        ``models.GuestAccessRule.__table_args__``. Deduplication is
        therefore this method's job alone, and a second writer racing the
        same upload could still produce a pair. Adding the constraint needs
        a migration *and* a decision about the duplicates already in
        production, neither of which belongs in this change.
        """
        self._enforce_tenant_scope(organization_id, requesting_organization_id)
        now = datetime.now(UTC)
        imported_ids: list[uuid.UUID] = []
        updated_ids: list[uuid.UUID] = []
        rejected: list[RejectedGuestRuleImportRow] = []

        for row_number, raw in enumerate(rows, start=1):
            raw_identifier = str(raw.get("identifier") or "")
            try:
                # The whole reason this endpoint is worth building rather
                # than looping the single-rule POST client-side: every row
                # goes through the *same* canonicalisation
                # ``create_guest_rule`` uses, server-side, once, before it
                # is stored. Deliberately not a second normaliser wired up
                # next to it -- two normalisers that disagree is exactly
                # how the 2026-09 "Always Allowed matches nobody" defect
                # was born, and a bulk endpoint would reproduce it a
                # thousand rows at a time.
                identifier = canonicalize_rule_identifier(raw_identifier)
                # Raises ``CountryCodeRequiredError`` for a bare national
                # number rather than guessing +91. A hotel's PMS export is
                # full of them, so this is the rejection an operator will
                # see most; it is also the only one whose fix is a column
                # formula, which is why it carries its own code.
                validate_identifier_shape(identifier)
                if len(identifier) > _IDENTIFIER_MAX_LENGTH:
                    # A misaligned column (a whole postal address pasted
                    # into the phone column) would otherwise be a database
                    # error that takes the request down with it.
                    raise InvalidGuestIdentifierError(identifier)
                rule_type = self._resolve_import_rule_type(
                    raw.get("rule_type"), default_rule_type
                )
                location_id = _parse_location_id(
                    self._resolve_override(raw, "location_id", default_location_id)
                )
                expires_at = _parse_expires_at(
                    self._resolve_override(raw, "expires_at", default_expires_at)
                )
                email = _parse_contact_email(raw.get("email"))
                reason = _blank_to_none(raw.get("reason"))
                validate_rule_expiry(
                    rule_type=rule_type, expires_at=expires_at, now=now
                )
                # A caller confined to particular sites must not be able to
                # write another site's list, and checking the *effective*
                # location per row (rather than once against the batch
                # default) is what stops row 137 from smuggling one there.
                enforce_entity_location(
                    entity_location_id=location_id,
                    caller_location_scope=self.caller_location_scope,
                    error=CrossLocationAccessRuleError(),
                )
            except (GuestAccessError, ValueError) as exc:
                rejected.append(
                    RejectedGuestRuleImportRow(
                        row_number=row_number,
                        identifier=raw_identifier,
                        code=_import_rejection_code(exc),
                        reason=str(exc),
                    )
                )
                continue

            existing = await self.repository.find_guest_rule_for_import(
                organization_id=organization_id,
                location_id=location_id,
                identifier=identifier,
                rule_type=rule_type.value,
            )
            if existing is not None:
                updated = await self.repository.update_guest_rule(
                    existing,
                    {
                        # Written unconditionally -- including when it
                        # resolves to ``None``. This upload is the venue's
                        # current statement of who is allowed and until
                        # when, so a list re-uploaded with no expiry makes
                        # its rules permanent rather than leaving yesterday's
                        # checkout time in place. That is the half of "twenty
                        # rows changed" that a skip-on-duplicate would drop.
                        "expires_at": expires_at,
                        "is_active": True,
                        "updated_by": actor_user_id,
                        # Repairs a pre-E.164 row in place. The lookup
                        # matches a stored bare national number as the same
                        # rule (see
                        # ``repository.find_guest_rule_for_import``), and
                        # this upload is the first time anyone has told the
                        # platform which country it belongs to. Written
                        # unconditionally because for an already-canonical
                        # match it is a no-op, and leaving the bare
                        # spelling in place would keep the row dependent on
                        # ``identifier_match_terms``' widened -- and
                        # deliberately lossy -- comparison forever.
                        "identifier": identifier,
                        # ``reason``/``email`` are per-guest annotations a
                        # CSV often just doesn't have a column for. An
                        # absent column must not erase a note somebody
                        # typed, so these are written only when supplied.
                        **({"reason": reason} if reason else {}),
                        **({"email": email} if email else {}),
                    },
                )
                updated_ids.append(updated.id)
                continue

            rule = await self.repository.create_guest_rule(
                organization_id=organization_id,
                location_id=location_id,
                identifier=identifier,
                rule_type=rule_type.value,
                reason=reason,
                email=email,
                expires_at=expires_at,
                is_active=True,
                enforcement_status=self._initial_enforcement_status(rule_type).value,
                created_by=actor_user_id,
                updated_by=actor_user_id,
            )
            imported_ids.append(rule.id)

        event = AccessRulesImported(
            organization_id=organization_id,
            location_id=default_location_id,
            imported_count=len(imported_ids),
            updated_count=len(updated_ids),
            rejected_count=len(rejected),
        )
        logger.info("guest_access_rules_imported", extra=_event_extra(event))
        # One audit row for the batch, not one per rule. An auditor asks
        # who uploaded a guest list at which property and when -- not which
        # of two hundred rows it contained -- and a per-row entry would
        # write 200 audit rows a night per property forever. Mirrors
        # ``VoucherService.import_voucher_codes``'s own batch-level audit.
        if imported_ids or updated_ids:
            await self._audit(
                actor_user_id,
                AuditAction.GUEST_ACCESS_RULES_IMPORTED,
                entity_type="guest_access_rule_import",
                entity_id=organization_id,
                description=(
                    f"{len(imported_ids)} guest access rule(s) imported, "
                    f"{len(updated_ids)} updated, {len(rejected)} rejected"
                ),
                organization_id=organization_id,
                location_id=default_location_id,
            )
        return GuestRuleImportResult(
            imported_count=len(imported_ids),
            updated_count=len(updated_ids),
            imported_ids=imported_ids,
            updated_ids=updated_ids,
            rejected=rejected,
        )

    def _resolve_import_rule_type(
        self, raw_rule_type: object, default_rule_type: AccessRuleType
    ) -> AccessRuleType:
        """The row's own ``rule_type`` if it named one, else the batch
        default -- refusing anything outside
        ``constants.IMPORTABLE_RULE_TYPES``.

        An unrecognised string raises ``ValueError`` out of
        ``AccessRuleType``; that is the only ``ValueError`` the import loop
        can produce, which is why it catches one at all.
        """
        rule_type = (
            default_rule_type
            if raw_rule_type is None
            else AccessRuleType(raw_rule_type)
        )
        if rule_type not in IMPORTABLE_RULE_TYPES:
            raise RuleTypeNotImportableError(rule_type.value)
        return rule_type

    @staticmethod
    def _resolve_override(raw: dict[str, object], key: str, default: object) -> object:
        """A per-row value, falling back to the batch default.

        Absence, an explicit ``null`` and an empty string are all treated
        the same on purpose: a CSV has no way to say "explicitly nothing"
        -- a blank cell arrives as ``""`` from one client and as ``null``
        from the next -- so a row that leaves ``expires_at`` blank inherits
        the batch's expiry rather than silently becoming permanent while
        every row around it expires at checkout. That difference is one a
        guest would feel: a permanent rule where a nightly one was meant
        leaves a departed guest on the network indefinitely.
        """
        value = raw.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            return default
        return value

    async def export_guest_rules_csv(
        self, *, requesting_organization_id: uuid.UUID | None
    ) -> str:
        """Every live guest rule for this organization as CSV, so a venue
        can round-trip its own list.

        Mirrors ``app.domains.mac_authorization.service
        .MacAuthorizationService.export_entries_csv``. The column order is
        deliberately the import row's own field order, so a downloaded file
        can be edited and posted straight back without a human rearranging
        columns first -- an export nobody can re-import is a dead end.

        Rows at locations outside a confined caller's own scope are
        filtered out rather than raising: an export legitimately spans a
        whole organization, including org-wide rules that belong to no
        location, so refusing the entire download because one row is out of
        scope would deny a site manager their own site's list. Filtering
        gives them exactly what they may see.
        """
        if requesting_organization_id is None:
            raise OrganizationRequiredError()
        rules = await self.repository.list_all_guest_rules_for_organization(
            requesting_organization_id
        )
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "identifier",
                "rule_type",
                "location_id",
                "expires_at",
                "reason",
                "email",
                "is_active",
                "created_at",
            ]
        )
        for rule in rules:
            if not self._may_export(rule):
                continue
            writer.writerow(
                [
                    # NOT sanitized, deliberately. An E.164 number begins
                    # with "+", which ``sanitize_spreadsheet_cell`` treats
                    # as a formula prefix and would escape to
                    # "'+919876543210" -- a string that no longer
                    # canonicalizes, so the file this endpoint exists to
                    # let a venue edit and re-upload would reject every row
                    # on the way back in. The column is also not free text:
                    # every value in it is "+" and digits or an email
                    # address, a number cell rather than a call to
                    # anything. The free-text columns below are where the
                    # actual risk lives, and they are escaped.
                    rule.identifier,
                    rule.rule_type,
                    str(rule.location_id) if rule.location_id else "",
                    rule.expires_at.isoformat() if rule.expires_at else "",
                    # ``reason`` is whatever an operator typed into the
                    # Always Allowed form, and this file is opened on a
                    # colleague's machine -- the exact shape
                    # ``app.common.spreadsheet_safety`` exists for. Its
                    # module docstring has the incident.
                    sanitize_spreadsheet_cell(rule.reason or ""),
                    sanitize_spreadsheet_cell(rule.email or ""),
                    rule.is_active,
                    rule.created_at.isoformat(),
                ]
            )
        return buffer.getvalue()

    def _may_export(self, rule: GuestAccessRule) -> bool:
        try:
            enforce_entity_location(
                entity_location_id=rule.location_id,
                caller_location_scope=self.caller_location_scope,
                error=CrossLocationAccessRuleError(),
            )
        except CrossLocationAccessRuleError:
            return False
        return True

    # -- device (MAC-keyed) rules --------------------------------------------

    async def create_device_rule(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        mac_address: str,
        rule_type: AccessRuleType,
        reason: str | None,
        email: str | None = None,
        expires_at: datetime | None,
        actor_user_id: uuid.UUID | None,
    ) -> DeviceAccessRule:
        self._enforce_tenant_scope(organization_id, requesting_organization_id)
        mac_address = normalize_mac_address(mac_address)
        now = datetime.now(UTC)
        validate_rule_expiry(rule_type=rule_type, expires_at=expires_at, now=now)
        rule = await self.repository.create_device_rule(
            organization_id=organization_id,
            location_id=location_id,
            mac_address=mac_address,
            rule_type=rule_type.value,
            reason=reason,
            email=email,
            expires_at=expires_at,
            is_active=True,
            created_by=actor_user_id,
            updated_by=actor_user_id,
        )
        event = AccessRuleCreated(
            rule_id=rule.id, organization_id=organization_id, rule_type=rule_type.value
        )
        logger.info("device_access_rule_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_ACCESS_RULE_CREATED,
            entity_type="device_access_rule",
            entity_id=rule.id,
            description=(
                f"Device access rule created for '{mac_address}' ({rule_type.value})"
            ),
            organization_id=organization_id,
            location_id=location_id,
        )
        return rule

    async def get_device_rule(
        self,
        rule_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DeviceAccessRule:
        rule = await self.repository.get_device_rule_by_id(rule_id)
        if rule is None:
            raise AccessRuleNotFoundError(rule_id)
        self._enforce_tenant_scope(rule.organization_id, requesting_organization_id)
        # Two entities in this domain, both reached by their own id, so
        # both getters enforce -- confining one and not the other would
        # be the `voucher` mistake.
        enforce_entity_location(
            entity_location_id=getattr(rule, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationAccessRuleError(),
        )
        return rule

    async def list_device_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        mac_address: str | None = None,
        rule_type: AccessRuleType | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> DeviceRuleListResult:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if mac_address is not None:
            filters["mac_address"] = normalize_mac_address(mac_address)
        if rule_type is not None:
            filters["rule_type"] = rule_type.value
        items, meta = await self.repository.list_device_rules(
            page=page, page_size=page_size, filters=filters or None
        )
        return DeviceRuleListResult(items=items, meta=meta)

    async def deactivate_device_rule(
        self,
        *,
        rule_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> DeviceAccessRule:
        rule = await self.get_device_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_device_rule(
            rule, {"is_active": False, "updated_by": actor_user_id}
        )
        event = AccessRuleDeactivated(rule_id=updated.id)
        logger.info("device_access_rule_deactivated", extra=_event_extra(event))
        return updated

    async def delete_device_rule(
        self,
        *,
        rule_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> None:
        rule = await self.get_device_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        await self.repository.delete_device_rule(rule)
        event = AccessRuleDeleted(rule_id=rule.id)
        logger.info("device_access_rule_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_ACCESS_RULE_DELETED,
            entity_type="device_access_rule",
            entity_id=rule.id,
            description=f"Device access rule for '{rule.mac_address}' deleted",
            organization_id=rule.organization_id,
            location_id=rule.location_id,
        )

    # -- decision check ----------------------------------------------------

    async def check_access(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        identifier: str | None,
        mac_address: str | None,
    ) -> AccessDecision:
        """The read path both this module's own ``POST .../check`` endpoint
        and ``GuestService``'s optional enforcement hook call. Fetches
        every matching, active, non-expired rule for whichever of
        ``identifier``/``mac_address`` were supplied, then hands them to
        ``AccessDecisionResolver`` for pure precedence resolution."""
        self._enforce_tenant_scope(organization_id, requesting_organization_id)
        now = datetime.now(UTC)
        guest_rules: list[GuestAccessRule] = []
        device_rules: list[DeviceAccessRule] = []
        if identifier is not None:
            guest_rules = await self.repository.list_matching_guest_rules(
                organization_id=organization_id,
                location_id=location_id,
                identifier=canonicalize_rule_identifier(identifier),
                now=now,
            )
        if mac_address is not None:
            device_rules = await self.repository.list_matching_device_rules(
                organization_id=organization_id,
                location_id=location_id,
                mac_address=normalize_mac_address(mac_address),
                now=now,
            )
        decision = self.resolver.resolve(
            guest_rules=guest_rules, device_rules=device_rules
        )
        if not decision.allowed and decision.matched_rule_id is not None:
            event = GuestAccessDenied(
                identifier=identifier,
                mac_address=mac_address,
                matched_rule_id=decision.matched_rule_id,
            )
            logger.info("guest_access_denied", extra=_event_extra(event))
        return decision

    # -- internal helpers ----------------------------------------------------

    def _enforce_tenant_scope(
        self,
        rule_organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if (
            requesting_organization_id is not None
            and rule_organization_id != requesting_organization_id
        ):
            raise CrossOrganizationAccessRuleError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_type: str,
        entity_id: uuid.UUID,
        description: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> None:
        if self.audit_writer is None or actor_user_id is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
            location_id=location_id,
        )


__all__ = [
    "AccessDecision",
    "RejectedGuestRuleImportRow",
    "GuestRuleImportResult",
    "BlockEnforcerProtocol",
    "AccessDecisionResolver",
    "AccessRuleListResult",
    "DeviceRuleListResult",
    "GuestAccessService",
    "AuditLogWriter",
]
