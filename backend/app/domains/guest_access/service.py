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

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.database.utils.pagination import PaginationMeta
from app.domains.rbac.enums import AuditAction

from .constants import (
    ACCESS_RULE_TYPE_PRECEDENCE,
    AccessRuleType,
    BlockEnforcementStatus,
)
from .enforcement import BlockEnforcementReport
from .events import (
    AccessRuleCreated,
    AccessRuleDeactivated,
    AccessRuleDeleted,
    GuestAccessDenied,
)
from .exceptions import AccessRuleNotFoundError, CrossOrganizationAccessRuleError
from .models import DeviceAccessRule, GuestAccessRule
from .repository import GuestAccessRepositoryProtocol
from .validators import (
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
    ) -> None:
        self.repository = repository
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
        identifier = normalize_identifier(identifier)
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
                identifier=normalize_identifier(identifier),
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
    "BlockEnforcerProtocol",
    "AccessDecisionResolver",
    "AccessRuleListResult",
    "DeviceRuleListResult",
    "GuestAccessService",
    "AuditLogWriter",
]
