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

from .constants import ACCESS_RULE_TYPE_PRECEDENCE, AccessRuleType
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


class GuestAccessService:
    """CRUD over both rule tables, plus ``check_access`` (the read path
    ``GuestService``'s optional hook, and this module's own
    ``POST .../check`` endpoint, both call)."""

    def __init__(
        self,
        repository: GuestAccessRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
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
        expires_at: datetime | None,
        actor_user_id: uuid.UUID | None,
    ) -> GuestAccessRule:
        self._enforce_tenant_scope(organization_id, requesting_organization_id)
        identifier = normalize_identifier(identifier)
        now = datetime.now(UTC)
        validate_rule_expiry(rule_type=rule_type, expires_at=expires_at, now=now)
        rule = await self.repository.create_guest_rule(
            organization_id=organization_id,
            location_id=location_id,
            identifier=identifier,
            rule_type=rule_type.value,
            reason=reason,
            expires_at=expires_at,
            is_active=True,
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
        return rule

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
    "AccessDecisionResolver",
    "AccessRuleListResult",
    "DeviceRuleListResult",
    "GuestAccessService",
    "AuditLogWriter",
]
