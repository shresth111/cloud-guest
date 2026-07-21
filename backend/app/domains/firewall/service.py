"""Firewall Rule Management business logic: per-router packet-filter rule
CRUD with real port/address validation.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## No live device push in this pass, and no conflict detection

Mirrors ``app.domains.dhcp``/``app.domains.vlan``'s own "config resource,
realized onto a device later" precedent -- real RouterOS firewall-filter
provisioning belongs to ``app.domains.network_config``'s existing
provisioning-integration layer, not this one. See ``models.FirewallRule``'s
own module docstring for why overlapping rules are valid, intentional
policy here, unlike ``app.domains.dhcp``/``app.domains.port_forwarding``'s
own conflict checks.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import DEFAULT_PRIORITY, FirewallAction, FirewallChain, FirewallProtocol
from .events import FirewallRuleCreated, FirewallRuleDeleted, FirewallRuleUpdated
from .exceptions import (
    CrossOrganizationFirewallRuleAccessError,
    FirewallRuleNotFoundError,
)
from .models import FirewallRule
from .repository import FirewallRepositoryProtocol
from .validators import validate_address, validate_port

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class FirewallService:
    """Core Firewall Rule Management business logic."""

    def __init__(
        self,
        repository: FirewallRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer

    async def create_rule(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        name: str,
        chain: FirewallChain = FirewallChain.FORWARD,
        action: FirewallAction = FirewallAction.ACCEPT,
        protocol: FirewallProtocol = FirewallProtocol.ALL,
        source_address: str | None = None,
        destination_address: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        in_interface: str | None = None,
        priority: int = DEFAULT_PRIORITY,
        comment: str | None = None,
        is_enabled: bool = True,
    ) -> FirewallRule:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_address("source_address", source_address)
        validate_address("destination_address", destination_address)
        validate_port("source_port", source_port)
        validate_port("destination_port", destination_port)

        rule = await self.repository.create_rule(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            name=name,
            chain=chain.value,
            action=action.value,
            protocol=protocol.value,
            source_address=source_address,
            destination_address=destination_address,
            source_port=source_port,
            destination_port=destination_port,
            in_interface=in_interface,
            priority=priority,
            comment=comment,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = FirewallRuleCreated(id=rule.id, router_id=router.id)
        logger.info("firewall_rule_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.FIREWALL_RULE_CREATED,
            entity_id=rule.id,
            organization_id=rule.organization_id,
            description=f"Firewall rule '{name}' created for router {router.id}",
        )
        return rule

    async def get_rule(
        self,
        rule_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> FirewallRule:
        rule = await self.repository.get_rule_by_id(rule_id)
        if rule is None:
            raise FirewallRuleNotFoundError(rule_id)
        if (
            requesting_organization_id is not None
            and rule.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationFirewallRuleAccessError()
        return rule

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[FirewallRule], object]:
        return await self.repository.list_rules(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def list_rules_for_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[FirewallRule]:
        """Every non-deleted rule for this router, in priority order,
        unpaginated -- the real read source ``app.domains.network_config``
        composes to render a router's full firewall config."""
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_rules_for_router(router_id)

    async def update_rule(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> FirewallRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        if "source_address" in fields:
            validate_address("source_address", fields["source_address"])
        if "destination_address" in fields:
            validate_address("destination_address", fields["destination_address"])
        if "source_port" in fields:
            validate_port("source_port", fields["source_port"])
        if "destination_port" in fields:
            validate_port("destination_port", fields["destination_port"])
        for enum_field, enum_cls in (
            ("chain", FirewallChain),
            ("action", FirewallAction),
            ("protocol", FirewallProtocol),
        ):
            if enum_field in fields and isinstance(fields[enum_field], enum_cls):
                fields[enum_field] = fields[enum_field].value

        updated = await self.repository.update_rule(
            rule, {**fields, "updated_by": actor_user_id}
        )
        event = FirewallRuleUpdated(id=updated.id)
        logger.info("firewall_rule_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.FIREWALL_RULE_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Firewall rule '{updated.name}' updated",
        )
        return updated

    async def delete_rule(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> FirewallRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_rule(rule)
        event = FirewallRuleDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("firewall_rule_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.FIREWALL_RULE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Firewall rule '{deleted.name}' deleted",
        )
        return deleted

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="firewall_rule",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["RouterLookupProtocol", "AuditLogWriter", "FirewallService"]
