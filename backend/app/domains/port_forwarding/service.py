"""Port Forwarding Management business logic: per-router DSTNAT rule CRUD
with real address/port validation and conflict detection.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## No live device push in this pass

Unlike ``app.domains.isp``, this domain has no ``device_adapters.py`` and
no Celery task -- it is a pure rules/inventory domain, mirroring
``app.domains.dhcp``/``app.domains.vlan``'s own "config resource, realized
onto a device later" precedent. Real RouterOS ``/ip firewall nat`` DSTNAT
provisioning belongs to the not-yet-built Network Configuration
Management domain's own provisioning-integration layer, not this one.

## Validation and conflict detection

``destination_port``/``internal_port`` must fall within the real 1-65535
range. ``source_address``/``destination_address``, when supplied, must be
real, parseable IP addresses or CIDR blocks; ``internal_address`` must be
a real, parseable single-host IP (never a CIDR -- a DSTNAT rule's own
target is always exactly one host). A new/updated rule is also checked
against every other non-deleted rule on the *same router* whose own
``(protocol, destination_address, destination_port)`` overlaps -- two
rules can't both claim to forward the same external port/protocol/address
to different internal targets (``PortForwardingConflictError``). See
``models.PortForwardingRule``'s own module docstring for why this is a
service-layer check, not a database constraint.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import PortForwardingProtocol
from .events import (
    PortForwardingRuleCreated,
    PortForwardingRuleDeleted,
    PortForwardingRuleUpdated,
)
from .exceptions import (
    CrossOrganizationPortForwardingRuleAccessError,
    PortForwardingConflictError,
    PortForwardingRuleNotFoundError,
)
from .models import PortForwardingRule
from .repository import PortForwardingRepositoryProtocol
from .validators import (
    addresses_overlap,
    protocols_overlap,
    validate_address,
    validate_ip_address,
    validate_port,
)

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick every other domain's own ``_event_extra`` uses."""
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


class PortForwardingService:
    """Core Port Forwarding Management business logic."""

    def __init__(
        self,
        repository: PortForwardingRepositoryProtocol,
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
        destination_port: int,
        internal_address: str,
        internal_port: int,
        protocol: PortForwardingProtocol = PortForwardingProtocol.BOTH,
        source_address: str | None = None,
        destination_address: str | None = None,
        description: str | None = None,
        is_enabled: bool = True,
    ) -> PortForwardingRule:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_port("destination_port", destination_port)
        validate_port("internal_port", internal_port)
        validate_address("source_address", source_address)
        validate_address("destination_address", destination_address)
        validate_ip_address("internal_address", internal_address)
        await self._check_conflict(
            router.id, protocol.value, destination_address, destination_port
        )

        rule = await self.repository.create_rule(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            name=name,
            protocol=protocol.value,
            source_address=source_address,
            destination_address=destination_address,
            destination_port=destination_port,
            internal_address=internal_address,
            internal_port=internal_port,
            description=description,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = PortForwardingRuleCreated(id=rule.id, router_id=router.id)
        logger.info("port_forwarding_rule_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PORT_FORWARDING_RULE_CREATED,
            entity_id=rule.id,
            organization_id=rule.organization_id,
            description=f"Port forwarding rule '{name}' created for router {router.id}",
        )
        return rule

    async def get_rule(
        self,
        rule_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> PortForwardingRule:
        rule = await self.repository.get_rule_by_id(rule_id)
        if rule is None:
            raise PortForwardingRuleNotFoundError(rule_id)
        if (
            requesting_organization_id is not None
            and rule.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationPortForwardingRuleAccessError()
        return rule

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[PortForwardingRule], object]:
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
    ) -> list[PortForwardingRule]:
        """Every non-deleted rule for this router, unpaginated -- the real
        read source ``app.domains.network_config`` composes to render a
        router's full port-forwarding config, mirroring
        ``app.domains.dhcp.DhcpService.list_pools_for_router``'s identical
        shape."""
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
    ) -> PortForwardingRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        new_protocol = fields.get("protocol", rule.protocol)
        new_destination_address = fields.get(
            "destination_address", rule.destination_address
        )
        new_destination_port = fields.get("destination_port", rule.destination_port)
        conflict_fields_changed = (
            new_protocol != rule.protocol
            or new_destination_address != rule.destination_address
            or new_destination_port != rule.destination_port
        )
        if "destination_port" in fields:
            validate_port("destination_port", fields["destination_port"])
        if "internal_port" in fields:
            validate_port("internal_port", fields["internal_port"])
        if "source_address" in fields:
            validate_address("source_address", fields["source_address"])
        if "destination_address" in fields:
            validate_address("destination_address", fields["destination_address"])
        if "internal_address" in fields:
            validate_ip_address("internal_address", fields["internal_address"])
        if conflict_fields_changed:
            await self._check_conflict(
                rule.router_id,
                new_protocol,
                new_destination_address,
                new_destination_port,
                exclude_rule_id=rule.id,
            )

        updated = await self.repository.update_rule(
            rule, {**fields, "updated_by": actor_user_id}
        )
        event = PortForwardingRuleUpdated(id=updated.id)
        logger.info("port_forwarding_rule_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PORT_FORWARDING_RULE_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Port forwarding rule '{updated.name}' updated",
        )
        return updated

    async def delete_rule(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> PortForwardingRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_rule(rule)
        event = PortForwardingRuleDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("port_forwarding_rule_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PORT_FORWARDING_RULE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Port forwarding rule '{deleted.name}' deleted",
        )
        return deleted

    async def _check_conflict(
        self,
        router_id: uuid.UUID,
        protocol: str,
        destination_address: str | None,
        destination_port: int,
        *,
        exclude_rule_id: uuid.UUID | None = None,
    ) -> None:
        existing = await self.repository.list_rules_for_router(router_id)
        for other in existing:
            if other.is_deleted:
                continue
            if exclude_rule_id is not None and other.id == exclude_rule_id:
                continue
            if other.destination_port != destination_port:
                continue
            if not protocols_overlap(protocol, other.protocol):
                continue
            if not addresses_overlap(destination_address, other.destination_address):
                continue
            raise PortForwardingConflictError(router_id, other.id)

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
            entity_type="port_forwarding_rule",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["RouterLookupProtocol", "AuditLogWriter", "PortForwardingService"]
