"""ISP Routing business logic: traffic-steering rule CRUD, deciding which
``IspLink`` a piece of traffic routes through.

## Composition, not duplication, with ``app.domains.router``/``app.domains.isp``

This module never resolves a router or an ISP link's own row itself.
``RouterLookupProtocol`` (satisfied structurally by
``app.domains.router.service.RouterService``) and ``IspLinkLookupProtocol``
(satisfied structurally by ``app.domains.isp.service.IspService``) are the
identical narrow, duck-typed Protocol composition-over-duplication pattern
every domain in this codebase establishes.

## No live device push in this pass

Unlike ``app.domains.isp``, this domain has no ``device_adapters.py`` and
no Celery sweep -- it is a pure rules/inventory domain, mirroring
``app.domains.policy``'s own "priority + enable/disable, realized onto a
device later" precedent. Real RouterOS policy routing needs
``/ip firewall mangle`` + ``/routing table``/``/ip route`` plumbing, which
belongs to the not-yet-built Network Configuration Management domain's own
provisioning-integration layer, not this one. See module docstring in
``__init__.py`` and ``docs/isp_routing/FLOW.md``.

## One match field per ``rule_type``

Every create/update validates via ``validators.validate_match_fields`` that
exactly the one match field ``rule_type`` names is populated and every
other match field is ``None`` -- see that function's own docstring.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.isp.models import IspLink
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import IspRoutingRuleType
from .events import IspRoutingRuleCreated, IspRoutingRuleDeleted, IspRoutingRuleUpdated
from .exceptions import (
    CrossOrganizationIspRoutingRuleAccessError,
    IspRoutingLinkRouterMismatchError,
    IspRoutingRuleNotFoundError,
)
from .models import IspRoutingRule
from .repository import IspRoutingRepositoryProtocol
from .validators import validate_match_fields

logger = logging.getLogger(__name__)

_MATCH_FIELDS = (
    "vlan_id",
    "source_mac_address",
    "ip_address",
    "source_cidr",
    "interface_name",
    "policy_id",
)


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


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


class IspLinkLookupProtocol(Protocol):
    """The one ``IspService`` method this module needs -- reused directly,
    never reimplemented."""

    async def get_link(
        self,
        link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> IspLink: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Service
# ============================================================================


class IspRoutingService:
    """Core ISP Routing business logic."""

    def __init__(
        self,
        repository: IspRoutingRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        isp_link_lookup: IspLinkLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.isp_link_lookup = isp_link_lookup
        self.audit_writer = audit_writer

    async def create_rule(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        isp_link_id: uuid.UUID,
        rule_type: IspRoutingRuleType,
        name: str,
        description: str | None = None,
        priority: int = 0,
        is_enabled: bool = True,
        vlan_id: int | None = None,
        source_mac_address: str | None = None,
        ip_address: str | None = None,
        source_cidr: str | None = None,
        interface_name: str | None = None,
        policy_id: uuid.UUID | None = None,
    ) -> IspRoutingRule:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        link = await self.isp_link_lookup.get_link(
            isp_link_id, requesting_organization_id=requesting_organization_id
        )
        if link.router_id != router.id:
            raise IspRoutingLinkRouterMismatchError(isp_link_id, router.id)
        validate_match_fields(
            rule_type,
            vlan_id=vlan_id,
            source_mac_address=source_mac_address,
            ip_address=ip_address,
            source_cidr=source_cidr,
            interface_name=interface_name,
            policy_id=policy_id,
        )
        rule = await self.repository.create_rule(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            isp_link_id=link.id,
            rule_type=rule_type.value,
            name=name,
            description=description,
            priority=priority,
            is_enabled=is_enabled,
            vlan_id=vlan_id,
            source_mac_address=source_mac_address,
            ip_address=ip_address,
            source_cidr=source_cidr,
            interface_name=interface_name,
            policy_id=policy_id,
            created_by=actor_user_id,
        )
        event = IspRoutingRuleCreated(
            rule_id=rule.id, router_id=router.id, rule_type=rule_type.value
        )
        logger.info("isp_routing_rule_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_ROUTING_RULE_CREATED,
            entity_id=rule.id,
            organization_id=rule.organization_id,
            description=f"ISP routing rule '{name}' ({rule_type.value}) created "
            f"for router {router.id}",
        )
        return rule

    async def get_rule(
        self,
        rule_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> IspRoutingRule:
        rule = await self.repository.get_rule_by_id(rule_id)
        if rule is None:
            raise IspRoutingRuleNotFoundError(rule_id)
        if (
            requesting_organization_id is not None
            and rule.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationIspRoutingRuleAccessError()
        return rule

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[IspRoutingRule], object]:
        return await self.repository.list_rules(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def update_rule(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> IspRoutingRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        new_isp_link_id = fields.get("isp_link_id", rule.isp_link_id)
        if new_isp_link_id != rule.isp_link_id:
            link = await self.isp_link_lookup.get_link(
                new_isp_link_id, requesting_organization_id=requesting_organization_id
            )
            if link.router_id != rule.router_id:
                raise IspRoutingLinkRouterMismatchError(new_isp_link_id, rule.router_id)

        new_rule_type = fields.get("rule_type", rule.rule_type)
        match_field_values = {
            name: fields.get(name, getattr(rule, name)) for name in _MATCH_FIELDS
        }
        validate_match_fields(IspRoutingRuleType(new_rule_type), **match_field_values)

        updated = await self.repository.update_rule(
            rule, {**fields, "updated_by": actor_user_id}
        )
        event = IspRoutingRuleUpdated(rule_id=updated.id)
        logger.info("isp_routing_rule_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_ROUTING_RULE_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"ISP routing rule '{updated.name}' updated",
        )
        return updated

    async def delete_rule(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> IspRoutingRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_rule(rule)
        event = IspRoutingRuleDeleted(rule_id=deleted.id, router_id=deleted.router_id)
        logger.info("isp_routing_rule_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_ROUTING_RULE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"ISP routing rule '{deleted.name}' deleted",
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
            entity_type="isp_routing_rule",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "RouterLookupProtocol",
    "IspLinkLookupProtocol",
    "AuditLogWriter",
    "IspRoutingService",
]
