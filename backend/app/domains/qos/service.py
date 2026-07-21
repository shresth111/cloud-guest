"""QoS & VOIP Priority business logic: per-router traffic-classification
rule CRUD with real port-range/DSCP/priority validation.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## No live device push in this pass

Unlike ``app.domains.isp``, this domain has no ``device_adapters.py`` and
no Celery task -- it is a pure rules/inventory domain, mirroring
``app.domains.dhcp``/``app.domains.vlan``/``app.domains
.port_forwarding``/``app.domains.hotspot``'s own "config resource,
realized onto a device later" precedent. Real RouterOS
``/ip firewall mangle`` provisioning is composed via
``app.domains.network_config``, not this domain.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .events import QosTrafficRuleCreated, QosTrafficRuleDeleted, QosTrafficRuleUpdated
from .exceptions import (
    CrossOrganizationQosTrafficRuleAccessError,
    QosTrafficRuleNotFoundError,
)
from .models import QosTrafficRule
from .repository import QosRepositoryProtocol
from .validators import validate_priority, validate_traffic_match

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


class QosService:
    """Core QoS & VOIP Priority business logic."""

    def __init__(
        self,
        repository: QosRepositoryProtocol,
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
        protocol: str | None = None,
        port_range_start: int | None = None,
        port_range_end: int | None = None,
        dscp_value: int | None = None,
        priority: int,
        is_enabled: bool = True,
    ) -> QosTrafficRule:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_traffic_match(
            port_range_start=port_range_start,
            port_range_end=port_range_end,
            dscp_value=dscp_value,
        )
        validate_priority(priority)

        rule = await self.repository.create_rule(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            name=name,
            protocol=protocol,
            port_range_start=port_range_start,
            port_range_end=port_range_end,
            dscp_value=dscp_value,
            priority=priority,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = QosTrafficRuleCreated(id=rule.id, router_id=router.id)
        logger.info("qos_traffic_rule_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.QOS_TRAFFIC_RULE_CREATED,
            entity_id=rule.id,
            organization_id=rule.organization_id,
            description=f"QoS traffic rule '{name}' created for router {router.id}",
        )
        return rule

    async def get_rule(
        self,
        rule_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> QosTrafficRule:
        rule = await self.repository.get_rule_by_id(rule_id)
        if rule is None:
            raise QosTrafficRuleNotFoundError(rule_id)
        if (
            requesting_organization_id is not None
            and rule.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationQosTrafficRuleAccessError()
        return rule

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[QosTrafficRule], object]:
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
    ) -> list[QosTrafficRule]:
        """Every non-deleted rule for this router, unpaginated -- the
        real read source ``app.domains.network_config`` composes to
        render a router's full QoS mangle config, mirroring
        ``app.domains.hotspot.HotspotService
        .list_profiles_for_router``'s identical shape."""
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
    ) -> QosTrafficRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        new_port_start = fields.get("port_range_start", rule.port_range_start)
        new_port_end = fields.get("port_range_end", rule.port_range_end)
        new_dscp_value = fields.get("dscp_value", rule.dscp_value)
        match_changed = (
            new_port_start != rule.port_range_start
            or new_port_end != rule.port_range_end
            or new_dscp_value != rule.dscp_value
        )
        if match_changed:
            validate_traffic_match(
                port_range_start=new_port_start,
                port_range_end=new_port_end,
                dscp_value=new_dscp_value,
            )
        if "priority" in fields:
            validate_priority(fields["priority"])

        updated = await self.repository.update_rule(
            rule, {**fields, "updated_by": actor_user_id}
        )
        event = QosTrafficRuleUpdated(id=updated.id)
        logger.info("qos_traffic_rule_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.QOS_TRAFFIC_RULE_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"QoS traffic rule '{updated.name}' updated",
        )
        return updated

    async def delete_rule(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> QosTrafficRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_rule(rule)
        event = QosTrafficRuleDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("qos_traffic_rule_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.QOS_TRAFFIC_RULE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"QoS traffic rule '{deleted.name}' deleted",
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
            entity_type="qos_traffic_rule",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["QosService"]
