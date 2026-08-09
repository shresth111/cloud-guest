"""Content Filtering business logic: per-router content-filtering rule
CRUD with real domain/IP-CIDR validation.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## No live device push in this pass

Mirrors ``app.domains.firewall``/``app.domains.mac_authorization``'s own
"config resource, realized onto a device later" precedent -- real
RouterOS DNS-sinkhole/address-list provisioning happens through
``app.domains.network_config``'s existing push pipeline
(``renderers.render_content_filter_rule``), not this one. See that
module's own "Content Filtering" docstring section for the full, honest
scope write-up (DNS sinkhole + address-list/firewall-filter, no Layer7,
no web-proxy, no TLS interception).
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import ContentFilterCategory, ContentFilterValueType
from .events import (
    ContentFilterRuleCreated,
    ContentFilterRuleDeleted,
    ContentFilterRuleUpdated,
)
from .exceptions import (
    ContentFilterRuleAlreadyExistsError,
    ContentFilterRuleNotFoundError,
    CrossOrganizationContentFilterRuleAccessError,
)
from .models import ContentFilterRule
from .repository import ContentFilterRepositoryProtocol
from .validators import normalize_rule_value

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


class ContentFilterService:
    """Core Content Filtering business logic."""

    def __init__(
        self,
        repository: ContentFilterRepositoryProtocol,
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
        value_type: ContentFilterValueType,
        value: str,
        category: ContentFilterCategory | None = None,
        comment: str | None = None,
        is_enabled: bool = True,
    ) -> ContentFilterRule:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        normalized_value = normalize_rule_value(value_type, value)
        existing = await self.repository.get_rule_by_router_and_value(
            router.id, value_type.value, normalized_value
        )
        if existing is not None:
            raise ContentFilterRuleAlreadyExistsError(
                router.id, value_type.value, normalized_value
            )

        rule = await self.repository.create_rule(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            name=name,
            category=category.value if category is not None else None,
            value_type=value_type.value,
            value=normalized_value,
            comment=comment,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = ContentFilterRuleCreated(id=rule.id, router_id=router.id)
        logger.info("content_filter_rule_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CONTENT_FILTER_RULE_CREATED,
            entity_id=rule.id,
            organization_id=rule.organization_id,
            description=f"Content filter rule '{name}' created for router {router.id}",
        )
        return rule

    async def get_rule(
        self,
        rule_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> ContentFilterRule:
        rule = await self.repository.get_rule_by_id(rule_id)
        if rule is None:
            raise ContentFilterRuleNotFoundError(rule_id)
        if (
            requesting_organization_id is not None
            and rule.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationContentFilterRuleAccessError()
        return rule

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ContentFilterRule], object]:
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
    ) -> list[ContentFilterRule]:
        """Every non-deleted rule for this router, unpaginated -- the real
        read source ``app.domains.network_config`` composes to render a
        router's full content-filtering config."""
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
    ) -> ContentFilterRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        new_value_type = ContentFilterValueType(
            fields.get("value_type", rule.value_type)
        )
        if "value_type" in fields:
            fields["value_type"] = new_value_type.value
        if "category" in fields and fields["category"] is not None:
            fields["category"] = ContentFilterCategory(fields["category"]).value

        if "value" in fields or "value_type" in fields:
            normalized_value = normalize_rule_value(
                new_value_type, str(fields.get("value", rule.value))
            )
            if (
                normalized_value != rule.value
                or new_value_type.value != rule.value_type
            ):
                existing = await self.repository.get_rule_by_router_and_value(
                    rule.router_id, new_value_type.value, normalized_value
                )
                if existing is not None and existing.id != rule.id:
                    raise ContentFilterRuleAlreadyExistsError(
                        rule.router_id, new_value_type.value, normalized_value
                    )
            fields["value"] = normalized_value

        updated = await self.repository.update_rule(
            rule, {**fields, "updated_by": actor_user_id}
        )
        event = ContentFilterRuleUpdated(id=updated.id)
        logger.info("content_filter_rule_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CONTENT_FILTER_RULE_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Content filter rule '{updated.name}' updated",
        )
        return updated

    async def delete_rule(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ContentFilterRule:
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_rule(rule)
        event = ContentFilterRuleDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("content_filter_rule_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CONTENT_FILTER_RULE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Content filter rule '{deleted.name}' deleted",
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
            entity_type="content_filter_rule",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["RouterLookupProtocol", "AuditLogWriter", "ContentFilterService"]
