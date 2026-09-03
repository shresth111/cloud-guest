"""Content Filtering business logic: per-router content-filtering rule
CRUD with real domain/IP-CIDR validation.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## Live device push

``push_rule_to_device`` realizes one blocked site on its router over the
RouterOS API, through ``device_adapters``. This paragraph used to say the
opposite -- "no live device push in this pass ... real RouterOS
provisioning happens through ``app.domains.network_config``'s existing
push pipeline" -- and that deferral is what made blocking a site a
database-only operation. The customer typed ``facebook.com``, the
dashboard answered "blocked", and every guest on that router kept
reaching it. Creation still writes only a row, deliberately: renaming a
rule must not be able to fail with a connection error, and a customer
must be able to retry a push without re-submitting the form.

Deleting, unlike creating, *does* reach the device -- see
``delete_rule``. A soft-deleted row whose sinkhole is still answering is
drift this platform cannot see from either side.

## Per-rule, not per-router, and why

The push is scoped to one ``ContentFilterRule``: ``POST
/content-filter-rules/{rule_id}/push``, one row's own
``device_push_status``. A router holds many rules, so the alternative was
real -- one connection realizing all of a router's rules at once is fewer
sockets and one round trip instead of fifteen.

Per-rule wins on three counts, and the first is decisive:

1. **One bad rule must not strand the rest.** A router that refuses one
   value -- a malformed address the validators let through, a name
   already claimed by a hand-written ``/ip dns static`` entry -- fails
   that rule and only that rule. A per-router push would have to either
   abort partway, leaving some rules on the device and some not with no
   per-row record of which, or swallow the failure and report success.
   Both are the shape of bug this domain is being wired up to remove.
2. **The status columns can be honest.** ``device_push_status`` is
   per-row because the fact is per-row. A per-router push would have to
   collapse "fourteen enforcing, one refused" into one value, and
   whichever value it chose would lie about fourteen rows or about one.
3. **It matches the established precedent.** ``vlan`` and ``dhcp`` both
   push one row at a time through the identical shape, and a customer
   who has learned what the button does on one screen should not find it
   means something different here.

The cost is real and accepted: blocking ten sites at once is ten
connections. Each is a short RouterOS API session on 8728, and each is
independent -- a caller looping over rules gets nine successes and one
typed failure rather than one opaque partial outcome. Should batching
ever be worth it, the honest shape is a router-level endpoint that pushes
each rule and reports per-rule results, not one that collapses them.

## Honest scope, unchanged

DNS sinkhole + address-list/firewall-filter only: no Layer7, no
web-proxy, and under no circumstances TLS interception. See this
package's own ``__init__.py`` docstring for the full write-up, and
``wyfy_device_gateway.mikrotik_adapter.configure_content_filter_rule``
for the exact RouterOS objects a blocked site becomes.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import (
    ContentFilterCategory,
    ContentFilterDevicePushStatus,
    ContentFilterValueType,
)
from .device_adapters import ContentFilterCredentials, get_content_filter_adapter
from .events import (
    ContentFilterRuleCreated,
    ContentFilterRuleDeleted,
    ContentFilterRulePushed,
    ContentFilterRuleUpdated,
)
from .exceptions import (
    ContentFilterMissingCredentialsError,
    ContentFilterRuleAlreadyExistsError,
    ContentFilterRuleNotEnabledError,
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

    # Declared because the device-push path really calls it. Leaving it out
    # would let this Protocol under-describe what the service requires: a
    # collaborator could satisfy the annotation and still blow up at
    # runtime, with no type checker able to see it coming.
    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


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
            # Written explicitly rather than left to the column default,
            # which only applies at INSERT: a freshly constructed row would
            # otherwise carry None until it round-trips through the
            # database, and "has this reached a device" must never read as
            # unknown -- least of all on a domain whose whole defect was a
            # dashboard treating "unknown" as "blocked".
            device_push_status=ContentFilterDevicePushStatus.PENDING.value,
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

    async def push_rule_to_device(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ContentFilterRule:
        """Realizes one blocked site on its own router, over the RouterOS
        API.

        Until this existed, ``create_rule`` wrote a row, returned 201, and
        the device was never contacted -- so "blocked" meant "a database
        row exists" and nothing more, on a screen that presented it as an
        enforced restriction. That is the worst shape a gap can take: a
        missing VLAN is visibly missing, a missing block is not.

        **Separate from create/update, deliberately.** Renaming a rule
        must not be able to fail with a connection error, and a customer
        must be able to retry a push without re-submitting the form.

        **Every precondition is checked before a socket is opened**, so a
        misconfigured row fails as a 4xx naming the problem rather than as
        a device timeout.

        **A failure is committed, then re-raised.**
        ``GenericRepository.update`` only ``flush()``es and
        ``get_db_session`` rolls back on any exception, so a failure
        record written just before a re-raise is otherwise discarded and
        the row still reads ``pending`` with ``device_push_error`` NULL.
        Committing explicitly is what makes the record survive to be read
        -- and on this domain that record is the only thing standing
        between a customer and a second silent "blocked" that is not.

        The exception then propagates as a real non-2xx. It must not
        become a ``200 {"success": false}``: the frontend interceptor
        unwraps ``data`` and never reads ``success``, so such a response
        is indistinguishable from success to every caller in the app.
        """
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )

        if not rule.is_enabled:
            # A disabled rule is the customer saying this site should not
            # be blocked. Pushing it would block the site the toggle exists
            # to unblock, and reporting success for having done so.
            raise ContentFilterRuleNotEnabledError(rule.id)

        router = await self.router_lookup.get_router(
            rule.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_content_filter_adapter(router.vendor)

        try:
            await adapter.configure_content_filter_rule(
                credentials,
                rule_id=str(rule.id),
                value_type=rule.value_type,
                value=rule.value,
                label=rule.name,
            )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_rule(
                rule,
                {
                    "device_push_status": ContentFilterDevicePushStatus.FAILED.value,
                    "device_push_error": str(exc),
                },
            )
            await self.repository.commit()
            raise

        updated = await self.repository.update_rule(
            rule,
            {
                "device_push_status": ContentFilterDevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = ContentFilterRulePushed(
            id=updated.id,
            router_id=updated.router_id,
            value_type=updated.value_type,
        )
        logger.info("content_filter_rule_pushed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CONTENT_FILTER_RULE_PUSHED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"Content filter rule '{updated.name}' ({updated.value}) "
                f"pushed to router {updated.router_id}"
            ),
        )
        return updated

    async def delete_rule(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ContentFilterRule:
        """Removes the rule from its router, then soft-deletes the row.

        Deleting used to soft-delete the row and nothing else, so a site
        this platform had blocked stayed blocked on the device after the
        customer unblocked it -- with nothing anywhere to say so, and
        nothing in the dashboard that could ever show it.

        **The device comes first, and a device failure aborts the
        delete.** Removing the row while the sinkhole is still answering
        is exactly the drift this closes: the customer would believe the
        site was reachable again, and nothing would ever reconcile it.
        Failing loudly leaves both sides consistent and the delete
        retryable.

        The trade-off is real and worth stating: a rule on a permanently
        unreachable router cannot be deleted through this path. That is
        the safer side to err on -- an undeletable row is visible, a
        permanently blocked site nobody can find the cause of is not --
        but it means decommissioning a dead router needs a deliberate
        escape hatch, which this method does not provide.
        """
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        await self._remove_from_device(
            rule, requesting_organization_id=requesting_organization_id
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

    async def _remove_from_device(
        self, rule: ContentFilterRule, *, requesting_organization_id: uuid.UUID | None
    ) -> None:
        """Tears the rule off its router, when there is anything there.

        Skipped entirely unless ``device_push_status`` is ``ACTIVE``: a row
        that was never pushed, or whose last push failed, has nothing on
        the device, and opening a connection to delete nothing would make
        every such delete fail whenever a router happened to be
        unreachable.

        Only the rule's id is passed on. The current ``value``/
        ``value_type`` are deliberately not consulted: a customer who
        edited a rule and never re-pushed it has objects on the device
        matching the *old* value, and matching on the new one is exactly
        how they would be orphaned instead of removed.
        """
        if rule.device_push_status != ContentFilterDevicePushStatus.ACTIVE.value:
            return
        router = await self.router_lookup.get_router(
            rule.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_content_filter_adapter(router.vendor)
        await adapter.delete_content_filter_rule(credentials, rule_id=str(rule.id))

    def _resolve_device_credentials(self, router: Router) -> ContentFilterCredentials:
        """Raise rather than guess -- mirrors ``vlan``/``dhcp``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise ContentFilterMissingCredentialsError(router.id)
        return ContentFilterCredentials(
            host=host, username=router.api_username, password=secret
        )

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
