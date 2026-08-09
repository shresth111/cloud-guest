"""QoS & VOIP Priority business logic: per-router traffic-classification
rule CRUD with real port-range/DSCP/priority validation, plus a real
device push for the paired ``/queue tree`` priority queue.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes -- now widened by one
method (``get_decrypted_api_secret``) to resolve real device credentials
for :meth:`QosService.push_rule_to_device`, mirroring
``app.domains.queue_management.service``'s own identical
``RouterLookupProtocol`` shape.

## Real device push: what was missing, and what closes it

RouterOS realizes QoS as two independent steps: (1) a mangle **mark**
(``/ip firewall mangle ... action=mark-packet``), and (2) a
``/queue tree`` entry that **references** that mark to actually apply
priority treatment -- a mark with nothing referencing it is inert.

Step (1) was already real: ``app.domains.network_config.renderers
.render_qos_traffic_rule`` renders it, pushed through that domain's own
already-working ``ConfigVersion``/``ProvisioningJob`` pipeline
(``POST /network-config/routers/{router_id}/push``). Step (2) had no
code anywhere -- ``docs/qos/FLOW.md`` Section 2 documented this
explicitly as a deliberate, unclosed gap. :meth:`push_rule_to_device`
closes it: a real, direct device push (this domain's own new
``device_adapters.py``, mirroring ``app.domains.queue_management``'s
established device-push pattern) that creates/updates a ``/queue tree``
entry referencing this exact rule's own packet-mark identifier
(``app.domains.qos.identifiers.qos_packet_mark_identifier`` -- the single
source of truth both this method and ``render_qos_traffic_rule`` derive
from, so the two halves can never reference different marks).

**Why a separate, explicit push endpoint, not auto-push on every
create/update/delete.** Every other "config resource" domain in this
codebase (``dhcp``/``vlan``/``port_forwarding``/``hotspot``, and this
domain's own pre-existing CRUD) deliberately keeps plain CRUD as pure,
synchronous database writes with no device I/O in the request path --
real device pushes are a separate, explicit action
(``network_config.push_config``, ``queue_management.apply_queue``, ...).
Auto-pushing on every ``update_rule`` call would make an ordinary rename
or priority tweak able to fail with a device connection error, a real
behavior change this domain's existing CRUD callers do not expect.
:meth:`push_rule_to_device` is that domain's own explicit action instead
-- reachable via ``POST /qos-rules/{rule_id}/push`` (new, ``qos.execute``-
gated, see ``router.py``), the real endpoint a future "Call Priority"
frontend push affordance would call.

``delete_rule`` is the one exception: deleting a rule that has already
been pushed also removes its live device queue tree (see that method's
own docstring) -- leaving a stale ``/queue tree`` entry referencing a
mark that will never be set again (the mangle rule is gone/re-rendered
without it) would be a real, silent device-side leak, not a "config
resource, realized later" case like ordinary CRUD.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import QosDevicePushStatus
from .device_adapters import (
    BaseQosPriorityQueueAdapter,
    QosCredentials,
    get_qos_queue_adapter,
)
from .events import (
    QosTrafficRuleCreated,
    QosTrafficRuleDeleted,
    QosTrafficRulePushed,
    QosTrafficRuleUpdated,
)
from .exceptions import (
    CrossOrganizationQosTrafficRuleAccessError,
    QosMissingCredentialsError,
    QosTrafficRuleNotEnabledError,
    QosTrafficRuleNotFoundError,
)
from .identifiers import qos_packet_mark_identifier
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

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class QosService:
    """Core QoS & VOIP Priority business logic -- see module docstring for
    the real device-push write-up."""

    def __init__(
        self,
        repository: QosRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        device_adapter_resolver: Callable[[str], BaseQosPriorityQueueAdapter] = (
            get_qos_queue_adapter
        ),
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver

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
        """Soft-deletes the row -- and, if a real ``/queue tree`` entry was
        ever pushed for it (``device_queue_id`` set), removes that device-
        side entry first. See module docstring's "why delete is the one
        exception" section for why this is real device I/O, unlike every
        other CRUD method here: a soft-deleted rule is never re-rendered
        by ``network_config`` (its mangle mark disappears from the next
        push), so a queue tree left behind would permanently reference a
        mark nothing on the device will ever set again -- a real, silent
        device-side leak, not a "config resource, realized later" case.

        Mirrors ``app.domains.queue_management.service.QueueManagementService
        .remove_queue``'s own ordering: the device call happens, and is
        allowed to raise, *before* the row is soft-deleted -- never
        swallowed, so a real device failure here leaves both the row and
        its device state intact for a retry, rather than silently
        soft-deleting a row whose device queue is actually still live."""
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        if rule.device_queue_id is not None:
            router = await self.router_lookup.get_router(
                rule.router_id, requesting_organization_id=requesting_organization_id
            )
            credentials = self._resolve_device_credentials(router)
            adapter = self._get_device_adapter(router.vendor)
            await adapter.remove_priority_queue(
                credentials, device_queue_id=rule.device_queue_id
            )
            rule = await self.repository.update_rule(
                rule,
                {
                    "device_queue_id": None,
                    "device_packet_mark": None,
                    "device_push_status": QosDevicePushStatus.PENDING.value,
                    "device_push_error": None,
                },
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

    # ========================================================================
    # Real device push -- the paired /queue tree entry (see module
    # docstring)
    # ========================================================================

    async def push_rule_to_device(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> QosTrafficRule:
        """Pushes (creates, or updates in place) a real ``/queue tree``
        entry on this rule's own router, referencing this rule's own
        packet-mark identifier -- the real fix this module exists for. See
        module docstring's "Real device push" section for the full
        before/after write-up.

        **Create vs. update.** A rule with no ``device_queue_id`` yet gets
        a fresh ``create_priority_queue`` call. A rule that already has one
        *and* whose current packet-mark identifier still matches
        ``device_packet_mark`` (i.e. the rule was not renamed since its
        last push -- ``qos_packet_mark_identifier`` is derived from
        ``name`` + row id, see ``identifiers.py``) gets the cheap
        ``set_priority`` path: only the ``priority`` field changes,
        matching the task's own guidance to use RouterOS's real
        ``/queue tree`` priority mechanism for the actual priority level.
        A rule whose identifier *did* change (a rename) cannot be updated
        in place -- ``BaseQosPriorityQueueAdapter`` has no "update packet-
        mark" primitive, mirroring RouterOS's own real ``/queue tree``
        shape (``packet-mark`` is set at creation) -- so the stale entry
        is removed and a fresh one created against the new identifier.

        **Failure is recorded, then re-raised, never swallowed** -- mirrors
        ``app.domains.queue_management.service.QueueManagementService
        .apply_queue``'s identical try/except shape exactly: a connection
        or RouterOS command failure updates ``device_push_status``/
        ``device_push_error`` on the row (so a caller inspecting the rule
        afterward sees the real failure, not silence) and then propagates
        the real exception -- this method never returns a "success" result
        for a push that did not actually happen."""
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        if not rule.is_enabled:
            raise QosTrafficRuleNotEnabledError(rule.id)

        router = await self.router_lookup.get_router(
            rule.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = self._get_device_adapter(router.vendor)
        packet_mark = qos_packet_mark_identifier(rule)

        try:
            if (
                rule.device_queue_id is not None
                and rule.device_packet_mark == packet_mark
            ):
                device_queue_id = rule.device_queue_id
                await adapter.set_priority(
                    credentials,
                    device_queue_id=device_queue_id,
                    priority=rule.priority,
                )
            else:
                if rule.device_queue_id is not None:
                    # The identifier changed (a rename) since the last
                    # push -- the stale entry references a mark that no
                    # longer exists once network_config next re-renders
                    # this rule, so it must be removed, not left behind.
                    # See this method's own docstring.
                    await adapter.remove_priority_queue(
                        credentials, device_queue_id=rule.device_queue_id
                    )
                device_queue_id = await adapter.create_priority_queue(
                    credentials,
                    name=f"cloudguest-qos-{rule.id}",
                    packet_mark=packet_mark,
                    priority=rule.priority,
                )
        except Exception as exc:  # noqa: BLE001 -- recorded, then re-raised, see docstring
            await self.repository.update_rule(
                rule,
                {
                    "device_push_status": QosDevicePushStatus.FAILED.value,
                    "device_push_error": str(exc),
                },
            )
            raise

        updated = await self.repository.update_rule(
            rule,
            {
                "device_queue_id": device_queue_id,
                "device_packet_mark": packet_mark,
                "device_push_status": QosDevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = QosTrafficRulePushed(
            id=updated.id, router_id=updated.router_id, device_queue_id=device_queue_id
        )
        logger.info("qos_traffic_rule_pushed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.QOS_TRAFFIC_RULE_PUSHED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"QoS traffic rule '{updated.name}' priority queue pushed "
                f"to router {updated.router_id}"
            ),
        )
        return updated

    def _resolve_device_credentials(self, router: Router) -> QosCredentials:
        """Mirrors ``app.domains.queue_management.service
        .QueueManagementService._resolve_device_credentials`` exactly --
        the same real ``management_ip_address``-or-``public_ip_address``
        fallback and the same "raise, don't guess" posture for a router
        with incomplete connection data."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise QosMissingCredentialsError(router.id)
        return QosCredentials(host=host, username=router.api_username, password=secret)

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
