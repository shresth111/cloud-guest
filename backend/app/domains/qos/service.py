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
priority treatment. Either one without the other is inert.

:meth:`push_rule_to_device` pushes **both**, in that order, through this
domain's own ``device_adapters.py``. It did not always: it pushed only
step (2), on the stated grounds that step (1) was "already real" through
``app.domains.network_config.renderers.render_qos_traffic_rule`` and that
domain's ``ConfigVersion``/``ProvisioningJob`` pipeline. That renderer is
real, but the only endpoint that applies it
(``POST /network-config/routers/{router_id}/push``) is not reachable from
any customer surface and no scheduled job calls it -- see
``docs/qa/NETWORK_FEATURES_AUDIT.md`` §4. So the shipped behaviour was: a
customer clicks Apply, a real ``/queue tree`` entry appears on their
router, it matches zero packets, the row reads ``active``, and the
dashboard says "Applied to your router". Pushing half a mechanism and
reporting success for it is a worse failure than pushing none, because
the half that did land makes the claim look corroborated.

Both objects derive their mark from one source of truth
(``app.domains.qos.identifiers.qos_packet_mark_identifier``, which
``render_qos_traffic_rule`` also uses), so the two halves can never
reference different strings.

**What is still unverified, and is not claimed anywhere in the UI.**
``/ip firewall mangle`` is order-sensitive: this rule sets
``passthrough=no``, so an earlier rule in ``prerouting`` matching the same
packet pre-empts it. The push appends, exactly as
``render_qos_traffic_rule``'s own ``add`` line always has, and introduces
no ordering scheme of its own -- the ordered-write design (a sentinel band
plus ``place-before``) lives in
``docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md`` §5.2 and is gated on
device tests T1/T2 that have not been run. That, and whether RouterOS
honours ``priority`` on a queue whose parent (``global``) has no ceiling
(see ``constants.QOS_QUEUE_TREE_PARENT``), are the two open
hardware questions for this feature.

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
mark that will never be set again would be a real, silent device-side
leak, not a "config resource, realized later" case like ordinary CRUD.
``delete_rule`` removes the mangle rule too, for the mirror-image reason:
leaving it behind means the router goes on marking packets for a rule the
customer deleted.

``update_rule`` is the other exception, and a smaller one: it issues no
device I/O, but an edit to a field the router actually carries demotes
``device_push_status`` back to ``pending`` in the same write, so a row
stops claiming ``active`` for values no device has. See
``app.common.device_push``.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from app.common.device_push import demote_device_push_on_edit
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import DEVICE_CARRIED_FIELDS, QosDevicePushStatus
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

        # An edit to a field the router actually carries invalidates what
        # the router is holding, so the row stops claiming ``active`` in the
        # same UPDATE that changes the values -- see
        # ``app.common.device_push`` for the rule and ``constants
        # .DEVICE_CARRIED_FIELDS`` for which of this domain's columns count
        # (``name`` among them here: it is half the packet-mark identifier).
        demotion = demote_device_push_on_edit(
            rule,
            fields,
            device_carried_fields=DEVICE_CARRIED_FIELDS,
            active_status=QosDevicePushStatus.ACTIVE.value,
            pending_status=QosDevicePushStatus.PENDING.value,
        )
        updated = await self.repository.update_rule(
            rule, {**fields, **demotion, "updated_by": actor_user_id}
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
        # ``device_pushed_at`` as well as ``device_queue_id``, because the
        # two halves can come apart: a push whose mangle write landed and
        # whose queue write then failed has a real mangle rule and no queue
        # id. Both predicates survive the ``pending`` demotion an edit
        # applies (see ``app.common.device_push``), which is the point --
        # a demoted row is one the device is still holding objects for.
        if rule.device_queue_id is not None or rule.device_pushed_at is not None:
            router = await self.router_lookup.get_router(
                rule.router_id, requesting_organization_id=requesting_organization_id
            )
            credentials = self._resolve_device_credentials(router)
            adapter = self._get_device_adapter(router.vendor)
            if rule.device_queue_id is not None:
                await adapter.remove_priority_queue(
                    credentials, device_queue_id=rule.device_queue_id
                )
            # Both halves come off, in the reverse of the order the push
            # put them on. Removing only the queue used to leave the router
            # marking packets for a rule the customer had deleted, until
            # somebody re-pushed a whole config script -- which, on the
            # customer path, nobody ever does. The mangle removal is
            # idempotent, so it is safe on a rule that never got one.
            await adapter.remove_packet_mark(credentials, rule_id=str(rule.id))
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
        """Puts both halves of this rule on its own router: the
        ``/ip firewall mangle`` rule that sets its packet mark, then the
        ``/queue tree`` entry that references that mark and applies the
        priority. See the module docstring's "Real device push" section for
        why pushing only the second one -- which is what this method used to
        do -- was worse than pushing neither, and for the one ordering
        question that remains unverified against hardware.

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

        **A failure is recorded, committed, then re-raised.** The commit is
        the whole point, and its absence was a real bug this docstring used
        to deny: ``GenericRepository.update`` only ``flush()``es and
        ``get_db_session`` rolls the session back on any exception, so the
        failure record written here was discarded on the way out. After a
        real device failure the row still read ``pending`` with
        ``device_push_error`` NULL, and the dashboard's failure tooltip
        could never fire. Worse, the rolled-back write took
        ``device_queue_id`` with it, so a push that failed *after* the
        queue was created left the platform with no pointer to a queue that
        exists -- which is why the gateway's ``create_queue_tree`` now
        keys on the queue's own deterministic name rather than trusting
        that pointer. ``dhcp`` (``push_pool_to_device``) and ``vlan``
        (``push_vlan_to_device``) had it right; this now matches them.

        The exception then propagates as a real non-2xx. It must not become
        a ``200 {"success": false}``: the frontend interceptor unwraps
        ``data`` and never reads ``success``, so such a response is
        indistinguishable from success to every caller in the app."""
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
            # The mark before the queue that reads it: a /queue tree entry
            # referencing a mark nothing sets is inert, so writing the
            # queue first would leave the router in the exact state this
            # method exists to stop -- half a mechanism -- for as long as
            # the mangle write takes, or forever if it fails. Same
            # dependency ordering vlan's push uses for interface-before-NAT.
            await adapter.apply_packet_mark(
                credentials,
                rule_id=str(rule.id),
                packet_mark=packet_mark,
                label=rule.name,
                priority=rule.priority,
                protocol=rule.protocol,
                port_range_start=rule.port_range_start,
                port_range_end=rule.port_range_end,
                dscp_value=rule.dscp_value,
            )
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
                    # longer exists, since apply_packet_mark above just
                    # rewrote this rule's mangle rule to set the new one.
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
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_rule(
                rule,
                {
                    "device_push_status": QosDevicePushStatus.FAILED.value,
                    "device_push_error": str(exc),
                },
            )
            await self.repository.commit()
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
