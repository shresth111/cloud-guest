"""Port Forwarding Management business logic: per-router DSTNAT rule CRUD
with real address/port validation and conflict detection.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## Live device push

``push_rule_to_device`` realizes a rule on its router over the RouterOS
API, through ``device_adapters``. This paragraph previously said the
opposite -- "a pure rules/inventory domain, no ``device_adapters.py`` and
no Celery task" -- and deferred real ``/ip firewall nat`` DSTNAT
provisioning to a "not-yet-built Network Configuration Management domain".
That deferral is what made publishing a port a database-only operation:
the dashboard listed the forward, the router had none, and the service
behind it -- a camera, a PMS terminal, an office NAS -- answered nothing
from outside, with no failure anywhere to point at.

The gateway writer already existed
(``wyfy_device_gateway.mikrotik_adapter.configure_port_forward``, the real
``/ip firewall nat add chain=dstnat ... action=dst-nat`` over librouteros
on 8728) with no callers. Creation still writes only a row, deliberately:
renaming a rule must not be able to fail with a connection error, and an
operator must be able to retry a push without re-submitting the form.

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
from datetime import UTC, datetime
from typing import Protocol

from app.common.device_push import demote_device_push_on_edit
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import (
    DEVICE_CARRIED_FIELDS,
    PortForwardingDevicePushStatus,
    PortForwardingProtocol,
)
from .device_adapters import PortForwardingCredentials, get_port_forwarding_adapter
from .events import (
    PortForwardingRuleCreated,
    PortForwardingRuleDeleted,
    PortForwardingRulePushed,
    PortForwardingRuleUpdated,
)
from .exceptions import (
    CrossOrganizationPortForwardingRuleAccessError,
    PortForwardingConflictError,
    PortForwardingMissingCredentialsError,
    PortForwardingRuleNotEnabledError,
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

    # Declared because the device-push path really calls it. Leaving it out
    # would let this Protocol under-describe what the service requires: a
    # collaborator could satisfy the annotation and still blow up at
    # runtime, with no type checker able to see it coming.
    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


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
            # Written explicitly rather than left to the column default,
            # which only applies at INSERT: a freshly constructed row would
            # otherwise carry None until it round-trips through the
            # database, and "has this reached a device" must never read as
            # unknown.
            device_push_status=PortForwardingDevicePushStatus.PENDING.value,
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

        # An edit to a field the router actually carries invalidates what
        # the router is holding, so the row stops claiming ``active`` in the
        # same UPDATE that changes the values -- see
        # ``app.common.device_push`` for the rule and ``constants
        # .DEVICE_CARRIED_FIELDS`` for which of this domain's columns count.
        demotion = demote_device_push_on_edit(
            rule,
            fields,
            device_carried_fields=DEVICE_CARRIED_FIELDS,
            active_status=PortForwardingDevicePushStatus.ACTIVE.value,
            pending_status=PortForwardingDevicePushStatus.PENDING.value,
        )
        updated = await self.repository.update_rule(
            rule, {**fields, **demotion, "updated_by": actor_user_id}
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
        """Removes the rule from its router, then soft-deletes the row.

        Deleting used to soft-delete the row and nothing else, so a DSTNAT
        rule this platform had created went on forwarding a public port
        into the customer's LAN after the operator deleted it -- the one
        piece of drift in this codebase that is an exposure rather than
        just an inconsistency, and invisible from the dashboard precisely
        because the row it came from is gone.

        **The device comes first, and a device failure aborts the delete.**
        Removing the row while the forward is still live is exactly the
        drift this closes. Failing loudly leaves both sides consistent and
        the delete retryable.

        The trade-off is real: a rule on a permanently unreachable router
        cannot be deleted through this path. That is the safer side to err
        on -- an undeletable row is visible, an orphaned live port forward
        is not.
        """
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )
        await self._remove_from_device(
            rule, requesting_organization_id=requesting_organization_id
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

    async def push_rule_to_device(
        self,
        rule_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> PortForwardingRule:
        """Realizes one port-forwarding rule on its own router, over the
        RouterOS API.

        Until this existed, ``create_rule`` wrote a row, returned 201, and
        the device was never contacted -- this module's own docstring said
        so and called it deliberate. The visible consequence was a service
        the dashboard listed as published on a port that answered nothing
        from outside.

        **Separate from create/update, deliberately.** Renaming a rule must
        not be able to fail with a connection error, and an operator must be
        able to retry a push without re-submitting the form.

        **Every precondition is checked before a socket is opened**, so a
        misconfigured row fails as a 4xx naming the problem rather than as a
        device timeout.

        **A failure is committed, then re-raised.**
        ``GenericRepository.update`` only ``flush()``es and
        ``get_db_session`` rolls back on any exception, so a failure record
        written just before a re-raise is otherwise discarded and the row
        still reads ``pending`` with ``device_push_error`` NULL. Committing
        explicitly is what makes the record survive to be read.

        The exception then propagates as a real non-2xx. It must not become
        a ``200 {"success": false}``: the frontend interceptor unwraps
        ``data`` and never reads ``success``, so such a response is
        indistinguishable from success to every caller in the app.
        """
        rule = await self.get_rule(
            rule_id, requesting_organization_id=requesting_organization_id
        )

        if not rule.is_enabled:
            # A disabled rule is intent to *not* forward. Pushing one opens
            # a live inbound path through the WAN for a row the operator
            # switched off -- the failure mode here is an exposure, not
            # drift, so it is refused rather than silently skipped.
            raise PortForwardingRuleNotEnabledError(rule.id)

        router = await self.router_lookup.get_router(
            rule.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_port_forwarding_adapter(router.vendor)

        try:
            await adapter.configure_port_forward(
                credentials,
                rule_id=str(rule.id),
                protocol=rule.protocol,
                external_port=rule.destination_port,
                internal_ip=rule.internal_address,
                internal_port=rule.internal_port,
                destination_address=rule.destination_address,
                source_address=rule.source_address,
            )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_rule(
                rule,
                {
                    "device_push_status": (
                        PortForwardingDevicePushStatus.FAILED.value
                    ),
                    "device_push_error": str(exc),
                },
            )
            await self.repository.commit()
            raise

        updated = await self.repository.update_rule(
            rule,
            {
                "device_push_status": PortForwardingDevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = PortForwardingRulePushed(
            id=updated.id,
            router_id=updated.router_id,
            destination_port=updated.destination_port,
        )
        logger.info("port_forwarding_rule_pushed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PORT_FORWARDING_RULE_PUSHED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"Port forwarding rule {updated.id} pushed to router "
                f"{updated.router_id}"
            ),
        )
        return updated

    async def _remove_from_device(
        self,
        rule: PortForwardingRule,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        """Tears the rule off its router, when there is anything there.

        Skipped entirely unless this row has actually been pushed at some
        point (``device_pushed_at`` is set): a row that was never pushed,
        or whose first push failed, has nothing on the device, and opening
        a connection to delete nothing would make every such delete fail
        whenever a router happened to be unreachable.

        Keyed on ``device_pushed_at``, not on ``device_push_status ==
        ACTIVE``, and the difference is load-bearing: an edit to a
        device-carried field demotes a live row to ``pending`` (see
        ``app.common.device_push``) precisely *because* the device is still
        holding the previous values. Reading ``pending`` as "nothing to
        remove" would orphan exactly the objects the demotion exists to
        flag.
        """
        if rule.device_pushed_at is None:
            return
        router = await self.router_lookup.get_router(
            rule.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_port_forwarding_adapter(router.vendor)
        # Only the id: the rule is found on the device by its identity, so a
        # rule left from an earlier port or internal host is removed too.
        await adapter.delete_port_forward(credentials, rule_id=str(rule.id))

    def _resolve_device_credentials(
        self, router: Router
    ) -> PortForwardingCredentials:
        """Raise rather than guess -- mirrors ``dhcp``/``vlan``/``qos``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise PortForwardingMissingCredentialsError(router.id)
        return PortForwardingCredentials(
            host=host, username=router.api_username, password=secret
        )

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
