"""Firewall Rule Management business logic: per-router packet-filter rule
CRUD with real port/address validation, and the push that puts a router's
rules on the device.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## The device push is per router, not per rule

``push_rules_to_router`` converges a router's whole enabled rule set onto
the device over the RouterOS API (8728), inside the sentinel band
(``wyfy_device_gateway.mikrotik_firewall``). Per router because a rule's
effect depends on its position, and position is ``priority`` *relative to
the other rules* -- pushing one row alone cannot say where it goes. A
disabled or deleted rule is removed by the next push.

Create/update/delete stay device-free, as before: editing a row must not be
able to fail with a connection error, and an edit to a device-carried field
demotes an ``ACTIVE`` row to ``PENDING`` so the dashboard never shows a
green badge over values the router does not hold.

**MikroTik only.** A controller-managed (Omada) router is refused before a
row is written and before any push -- the same gate every device domain
uses, unchanged.

## What the push does not cover

It snapshots this platform's own rules before writing and restores them if
a write or the read-back verification fails. It does not test connectivity
after a successful push and revert on loss (no safety-revert), and it holds
no per-router lock, so two pushes to one router at the same moment are not
serialised. See the gateway module's "What this does NOT do".

No conflict detection: see ``models.FirewallRule``'s own module docstring
for why overlapping rules are valid, intentional policy here.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from wyfy_device_gateway.contract import FirewallBandResult, FirewallFilterRuleConfig

from app.common.device_push import demote_device_push_on_edit
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import LocationScope, enforce_entity_location
from app.domains.router.device_domain_gate import ensure_not_controller_managed
from app.domains.router.models import Router

from .constants import (
    DEFAULT_PRIORITY,
    DEVICE_CARRIED_FIELDS,
    FirewallAction,
    FirewallChain,
    FirewallDevicePushStatus,
    FirewallProtocol,
)
from .device_adapters import FirewallCredentials, get_firewall_adapter
from .events import (
    FirewallBandInstalled,
    FirewallRuleCreated,
    FirewallRuleDeleted,
    FirewallRulesPushed,
    FirewallRuleUpdated,
)
from .exceptions import (
    CrossLocationFirewallRuleAccessError,
    CrossOrganizationFirewallRuleAccessError,
    FirewallChainNotPushableError,
    FirewallMissingCredentialsError,
    FirewallPushFailedError,
    FirewallRuleNotFoundError,
)
from .models import FirewallRule
from .repository import FirewallRepositoryProtocol
from .validators import validate_address, validate_port

logger = logging.getLogger(__name__)

#: The venue-facing name of this screen, as it goes into the
#: controller-managed refusal a venue owner reads.
_FEATURE_NAME = "Firewall Rules"


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

    # Declared because the device push really calls it.
    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


@dataclasses.dataclass(frozen=True, slots=True)
class FirewallPushOutcome:
    """A router's rules after a successful push, and what the push did."""

    rules: list[FirewallRule]
    added: int
    removed: int
    unchanged: int


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
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        # Constructor-injected, deliberately, while `requesting_organization_id`
        # stays a per-method argument. The two look similar and are not: an
        # organization id is an *argument* -- which tenant's data this call is
        # about, and a system-internal caller legitimately passes a different
        # one per call. A location confinement is a *property of the caller*,
        # fixed for the whole request, and it is a security control.
        #
        # Threading a security control through every method means every method
        # can forget it. A mutator that accepts `caller_location_scope` and
        # forgets to pass it into `get_rule` produces no error, no test
        # failure, and no enforcement -- a guard that fails open silently.
        # Here every path funnels through `get_rule`, so there is nothing
        # per-method to forget.
        #
        # This is only safe because the service is built fresh per request (a
        # plain FastAPI dependency, no caching, no module-level instance). If
        # one were ever shared between requests it would hand one caller's
        # confinement to another's. `test_location_scope_in_services` asserts
        # the per-request property rather than trusting it.
        self.caller_location_scope = caller_location_scope

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
        # Refused here, before a row exists. The adapter registry below would
        # decline this vendor eventually -- but only on a later `push`, after
        # this method has returned 201 and the venue has been shown a saved
        # setting that will never reach any device. See
        # `app.domains.router.device_domain_gate` for why the message is
        # written for the venue rather than for the registry.
        ensure_not_controller_managed(router, feature=_FEATURE_NAME)
        # Creating a rule on a router at a site the caller has no grant on is
        # the same defect as editing one there.
        enforce_entity_location(
            caller_location_scope=self.caller_location_scope,
            entity_location_id=router.location_id,
            error=CrossLocationFirewallRuleAccessError(),
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
            # Explicit rather than left to the column default, which only
            # applies at INSERT: the response is built from this object, and
            # "is this on the router" must never read as unknown.
            device_push_status=FirewallDevicePushStatus.PENDING.value,
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
        # The organization comparison above is not enough on its own. A rule is
        # reached by its own id, so `RequirePermission` had nothing to pin the
        # check to and a LOCATION-scoped grant on the caller's *own* site
        # satisfied it; without this, that account could read, edit and delete
        # the firewall rules of every other site in the same organization.
        enforce_entity_location(
            caller_location_scope=self.caller_location_scope,
            entity_location_id=rule.location_id,
            error=CrossLocationFirewallRuleAccessError(),
        )
        return rule

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[FirewallRule], object]:
        # A confined caller sees only their own sites' rules. Filtering rather
        # than refusing: a list is a legitimate request whose *answer* is
        # narrower, unlike fetching one specific foreign rule.
        return await self.repository.list_rules(
            requesting_organization_id=requesting_organization_id,
            location_ids=self.caller_location_scope,
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
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        enforce_entity_location(
            caller_location_scope=self.caller_location_scope,
            entity_location_id=router.location_id,
            error=CrossLocationFirewallRuleAccessError(),
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
            rule_id,
            requesting_organization_id=requesting_organization_id,
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

        # An edit to anything the device carries means the router no longer
        # holds what this row describes. See `app.common.device_push`.
        demotion = demote_device_push_on_edit(
            rule,
            fields,
            device_carried_fields=DEVICE_CARRIED_FIELDS,
            active_status=FirewallDevicePushStatus.ACTIVE.value,
            pending_status=FirewallDevicePushStatus.PENDING.value,
        )
        updated = await self.repository.update_rule(
            rule, {**fields, **demotion, "updated_by": actor_user_id}
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
            rule_id,
            requesting_organization_id=requesting_organization_id,
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

    async def push_rules_to_router(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> FirewallPushOutcome:
        """Put this router's enabled rules on the device, in priority order,
        inside its sentinel band; take off any of ours that are no longer
        enabled.

        Every precondition is checked before a socket opens: the vendor gate,
        the caller's site scope, credentials, and that every enabled rule is
        in ``forward`` (the only chain with a band). The gateway then refuses
        on its own -- band missing, a marker it cannot explain, a rule that
        would cut the management path -- before writing anything.

        **A failure is committed, then re-raised**, exactly as
        ``ContentFilterService.push_rule_to_device`` does: the session rolls
        back on any exception, so the failure record would otherwise vanish.
        What the rows say after a failure depends on what the device now
        holds. A refusal, a connection failure, or a failed push whose
        snapshot was restored leaves the device as it was -- rules that were
        ``ACTIVE`` stay ``ACTIVE``, the rest become ``FAILED`` with the
        reason. A failed push that could NOT be restored leaves the device
        unknown, so every enabled rule becomes ``FAILED``.
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        ensure_not_controller_managed(router, feature=_FEATURE_NAME)
        enforce_entity_location(
            caller_location_scope=self.caller_location_scope,
            entity_location_id=router.location_id,
            error=CrossLocationFirewallRuleAccessError(),
        )
        rules = await self.repository.list_rules_for_router(router.id)
        enabled = [rule for rule in rules if rule.is_enabled]
        unpushable = [
            rule.name for rule in enabled if rule.chain != FirewallChain.FORWARD.value
        ]
        if unpushable:
            raise FirewallChainNotPushableError(unpushable)

        credentials = self._resolve_device_credentials(router)
        adapter = get_firewall_adapter(router.vendor)
        known_ids = await self.repository.list_rule_ids_for_router(router.id)

        try:
            result = await adapter.sync_firewall_rules(
                credentials,
                rules=[self._to_config(rule) for rule in enabled],
                known_rule_ids=[str(rule_id) for rule_id in known_ids],
            )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            device_unknown = (
                isinstance(exc, FirewallPushFailedError) and not exc.restored
            )
            for rule in enabled:
                if (
                    not device_unknown
                    and rule.device_push_status
                    == FirewallDevicePushStatus.ACTIVE.value
                ):
                    continue
                await self.repository.update_rule(
                    rule,
                    {
                        "device_push_status": FirewallDevicePushStatus.FAILED.value,
                        "device_push_error": str(exc),
                    },
                )
            await self.repository.commit()
            raise

        now = datetime.now(UTC)
        updated: list[FirewallRule] = []
        for rule in rules:
            if rule.is_enabled:
                changes: dict[str, object] = {
                    "device_push_status": FirewallDevicePushStatus.ACTIVE.value,
                    "device_push_error": None,
                    "device_pushed_at": now,
                }
            else:
                # Taken off the router by this push (or never on it).
                changes = {
                    "device_push_status": FirewallDevicePushStatus.PENDING.value,
                    "device_push_error": None,
                    "device_pushed_at": None,
                }
            updated.append(await self.repository.update_rule(rule, changes))

        event = FirewallRulesPushed(
            router_id=router.id,
            added=result.added,
            removed=result.removed,
            unchanged=result.unchanged,
        )
        logger.info("firewall_rules_pushed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.FIREWALL_RULES_PUSHED,
            entity_id=router.id,
            entity_type="router",
            organization_id=router.organization_id,
            description=(
                f"Firewall rules pushed to router {router.id}: "
                f"{len(enabled)} enabled ({result.added} added, "
                f"{result.removed} removed, {result.unchanged} unchanged)"
            ),
        )
        return FirewallPushOutcome(
            rules=updated,
            added=result.added,
            removed=result.removed,
            unchanged=result.unchanged,
        )

    async def install_firewall_band(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
    ) -> FirewallBandResult:
        """Place the router's forward-chain sentinel band, once.

        A provisioning-time, platform-operator action (PRD §37.2): the band
        goes directly above the platform's own established/related accept,
        found by comment and required to exist exactly once, or nothing is
        written. An existing band is never moved. The route that calls this
        is pinned to GLOBAL scope -- a venue cannot place or move it."""
        router = await self.router_lookup.get_router(router_id)
        ensure_not_controller_managed(router, feature=_FEATURE_NAME)
        credentials = self._resolve_device_credentials(router)
        adapter = get_firewall_adapter(router.vendor)
        result = await adapter.install_firewall_band(credentials)

        event = FirewallBandInstalled(router_id=router.id, created=result.created)
        logger.info("firewall_band_installed", extra=_event_extra(event))
        if result.created:
            await self._audit(
                actor_user_id,
                AuditAction.FIREWALL_BAND_INSTALLED,
                entity_id=router.id,
                entity_type="router",
                organization_id=router.organization_id,
                description=(
                    f"Firewall sentinel band placed on router {router.id} "
                    f"above rule {result.anchor_id}"
                ),
            )
        return result

    @staticmethod
    def _to_config(rule: FirewallRule) -> FirewallFilterRuleConfig:
        return FirewallFilterRuleConfig(
            rule_id=str(rule.id),
            chain=rule.chain,
            action=rule.action,
            priority=rule.priority,
            protocol=(
                None if rule.protocol == FirewallProtocol.ALL.value else rule.protocol
            ),
            src_address=rule.source_address,
            dst_address=rule.destination_address,
            src_port=rule.source_port,
            dst_port=rule.destination_port,
            in_interface=rule.in_interface,
        )

    def _resolve_device_credentials(self, router: Router) -> FirewallCredentials:
        """Raise rather than guess -- mirrors ``content_filtering``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise FirewallMissingCredentialsError(router.id)
        return FirewallCredentials(
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
        entity_type: str = "firewall_rule",
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "RouterLookupProtocol",
    "AuditLogWriter",
    "FirewallPushOutcome",
    "FirewallService",
]
