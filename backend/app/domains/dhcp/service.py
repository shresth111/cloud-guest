"""DHCP Pool Management business logic: per-router DHCP pool CRUD with
real IP-range validation and conflict detection.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## Live device push

``push_pool_to_device`` realizes a pool on its router over the RouterOS
API, through ``device_adapters``. This paragraph previously said the
opposite -- "no live device push in this pass ... no ``device_adapters.py``
and no Celery task" -- and deferred real provisioning to a "not-yet-built
Network Configuration Management domain". That deferral is what made
creating a DHCP pool a database-only operation: the dashboard reported a
pool, the router had none, and guests on the network received no address
at all.

The gateway writer already existed
(``wyfy_device_gateway.mikrotik_adapter.configure_dhcp_pool``, three real
RouterOS operations over librouteros on 8728) with no callers. Creation
still writes only a row, deliberately: renaming a pool must not be able to
fail with a connection error, and an operator must be able to retry a push
without re-submitting the form.

## Validation and conflict detection

``address_range_start``/``address_range_end`` must both be real, parseable
IP addresses of the same family with start <= end
(``validators.validate_address_range``). ``gateway_ip_address``/
``dns_primary``/``dns_secondary``, when supplied, must be real, parseable
IP addresses too. A new/updated pool's range is also checked against
every other non-deleted pool on the *same router and interface* (two
different interfaces are different L2 domains and may legitimately reuse
the same private range) -- see ``models.DhcpPool``'s own module docstring
for why this is a service-layer check, not a database constraint.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.common.device_push import demote_device_push_on_edit
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import (
    LocationScope,
    enforce_entity_location,
)
from app.domains.router.device_domain_gate import ensure_not_controller_managed
from app.domains.router.models import Router

from .constants import (
    CAPTIVE_PORTAL_DHCP_OPTION_CODE,
    CAPTIVE_PORTAL_DHCP_OPTION_NAME,
    CAPTIVE_PORTAL_DHCP_OPTION_SET_NAME,
    DEFAULT_LEASE_TIME_SECONDS,
    DEVICE_CARRIED_FIELDS,
    DhcpDevicePushStatus,
    RogueDhcpAlertState,
)
from .device_adapters import (
    DhcpCredentials,
    DhcpOptionSnapshotReading,
    DhcpOptionSpec,
    RogueDhcpInterfaceReading,
    get_dhcp_adapter,
)
from .events import (
    DhcpPoolCreated,
    DhcpPoolDeleted,
    DhcpPoolPushed,
    DhcpPoolUpdated,
)
from .exceptions import (
    CrossLocationDhcpPoolAccessError,
    CrossOrganizationDhcpPoolAccessError,
    DhcpError,
    DhcpMissingCredentialsError,
    DhcpOptionValueRequiredError,
    DhcpPoolMissingGatewayError,
    DhcpPoolMissingInterfaceError,
    DhcpPoolNotEnabledError,
    DhcpPoolNotFoundError,
    DhcpPoolRangeConflictError,
)
from .models import DhcpPool, RouterRogueDhcpStatus
from .repository import DhcpRepositoryProtocol
from .validators import ranges_overlap, validate_address_range, validate_ip_address

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


@dataclasses.dataclass(frozen=True, slots=True)
class RogueDhcpDetectionSummary:
    """What one router's detection pass actually established.

    ``unknown`` is its own count, never folded into ``unguarded``. A
    router we could not reach is not a router we know is unwatched, and a
    summary that reported them as one number would be the same conflation
    the tri-state exists to prevent -- twice over, since the number is what
    gets logged and read later.
    """

    interfaces: int = 0
    guarded: int = 0
    unguarded: int = 0
    unknown: int = 0


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    # Declared because the device-push path really calls it. It was
    # previously left out, so this Protocol under-described what the
    # service requires: a collaborator could satisfy the annotation and
    # still blow up at runtime, and no type checker could see it coming.
    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


@dataclasses.dataclass(frozen=True, slots=True)
class CaptivePortalDhcpOptionConvergence:
    """What one router's option-114 convergence actually did.

    ``changed`` is the device's own answer, never the caller's intent. Both
    directions are idempotent, so "no exception" is true of a router that
    was already in the desired state and of one that was not, and a report
    that could not tell those apart would make a fleet sweep unreadable:
    the only rows worth a human's attention are the venues that still had
    the option when the sweep reached them.
    """

    router_id: uuid.UUID
    present: bool
    changed: bool
    option_removed: bool = False
    option_sets_removed: tuple[str, ...] = ()
    option_sets_rewritten: tuple[str, ...] = ()
    bindings_detached: tuple[str, ...] = ()


class DhcpService:
    """Core DHCP Pool Management business logic."""

    def __init__(
        self,
        repository: DhcpRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        # Constructor-injected while `requesting_organization_id` stays
        # per-method: an organization id is an *argument* (which tenant
        # this call is about, and a Celery task legitimately varies it
        # per call), whereas a location confinement is a *property of
        # the caller*, fixed for the request, and a security control.
        # Threading a security control through every method means every
        # method can forget it, silently. See
        # `app.domains.rbac.location_scope`.
        self.caller_location_scope = caller_location_scope

    async def create_pool(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        name: str,
        address_range_start: str,
        address_range_end: str,
        interface: str | None = None,
        gateway_ip_address: str | None = None,
        dns_primary: str | None = None,
        dns_secondary: str | None = None,
        lease_time_seconds: int = DEFAULT_LEASE_TIME_SECONDS,
        is_enabled: bool = True,
    ) -> DhcpPool:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        # Refused here, before a row exists. The adapter registry below would
        # decline this vendor eventually -- but only on a later `push`, after
        # this method has returned 201 and the venue has been shown a saved
        # setting that will never reach any device. See
        # `app.domains.router.device_domain_gate` for why the message is
        # written for the venue rather than for the registry.
        ensure_not_controller_managed(router, feature="IP Addresses")
        validate_address_range(address_range_start, address_range_end)
        validate_ip_address("gateway_ip_address", gateway_ip_address)
        validate_ip_address("dns_primary", dns_primary)
        validate_ip_address("dns_secondary", dns_secondary)
        await self._check_range_conflict(
            router.id, interface, address_range_start, address_range_end
        )

        pool = await self.repository.create_pool(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            name=name,
            interface=interface,
            address_range_start=address_range_start,
            address_range_end=address_range_end,
            gateway_ip_address=gateway_ip_address,
            dns_primary=dns_primary,
            dns_secondary=dns_secondary,
            lease_time_seconds=lease_time_seconds,
            is_enabled=is_enabled,
            # Written explicitly rather than left to the column default,
            # which only applies at INSERT: a freshly constructed row would
            # otherwise carry None until it round-trips through the
            # database, and "has this reached a device" must never read as
            # unknown.
            device_push_status=DhcpDevicePushStatus.PENDING.value,
            created_by=actor_user_id,
        )
        event = DhcpPoolCreated(id=pool.id, router_id=router.id)
        logger.info("dhcp_pool_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DHCP_POOL_CREATED,
            entity_id=pool.id,
            organization_id=pool.organization_id,
            description=f"DHCP pool '{name}' created for router {router.id}",
        )
        return pool

    async def get_pool(
        self,
        pool_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DhcpPool:
        pool = await self.repository.get_pool_by_id(pool_id)
        if pool is None:
            raise DhcpPoolNotFoundError(pool_id)
        if (
            requesting_organization_id is not None
            and pool.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationDhcpPoolAccessError()
        # Not enough on its own: this row is reached by its own id, so the
        # permission check had nothing to pin to and a LOCATION grant on
        # the caller's own site satisfied it.
        enforce_entity_location(
            entity_location_id=getattr(pool, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationDhcpPoolAccessError(),
        )
        return pool

    async def list_pools(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DhcpPool], object]:
        return await self.repository.list_pools(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def list_pools_for_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[DhcpPool]:
        """Every non-deleted pool for this router, unpaginated -- the real
        read source ``app.domains.network_config`` composes to render a
        router's full DHCP config, mirroring ``get_pool``'s own tenant
        validation via ``router_lookup`` rather than a per-row organization
        comparison (there is no single row here to compare against)."""
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_pools_for_router(router_id)

    async def update_pool(
        self,
        pool_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> DhcpPool:
        pool = await self.get_pool(
            pool_id, requesting_organization_id=requesting_organization_id
        )
        new_start = fields.get("address_range_start", pool.address_range_start)
        new_end = fields.get("address_range_end", pool.address_range_end)
        new_interface = fields.get("interface", pool.interface)
        range_or_interface_changed = (
            new_start != pool.address_range_start
            or new_end != pool.address_range_end
            or new_interface != pool.interface
        )
        if range_or_interface_changed:
            validate_address_range(new_start, new_end)
            await self._check_range_conflict(
                pool.router_id,
                new_interface,
                new_start,
                new_end,
                exclude_pool_id=pool.id,
            )
        if "gateway_ip_address" in fields:
            validate_ip_address("gateway_ip_address", fields["gateway_ip_address"])
        if "dns_primary" in fields:
            validate_ip_address("dns_primary", fields["dns_primary"])
        if "dns_secondary" in fields:
            validate_ip_address("dns_secondary", fields["dns_secondary"])

        # An edit to a field the router actually carries invalidates what
        # the router is holding, so the row stops claiming ``active`` in the
        # same UPDATE that changes the values -- see
        # ``app.common.device_push`` for the rule and ``constants
        # .DEVICE_CARRIED_FIELDS`` for which of this domain's columns count.
        demotion = demote_device_push_on_edit(
            pool,
            fields,
            device_carried_fields=DEVICE_CARRIED_FIELDS,
            active_status=DhcpDevicePushStatus.ACTIVE.value,
            pending_status=DhcpDevicePushStatus.PENDING.value,
        )
        updated = await self.repository.update_pool(
            pool, {**fields, **demotion, "updated_by": actor_user_id}
        )
        event = DhcpPoolUpdated(id=updated.id)
        logger.info("dhcp_pool_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DHCP_POOL_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"DHCP pool '{updated.name}' updated",
        )
        return updated

    async def delete_pool(
        self,
        pool_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DhcpPool:
        """Removes the pool from its router, then soft-deletes the row.

        Deleting used to soft-delete the row and nothing else, so a DHCP
        server this platform had created went on handing out addresses on
        the device after the operator deleted the pool -- and a later pool
        on the same interface would collide with an object nothing knew
        about.

        **The device comes first, and a device failure aborts the delete.**
        Removing the row while the server is still live is exactly the
        drift this closes. Failing loudly leaves both sides consistent and
        the delete retryable.

        The trade-off is real: a pool on a permanently unreachable router
        cannot be deleted through this path. That is the safer side to err
        on -- an undeletable row is visible, an orphaned live DHCP server
        is not.
        """
        pool = await self.get_pool(
            pool_id, requesting_organization_id=requesting_organization_id
        )
        await self._remove_from_device(
            pool, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_pool(pool)
        event = DhcpPoolDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("dhcp_pool_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DHCP_POOL_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"DHCP pool '{deleted.name}' deleted",
        )
        return deleted

    async def _check_range_conflict(
        self,
        router_id: uuid.UUID,
        interface: str | None,
        start: str,
        end: str,
        *,
        exclude_pool_id: uuid.UUID | None = None,
    ) -> None:
        existing = await self.repository.list_pools_for_router(router_id)
        for other in existing:
            if other.is_deleted:
                continue
            if exclude_pool_id is not None and other.id == exclude_pool_id:
                continue
            if other.interface != interface:
                continue
            if ranges_overlap(
                start, end, other.address_range_start, other.address_range_end
            ):
                raise DhcpPoolRangeConflictError(router_id, other.id)

    async def push_pool_to_device(
        self,
        pool_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DhcpPool:
        """Realizes one DHCP pool on its own router, over the RouterOS API.

        Until this existed, ``create_pool`` wrote a row, returned 201, and
        the device was never contacted -- this module's own docstring said
        so and called it deliberate. The visible consequence was not a
        missing pool but a broken network: a guest joining a VLAN the
        dashboard reported as created received no address at all, because
        no ``/ip dhcp-server`` had ever been created to answer them.

        **Separate from create/update, deliberately.** Renaming a pool must
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
        pool = await self.get_pool(
            pool_id, requesting_organization_id=requesting_organization_id
        )

        if not pool.is_enabled:
            raise DhcpPoolNotEnabledError(pool.id)
        if not pool.interface:
            # render_dhcp_pool handles this by emitting a comment and
            # skipping -- fine for a script, but on a direct push the same
            # silence would report success for a device that received
            # nothing. The adapter also derives both RouterOS identifiers
            # from this field.
            raise DhcpPoolMissingInterfaceError(pool.id)
        if not pool.gateway_ip_address:
            # Handing out addresses with no gateway gives guests an IP and
            # no route off the subnet. Defaulting to ``.1`` would be a
            # fabricated network fact.
            raise DhcpPoolMissingGatewayError(pool.id)

        router = await self.router_lookup.get_router(
            pool.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_dhcp_adapter(router.vendor)

        try:
            await adapter.configure_dhcp_pool(
                credentials,
                interface=pool.interface,
                range_start=pool.address_range_start,
                range_end=pool.address_range_end,
                gateway=pool.gateway_ip_address,
                dns_servers=self._dns_servers(pool),
                lease_time_seconds=pool.lease_time_seconds,
            )
            # A DHCP server has just appeared on this interface, which is
            # the moment the segment becomes worth guarding: a consumer
            # router plugged in here would answer leases too, and win
            # whenever it answers first. One was seen on this fleet's guest
            # bridge announcing the WAN gateway's address.
            #
            # Deliberately NOT part of the push's success or failure. The
            # alert is a guard around the feature, not the feature, and a
            # pool that reached the router must not be reported as failed
            # because a watch could not be set beside it. It is logged
            # instead, and `read_rogue_dhcp_alerts` reports the truth
            # separately -- so this stays quiet without ever claiming the
            # segment is guarded when it is not.
            try:
                trusted = await adapter.ensure_rogue_dhcp_alert(
                    credentials, interface=pool.interface
                )
                if trusted is None:
                    logger.warning(
                        "dhcp_rogue_alert_skipped_no_mac",
                        extra={
                            "event_pool_id": str(pool.id),
                            "event_interface": pool.interface,
                        },
                    )
            except Exception as exc:  # noqa: BLE001 -- never fails the push
                logger.warning(
                    "dhcp_rogue_alert_failed",
                    extra={
                        "event_pool_id": str(pool.id),
                        "event_interface": pool.interface,
                        "event_error": str(exc),
                    },
                )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_pool(
                pool,
                {
                    "device_push_status": DhcpDevicePushStatus.FAILED.value,
                    "device_push_error": str(exc),
                },
            )
            await self.repository.commit()
            raise

        updated = await self.repository.update_pool(
            pool,
            {
                "device_push_status": DhcpDevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = DhcpPoolPushed(
            id=updated.id,
            router_id=updated.router_id,
            interface=updated.interface or "",
        )
        logger.info("dhcp_pool_pushed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DHCP_POOL_PUSHED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"DHCP pool {updated.id} pushed to router {updated.router_id}"
            ),
        )
        return updated

    async def _remove_from_device(
        self, pool: DhcpPool, *, requesting_organization_id: uuid.UUID | None
    ) -> None:
        """Tears the pool off its router, when there is anything there.

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
        if pool.device_pushed_at is None:
            return
        if not pool.interface:
            # Cannot be ACTIVE without one -- push refuses without an
            # interface -- but the column is nullable, and the adapter
            # derives every object name from it, so there is nothing safe
            # to delete on.
            return
        router = await self.router_lookup.get_router(
            pool.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_dhcp_adapter(router.vendor)
        await adapter.delete_dhcp_pool(
            credentials,
            interface=pool.interface,
            range_start=pool.address_range_start,
            range_end=pool.address_range_end,
        )

    @staticmethod
    def _dns_servers(pool: DhcpPool) -> list[str]:
        """The DNS servers to advertise, in the operator's own order,
        falling back to the gateway -- this router -- when the operator set
        none.

        The fallback is the point, and this docstring used to argue the
        opposite: that an empty list "means the adapter omits
        ``dns-server=`` entirely rather than sending a blank value, which
        RouterOS would take as no DNS in a way that looks configured".
        Omitting it does not mean no DNS. MikroTik documents that a DHCP
        server with no ``dns-server`` hands out **the router's own
        upstream resolvers** -- so every guest on such a pool resolves
        past this router entirely.

        That silently disables everything built on the router's resolver.
        Website Blocking realizes a blocked domain as an ``/ip dns static``
        entry; a guest asking 8.8.8.8 directly never sees it. Both DNS
        fields are optional and blank by default on the customer's screen,
        so the ordinary pool is the broken one, and nobody has to touch a
        DNS setting to cause it.

        Pointing guests at the gateway is what ``_render_vlan_hotspot``
        has always done for the hotspot path. This makes the plain-pool
        path agree with it.

        Returns empty only when there is no gateway either -- there is
        then nothing truthful to advertise, and the caller must not invent
        one.
        """
        configured = [
            server
            for server in (pool.dns_primary, pool.dns_secondary)
            if server
        ]
        if configured:
            return configured
        return [pool.gateway_ip_address] if pool.gateway_ip_address else []


    # ========================================================================
    # Rogue-DHCP detection -- the reader, on a schedule
    # ========================================================================

    async def get_rogue_dhcp_statuses(
        self, router_id: uuid.UUID
    ) -> list[RouterRogueDhcpStatus]:
        """Every persisted rogue-DHCP finding for this router. Reads the
        database only -- **no device I/O, ever**.

        This is the method the readiness checklist composes, and the
        no-device-I/O property is the whole reason it can.
        ``ReadinessService.get_checklist`` re-runs every AUTO item on every
        single GET, so anything it calls is on a hot request path; a
        RouterOS round trip there would put a device timeout behind a
        dashboard page load. The device read already happened, off the
        request path, in ``run_rogue_dhcp_detection_for_router`` below.

        Deliberately takes no ``requesting_organization_id``: it performs no
        authorization of its own and must never be called before the caller
        has resolved the router through its own scoped lookup. Readiness
        does exactly that -- ``get_checklist`` resolves the router (and
        raises on a cross-tenant id) before ``_run_auto_detection`` is
        reached. Accepting an org id here and then filtering on
        ``router_id`` anyway is the precise shape of the path-id scoping
        defect found across this codebase: the check reads one thing and
        the query reads another.
        """
        return await self.repository.list_rogue_dhcp_statuses(router_id)

    async def run_rogue_dhcp_detection_for_router(
        self, router_id: uuid.UUID
    ) -> RogueDhcpDetectionSummary:
        """Ask one router which of its DHCP-serving interfaces are actually
        being watched, and persist the answer.

        Called only from ``tasks.detect_rogue_dhcp_for_router`` -- a
        scheduled, fanned-out leaf task on the device-I/O queue. Nothing on
        a request path calls this.

        ## An unreachable router is an unanswered question

        Every way this can fail to get an answer -- no credentials, an
        unsupported vendor, a refused connection, a RouterOS error -- lands
        as ``RogueDhcpAlertState.UNKNOWN`` with the reason in ``detail``,
        never as ``UNGUARDED``. Only a device that *answered*, and answered
        either "no alert row" or "row present, switched off", is unguarded.

        That distinction is not decoration. ``UNGUARDED`` says a real
        segment is handing out addresses with nothing watching it, and the
        readiness item fails on it. ``UNKNOWN`` says we do not know, and
        maps to NOT_CHECKED. Reporting an unreachable router as unguarded
        would produce a failure an operator cannot act on, on every
        offline router in the fleet -- and reporting it as guarded would be
        worse. This is the same posture
        ``app.domains.monitoring.constants.HealthStatus.UNKNOWN`` already
        documents, and this codebase has been bitten by collapsing the two
        before.
        """
        checked_at = datetime.now(UTC)
        try:
            router = await self.router_lookup.get_router(router_id)
            credentials = self._resolve_device_credentials(router)
            adapter = get_dhcp_adapter(router.vendor)
            readings = await adapter.read_rogue_dhcp_alerts(credentials)
        except DhcpError as exc:
            # Every domain failure mode -- missing credentials, unsupported
            # vendor, connection refused, RouterOS error -- is the same
            # answer: we did not learn anything. Narrowed to ``DhcpError``
            # rather than a bare ``except Exception`` on purpose: a bug in
            # this method (an AttributeError from a collaborator that does
            # not implement the reader, say) must surface as a failed task,
            # not be quietly recorded as an unreachable router. A blanket
            # handler swallowing exactly that AttributeError is how a fake
            # missing the new method let untested wiring pass in this domain
            # once already (cloud-guest#131).
            return await self._record_rogue_dhcp_unknown(
                router_id, checked_at=checked_at, detail=str(exc)
            )
        return await self._record_rogue_dhcp_readings(
            router_id, readings, checked_at=checked_at
        )

    async def _record_rogue_dhcp_readings(
        self,
        router_id: uuid.UUID,
        readings: list[RogueDhcpInterfaceReading],
        *,
        checked_at: datetime,
    ) -> RogueDhcpDetectionSummary:
        """Persist a successful read, and retire rows the device no longer
        reports.

        The reader returns one entry per interface serving DHCP *and* one
        per alert row present, so an interface absent from the answer has
        neither -- there is no finding left to make about it, and a stale
        ``unguarded`` row would keep failing the readiness item for a
        segment that no longer exists. See
        ``repository.delete_rogue_dhcp_statuses``.
        """
        summary_counts = {"guarded": 0, "unguarded": 0}
        seen: set[str] = set()
        for reading in readings:
            interface = reading.interface
            seen.add(interface)
            watched = reading.watched
            state = (
                RogueDhcpAlertState.GUARDED
                if watched
                else RogueDhcpAlertState.UNGUARDED
            )
            summary_counts["guarded" if watched else "unguarded"] += 1
            await self.repository.upsert_rogue_dhcp_status(
                router_id,
                interface,
                {
                    "alert_state": state.value,
                    # Stored beside the rolled-up state, never merged into
                    # it: "no row at all" and "row present, switched off"
                    # are both unguarded, and only these two columns say
                    # which. RouterOS's default produces the second.
                    "alert_present": reading.alert_present,
                    "enabled": reading.enabled,
                    "serves_dhcp": reading.serves_dhcp,
                    "checked_at": checked_at,
                    "detail": _rogue_dhcp_detail(reading),
                },
            )
        existing = await self.repository.list_rogue_dhcp_statuses(router_id)
        stale = {row.interface for row in existing} - seen
        if stale:
            await self.repository.delete_rogue_dhcp_statuses(router_id, stale)
        return RogueDhcpDetectionSummary(
            interfaces=len(seen),
            guarded=summary_counts["guarded"],
            unguarded=summary_counts["unguarded"],
            unknown=0,
        )

    async def _record_rogue_dhcp_unknown(
        self,
        router_id: uuid.UUID,
        *,
        checked_at: datetime,
        detail: str,
    ) -> RogueDhcpDetectionSummary:
        """Record that this pass learned nothing, without inventing a
        finding.

        Marks every interface we already had a row for, plus every enabled
        pool interface this platform believes it serves. Nothing is
        deleted: the previous answer's *shape* is still the best guess at
        which interfaces exist, and dropping the rows would silently turn
        "we could not reach this router" into "this router has nothing to
        report", which reads as fine.

        ``alert_present``/``enabled``/``serves_dhcp`` are all forced false
        alongside ``UNKNOWN`` rather than left at their last-known values.
        A stale ``enabled=True`` beside an ``UNKNOWN`` state invites
        exactly the reading this whole change exists to prevent -- a
        consumer glancing at the boolean and concluding the segment is
        watched, on evidence that is now of unknown age. ``alert_state`` is
        the only field that carries an answer here; ``detail`` carries why.
        """
        interfaces = {
            row.interface
            for row in await self.repository.list_rogue_dhcp_statuses(router_id)
        }
        for pool in await self.repository.list_pools_for_router(router_id):
            if pool.is_enabled and pool.interface:
                interfaces.add(pool.interface)
        for interface in sorted(interfaces):
            await self.repository.upsert_rogue_dhcp_status(
                router_id,
                interface,
                {
                    "alert_state": RogueDhcpAlertState.UNKNOWN.value,
                    "alert_present": False,
                    "enabled": False,
                    "serves_dhcp": False,
                    "checked_at": checked_at,
                    "detail": detail,
                },
            )
        logger.warning(
            "dhcp_rogue_detection_unknown",
            extra={
                "event_router_id": str(router_id),
                "event_interfaces": len(interfaces),
                "event_error": detail,
            },
        )
        return RogueDhcpDetectionSummary(
            interfaces=len(interfaces),
            guarded=0,
            unguarded=0,
            unknown=len(interfaces),
        )

    # ------------------------------------------------------------------
    # The captive-portal DHCP option (RFC 8910, code 114)
    # ------------------------------------------------------------------

    async def read_captive_portal_dhcp_option(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DhcpOptionSnapshotReading:
        """What this router currently advertises. Reads only.

        Separate from the converger so an audit -- "which venues still hand
        out the option?" -- is not itself a fleet change. Errors propagate
        rather than being flattened into a "clean" answer: a router we
        could not reach is not a router without the option, and a sweep
        that reported it as one would certify exactly the venues nobody has
        checked.
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_dhcp_adapter(router.vendor)
        return await adapter.read_dhcp_options(credentials)

    async def converge_captive_portal_dhcp_option_for_router(
        self,
        router_id: uuid.UUID,
        *,
        present: bool,
        option_value: str | None = None,
        network_addresses: tuple[str, ...] = (),
        actor_user_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> CaptivePortalDhcpOptionConvergence:
        """Bring one router's option-114 state to ``present`` or absent,
        over the RouterOS API on 8728.

        ## Why this exists

        Before it, **the platform could not write a DHCP option at all.**
        ``network_config/renderers.py`` renders ``/ip pool``, ``/ip
        dhcp-server`` and ``/ip dhcp-server network``, and has never
        rendered an ``option`` line. The only writer of option 114 in the
        entire system was a human pasting the Master Console setup script,
        which made the only remover a human too -- so remediating a live
        venue meant somebody opening an API session against a production
        router by hand, and meant doing it again on the next router, and
        forgetting.

        ## Why the removal direction is the one being used today

        The option points clients at ``GET /captive-portal/rfc8908``, whose
        ``captive`` member is hardcoded ``true``. An RFC 8908 client
        re-polls that URI precisely to learn whether it is *still* captive
        and is always told yes, so the portal sheet never closes after a
        successful login. The endpoint cannot be made truthful: every guest
        reaches the cloud from behind the venue's NAT as one source IP, so
        it cannot tell one guest's session from another's. With no option
        114 at all, the OS's own probe interception gets both directions
        right. Retiring the endpoint is a separate decision; **not
        advertising it is this one.**

        ## Removal never needs a value; creation always does

        ``present=False`` needs only the option's name, and what it is
        attached to is discovered from the device rather than assumed --
        which is what makes it safe against routers configured by a pasted
        script this platform never saw, i.e. every router in the fleet.

        ``present=True`` requires ``option_value``. There is deliberately
        no default: this database has never stored a per-router option-114
        value (the only writer was that script), so a fallback here would
        be a fabricated URI handed to every guest device on the network.
        """
        option = DhcpOptionSpec(
            name=CAPTIVE_PORTAL_DHCP_OPTION_NAME,
            code=CAPTIVE_PORTAL_DHCP_OPTION_CODE,
            value=option_value,
            # Matches what the setup script writes, and what the fleet
            # actually carries: with force, every client gets the option
            # whether or not it asked for the code. That is why this
            # defect went from intermittent to universal.
            force=True,
            option_set_name=CAPTIVE_PORTAL_DHCP_OPTION_SET_NAME,
            network_addresses=network_addresses,
        )
        if present and not option_value:
            raise DhcpOptionValueRequiredError(router_id)

        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_dhcp_adapter(router.vendor)

        if present:
            await adapter.configure_dhcp_option(credentials, option=option)
            convergence = CaptivePortalDhcpOptionConvergence(
                router_id=router_id, present=True, changed=True
            )
        else:
            report = await adapter.remove_dhcp_option(credentials, option=option)
            convergence = CaptivePortalDhcpOptionConvergence(
                router_id=router_id,
                present=False,
                # The device's own answer, not the request's intent. A
                # removal succeeds against an already-clean router too, so
                # "it worked" says nothing; this is the only field that
                # distinguishes "this venue still had it" from "this venue
                # was cleaned last week".
                changed=report.changed,
                option_removed=report.option_removed,
                option_sets_removed=report.option_sets_removed,
                option_sets_rewritten=report.option_sets_rewritten,
                bindings_detached=report.bindings_detached,
            )

        logger.info(
            "dhcp_captive_portal_option_converged",
            extra={
                "router_id": str(router_id),
                "option": CAPTIVE_PORTAL_DHCP_OPTION_NAME,
                "present": present,
                "changed": convergence.changed,
            },
        )
        # Audited only when the device actually changed. A fleet sweep that
        # wrote an audit row per router per run would bury the handful of
        # entries that record a real change to a production network under
        # thousands that record nothing happening.
        if convergence.changed:
            await self._audit(
                actor_user_id,
                AuditAction.DHCP_OPTION_WRITTEN
                if present
                else AuditAction.DHCP_OPTION_REMOVED,
                entity_id=router_id,
                organization_id=router.organization_id,
                description=(
                    f"DHCP option {CAPTIVE_PORTAL_DHCP_OPTION_NAME} "
                    f"{'written to' if present else 'removed from'} "
                    f"router {router_id}"
                ),
                entity_type="router",
            )
        return convergence

    def _resolve_device_credentials(self, router: Router) -> DhcpCredentials:
        """Raise rather than guess -- mirrors ``vlan``/``qos``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise DhcpMissingCredentialsError(router.id)
        return DhcpCredentials(
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
        # Defaulted rather than always passed: every caller but the
        # captive-portal option converger audits a pool. That one audits a
        # *router* -- the option is a property of the device, not of any
        # DhcpPool row, and stamping it "dhcp_pool" would make the trail
        # point at an entity that does not exist.
        entity_type: str = "dhcp_pool",
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


def _rogue_dhcp_detail(reading: RogueDhcpInterfaceReading) -> str:
    """One short, human-readable sentence for one interface's finding.

    Detector-only wording, everywhere, without exception. ``/ip
    dhcp-server alert`` writes a log entry and does nothing else -- it does
    not drop the offer, block the port, or rate-limit anything. Copy that
    says "protected" or "blocked" would describe a capability RouterOS does
    not have, and an operator who believed it would stop looking for the
    rogue server. See ``constants.RogueDhcpAlertState``.
    """
    if reading.watched:
        return "Detection is active on this interface."
    if reading.alert_present:
        # The state RouterOS's own default creates, and the reason
        # ``alert_present`` and ``enabled`` are separate columns: this row
        # reads as configured and watches nothing.
        return (
            "Detection is configured on this interface but switched off, "
            "so nothing is being watched."
        )
    return "This interface hands out addresses with no detection configured."


__all__ = [
    "RouterLookupProtocol",
    "AuditLogWriter",
    "CaptivePortalDhcpOptionConvergence",
    "DhcpService",
    "RogueDhcpDetectionSummary",
]
