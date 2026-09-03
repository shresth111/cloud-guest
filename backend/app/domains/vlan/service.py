"""VLAN Management business logic: per-router VLAN inventory CRUD.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## Live device push

``push_vlan_to_device`` realizes a VLAN on its router over the RouterOS
API, through ``device_adapters``. This paragraph used to say the opposite
-- "no live device push in this pass ... this domain has no
``device_adapters.py``" -- and stayed after the adapter was added, which
is exactly the kind of stale claim that makes a docstring worse than
none. Creation still writes only a row, deliberately: renaming a VLAN must
not be able to fail with a connection error.

## NAT / Internet Access

``nat_enabled`` decides whether the push also realizes a source-NAT
masquerade rule for the VLAN's own ``cidr`` on the router's real WAN
interface. Without it a pushed VLAN is a complete *local* network and
nothing more -- guests get a lease, a gateway, and no route off the
router, with no error anywhere to say so.

Both directions are part of the same push: NAT on applies the rule, NAT
off removes it. That is what makes the toggle honest -- were the disabled
case a no-op, turning NAT off would leave the last-pushed rule
masquerading a network the operator has since decided must not reach the
internet, and the push would report success.

The WAN interface is never stored or assumed. It is derived from the
router's own live default route by the vendor adapter
(``mikrotik_adapter.resolve_wan_interface``), because nothing here knows
which port a given site's uplink is in, and a hardcoded ``"WAN"``/
``"ether1"`` would be wrong at the first site that names its ports
differently. When the router's state does not identify one, the push
fails with ``VlanNatWanInterfaceUnresolvedError`` rather than guessing.
This is the same rule ``network_config.wan.renderers
._uplink_discovery_statements`` applies device-side -- active default
route, verified to be a real interface, degrade rather than guess --
arrived at independently and worth keeping aligned.

**This rule coexists with the router-wide one, and does not replace
it.** ``network_config.renderers.render_guest_data_path`` ships a
masquerade scoped by ``out-interface`` alone, marked
``comment="cloudguest-nat-live"``, to every enrolled router. The two
never touch: each finds its own rule by its own comment, so neither
counts, re-points, or removes the other's. But the consequence is worth
stating plainly -- **on a router carrying that rule, turning
``nat_enabled`` off does not actually cut that VLAN off from the
internet**, because the router-wide rule still NATs everything leaving
the uplink. This push removes the VLAN's own rule and nothing else;
removing the shared one would take a whole venue offline, which is not a
per-VLAN toggle's decision to make.

**A pushed VLAN is not automatically a working VLAN.** ``/interface vlan``
on a bridge only segments traffic when that bridge has
``vlan-filtering=yes``; MikroTik's own documentation is explicit that with
``vlan-filtering=no`` "the bridge ignores VLAN tags, works in a
shared-VLAN-learning (SVL) mode, and cannot modify VLAN tags of packets".
This domain creates the interface and its address and reports exactly
that -- it does not turn on bridge VLAN filtering, which is a bridge-wide
change that drops untagged frames on any port without a correct PVID and
can lock an operator out of the router. See ``docs/vlan/FLOW.md``.

## Captive Portal

``enable_hotspot`` decides whether the push also realizes a standalone
captive portal *on this VLAN's own interface* -- its own ``/ip pool``,
``/ip dhcp-server`` and network row, ``/ip hotspot profile``, the
``/ip dns static`` record that makes that profile's ``dns-name`` resolve,
and the ``/ip hotspot`` server. Every object is named from ``vlan_id`` and
bound to this VLAN's interface, so turning a portal on for one VLAN
touches neither another VLAN's portal nor the router's default
``hotspot1``.

This push used to *refuse* the toggle outright
(``VlanHotspotPushUnsupportedError``) because the adapter had no hotspot
support. It has one now; the exception is gone rather than left behind
raising for a reason that stopped being true.

Both directions are part of the same push, for the same reason NAT is:
portal on applies it, portal off removes it. A no-op on the disabled side
would leave the last-pushed portal challenging guests on a network the
operator has since decided must not have one, and the push would report
success.

**A captive portal owns DHCP on its own interface.** RouterOS allows one
``/ip dhcp-server`` per interface, and a hotspot must have one. This
platform also offers a separate DHCP Pool feature that the customer can
point at the same interface, so the two can be configured into a
collision that only appears as a device error at push time -- or, worse,
as a portal that hands out leases with no login page. The rule is that
the portal wins by *refusing*, in both directions: this push raises
``VlanHotspotDhcpPoolConflictError`` when an enabled ``DhcpPool`` row on
the same router already targets this VLAN's bind interface, and
``DhcpService.push_pool_to_device`` raises its own mirror-image error when
a portal already owns the interface a pool names. Neither silently
deletes the other's object: both are things an operator deliberately
created and can still see, and a push that quietly removed one would
report success while serving nobody. The check is a database read, so it
happens before any socket is opened.

## Validation

Everything the customer can get wrong is checked before a connection is
opened, where the check does not need the device: the VLAN's own tag is in
range and unclaimed on that router, its CIDR and gateway parse, the
gateway sits *inside* the CIDR (each half can be valid alone and the pair
still describe a router address on a subnet the VLAN does not have), and
the portal/NAT toggles have the subnet they each require.

Three checks genuinely need the router and are made in **one** read
(``adapter.read_network_snapshot``, ``/interface`` + ``/ip address``):
that the router answers at all, that the named trunk parent or access
port really exists on it, and that this VLAN's subnet does not overlap an
address the device already carries. That last one is compared against the
*device's* address table rather than against other ``Vlan`` rows on
purpose -- a router carries its LAN bridge, its uplink, and anything
configured outside this platform, none of which has a row here, and it is
the device's set that decides whether the push produces two matching
routes.

``vlan_id`` must fall within IEEE 802.1Q's real 1-4094 usable range
(``validators.validate_vlan_id``) and must be unique per router among
non-deleted rows (``VlanIdAlreadyExistsError``). ``cidr``/
``gateway_ip_address``, when supplied, must be real, parseable values
(Python's own ``ipaddress`` module) -- a malformed value is rejected at
create/update time, never silently stored.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.domains.network_config.renderers import (
    HOTSPOT_DNS_NAME,
    HOTSPOT_HTML_DIRECTORY,
)
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import VlanDevicePushStatus
from .device_adapters import (
    BaseVlanAdapter,
    VlanCredentials,
    VlanDeviceInterface,
    VlanNetworkSnapshot,
    get_vlan_adapter,
)
from .events import VlanCreated, VlanDeleted, VlanPushed, VlanUpdated
from .exceptions import (
    CrossOrganizationVlanAccessError,
    VlanAccessPortNotFoundError,
    VlanDeviceConnectionError,
    VlanDeviceOperationError,
    VlanHotspotDhcpPoolConflictError,
    VlanHotspotRequiresSubnetError,
    VlanIdAlreadyExistsError,
    VlanMissingCredentialsError,
    VlanMissingInterfaceError,
    VlanNatRequiresCidrError,
    VlanNotEnabledError,
    VlanNotFoundError,
    VlanParentInterfaceNotFoundError,
    VlanSubnetConflictError,
)
from .models import Vlan
from .repository import VlanRepositoryProtocol
from .validators import (
    validate_cidr,
    validate_gateway_ip_address,
    validate_gateway_within_cidr,
    validate_vlan_id,
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

    # Declared because the device-push path really calls it. It was
    # previously left out, so this Protocol under-described what the
    # service requires: a collaborator could satisfy the annotation and
    # still blow up at runtime, and no type checker could see it coming.
    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class DhcpPoolRow(Protocol):
    """The three fields this domain reads off a DHCP pool. Deliberately
    not ``app.domains.dhcp.models.DhcpPool``: naming the concrete model
    here would couple two domains through their ORM classes, where the
    only fact needed is "is something else already serving DHCP on this
    interface"."""

    name: str
    interface: str | None
    is_enabled: bool


class DhcpPoolLookupProtocol(Protocol):
    """Satisfied structurally by ``app.domains.dhcp.repository
    .DhcpRepository``.

    The *repository*, not ``DhcpService``, and that is deliberate: the
    DHCP service composes this one back the other way (its own push has to
    refuse a pool on an interface a captive portal owns), and two services
    depending on each other is a FastAPI dependency cycle that never
    resolves. Repositories depend on nothing but a session, so the two
    domains can each read the other's rows without either owning the
    other. Tenant scoping is already settled by the caller, which has
    resolved the router within the requesting organization before it gets
    here.
    """

    async def list_pools_for_router(
        self, router_id: uuid.UUID
    ) -> list[DhcpPoolRow]: ...


class VlanService:
    """Core VLAN Management business logic."""

    def __init__(
        self,
        repository: VlanRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        dhcp_pool_lookup: DhcpPoolLookupProtocol,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        # Required, not optional-with-a-None-default. The captive-portal
        # DHCP conflict check is the one thing standing between a customer
        # and two DHCP servers on one interface, and a default of None
        # would let a mis-wired construction skip it silently -- which is
        # exactly the failure shape this check exists to remove.
        self.dhcp_pool_lookup = dhcp_pool_lookup
        self.audit_writer = audit_writer

    async def create_vlan(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        vlan_id: int,
        name: str,
        gateway_ip_address: str | None = None,
        cidr: str | None = None,
        interface: str | None = None,
        port_mode: str = "trunk",
        enable_hotspot: bool = False,
        nat_enabled: bool = False,
        description: str | None = None,
        is_enabled: bool = True,
    ) -> Vlan:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_vlan_id(vlan_id)
        validate_cidr(cidr)
        validate_gateway_ip_address(gateway_ip_address)
        validate_gateway_within_cidr(gateway_ip_address, cidr)
        if port_mode not in ("trunk", "access"):
            raise ValueError("port_mode must be 'trunk' or 'access'")
        existing = await self.repository.get_vlan_by_router_and_tag(router.id, vlan_id)
        if existing is not None:
            raise VlanIdAlreadyExistsError(router.id, vlan_id)

        vlan = await self.repository.create_vlan(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            vlan_id=vlan_id,
            name=name,
            gateway_ip_address=gateway_ip_address,
            cidr=cidr,
            interface=interface,
            port_mode=port_mode,
            enable_hotspot=enable_hotspot,
            nat_enabled=nat_enabled,
            description=description,
            is_enabled=is_enabled,
            # Written explicitly rather than left to the column default,
            # which only applies at INSERT: a freshly constructed row would
            # otherwise carry None until it round-trips through the
            # database, and "has this reached a device" must never read as
            # unknown.
            device_push_status=VlanDevicePushStatus.PENDING.value,
            created_by=actor_user_id,
        )
        event = VlanCreated(id=vlan.id, router_id=router.id, tag=vlan_id)
        logger.info("vlan_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_CREATED,
            entity_id=vlan.id,
            organization_id=vlan.organization_id,
            description=f"VLAN '{name}' (tag {vlan_id}) created for router {router.id}",
        )
        return vlan

    async def get_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Vlan:
        vlan = await self.repository.get_vlan_by_id(vlan_pk)
        if vlan is None:
            raise VlanNotFoundError(vlan_pk)
        if (
            requesting_organization_id is not None
            and vlan.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationVlanAccessError()
        return vlan

    async def list_vlans(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Vlan], object]:
        return await self.repository.list_vlans(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )

    async def list_vlans_for_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[Vlan]:
        """Every non-deleted VLAN for this router, unpaginated -- the real
        read source ``app.domains.network_config`` composes to render a
        router's full VLAN config, mirroring
        ``app.domains.dhcp.DhcpService.list_pools_for_router``'s identical
        shape."""
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_vlans_for_router(router_id)

    async def list_device_interfaces(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[list[VlanDeviceInterface], str]:
        """The router's real interfaces, for the VLAN form's own picker.

        Returns the list *and the sentence explaining it*, because an empty
        list has three different meanings -- this router has no credentials
        stored, it did not answer, or it genuinely has nothing to offer --
        and a picker that renders an empty dropdown for all three teaches
        an operator that the feature is broken.

        **A router this platform cannot reach is not an error here.** The
        form is being filled in; refusing to render it because a device is
        momentarily unreachable helps nobody, and a 500 would be a lie
        about whose fault it is. The push path is where unreachability has
        to be fatal, and it is.

        **The empty cases still return a 2xx with ``success: true``.** The
        honesty lives in the message, deliberately: the frontend's
        interceptor unwraps ``response.data.data`` and never reads
        ``success``, so a ``200 {"success": false}`` reaches the UI
        indistinguishable from success -- with the added cost that the
        message explaining *why* the list is empty would be the part
        thrown away.

        Unlike ``app.domains.router``'s ``/device-interfaces``, nothing is
        filtered out. That endpoint exists to back a DHCP picker and drops
        every interface already bound to an ``/ip dhcp-server``, which on
        a real router drops ``bridge`` -- verified on the lab box, whose
        ``bridge`` was simply absent from its output. ``bridge`` is the
        interface most VLAN trunks hang off, so reusing it here would hide
        the one option most customers need.
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        try:
            credentials = self._resolve_device_credentials(router)
        except VlanMissingCredentialsError:
            return [], (
                "This router has no device connection credentials stored, so "
                "its interfaces cannot be read"
            )
        adapter = get_vlan_adapter(router.vendor)
        try:
            snapshot = await adapter.read_network_snapshot(credentials)
        except (VlanDeviceConnectionError, VlanDeviceOperationError) as exc:
            # Logged rather than swallowed: the operator gets a sentence,
            # and whoever is debugging the fleet gets the device's own
            # words.
            logger.info(
                "vlan_device_interfaces_unavailable",
                extra={"router_id": str(router.id), "detail": exc.message},
            )
            return [], exc.message
        return snapshot.interfaces, "Device interfaces retrieved"

    async def update_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> Vlan:
        vlan = await self.get_vlan(
            vlan_pk, requesting_organization_id=requesting_organization_id
        )
        new_vlan_id = fields.get("vlan_id", vlan.vlan_id)
        if new_vlan_id != vlan.vlan_id:
            validate_vlan_id(new_vlan_id)
            existing = await self.repository.get_vlan_by_router_and_tag(
                vlan.router_id, new_vlan_id
            )
            if existing is not None and existing.id != vlan.id:
                raise VlanIdAlreadyExistsError(vlan.router_id, new_vlan_id)
        if "cidr" in fields:
            validate_cidr(fields["cidr"])
        if "gateway_ip_address" in fields:
            validate_gateway_ip_address(fields["gateway_ip_address"])
        # Checked against the *merged* row, not against the submitted
        # fields: editing only the gateway must still be rejected when it
        # lands outside the CIDR the row already has.
        validate_gateway_within_cidr(
            fields.get("gateway_ip_address", vlan.gateway_ip_address),
            fields.get("cidr", vlan.cidr),
        )
        if fields.get("port_mode") not in (None, "trunk", "access"):
            raise ValueError("port_mode must be 'trunk' or 'access'")

        updated = await self.repository.update_vlan(
            vlan, {**fields, "updated_by": actor_user_id}
        )
        event = VlanUpdated(id=updated.id)
        logger.info("vlan_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"VLAN '{updated.name}' updated",
        )
        return updated

    async def delete_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> Vlan:
        """Removes the VLAN from its router, then soft-deletes the row.

        Deleting used to soft-delete the row and nothing else, so a VLAN
        this platform had created went on carrying traffic on the device
        after the operator deleted it -- with nothing anywhere to say so.

        **The device comes first, and a device failure aborts the delete.**
        Removing the row while the interface is still live is exactly the
        drift this closes: the operator would believe it was gone, and
        nothing would ever reconcile it. Failing loudly leaves both sides
        consistent and the delete retryable.

        The trade-off is real and worth stating: a VLAN on a permanently
        unreachable router cannot be deleted through this path. That is the
        safer side to err on -- an undeletable row is visible, an orphaned
        live interface is not -- but it means decommissioning a dead router
        needs a deliberate escape hatch, which this method does not provide.
        """
        vlan = await self.get_vlan(
            vlan_pk, requesting_organization_id=requesting_organization_id
        )
        await self._remove_from_device(
            vlan, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_vlan(vlan)
        event = VlanDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("vlan_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"VLAN '{deleted.name}' deleted",
        )
        return deleted

    async def push_vlan_to_device(
        self,
        vlan_pk: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> Vlan:
        """Realizes one VLAN on its own router, over the RouterOS API.

        Until this existed, ``create_vlan`` wrote a row, returned 201, and
        the device was never contacted -- so "VLAN created" meant "a
        database row exists" and nothing more. Verified against the live
        fleet: one VLAN row, zero ``/interface vlan`` entries on the router.

        **Separate from create/update, deliberately.** Renaming a VLAN must
        not be able to fail with a connection error, and an operator must be
        able to retry a push without re-submitting the form.

        **Every precondition is checked before a socket is opened**, so a
        misconfigured row fails as a 4xx naming the problem rather than as a
        device timeout.

        **A failure is committed, then re-raised.** This is the one place
        this method deliberately does *not* copy ``qos.push_rule_to_device``:
        that method writes the failure and re-raises, but
        ``GenericRepository.update`` only ``flush()``es and
        ``get_db_session`` rolls back on any exception -- so its failure
        record is discarded and the row still reads ``pending`` after a real
        device failure, with ``device_push_error`` NULL. Its docstring
        claims the opposite, and the unit test that "proves" it uses an
        in-memory fake with no transaction. Committing explicitly before
        raising is what makes the record survive to be read.

        The exception then propagates as a real non-2xx. It must not become
        a ``200 {"success": false}``: the frontend interceptor unwraps
        ``data`` and never reads ``success``, so such a response is
        indistinguishable from success to every caller in the app.
        """
        vlan = await self.get_vlan(
            vlan_pk, requesting_organization_id=requesting_organization_id
        )
        await self._check_preconditions(vlan)

        router = await self.router_lookup.get_router(
            vlan.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_vlan_adapter(router.vendor)
        bind_interface = self._bind_interface(vlan)

        # PROVISIONING is written and committed before the first socket, so
        # a customer refreshing the page while a slow push runs sees the
        # work in progress rather than the previous attempt's outcome -- and
        # so a process killed mid-write leaves a row that says "nobody
        # confirmed this" instead of a stale ACTIVE.
        await self.repository.update_vlan(
            vlan,
            {
                "device_push_status": VlanDevicePushStatus.PROVISIONING.value,
                "device_push_error": None,
            },
        )
        await self.repository.commit()

        try:
            # One device read answers the three preconditions that cannot
            # be answered without the router: is it reachable, does the
            # named interface exist on it, is this subnet already taken.
            # Inside the try because a preflight failure is a real push
            # failure and belongs in device_push_error like any other.
            await self._preflight_device(vlan, credentials, adapter)

            await adapter.configure_vlan(
                credentials,
                vlan_id=vlan.vlan_id,
                name=vlan.name,
                interface=vlan.interface,
                ip_cidr=self._device_address(vlan),
                port_mode=vlan.port_mode,
            )
            # The portal after the interface it binds to, and before NAT:
            # its DHCP server has to sit on an interface that exists, and
            # NAT is about what happens after a guest already has a lease.
            #
            # The *disabled* case issues a delete rather than doing
            # nothing, for the reason the NAT branch below does: a no-op
            # would leave the last-pushed portal challenging guests on a
            # network the operator has since decided must not have one,
            # and this push would report success.
            await self._apply_hotspot(vlan, credentials, adapter, bind_interface)
            # NAT after the interface exists, so the push reads on the
            # device in the order the config depends: a masquerade rule for
            # a subnet no interface carries is a rule that matches nothing.
            #
            # The *disabled* case issues a delete rather than doing nothing,
            # and that is what makes "turning NAT off removes the rule"
            # true. Doing nothing would leave the last-pushed rule
            # masquerading a network the operator has since decided must
            # not reach the internet -- and this push would report success.
            # The delete is idempotent, so on a VLAN that never had NAT it
            # is a harmless no-op.
            if vlan.nat_enabled:
                await adapter.configure_nat_masquerade(
                    credentials, vlan_id=vlan.vlan_id, src_cidr=vlan.cidr
                )
            else:
                await adapter.delete_nat_masquerade(
                    credentials, vlan_id=vlan.vlan_id
                )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_vlan(
                vlan,
                {
                    "device_push_status": VlanDevicePushStatus.FAILED.value,
                    "device_push_error": str(exc),
                },
            )
            await self.repository.commit()
            raise

        updated = await self.repository.update_vlan(
            vlan,
            {
                "device_push_status": VlanDevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                # What the router was actually told to call this, recorded
                # by the push that told it rather than recomputed later by
                # whoever reads the row -- see the column's own comment.
                "mikrotik_interface_name": bind_interface,
                "updated_by": actor_user_id,
            },
        )
        event = VlanPushed(
            id=updated.id, router_id=updated.router_id, port_mode=updated.port_mode
        )
        logger.info("vlan_pushed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_PUSHED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"VLAN {updated.vlan_id} ('{updated.name}') pushed to router "
                f"{updated.router_id} in {updated.port_mode} mode"
            ),
        )
        return updated

    async def _check_preconditions(self, vlan: Vlan) -> None:
        """Everything that can be decided without the router, decided
        before a socket is opened.

        Ordered cheapest-first and, within that, "what is missing" before
        "what conflicts": an operator who left the interface blank should
        be told that, not told about a subnet collision they would have hit
        second.
        """
        if not vlan.is_enabled:
            raise VlanNotEnabledError(vlan.id)
        if not vlan.interface:
            # render_vlan handles this by emitting a comment and skipping --
            # fine for a script, but on a direct push the same silence would
            # report success for a device that received nothing.
            raise VlanMissingInterfaceError(vlan.id)

        # Re-validated at push time, not only at create/update. A row can
        # predate a validator, and this is the last point before the values
        # become real device state.
        validate_vlan_id(vlan.vlan_id)
        validate_cidr(vlan.cidr)
        validate_gateway_ip_address(vlan.gateway_ip_address)
        validate_gateway_within_cidr(vlan.gateway_ip_address, vlan.cidr)

        # A second live row holding this tag on this router means one of
        # the two is about to overwrite the other's device object -- both
        # would resolve to the same ``vlan<id>``. The partial unique index
        # makes this unreachable in practice; it is checked anyway because
        # the consequence of it ever being reachable is silent.
        claimant = await self.repository.get_vlan_by_router_and_tag(
            vlan.router_id, vlan.vlan_id
        )
        if claimant is not None and claimant.id != vlan.id:
            raise VlanIdAlreadyExistsError(vlan.router_id, vlan.vlan_id)

        if vlan.enable_hotspot:
            if not vlan.cidr or not vlan.gateway_ip_address:
                # A portal is a pool of real addresses plus a real address
                # of its own to answer on. _render_vlan_hotspot refuses the
                # same combination with a skip comment.
                raise VlanHotspotRequiresSubnetError(vlan.id)
            await self._check_hotspot_dhcp_conflict(vlan)

        if vlan.nat_enabled and not vlan.cidr:
            # NAT is a rule about a source subnet, and this row has none.
            # Skipping the NAT step instead would report a successful push
            # for a VLAN whose guests still have no internet.
            raise VlanNatRequiresCidrError(vlan.id)

    async def _check_hotspot_dhcp_conflict(self, vlan: Vlan) -> None:
        """Refuses a captive portal on an interface a DHCP Pool row
        already serves.

        Both features create an ``/ip dhcp-server``, RouterOS permits one
        per interface, and a portal cannot go without. Disabled pool rows
        are ignored: they are intent this platform has not realized and
        will not realize, so they occupy no interface on the device.

        A database read, so this refusal arrives before any connection --
        the alternative is discovering it as an opaque RouterOS error
        halfway through a partially-applied portal.
        """
        pools = await self.dhcp_pool_lookup.list_pools_for_router(vlan.router_id)
        bind_interface = self._bind_interface(vlan)
        for pool in pools:
            if pool.is_enabled and pool.interface == bind_interface:
                raise VlanHotspotDhcpPoolConflictError(
                    vlan.id, bind_interface, pool.name
                )

    async def _preflight_device(
        self,
        vlan: Vlan,
        credentials: VlanCredentials,
        adapter: BaseVlanAdapter,
    ) -> None:
        """The three preconditions that need the router, in one read.

        Reachability is not checked separately -- it *is* this read: a
        router that does not answer raises ``VlanDeviceConnectionError``
        from the adapter before any of the rest is evaluated.
        """
        snapshot = await adapter.read_network_snapshot(credentials)
        names = {interface.name for interface in snapshot.interfaces}
        if vlan.interface not in names:
            # Two errors rather than one: "there is no such trunk" and
            # "there is no such port on this hardware" are different
            # problems with different fixes, and access mode's is the
            # quieter of the two.
            if vlan.port_mode == "access":
                raise VlanAccessPortNotFoundError(vlan.interface, credentials.host)
            raise VlanParentInterfaceNotFoundError(vlan.interface, credentials.host)
        self._check_subnet_conflict(vlan, snapshot, credentials.host)

    def _check_subnet_conflict(
        self, vlan: Vlan, snapshot: VlanNetworkSnapshot, host: str
    ) -> None:
        """Rejects a subnet that overlaps one the router already carries.

        Compared against the device's live ``/ip address`` table, never
        against other ``Vlan`` rows -- the router's LAN bridge, its uplink
        and anything configured outside this platform have no row here, and
        it is the device's set that decides whether the push leaves two
        matching routes and traffic going to whichever RouterOS picked.

        Two exclusions, both necessary rather than convenient:

        * addresses on this VLAN's *own* bind interface, or every re-push
          of an unchanged VLAN would conflict with itself;
        * disabled addresses, which are not in the routing table and so
          collide with nothing.
        """
        if not vlan.cidr:
            return
        wanted = ipaddress.ip_network(vlan.cidr, strict=False)
        bind_interface = self._bind_interface(vlan)
        for row in snapshot.addresses:
            if row.disabled or row.interface == bind_interface:
                continue
            try:
                existing = ipaddress.ip_interface(row.address).network
            except ValueError:
                # A row this platform cannot parse is not a licence to
                # claim the subnet, but it is also not evidence of a
                # conflict. Skipped rather than guessed at.
                continue
            if wanted.overlaps(existing):
                raise VlanSubnetConflictError(
                    vlan.cidr, row.address, row.interface or host
                )

    @staticmethod
    def _bind_interface(vlan: Vlan) -> str:
        """The interface this VLAN's address, portal and DHCP actually sit
        on -- which is not always ``vlan<id>``.

        In trunk mode the VLAN is a tagged sub-interface named
        deterministically from its tag. In access mode there is no
        ``/interface vlan`` entry at all: the VLAN is realized as the
        physical port itself, and everything binds there. Both branches
        mirror ``render_vlan``, which is what the operator was shown when
        they chose the mode.
        """
        if vlan.port_mode == "access" and vlan.interface:
            return vlan.interface
        return f"vlan{vlan.vlan_id}"

    @staticmethod
    def _hotspot_dns_name(vlan: Vlan) -> str:
        """Per-VLAN, not one shared literal. ``_render_vlan_hotspot`` can
        put a portal on several VLANs of one router, each with its own
        ``hotspot-address``; a single name would leave the router's
        ``/ip dns static`` table either rejecting the second ``add`` or
        round-robining one name across two gateways, sending some fraction
        of one VLAN's guests to another's."""
        return f"vlan{vlan.vlan_id}.{HOTSPOT_DNS_NAME}"

    async def _apply_hotspot(
        self,
        vlan: Vlan,
        credentials: VlanCredentials,
        adapter: BaseVlanAdapter,
        bind_interface: str,
    ) -> None:
        """Puts this VLAN's captive portal on the device, or takes it off.

        The off branch is a real delete, not a no-op, for the same reason
        NAT's is: the flag is current intent, the objects on the device are
        history, and leaving them would mean a VLAN whose portal the
        operator switched off still challenging its guests while the push
        reported success.

        The delete needs the subnet to find what it wrote (the DHCP network
        row is keyed on the address). A VLAN with the portal off and no
        subnet at all therefore gets nothing done here -- correctly: a
        portal can never have been created for it, since the enabled branch
        refuses without one.
        """
        if vlan.enable_hotspot:
            await adapter.configure_hotspot(
                credentials,
                vlan_id=vlan.vlan_id,
                interface=bind_interface,
                cidr=vlan.cidr,
                gateway=vlan.gateway_ip_address,
                dns_name=self._hotspot_dns_name(vlan),
                html_directory=HOTSPOT_HTML_DIRECTORY,
            )
            return
        if not vlan.cidr or not vlan.gateway_ip_address:
            return
        await adapter.delete_hotspot(
            credentials,
            vlan_id=vlan.vlan_id,
            interface=bind_interface,
            cidr=vlan.cidr,
            gateway=vlan.gateway_ip_address,
            dns_name=self._hotspot_dns_name(vlan),
            html_directory=HOTSPOT_HTML_DIRECTORY,
        )

    async def _remove_from_device(
        self, vlan: Vlan, *, requesting_organization_id: uuid.UUID | None
    ) -> None:
        """Tears the VLAN off its router, when there is anything there.

        Skipped entirely unless ``device_push_status`` is ``ACTIVE``: a row
        that was never pushed, or whose last push failed, has nothing on the
        device, and opening a connection to delete nothing would make every
        such delete fail whenever a router happened to be unreachable.
        """
        if vlan.device_push_status != VlanDevicePushStatus.ACTIVE.value:
            return
        if not vlan.interface:
            # Cannot be ACTIVE without one in practice -- push refuses
            # without an interface -- but the column is nullable, and
            # guessing an interface name to delete on would be worse than
            # doing nothing.
            return
        router = await self.router_lookup.get_router(
            vlan.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_vlan_adapter(router.vendor)
        # The exact reverse of the push order: the portal and then NAT come
        # off while the interface they reference is still there, then the
        # interface.
        #
        # All of it unconditional, not gated on ``enable_hotspot``/
        # ``nat_enabled``. Those flags are current intent; the objects on
        # the device are history. A VLAN pushed with a portal and later
        # switched off without a re-push still has one, and reading the flag
        # would leave exactly that behind on an interface that is about to
        # stop existing. Removing what is already absent is a no-op.
        #
        # The portal teardown needs the subnet to find its own DHCP network
        # row, so a VLAN with no CIDR skips it -- correctly, since the push
        # refuses to create a portal without one.
        if vlan.cidr and vlan.gateway_ip_address:
            await adapter.delete_hotspot(
                credentials,
                vlan_id=vlan.vlan_id,
                interface=self._bind_interface(vlan),
                cidr=vlan.cidr,
                gateway=vlan.gateway_ip_address,
                dns_name=self._hotspot_dns_name(vlan),
                html_directory=HOTSPOT_HTML_DIRECTORY,
            )
        await adapter.delete_nat_masquerade(credentials, vlan_id=vlan.vlan_id)
        await adapter.delete_vlan(
            credentials,
            vlan_id=vlan.vlan_id,
            name=vlan.name,
            interface=vlan.interface,
            ip_cidr=self._device_address(vlan),
            port_mode=vlan.port_mode,
        )

    @staticmethod
    def _device_address(vlan: Vlan) -> str | None:
        """The address line the device should carry, matching
        ``renderers._vlan_address_line`` exactly.

        When a gateway is set the router's own address is the *gateway*
        inside the subnet, not the network address -- sending ``cidr`` here
        would put the router at ``.0``. The two paths must agree: a VLAN
        pushed directly and the same VLAN rendered into a config script have
        to produce the same device state.
        """
        if not vlan.cidr:
            return None
        if vlan.gateway_ip_address:
            return f"{vlan.gateway_ip_address}/{vlan.cidr.split('/')[-1]}"
        return vlan.cidr

    def _resolve_device_credentials(self, router: Router) -> VlanCredentials:
        """Raise rather than guess -- mirrors ``qos``/``queue_management``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise VlanMissingCredentialsError(router.id)
        return VlanCredentials(
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
            entity_type="vlan",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "RouterLookupProtocol",
    "AuditLogWriter",
    "DhcpPoolLookupProtocol",
    "VlanService",
]
