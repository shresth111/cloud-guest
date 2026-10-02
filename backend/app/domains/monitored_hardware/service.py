"""Monitored Hardware business logic: registration CRUD plus the honest,
derived status lookup this whole domain exists for -- see ``__init__.py``'s
own module docstring for the full write-up.

## Composition, not duplication

``LocationLookupProtocol``/``RouterLookupProtocol`` are the identical
narrow, duck-typed Protocol composition-over-duplication pattern
``app.domains.network_device.service`` already establishes.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.domains.location.models import Location
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import (
    LocationScope,
    enforce_entity_location,
)
from app.domains.router.models import Router
from app.domains.router.vendor_capabilities import is_agent_managed

from .constants import (
    STALE_SIGHTING_AFTER_SECONDS,
    HardwareStatus,
    StatusReason,
    StatusSource,
)
from .events import MonitoredHardwareDeleted, MonitoredHardwareRegistered
from .exceptions import DuplicateMonitoredHardwareError, MonitoredHardwareNotFoundError
from .models import MonitoredHardware
from .repository import MonitoredHardwareRepositoryProtocol
from .validators import validate_mac_address

logger = logging.getLogger(__name__)

# A device is considered reachable ("up") only if connected_devices' own
# sync sweep marked it is_active on its most recent pass. That sweep runs
# every CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS (900s/15min as of
# this writing) -- is_active is a live flag maintained by that sweep
# itself, not a timestamp this domain has to age out on its own, so no
# separate "recently seen" threshold is needed here at all: it's already
# correct by construction.


def _event_extra(event: object) -> dict[str, object]:
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


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


@dataclasses.dataclass(frozen=True, slots=True)
class HardwareWithStatus:
    """A ``MonitoredHardware`` row plus its derived status -- see module
    docstring. ``last_seen_at`` is only ever a real
    ``ConnectedDevice.last_seen_at`` value (or ``None`` when the device
    has never been observed), never invented. ``connected_at`` is the
    companion fact that answers a different question -- "how long has
    this device actually been on the network" rather than "when did the
    sync sweep last see it" -- and is likewise only ever a real
    ``ConnectedDevice.connected_at`` (``None`` when never observed)."""

    device: MonitoredHardware
    status: HardwareStatus
    last_seen_at: datetime | None
    connected_at: datetime | None
    #: Whether anything on this platform measures this device at all, and
    #: why the status reads as it does. See ``constants.StatusSource`` for
    #: the full argument; in short, a controller-managed venue has no
    #: RouterOS session to probe through, so its rows are UNKNOWN forever
    #: and must say so rather than letting ``unknown`` be read as "we
    #: looked and never saw it". Defaulted so every existing construction
    #: of this dataclass -- and every test double -- keeps the pre-existing
    #: agent-managed meaning without being rewritten.
    status_source: StatusSource = StatusSource.MEASURED
    status_reason: StatusReason = StatusReason.LIVENESS_PROBE


class MonitoredHardwareService:
    """Core Monitored Hardware business logic."""

    def __init__(
        self,
        repository: MonitoredHardwareRepositoryProtocol,
        location_lookup: LocationLookupProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        self.location_lookup = location_lookup
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        # Constructor-injected -- see `app.domains.rbac.location_scope`.
        self.caller_location_scope = caller_location_scope

    async def register_device(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        name: str,
        mac_address: str,
        device_type: str,
        router_id: uuid.UUID | None = None,
        floor: str | None = None,
    ) -> MonitoredHardware:
        location = await self.location_lookup.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )
        if router_id is not None:
            await self.router_lookup.get_router(
                router_id, requesting_organization_id=location.organization_id
            )
        normalized_mac = validate_mac_address(mac_address)

        existing = await self.repository.get_device_by_mac(
            location.organization_id, normalized_mac
        )
        if existing is not None and not existing.is_deleted:
            raise DuplicateMonitoredHardwareError(normalized_mac)

        device = await self.repository.create_device(
            organization_id=location.organization_id,
            location_id=location.id,
            router_id=router_id,
            name=name,
            mac_address=normalized_mac,
            device_type=device_type,
            floor=floor,
            created_by=actor_user_id,
        )
        event = MonitoredHardwareRegistered(
            id=device.id, organization_id=device.organization_id
        )
        logger.info("monitored_hardware_registered", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MONITORED_HARDWARE_CREATED,
            entity_id=device.id,
            organization_id=device.organization_id,
            description=f"Monitored hardware '{normalized_mac}' registered",
        )
        return device

    async def get_device(
        self,
        device_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> MonitoredHardware:
        device = await self.repository.get_device_by_id(device_id)
        if device is None:
            raise MonitoredHardwareNotFoundError(device_id)
        if (
            requesting_organization_id is not None
            and device.organization_id != requesting_organization_id
        ):
            raise MonitoredHardwareNotFoundError(device_id)
        # Same reasoning as firewall, but raising this domain's own
        # NotFound rather than a 403: it already answers a foreign
        # *organization* that way so as not to confirm the row exists,
        # and a location refusal that 403s would leak exactly what the
        # organization refusal is careful not to.
        #
        # DO NOT "harmonise" this to the CrossLocation*AccessError 403 the
        # other domains raise. "No such row" and "that row is not yours"
        # are different answers, and this domain has deliberately chosen
        # the first. No test asserts that a refusal must be uninformative,
        # so that change would pass CI and quietly turn an
        # existence-hiding refusal into an existence-confirming one.
        enforce_entity_location(
            entity_location_id=getattr(device, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=MonitoredHardwareNotFoundError(device_id),
        )
        return device

    async def _router_vendors_at(
        self,
        location_id: uuid.UUID,
        cached: dict[uuid.UUID, dict[uuid.UUID, str]] | None,
    ) -> dict[uuid.UUID, str]:
        """``{router_id: vendor}`` for one location, from a batch the caller
        already fetched or from a fresh read for this location alone."""
        if cached is not None:
            return cached.get(location_id, {})
        fetched = await self.repository.router_vendors_for_locations([location_id])
        return fetched.get(location_id, {})

    async def with_status(
        self,
        device: MonitoredHardware,
        *,
        router_vendors: dict[uuid.UUID, dict[uuid.UUID, str]] | None = None,
    ) -> HardwareWithStatus:
        """This row's derived status, and -- new -- whether it was derived
        from a measurement at all.

        ## Why the vendor question is asked here

        Every UP/DOWN this method can return traces back to a
        ``ConnectedDevice`` row, and that row has exactly two writers:
        ``connected_devices``' DHCP-lease discovery sync and its ICMP/ARP
        liveness sweep. Both reach the venue by opening a RouterOS API
        session against the uplink router. A TP-Link Omada controller is a
        ``Router`` row with NULL credentials and no RouterOS at all
        (``app.domains.router.vendor_capabilities``), so at a venue whose
        only fleet row is a controller, neither writer ever runs: there is
        no ``ConnectedDevice`` row, the status is ``unknown``, and it will be
        ``unknown`` for as long as the venue exists.

        ``unknown`` on its own is read by the screen -- and by the person
        reading the screen -- as *we looked and never saw it*. Nothing here
        ever looked, and the difference matters: the first is a device to go
        and check, the second is a device this platform simply does not
        monitor, whose real inventory is the one its controller reports.

        ## The label, deliberately, and not the evidence

        ``is_agent_managed`` (the vendor label) rather than
        ``is_agent_managed_row`` (label + agent evidence), because this
        method must agree with what the sweep actually does, and the sweep's
        target list is narrowed in SQL by
        ``fleet_scope.agent_managed_only`` -- a label filter, as
        ``list_routers_for_sync`` has always been. Asking a different
        question here than the prober asks would reintroduce the exact
        defect in miniature: a row nothing probes, reported as measured.

        A vendor we cannot resolve reads as agent-managed, matching
        ``vendor_of``'s own choice that a missing vendor is the column's
        ``mikrotik`` default. That keeps every agent-managed venue's answer
        byte-identical to what it was before this field existed, including
        for a row whose uplink router has since been deleted.
        """
        vendors = await self._router_vendors_at(device.location_id, router_vendors)
        connected = await self.repository.get_connected_device_by_mac(
            device.location_id, device.mac_address
        )
        if connected is None:
            # No sighting. Either a probe path exists and has not produced
            # one yet (a MikroTik venue's freshly registered row -- the
            # pre-existing meaning of `unknown`), or the venue has fleet
            # rows and every one of them is a controller, in which case no
            # probe path exists and never will.
            venue_is_probeable = not vendors or any(
                is_agent_managed(vendor) for vendor in vendors.values()
            )
            return HardwareWithStatus(
                device=device,
                status=HardwareStatus.UNKNOWN,
                last_seen_at=None,
                connected_at=None,
                status_source=(
                    StatusSource.MEASURED
                    if venue_is_probeable
                    else StatusSource.UNMEASURED
                ),
                status_reason=(
                    StatusReason.NEVER_OBSERVED
                    if venue_is_probeable
                    else StatusReason.CONTROLLER_MANAGED
                ),
            )
        # A sighting exists -- but a stale one is not a measurement if the
        # router that would refresh it is a controller. `ConnectedDevice
        # .router_id` is the router that genuinely observed this MAC, which
        # is the same row the liveness sweep would dial, so it is the one
        # whose vendor decides this.
        if not is_agent_managed(vendors.get(connected.router_id)):
            return HardwareWithStatus(
                device=device,
                status=HardwareStatus.UNKNOWN,
                last_seen_at=connected.last_seen_at,
                connected_at=None,
                status_source=StatusSource.UNMEASURED,
                status_reason=StatusReason.CONTROLLER_MANAGED,
            )
        # An ``is_active`` row whose last sighting is older than the stale
        # window is not a live device -- it is a row the device-sync sweep
        # could not refresh (its uplink router went unreachable, or the
        # sweep itself stalled), and deriving UP from it repeats the
        # reported bug: a venue access point that physically went down kept
        # showing UP because the sweep that would have flipped ``is_active``
        # never ran. See STALE_SIGHTING_AFTER_SECONDS in this domain's
        # constants for the window's derivation. ``last_seen_at`` is never
        # None for a row the sync wrote (every create/update branch stamps
        # it), so a None here falls back to trusting ``is_active`` alone --
        # the pre-existing contract the unit tests pin.
        if connected.is_active and connected.last_seen_at is not None:
            age_seconds = (datetime.now(UTC) - connected.last_seen_at).total_seconds()
            is_active = age_seconds <= STALE_SIGHTING_AFTER_SECONDS
        else:
            is_active = connected.is_active
        status = HardwareStatus.UP if is_active else HardwareStatus.DOWN
        return HardwareWithStatus(
            device=device,
            status=status,
            last_seen_at=connected.last_seen_at,
            # ``connected_at`` is preserved by the sync sweep across ticks
            # for a device that stays active (see connected_devices/
            # service.py's own update branch) -- i.e. it is genuinely
            # "this device has been on the network since", the fact a
            # venue owner means when they ask "how long has it been up?".
            # Deliberately only surfaced for UP devices: a DOWN device's
            # stale ``connected_at`` would read as current uptime.
            connected_at=connected.connected_at if is_active else None,
        )

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[HardwareWithStatus], object]:
        devices, meta = await self.repository.list_devices(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )
        # One vendor read for the whole page rather than one per row: a
        # page can span several locations (the org-wide call from the
        # location picker's cross-location summary does exactly that).
        router_vendors = await self.repository.router_vendors_for_locations(
            {d.location_id for d in devices}
        )
        return [
            await self.with_status(d, router_vendors=router_vendors) for d in devices
        ], meta

    async def list_all_devices_with_status(
        self, *, organization_id: uuid.UUID
    ) -> list[HardwareWithStatus]:
        """Real, unpaginated "every device in this org, with its live
        derived status" composition for ``app.domains.monitoring``'s
        ``AlertService`` (its ``ALERT_TARGET_MONITORED_HARDWARE`` rule
        evaluation, see that module's own docstring) -- the same
        "read another domain's data for alert-rule evaluation" precedent
        ``MonitoringRepository.list_routers``/``list_isp_links`` already
        establish, done through this service (not a raw repository read)
        because deriving status here genuinely requires this domain's own
        ``with_status`` join logic, unlike ``Router``/``IspLink``'s already-
        persisted ``health_status`` column. A large page size stands in for
        real "no pagination" the same pragmatic way ``list_routers``/
        ``list_isp_links`` skip pagination entirely -- an organization's
        real hardware count is small enough that a single page comfortably
        covers it; revisit if that assumption ever stops holding."""
        devices, _ = await self.list_devices(
            requesting_organization_id=organization_id, page=1, page_size=500
        )
        return devices

    async def delete_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> MonitoredHardware:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_device(device)
        event = MonitoredHardwareDeleted(
            id=deleted.id, organization_id=deleted.organization_id
        )
        logger.info("monitored_hardware_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MONITORED_HARDWARE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Monitored hardware '{deleted.mac_address}' deleted",
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
            entity_type="monitored_hardware",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "LocationLookupProtocol",
    "RouterLookupProtocol",
    "AuditLogWriter",
    "HardwareWithStatus",
    "MonitoredHardwareService",
]
