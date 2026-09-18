"""Unit tests for the Monitored Hardware domain: registration CRUD (tenant
isolation, MAC format validation, duplicate-MAC rejection), the derived
up/down/unknown status lookup this domain exists for, and a structural
RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style,
mirroring ``tests/unit/test_network_device.py``'s own identical "fake the
narrow Protocol boundary" precedent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.connected_devices.models import ConnectedDevice
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.location.models import Location
from app.domains.monitored_hardware.constants import (
    HardwareStatus,
    StatusReason,
    StatusSource,
)
from app.domains.monitored_hardware.exceptions import (
    DuplicateMonitoredHardwareError,
    InvalidMacAddressError,
    MonitoredHardwareNotFoundError,
)
from app.domains.monitored_hardware.models import MonitoredHardware
from app.domains.monitored_hardware.router import router as monitored_hardware_router
from app.domains.monitored_hardware.service import MonitoredHardwareService
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

# ============================================================================
# Shared helpers
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _make_location(*, organization_id: uuid.UUID | None = None) -> Location:
    return Location(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            name="HQ",
            slug=f"hq-{uuid.uuid4()}",
            status="active",
            address_line1="1 Main St",
            address_line2=None,
            city="Austin",
            state_province="TX",
            postal_code="78701",
            country="US",
            timezone="UTC",
            latitude=None,
            longitude=None,
            contact_name=None,
            contact_phone=None,
            contact_email=None,
            settings={},
        )
    )


def _make_router(
    *,
    organization_id: uuid.UUID | None = None,
    location_id: uuid.UUID | None = None,
    vendor: str = "mikrotik",
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor=vendor,
            routeros_version=None,
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


def _make_connected_device(
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    router_id: uuid.UUID | None = None,
    mac_address: str,
    is_active: bool = True,
    last_seen_at: datetime | None = None,
) -> ConnectedDevice:
    return ConnectedDevice(
        **_base_fields(
            router_id=router_id or uuid.uuid4(),
            organization_id=organization_id,
            location_id=location_id,
            mac_address=mac_address,
            ip_address="10.0.0.50",
            hostname=None,
            vendor=None,
            connection_type="wired",
            interface=None,
            signal_strength_dbm=None,
            is_active=is_active,
            connected_at=_now(),
            last_seen_at=last_seen_at or _now(),
            comment=None,
            guest_id=None,
            guest_session_id=None,
        )
    )


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeMonitoredHardwareRepository:
    devices: dict[uuid.UUID, MonitoredHardware] = field(default_factory=dict)
    connected_devices: list[ConnectedDevice] = field(default_factory=list)
    # Fleet rows, for the one read that asks the vendor question. Left empty
    # by every pre-existing test on purpose: "this venue has no fleet row at
    # all" is the case that must keep behaving exactly as it did before
    # `status_source` existed.
    routers: list[Router] = field(default_factory=list)

    async def create_device(self, **fields: object) -> MonitoredHardware:
        device = MonitoredHardware(**_base_fields(**fields))
        self.devices[device.id] = device
        return device

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> MonitoredHardware | None:
        device = self.devices.get(device_id)
        if device is None or (device.is_deleted and not include_deleted):
            return None
        return device

    async def get_device_by_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> MonitoredHardware | None:
        for device in self.devices.values():
            if (
                device.organization_id == organization_id
                and device.mac_address == mac_address
            ):
                return device
        return None

    async def soft_delete_device(self, device: MonitoredHardware) -> MonitoredHardware:
        device.is_deleted = True
        device.deleted_at = _now()
        return device

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.devices.values() if not v.is_deleted]
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if location_id is not None:
            values = [v for v in values if v.location_id == location_id]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def get_connected_device_by_mac(
        self, location_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None:
        for cd in self.connected_devices:
            if cd.location_id == location_id and cd.mac_address == mac_address:
                return cd
        return None

    async def router_vendors_for_locations(
        self, location_ids
    ) -> dict[uuid.UUID, dict[uuid.UUID, str]]:
        wanted = set(location_ids)
        vendors: dict[uuid.UUID, dict[uuid.UUID, str]] = {}
        for router in self.routers:
            if router.location_id in wanted and not router.is_deleted:
                vendors.setdefault(router.location_id, {})[router.id] = router.vendor
        return vendors


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeLocationLookup:
    locations: dict[uuid.UUID, Location] = field(default_factory=dict)

    def add(self, location: Location) -> Location:
        self.locations[location.id] = location
        return location

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location:
        location = self.locations.get(location_id)
        if location is None:
            raise LocationNotFoundError(location_id)
        if (
            requesting_organization_id is not None
            and location.organization_id != requesting_organization_id
        ):
            raise LocationNotFoundError(location_id)
        return location


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)

    def add(self, router: Router) -> Router:
        self.routers[router.id] = router
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        if (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: MonitoredHardwareService
    repository: FakeMonitoredHardwareRepository
    location_lookup: FakeLocationLookup
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeMonitoredHardwareRepository()
    location_lookup = FakeLocationLookup()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = MonitoredHardwareService(
        repository, location_lookup, router_lookup, audit_writer=audit_writer
    )
    return Harness(
        service=service,
        repository=repository,
        location_lookup=location_lookup,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
    )


async def _register_device(
    h: Harness,
    location: Location,
    *,
    router_id: uuid.UUID | None = None,
    mac_address: str = "aa:bb:cc:dd:ee:01",
    name: str = "Lobby AP",
    device_type: str = "Access Point",
    floor: str | None = "GF",
) -> MonitoredHardware:
    return await h.service.register_device(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=location.organization_id,
        location_id=location.id,
        router_id=router_id,
        name=name,
        mac_address=mac_address,
        device_type=device_type,
        floor=floor,
    )


# ============================================================================
# Registration / CRUD
# ============================================================================


class TestMonitoredHardwareCrud:
    async def test_register_device(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, device_type="Camera")
        assert device.mac_address == "AA:BB:CC:DD:EE:01"
        assert device.organization_id == location.organization_id
        assert device.location_id == location.id
        assert device.device_type == "Camera"
        assert device.floor == "GF"
        assert len(h.audit_writer.entries) == 1

    async def test_register_normalizes_and_validates_mac(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        with pytest.raises(InvalidMacAddressError):
            await _register_device(h, location, mac_address="not-a-mac")

    async def test_register_rejects_duplicate_mac_in_same_organization(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        await _register_device(h, location, mac_address="aa:bb:cc:dd:ee:02")
        with pytest.raises(DuplicateMonitoredHardwareError):
            await _register_device(h, location, mac_address="AA:BB:CC:DD:EE:02")

    async def test_register_allows_same_mac_in_different_organization(self) -> None:
        h = make_harness()
        location_a = h.location_lookup.add(_make_location())
        location_b = h.location_lookup.add(_make_location())
        await _register_device(h, location_a, mac_address="aa:bb:cc:dd:ee:03")
        device_b = await _register_device(
            h, location_b, mac_address="aa:bb:cc:dd:ee:03"
        )
        assert device_b.organization_id == location_b.organization_id

    async def test_register_raises_for_unknown_location(self) -> None:
        h = make_harness()
        with pytest.raises(LocationNotFoundError):
            await _register_device(h, _make_location())

    async def test_register_with_router_validates_router_belongs_to_org(
        self,
    ) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        other_router = h.router_lookup.add(_make_router())
        with pytest.raises(RouterNotFoundError):
            await _register_device(h, location, router_id=other_router.id)

    async def test_register_with_valid_router(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        router = h.router_lookup.add(
            _make_router(organization_id=location.organization_id)
        )
        device = await _register_device(h, location, router_id=router.id)
        assert device.router_id == router.id

    async def test_get_device_cross_organization_raises(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location)
        with pytest.raises(MonitoredHardwareNotFoundError):
            await h.service.get_device(
                device.id, requesting_organization_id=uuid.uuid4()
            )

    async def test_get_device_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(MonitoredHardwareNotFoundError):
            await h.service.get_device(uuid.uuid4())

    async def test_delete_device(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location)
        deleted = await h.service.delete_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=location.organization_id,
        )
        assert deleted.is_deleted is True
        assert len(h.audit_writer.entries) == 2

    async def test_list_devices_scopes_to_organization(self) -> None:
        h = make_harness()
        location_a = h.location_lookup.add(_make_location())
        location_b = h.location_lookup.add(_make_location())
        await _register_device(h, location_a, mac_address="aa:bb:cc:dd:ee:04")
        await _register_device(h, location_b, mac_address="aa:bb:cc:dd:ee:05")
        items, meta = await h.service.list_devices(
            requesting_organization_id=location_a.organization_id, page=1, page_size=25
        )
        assert meta.total_items == 1
        assert items[0].device.organization_id == location_a.organization_id

    async def test_list_devices_scopes_to_location(self) -> None:
        h = make_harness()
        location_a = h.location_lookup.add(_make_location())
        location_b = h.location_lookup.add(
            _make_location(organization_id=location_a.organization_id)
        )
        await _register_device(h, location_a, mac_address="aa:bb:cc:dd:ee:06")
        await _register_device(h, location_b, mac_address="aa:bb:cc:dd:ee:07")
        items, meta = await h.service.list_devices(
            requesting_organization_id=location_a.organization_id,
            location_id=location_a.id,
            page=1,
            page_size=25,
        )
        assert meta.total_items == 1
        assert items[0].device.location_id == location_a.id


# ============================================================================
# Derived status -- the whole reason this domain exists (see its own
# module docstring). Never a fabricated ping.
# ============================================================================


class TestDerivedStatus:
    async def test_status_is_unknown_when_never_observed(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, mac_address="aa:bb:cc:dd:ee:08")
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UNKNOWN
        assert item.last_seen_at is None

    async def test_status_is_up_when_connected_device_is_active(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, mac_address="aa:bb:cc:dd:ee:09")
        seen_at = _now()
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                mac_address=device.mac_address,
                is_active=True,
                last_seen_at=seen_at,
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UP
        assert item.last_seen_at == seen_at

    async def test_status_is_down_when_connected_device_went_inactive(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, mac_address="aa:bb:cc:dd:ee:10")
        seen_at = _now() - timedelta(hours=6)
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                mac_address=device.mac_address,
                is_active=False,
                last_seen_at=seen_at,
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.DOWN
        assert item.last_seen_at == seen_at

    async def test_status_is_down_when_sighting_is_stale_even_if_still_active(
        self,
    ) -> None:
        """Regression: "AP Hall Lobby went down but the console still shows
        UP". ``is_active`` is only as fresh as the sweep that last wrote it;
        when the uplink router went unreachable (or the sweep stalled) the
        flip that would have marked the device down never ran, and the
        stale ``is_active=True`` row kept reporting UP. A sighting older
        than the stale window must read as DOWN regardless of the flag."""
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, mac_address="aa:bb:cc:dd:ee:14")
        stale_at = _now() - timedelta(hours=1)
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                mac_address=device.mac_address,
                is_active=True,
                last_seen_at=stale_at,
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.DOWN
        assert item.connected_at is None, (
            "a stale sighting must not surface connected_at as current uptime"
        )

    async def test_status_is_up_when_sighting_is_fresh(self) -> None:
        """A genuinely current sighting -- inside the stale window -- keeps
        reporting UP; the staleness guard must not invent outages for a
        device the sweep is actively refreshing."""
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, mac_address="aa:bb:cc:dd:ee:15")
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                mac_address=device.mac_address,
                is_active=True,
                last_seen_at=_now() - timedelta(minutes=20),
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UP

    async def test_status_lookup_is_scoped_to_the_devices_own_location(self) -> None:
        """A ConnectedDevice row for the same MAC at a *different* location
        must never leak into this device's status -- two venues sharing a
        MAC (e.g. a vendor's default AP MAC before a customer changes it)
        would otherwise cross-contaminate."""
        h = make_harness()
        location_a = h.location_lookup.add(_make_location())
        location_b = h.location_lookup.add(_make_location())
        device = await _register_device(
            h, location_a, mac_address="aa:bb:cc:dd:ee:11"
        )
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location_b.organization_id,
                location_id=location_b.id,
                mac_address=device.mac_address,
                is_active=True,
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UNKNOWN

    async def test_list_devices_includes_status_per_item(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        up_device = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:12"
        )
        unknown_device = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:13"
        )
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                mac_address=up_device.mac_address,
                is_active=True,
            )
        )
        items, _ = await h.service.list_devices(
            requesting_organization_id=location.organization_id, page=1, page_size=25
        )
        statuses = {item.device.id: item.status for item in items}
        assert statuses[up_device.id] == HardwareStatus.UP
        assert statuses[unknown_device.id] == HardwareStatus.UNKNOWN


# ============================================================================
# Honest status source -- measured vs. never measurable
# ============================================================================


class TestStatusSourceIsHonest:
    """`unknown` on a controller-managed venue is not the same fact as
    `unknown` on a MikroTik venue, and the API must be able to say which.

    A monitored-hardware UP/DOWN comes from a `ConnectedDevice` row, and
    both writers of that row open a RouterOS session against the venue's
    uplink. A TP-Link Omada controller has no RouterOS, so at a venue whose
    only fleet row is a controller nothing ever probes the device -- the row
    sits at `unknown` forever, and a screen reads that as "we looked and
    never saw it". These tests pin the distinction, and pin that an
    agent-managed venue's answer did not move.
    """

    async def test_agent_managed_venue_is_measured(self) -> None:
        """The pre-existing behaviour, now stated out loud: a MikroTik venue
        reports UP from a probe, and says the status was measured."""
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        router = _make_router(
            organization_id=location.organization_id, location_id=location.id
        )
        h.repository.routers.append(router)
        device = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:20"
        )
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                router_id=router.id,
                mac_address=device.mac_address,
                is_active=True,
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UP
        assert item.status_source == StatusSource.MEASURED
        assert item.status_reason == StatusReason.LIVENESS_PROBE

    async def test_agent_managed_venue_never_observed_is_still_measurable(
        self,
    ) -> None:
        """A freshly registered row at a MikroTik venue: unknown, because
        nothing has seen it *yet*. A probe path exists, so this is NOT the
        controller case -- the two must not collapse into one another."""
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        h.repository.routers.append(
            _make_router(
                organization_id=location.organization_id, location_id=location.id
            )
        )
        device = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:21"
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UNKNOWN
        assert item.status_source == StatusSource.MEASURED
        assert item.status_reason == StatusReason.NEVER_OBSERVED

    async def test_controller_managed_venue_is_unmeasured(self) -> None:
        """The defect. An AP registered at an Omada venue can never be
        pinged: the sweep's target list is narrowed to agent-managed uplinks
        in SQL, so this row is never dialled. It must not report as a device
        that was looked for and not found."""
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        h.repository.routers.append(
            _make_router(
                organization_id=location.organization_id,
                location_id=location.id,
                vendor="tplink_omada",
            )
        )
        device = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:22"
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UNKNOWN
        assert item.status_source == StatusSource.UNMEASURED
        assert item.status_reason == StatusReason.CONTROLLER_MANAGED

    async def test_controller_uplink_never_reports_up(self) -> None:
        """Even with an `is_active` ConnectedDevice row against a controller
        uplink, the answer is unmeasured -- nothing refreshes that row, so
        UP would be a claim about a reading no sweep is taking."""
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        controller = _make_router(
            organization_id=location.organization_id,
            location_id=location.id,
            vendor="tplink_omada",
        )
        h.repository.routers.append(controller)
        device = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:23"
        )
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                router_id=controller.id,
                mac_address=device.mac_address,
                is_active=True,
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UNKNOWN
        assert item.status_source == StatusSource.UNMEASURED
        assert item.status_reason == StatusReason.CONTROLLER_MANAGED

    async def test_mixed_venue_keeps_its_agent_managed_answer(self) -> None:
        """A venue running both a MikroTik and an Omada controller still has
        a probe path, and a device seen through the MikroTik is measured.
        The controller's presence must not demote its neighbour."""
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        mikrotik = _make_router(
            organization_id=location.organization_id, location_id=location.id
        )
        h.repository.routers.extend(
            [
                mikrotik,
                _make_router(
                    organization_id=location.organization_id,
                    location_id=location.id,
                    vendor="tplink_omada",
                ),
            ]
        )
        device = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:24"
        )
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                router_id=mikrotik.id,
                mac_address=device.mac_address,
                is_active=False,
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.DOWN
        assert item.status_source == StatusSource.MEASURED
        assert item.status_reason == StatusReason.LIVENESS_PROBE

    async def test_unresolvable_uplink_reads_as_agent_managed(self) -> None:
        """A sighting whose router row is gone (soft-deleted) falls back to
        the column's own `mikrotik` default, exactly as `vendor_of` does --
        so no agent-managed venue's answer can change because a row was
        tidied up."""
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:25"
        )
        h.repository.connected_devices.append(
            _make_connected_device(
                organization_id=location.organization_id,
                location_id=location.id,
                mac_address=device.mac_address,
                is_active=True,
            )
        )
        item = await h.service.with_status(device)
        assert item.status == HardwareStatus.UP
        assert item.status_source == StatusSource.MEASURED

    async def test_list_devices_reports_the_source_per_row(self) -> None:
        """The list path batches the vendor read; it must reach the same
        verdict the single-row path does."""
        h = make_harness()
        agent_location = h.location_lookup.add(_make_location())
        controller_location = h.location_lookup.add(
            _make_location(organization_id=agent_location.organization_id)
        )
        h.repository.routers.extend(
            [
                _make_router(
                    organization_id=agent_location.organization_id,
                    location_id=agent_location.id,
                ),
                _make_router(
                    organization_id=agent_location.organization_id,
                    location_id=controller_location.id,
                    vendor="tplink_omada",
                ),
            ]
        )
        agent_device = await _register_device(
            h, agent_location, mac_address="aa:bb:cc:dd:ee:26"
        )
        controller_device = await _register_device(
            h, controller_location, mac_address="aa:bb:cc:dd:ee:27"
        )
        items, _ = await h.service.list_devices(
            requesting_organization_id=agent_location.organization_id,
            page=1,
            page_size=25,
        )
        sources = {item.device.id: item.status_source for item in items}
        assert sources[agent_device.id] == StatusSource.MEASURED
        assert sources[controller_device.id] == StatusSource.UNMEASURED


# ============================================================================
# Structural RBAC check
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_monitored_hardware_route_has_a_permission_dependency(self) -> None:
        assert len(monitored_hardware_router.routes) == 3
        for route in monitored_hardware_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
