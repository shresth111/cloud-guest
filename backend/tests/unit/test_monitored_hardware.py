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
from app.domains.monitored_hardware.constants import HardwareStatus
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
    *, organization_id: uuid.UUID | None = None, location_id: uuid.UUID | None = None
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
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
# Structural RBAC check
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_monitored_hardware_route_has_a_permission_dependency(self) -> None:
        assert len(monitored_hardware_router.routes) == 3
        for route in monitored_hardware_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
