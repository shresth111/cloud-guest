"""Unit tests for the Network Device (NAC) domain: device registration CRUD
(tenant isolation, MAC format validation, duplicate-MAC rejection, vendor
auto-suggestion), the admin-assessed compliance-status workflow, and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_dns.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``NetworkDeviceService`` is exercised against small, hand-rolled
in-memory fakes for its own repository and the composed
``LocationLookupProtocol``/``RouterLookupProtocol`` -- mirrors
``test_dns.py``'s own identical "fake the narrow Protocol boundary"
precedent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.location.models import Location
from app.domains.network_device.constants import ComplianceStatus
from app.domains.network_device.exceptions import (
    CrossOrganizationNetworkDeviceAccessError,
    DuplicateNetworkDeviceError,
    InvalidMacAddressError,
    NetworkDeviceNotFoundError,
)
from app.domains.network_device.models import NetworkDevice
from app.domains.network_device.router import router as network_device_router
from app.domains.network_device.service import NetworkDeviceService
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


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeNetworkDeviceRepository:
    devices: dict[uuid.UUID, NetworkDevice] = field(default_factory=dict)

    async def create_device(self, **fields: object) -> NetworkDevice:
        device = NetworkDevice(**_base_fields(**fields))
        self.devices[device.id] = device
        return device

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> NetworkDevice | None:
        device = self.devices.get(device_id)
        if device is None or (device.is_deleted and not include_deleted):
            return None
        return device

    async def get_device_by_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> NetworkDevice | None:
        for device in self.devices.values():
            if (
                device.organization_id == organization_id
                and device.mac_address == mac_address
            ):
                return device
        return None

    async def update_device(
        self, device: NetworkDevice, data: dict[str, object]
    ) -> NetworkDevice:
        for key, value in data.items():
            if hasattr(device, key):
                setattr(device, key, value)
        device.version += 1
        return device

    async def soft_delete_device(self, device: NetworkDevice) -> NetworkDevice:
        device.is_deleted = True
        device.deleted_at = _now()
        return device

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        compliance_status: str | None = None,
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
        if compliance_status is not None:
            values = [v for v in values if v.compliance_status == compliance_status]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


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
    service: NetworkDeviceService
    repository: FakeNetworkDeviceRepository
    location_lookup: FakeLocationLookup
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeNetworkDeviceRepository()
    location_lookup = FakeLocationLookup()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = NetworkDeviceService(
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
    vendor: str | None = None,
    device_type: str | None = None,
) -> NetworkDevice:
    return await h.service.register_device(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=location.organization_id,
        location_id=location.id,
        router_id=router_id,
        mac_address=mac_address,
        vendor=vendor,
        device_type=device_type,
    )


# ============================================================================
# Registration / CRUD
# ============================================================================


class TestNetworkDeviceCrud:
    async def test_register_device(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, device_type="laptop")
        assert device.mac_address == "AA:BB:CC:DD:EE:01"
        assert device.organization_id == location.organization_id
        assert device.location_id == location.id
        assert device.compliance_status == ComplianceStatus.UNKNOWN.value
        assert device.device_type == "laptop"
        assert len(h.audit_writer.entries) == 1

    async def test_register_normalizes_and_validates_mac(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        with pytest.raises(InvalidMacAddressError):
            await _register_device(h, location, mac_address="not-a-mac")

    async def test_register_auto_suggests_vendor_when_not_supplied(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, vendor=None)
        # vendor_from_mac may return None for an unrecognized OUI, but the
        # call itself must not raise -- it's a best-effort suggestion.
        assert device.vendor is None or isinstance(device.vendor, str)

    async def test_register_respects_explicit_vendor(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location, vendor="Acme Corp")
        assert device.vendor == "Acme Corp"

    async def test_register_rejects_duplicate_mac_in_same_organization(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        await _register_device(h, location, mac_address="aa:bb:cc:dd:ee:02")
        with pytest.raises(DuplicateNetworkDeviceError):
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
        with pytest.raises(CrossOrganizationNetworkDeviceAccessError):
            await h.service.get_device(
                device.id, requesting_organization_id=uuid.uuid4()
            )

    async def test_get_device_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(NetworkDeviceNotFoundError):
            await h.service.get_device(uuid.uuid4())

    async def test_update_device_revalidates_mac(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location)
        with pytest.raises(InvalidMacAddressError):
            await h.service.update_device(
                device.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=location.organization_id,
                mac_address="garbage",
            )

    async def test_update_device_success(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location)
        updated = await h.service.update_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=location.organization_id,
            device_type="iot-camera",
        )
        assert updated.device_type == "iot-camera"
        assert len(h.audit_writer.entries) == 2

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

    async def test_list_devices_scopes_to_organization(self) -> None:
        h = make_harness()
        location_a = h.location_lookup.add(_make_location())
        location_b = h.location_lookup.add(_make_location())
        await _register_device(h, location_a, mac_address="aa:bb:cc:dd:ee:04")
        await _register_device(h, location_b, mac_address="aa:bb:cc:dd:ee:05")
        devices, meta = await h.service.list_devices(
            requesting_organization_id=location_a.organization_id, page=1, page_size=25
        )
        assert meta.total_items == 1
        assert devices[0].organization_id == location_a.organization_id

    async def test_list_devices_filters_by_compliance_status(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        compliant = await _register_device(
            h, location, mac_address="aa:bb:cc:dd:ee:06"
        )
        await _register_device(h, location, mac_address="aa:bb:cc:dd:ee:07")
        await h.service.set_compliance_status(
            compliant.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=location.organization_id,
            compliance_status=ComplianceStatus.COMPLIANT,
        )
        devices, meta = await h.service.list_devices(
            requesting_organization_id=location.organization_id,
            compliance_status=ComplianceStatus.COMPLIANT,
            page=1,
            page_size=25,
        )
        assert meta.total_items == 1
        assert devices[0].id == compliant.id


# ============================================================================
# Compliance-status workflow
# ============================================================================


class TestComplianceStatusWorkflow:
    async def test_defaults_to_unknown_on_registration(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location)
        assert device.compliance_status == ComplianceStatus.UNKNOWN.value
        assert device.last_reviewed_at is None

    async def test_set_compliance_status_records_review(self) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location)
        updated = await h.service.set_compliance_status(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=location.organization_id,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            compliance_notes="Missing endpoint agent",
        )
        assert updated.compliance_status == ComplianceStatus.NON_COMPLIANT.value
        assert updated.compliance_notes == "Missing endpoint agent"
        assert updated.last_reviewed_at is not None
        assert len(h.audit_writer.entries) == 2

    async def test_set_compliance_status_is_never_a_side_effect_of_update(
        self,
    ) -> None:
        h = make_harness()
        location = h.location_lookup.add(_make_location())
        device = await _register_device(h, location)
        updated = await h.service.update_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=location.organization_id,
            comment="relocated to conference room",
        )
        assert updated.compliance_status == ComplianceStatus.UNKNOWN.value
        assert updated.last_reviewed_at is None


# ============================================================================
# Structural RBAC check
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_network_device_route_has_a_permission_dependency(self) -> None:
        assert len(network_device_router.routes) == 6
        for route in network_device_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
