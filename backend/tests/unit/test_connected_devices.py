"""Unit tests for the Connected Device Management domain: real per-router
sync (device discovery merge, vendor lookup, existing-device updates,
marking a dropped-off device inactive), tenant isolation, admin actions
(disconnect/comment/delete/block/unblock/whitelist -- the latter three
composing a fake ``GuestAccessProtocol``), the read-only guest/session
association cross-reference (composing a fake ``GuestLookupProtocol``),
the platform-wide sync sweep's per-router failure isolation, and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_isp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``ConnectedDeviceService`` is exercised against small,
hand-rolled in-memory fakes for its own repository and every composed
cross-domain protocol (``RouterLookupProtocol``/``GuestAccessProtocol``/
``GuestLookupProtocol``) and a controllable fake device adapter --
mirrors ``test_isp.py``'s own identical "fake the narrow Protocol
boundary" precedent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.connected_devices.constants import ConnectionType
from app.domains.connected_devices.device_adapters import DiscoveredDevice
from app.domains.connected_devices.exceptions import (
    ConnectedDeviceMissingCredentialsError,
    ConnectedDeviceNotFoundError,
    CrossOrganizationConnectedDeviceAccessError,
)
from app.domains.connected_devices.models import ConnectedDevice
from app.domains.connected_devices.router import router as connected_devices_router
from app.domains.connected_devices.service import (
    ConnectedDeviceService,
    DeviceSyncSweepSummary,
    run_device_sync_sweep,
)
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
class FakeConnectedDeviceRepository:
    devices: dict[uuid.UUID, ConnectedDevice] = field(default_factory=dict)
    routers: list[Router] = field(default_factory=list)

    async def create_device(self, **fields: object) -> ConnectedDevice:
        device = ConnectedDevice(**_base_fields(**fields))
        self.devices[device.id] = device
        return device

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ConnectedDevice | None:
        device = self.devices.get(device_id)
        if device is None or (device.is_deleted and not include_deleted):
            return None
        return device

    async def get_device_by_router_and_mac(
        self, router_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None:
        for device in self.devices.values():
            if device.router_id == router_id and device.mac_address == mac_address:
                return device
        return None

    async def update_device(
        self, device: ConnectedDevice, data: dict[str, object]
    ) -> ConnectedDevice:
        for key, value in data.items():
            if hasattr(device, key):
                setattr(device, key, value)
        device.version += 1
        return device

    async def soft_delete_device(self, device: ConnectedDevice) -> ConnectedDevice:
        device.is_deleted = True
        device.deleted_at = _now()
        return device

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.devices.values() if not v.is_deleted]
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if router_id is not None:
            values = [v for v in values if v.router_id == router_id]
        if location_id is not None:
            values = [v for v in values if v.location_id == location_id]
        if is_active is not None:
            values = [v for v in values if v.is_active == is_active]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_devices_for_router(
        self, router_id: uuid.UUID
    ) -> list[ConnectedDevice]:
        return [
            v
            for v in self.devices.values()
            if v.router_id == router_id and not v.is_deleted
        ]

    async def list_routers_for_sync(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[Router]:
        if organization_id is not None:
            return [r for r in self.routers if r.organization_id == organization_id]
        return list(self.routers)


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    secrets: dict[uuid.UUID, str | None] = field(default_factory=dict)
    fail_router_ids: set = field(default_factory=set)

    def add(self, router: Router, *, secret: str | None = "decrypted-secret") -> Router:
        self.routers[router.id] = router
        self.secrets[router.id] = secret
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        if router_id in self.fail_router_ids:
            raise RouterNotFoundError(router_id)
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        if (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secrets.get(router.id)


@dataclass
class FakeDeviceRule:
    id: uuid.UUID
    mac_address: str
    rule_type: str
    is_active: bool = True


@dataclass
class FakeDeviceRuleListResult:
    items: list[FakeDeviceRule]


@dataclass
class FakeGuestAccessService:
    rules: list[FakeDeviceRule] = field(default_factory=list)
    created_calls: list[dict[str, object]] = field(default_factory=list)
    deactivated_ids: list[uuid.UUID] = field(default_factory=list)

    async def create_device_rule(self, **fields: object) -> FakeDeviceRule:
        self.created_calls.append(fields)
        rule = FakeDeviceRule(
            id=uuid.uuid4(),
            mac_address=fields["mac_address"],
            rule_type=fields["rule_type"],
        )
        self.rules.append(rule)
        return rule

    async def list_device_rules(self, **fields: object) -> FakeDeviceRuleListResult:
        mac_address = fields.get("mac_address")
        rule_type = fields.get("rule_type")
        matching = [
            r
            for r in self.rules
            if r.is_active
            and (mac_address is None or r.mac_address == mac_address)
            and (rule_type is None or r.rule_type == rule_type)
        ]
        return FakeDeviceRuleListResult(items=matching)

    async def deactivate_device_rule(self, **fields: object) -> FakeDeviceRule:
        rule_id = fields["rule_id"]
        self.deactivated_ids.append(rule_id)
        rule = next(r for r in self.rules if r.id == rule_id)
        rule.is_active = False
        return rule


@dataclass
class FakeGuestDevice:
    id: uuid.UUID
    guest_id: uuid.UUID


@dataclass
class FakeGuestSession:
    id: uuid.UUID
    device_id: uuid.UUID
    router_id: uuid.UUID


@dataclass
class FakeGuestLookup:
    devices_by_mac: dict[str, FakeGuestDevice] = field(default_factory=dict)
    sessions_by_guest: dict[uuid.UUID, list[FakeGuestSession]] = field(
        default_factory=dict
    )

    async def get_device_by_mac(self, mac_address: str) -> FakeGuestDevice | None:
        return self.devices_by_mac.get(mac_address)

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[FakeGuestSession]:
        return self.sessions_by_guest.get(guest_id, [])


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeConnectedDeviceAdapter:
    vendor: str = "mikrotik"
    discovered: list[DiscoveredDevice] = field(default_factory=list)
    disconnect_calls: list[dict[str, object]] = field(default_factory=list)

    async def discover_devices(self, credentials) -> list[DiscoveredDevice]:
        return self.discovered

    async def disconnect_device(self, credentials, *, mac_address, interface) -> None:
        self.disconnect_calls.append(
            {"mac_address": mac_address, "interface": interface}
        )


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: ConnectedDeviceService
    repository: FakeConnectedDeviceRepository
    router_lookup: FakeRouterLookup
    guest_access: FakeGuestAccessService
    guest_lookup: FakeGuestLookup
    audit_writer: FakeAuditLogWriter
    adapter: FakeConnectedDeviceAdapter


def make_harness(*, adapter: FakeConnectedDeviceAdapter | None = None) -> Harness:
    repository = FakeConnectedDeviceRepository()
    router_lookup = FakeRouterLookup()
    guest_access = FakeGuestAccessService()
    guest_lookup = FakeGuestLookup()
    audit_writer = FakeAuditLogWriter()
    device_adapter = adapter or FakeConnectedDeviceAdapter()
    service = ConnectedDeviceService(
        repository,
        router_lookup,
        guest_access,
        guest_lookup,
        audit_writer=audit_writer,
        device_adapter_resolver=lambda vendor: device_adapter,
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        guest_access=guest_access,
        guest_lookup=guest_lookup,
        audit_writer=audit_writer,
        adapter=device_adapter,
    )


# ============================================================================
# Sync
# ============================================================================


class TestSyncRouter:
    async def test_discovers_new_devices_with_vendor_lookup(self) -> None:
        adapter = FakeConnectedDeviceAdapter(
            discovered=[
                DiscoveredDevice(
                    mac_address="B8:27:EB:11:22:33",
                    ip_address="192.168.1.10",
                    hostname="pi-device",
                    interface="ether2",
                    is_wireless=False,
                    signal_strength_dbm=None,
                ),
                DiscoveredDevice(
                    mac_address="AA:BB:CC:DD:EE:01",
                    ip_address="192.168.1.20",
                    hostname="phone",
                    interface="wlan1",
                    is_wireless=True,
                    signal_strength_dbm=-55,
                ),
            ]
        )
        h = make_harness(adapter=adapter)
        router = h.router_lookup.add(_make_router())
        summary = await h.service.sync_router(router.id)
        assert summary.discovered == 2
        assert summary.updated == 0
        assert summary.disconnected == 0

        devices, meta = await h.service.list_devices(
            requesting_organization_id=router.organization_id
        )
        assert meta.total_items == 2
        pi_device = next(d for d in devices if d.mac_address == "B8:27:EB:11:22:33")
        assert pi_device.vendor == "Raspberry Pi Foundation"
        assert pi_device.connection_type == ConnectionType.WIRED.value
        wireless_device = next(
            d for d in devices if d.mac_address == "AA:BB:CC:DD:EE:01"
        )
        assert wireless_device.connection_type == ConnectionType.WIRELESS.value
        assert wireless_device.signal_strength_dbm == -55
        assert wireless_device.vendor is None

    async def test_second_sync_updates_existing_and_marks_dropped_device_inactive(
        self,
    ) -> None:
        adapter = FakeConnectedDeviceAdapter(
            discovered=[
                DiscoveredDevice(
                    mac_address="AA:BB:CC:DD:EE:01",
                    ip_address="192.168.1.20",
                    hostname="phone",
                    interface="wlan1",
                    is_wireless=True,
                    signal_strength_dbm=-55,
                ),
                DiscoveredDevice(
                    mac_address="AA:BB:CC:DD:EE:02",
                    ip_address="192.168.1.30",
                    hostname="laptop",
                    interface="ether2",
                    is_wireless=False,
                    signal_strength_dbm=None,
                ),
            ]
        )
        h = make_harness(adapter=adapter)
        router = h.router_lookup.add(_make_router())
        await h.service.sync_router(router.id)

        # Second sync: laptop drops off, phone's IP changes.
        adapter.discovered = [
            DiscoveredDevice(
                mac_address="AA:BB:CC:DD:EE:01",
                ip_address="192.168.1.99",
                hostname="phone",
                interface="wlan1",
                is_wireless=True,
                signal_strength_dbm=-60,
            ),
        ]
        summary = await h.service.sync_router(router.id)
        assert summary.updated == 1
        assert summary.disconnected == 1

        devices, _ = await h.service.list_devices(
            requesting_organization_id=router.organization_id
        )
        phone = next(d for d in devices if d.mac_address == "AA:BB:CC:DD:EE:01")
        assert phone.ip_address == "192.168.1.99"
        assert phone.is_active is True
        laptop = next(d for d in devices if d.mac_address == "AA:BB:CC:DD:EE:02")
        assert laptop.is_active is False

    async def test_missing_credentials_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router(), secret=None)
        with pytest.raises(ConnectedDeviceMissingCredentialsError):
            await h.service.sync_router(router.id)

    async def test_resolves_guest_and_session_association(self) -> None:
        adapter = FakeConnectedDeviceAdapter(
            discovered=[
                DiscoveredDevice(
                    mac_address="AA:BB:CC:DD:EE:05",
                    ip_address="192.168.1.50",
                    hostname="guest-phone",
                    interface="wlan1",
                    is_wireless=True,
                    signal_strength_dbm=-50,
                )
            ]
        )
        h = make_harness(adapter=adapter)
        router = h.router_lookup.add(_make_router())
        guest_id = uuid.uuid4()
        guest_device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        h.guest_lookup.devices_by_mac["AA:BB:CC:DD:EE:05"] = FakeGuestDevice(
            id=guest_device_id, guest_id=guest_id
        )
        h.guest_lookup.sessions_by_guest[guest_id] = [
            FakeGuestSession(
                id=session_id, device_id=guest_device_id, router_id=router.id
            )
        ]
        await h.service.sync_router(router.id)
        devices, _ = await h.service.list_devices(
            requesting_organization_id=router.organization_id
        )
        device = devices[0]
        assert device.guest_id == guest_id
        assert device.guest_session_id == session_id

    async def test_no_guest_association_when_mac_unknown(self) -> None:
        adapter = FakeConnectedDeviceAdapter(
            discovered=[
                DiscoveredDevice(
                    mac_address="AA:BB:CC:DD:EE:06",
                    ip_address="192.168.1.60",
                    hostname=None,
                    interface="ether2",
                    is_wireless=False,
                    signal_strength_dbm=None,
                )
            ]
        )
        h = make_harness(adapter=adapter)
        router = h.router_lookup.add(_make_router())
        await h.service.sync_router(router.id)
        devices, _ = await h.service.list_devices(
            requesting_organization_id=router.organization_id
        )
        assert devices[0].guest_id is None
        assert devices[0].guest_session_id is None


# ============================================================================
# Admin actions
# ============================================================================


class TestAdminActions:
    async def test_disconnect_device_calls_adapter_and_marks_inactive(self) -> None:
        adapter = FakeConnectedDeviceAdapter(
            discovered=[
                DiscoveredDevice(
                    mac_address="AA:BB:CC:DD:EE:07",
                    ip_address="192.168.1.70",
                    hostname=None,
                    interface="ether2",
                    is_wireless=False,
                    signal_strength_dbm=None,
                )
            ]
        )
        h = make_harness(adapter=adapter)
        router = h.router_lookup.add(_make_router())
        await h.service.sync_router(router.id)
        devices, _ = await h.service.list_devices(
            requesting_organization_id=router.organization_id
        )
        device = devices[0]
        updated = await h.service.disconnect_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert updated.is_active is False
        assert len(adapter.disconnect_calls) == 1
        assert adapter.disconnect_calls[0]["mac_address"] == "AA:BB:CC:DD:EE:07"
        assert len(h.audit_writer.entries) == 1

    async def test_add_comment(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        device = await h.repository.create_device(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            mac_address="AA:BB:CC:DD:EE:08",
            ip_address=None,
            hostname=None,
            vendor=None,
            connection_type=ConnectionType.UNKNOWN.value,
            interface=None,
            signal_strength_dbm=None,
            is_active=True,
            connected_at=_now(),
            last_seen_at=_now(),
            guest_id=None,
            guest_session_id=None,
        )
        updated = await h.service.add_comment(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            comment="Front desk laptop",
        )
        assert updated.comment == "Front desk laptop"
        assert len(h.audit_writer.entries) == 1

    async def test_delete_device_soft_deletes(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        device = await h.repository.create_device(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            mac_address="AA:BB:CC:DD:EE:09",
            ip_address=None,
            hostname=None,
            vendor=None,
            connection_type=ConnectionType.UNKNOWN.value,
            interface=None,
            signal_strength_dbm=None,
            is_active=True,
            connected_at=_now(),
            last_seen_at=_now(),
            guest_id=None,
            guest_session_id=None,
        )
        deleted = await h.service.delete_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        device = await h.repository.create_device(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            mac_address="AA:BB:CC:DD:EE:10",
            ip_address=None,
            hostname=None,
            vendor=None,
            connection_type=ConnectionType.UNKNOWN.value,
            interface=None,
            signal_strength_dbm=None,
            is_active=True,
            connected_at=_now(),
            last_seen_at=_now(),
            guest_id=None,
            guest_session_id=None,
        )
        with pytest.raises(CrossOrganizationConnectedDeviceAccessError):
            await h.service.get_device(
                device.id, requesting_organization_id=uuid.uuid4()
            )

    async def test_get_missing_device_raises(self) -> None:
        h = make_harness()
        with pytest.raises(ConnectedDeviceNotFoundError):
            await h.service.get_device(uuid.uuid4())


# ============================================================================
# location_id filter (Enterprise SaaS Phase E)
# ============================================================================


class TestListDevicesLocationFilter:
    async def test_list_devices_filters_by_location_id(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        other_location_id = uuid.uuid4()
        await h.repository.create_device(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            mac_address="AA:BB:CC:DD:EE:21",
            ip_address=None,
            hostname=None,
            vendor=None,
            connection_type=ConnectionType.UNKNOWN.value,
            interface=None,
            signal_strength_dbm=None,
            is_active=True,
            connected_at=_now(),
            last_seen_at=_now(),
            guest_id=None,
            guest_session_id=None,
        )
        await h.repository.create_device(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=other_location_id,
            mac_address="AA:BB:CC:DD:EE:22",
            ip_address=None,
            hostname=None,
            vendor=None,
            connection_type=ConnectionType.UNKNOWN.value,
            interface=None,
            signal_strength_dbm=None,
            is_active=True,
            connected_at=_now(),
            last_seen_at=_now(),
            guest_id=None,
            guest_session_id=None,
        )

        devices, meta = await h.service.list_devices(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
        )

        assert meta.total_items == 1
        assert devices[0].location_id == router.location_id


# ============================================================================
# Block / unblock / whitelist (composing GuestAccessProtocol)
# ============================================================================


class TestAccessRuleActions:
    async def _make_device(self, h: Harness, router: Router) -> ConnectedDevice:
        return await h.repository.create_device(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            mac_address="AA:BB:CC:DD:EE:11",
            ip_address=None,
            hostname=None,
            vendor=None,
            connection_type=ConnectionType.UNKNOWN.value,
            interface=None,
            signal_strength_dbm=None,
            is_active=True,
            connected_at=_now(),
            last_seen_at=_now(),
            guest_id=None,
            guest_session_id=None,
        )

    async def test_block_device_creates_blocklist_rule(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        device = await self._make_device(h, router)
        await h.service.block_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            reason="abuse",
        )
        assert len(h.guest_access.created_calls) == 1
        assert h.guest_access.created_calls[0]["rule_type"] == "blocklist"
        assert h.guest_access.created_calls[0]["mac_address"] == "AA:BB:CC:DD:EE:11"
        assert len(h.audit_writer.entries) == 1

    async def test_whitelist_device_creates_whitelist_rule(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        device = await self._make_device(h, router)
        await h.service.whitelist_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert h.guest_access.created_calls[0]["rule_type"] == "whitelist"

    async def test_unblock_device_deactivates_matching_blocklist_rules(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        device = await self._make_device(h, router)
        await h.service.block_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert len(h.guest_access.rules) == 1
        await h.service.unblock_device(
            device.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert len(h.guest_access.deactivated_ids) == 1
        assert h.guest_access.rules[0].is_active is False


# ============================================================================
# Platform-wide sync sweep: per-router failure isolation
# ============================================================================


class TestSyncSweep:
    async def test_sweep_isolates_per_router_failures(self) -> None:
        repository = FakeConnectedDeviceRepository()
        router_lookup = FakeRouterLookup()
        guest_access = FakeGuestAccessService()
        guest_lookup = FakeGuestLookup()
        audit_writer = FakeAuditLogWriter()

        good_router = router_lookup.add(_make_router())
        bad_router = router_lookup.add(_make_router())
        repository.routers = [good_router, bad_router]
        router_lookup.fail_router_ids = {bad_router.id}

        adapter = FakeConnectedDeviceAdapter(
            discovered=[
                DiscoveredDevice(
                    mac_address="AA:BB:CC:DD:EE:12",
                    ip_address="192.168.1.80",
                    hostname=None,
                    interface="ether2",
                    is_wireless=False,
                    signal_strength_dbm=None,
                )
            ]
        )
        summary = await run_device_sync_sweep(
            repository,
            router_lookup,
            guest_access,
            guest_lookup,
            audit_writer=audit_writer,
            device_adapter_resolver=lambda vendor: adapter,
        )
        assert isinstance(summary, DeviceSyncSweepSummary)
        assert summary.routers_synced == 1
        assert summary.routers_failed == 1
        assert summary.discovered == 1


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_connected_devices_route_has_a_permission_dependency(self) -> None:
        assert len(connected_devices_router.routes) == 10
        for route in connected_devices_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
