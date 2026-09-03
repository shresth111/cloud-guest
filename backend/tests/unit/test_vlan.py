"""Unit tests for the VLAN Management domain: VLAN CRUD (tenant
isolation), vlan_id range validation, vlan_id uniqueness per router (on
both create and update), CIDR/gateway IP validation, and a structural RBAC
check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_isp_routing.py``); ``asyncio_mode = "auto"`` runs async
tests directly. ``VlanService`` is exercised against small, hand-rolled
in-memory fakes for its own repository and the composed
``RouterLookupProtocol`` -- mirrors ``test_isp_routing.py``'s own identical
"fake the narrow Protocol boundary" precedent. Device I/O is faked at the
same boundary: ``FakeVlanAdapter`` stands in for the registry lookup
``service`` performs, so the push and delete paths are exercised without a
router. (This paragraph used to say the domain had no device I/O to test
at all; that stopped being true when ``device_adapters.py`` landed, and
the push path went untested for exactly as long.)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router
from app.domains.vlan.constants import VlanDevicePushStatus
from app.domains.vlan.device_adapters import (
    VlanDeviceAddress,
    VlanDeviceInterface,
    VlanNetworkSnapshot,
)
from app.domains.vlan.exceptions import (
    CrossOrganizationVlanAccessError,
    InvalidCidrError,
    InvalidGatewayIpAddressError,
    InvalidVlanIdError,
    VlanAccessPortNotFoundError,
    VlanDeviceConnectionError,
    VlanDeviceOperationError,
    VlanHotspotDhcpPoolConflictError,
    VlanHotspotRequiresSubnetError,
    VlanIdAlreadyExistsError,
    VlanMissingInterfaceError,
    VlanNatRequiresCidrError,
    VlanNotFoundError,
    VlanParentInterfaceNotFoundError,
    VlanSubnetConflictError,
)
from app.domains.vlan.models import Vlan
from app.domains.vlan.router import router as vlan_router
from app.domains.vlan.service import VlanService

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
class FakeVlanRepository:
    vlans: dict[uuid.UUID, Vlan] = field(default_factory=dict)

    async def create_vlan(self, **fields: object) -> Vlan:
        vlan = Vlan(**_base_fields(**fields))
        self.vlans[vlan.id] = vlan
        return vlan

    async def get_vlan_by_id(
        self, vlan_pk: uuid.UUID, *, include_deleted: bool = False
    ) -> Vlan | None:
        vlan = self.vlans.get(vlan_pk)
        if vlan is None or (vlan.is_deleted and not include_deleted):
            return None
        return vlan

    async def get_vlan_by_router_and_tag(
        self, router_id: uuid.UUID, tag: int
    ) -> Vlan | None:
        for vlan in self.vlans.values():
            if (
                vlan.router_id == router_id
                and vlan.vlan_id == tag
                and not vlan.is_deleted
            ):
                return vlan
        return None

    async def update_vlan(self, vlan: Vlan, data: dict[str, object]) -> Vlan:
        for key, value in data.items():
            if hasattr(vlan, key):
                setattr(vlan, key, value)
        vlan.version += 1
        return vlan

    #: Counts the explicit commit push_vlan_to_device issues before
    #: re-raising a device failure -- without it the failure record is
    #: discarded by the session rollback and the row still reads "pending".
    commits: int = 0

    async def commit(self) -> None:
        self.commits += 1

    async def soft_delete_vlan(self, vlan: Vlan) -> Vlan:
        vlan.is_deleted = True
        vlan.deleted_at = _now()
        return vlan

    async def list_vlans(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.vlans.values() if not v.is_deleted]
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if router_id is not None:
            values = [v for v in values if v.router_id == router_id]
        if location_id is not None:
            values = [v for v in values if v.location_id == location_id]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_vlans_for_router(self, router_id: uuid.UUID) -> list[Vlan]:
        return [
            v
            for v in self.vlans.values()
            if v.router_id == router_id and not v.is_deleted
        ]


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


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

    # Really part of the protocol -- the device paths call it. The sentinel
    # lets a test blank it out to exercise the missing-credentials guard.
    secret: str | None = "s3cret"

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secret


# ============================================================================
# Harness
# ============================================================================


@dataclass
class FakeDhcpPool:
    """Only the three fields ``DhcpPoolLookupProtocol`` reads."""

    name: str
    interface: str | None
    is_enabled: bool = True


@dataclass
class FakeDhcpPoolLookup:
    """Stands in for ``app.domains.dhcp.repository.DhcpRepository`` at the
    narrow Protocol boundary the VLAN service composes it through."""

    pools: dict[uuid.UUID, list[FakeDhcpPool]] = field(default_factory=dict)

    async def list_pools_for_router(self, router_id: uuid.UUID) -> list[FakeDhcpPool]:
        return self.pools.get(router_id, [])


@dataclass
class Harness:
    service: VlanService
    repository: FakeVlanRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter
    dhcp_pool_lookup: FakeDhcpPoolLookup


def make_harness() -> Harness:
    repository = FakeVlanRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    dhcp_pool_lookup = FakeDhcpPoolLookup()
    service = VlanService(
        repository,
        router_lookup,
        dhcp_pool_lookup=dhcp_pool_lookup,
        audit_writer=audit_writer,
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
        dhcp_pool_lookup=dhcp_pool_lookup,
    )


async def _create_vlan(
    h: Harness,
    router: Router,
    *,
    vlan_id: int = 100,
    interface: str | None = "bridge",
    port_mode: str = "trunk",
    nat_enabled: bool = False,
    cidr: str | None = "192.168.10.0/24",
) -> Vlan:
    return await h.service.create_vlan(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        vlan_id=vlan_id,
        name="Guest VLAN",
        gateway_ip_address="192.168.10.1",
        cidr=cidr,
        interface=interface,
        port_mode=port_mode,
        nat_enabled=nat_enabled,
    )


# ============================================================================
# VLAN CRUD
# ============================================================================


class TestVlanCrud:
    async def test_create_vlan(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        assert vlan.vlan_id == 100
        assert vlan.organization_id == router.organization_id
        assert vlan.location_id == router.location_id
        assert len(h.audit_writer.entries) == 1

    async def test_create_with_invalid_vlan_id_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidVlanIdError):
            await h.service.create_vlan(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                vlan_id=4095,
                name="Bad VLAN",
            )

    async def test_create_with_invalid_cidr_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidCidrError):
            await h.service.create_vlan(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                vlan_id=100,
                name="Bad VLAN",
                cidr="not-a-cidr",
            )

    async def test_create_with_invalid_gateway_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidGatewayIpAddressError):
            await h.service.create_vlan(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                vlan_id=100,
                name="Bad VLAN",
                gateway_ip_address="bogus",
            )

    async def test_create_duplicate_vlan_id_on_same_router_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_vlan(h, router, vlan_id=100)
        with pytest.raises(VlanIdAlreadyExistsError):
            await _create_vlan(h, router, vlan_id=100)

    async def test_same_vlan_id_on_different_routers_is_allowed(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        vlan_a = await _create_vlan(h, router_a, vlan_id=100)
        vlan_b = await _create_vlan(h, router_b, vlan_id=100)
        assert vlan_a.router_id != vlan_b.router_id
        assert vlan_a.vlan_id == vlan_b.vlan_id == 100

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        with pytest.raises(CrossOrganizationVlanAccessError):
            await h.service.get_vlan(vlan.id, requesting_organization_id=uuid.uuid4())

    async def test_get_missing_vlan_raises(self) -> None:
        h = make_harness()
        with pytest.raises(VlanNotFoundError):
            await h.service.get_vlan(uuid.uuid4())

    async def test_list_vlans_scoped_to_router(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_vlan(h, router_a, vlan_id=100)
        await _create_vlan(h, router_b, vlan_id=200)
        vlans, meta = await h.service.list_vlans(
            requesting_organization_id=router_a.organization_id, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert vlans[0].router_id == router_a.id

    async def test_list_vlans_filters_by_location_id(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_vlan(h, router_a, vlan_id=100)
        await _create_vlan(h, router_b, vlan_id=200)

        vlans, meta = await h.service.list_vlans(
            requesting_organization_id=None, location_id=router_a.location_id
        )

        assert meta.total_items == 1
        assert vlans[0].location_id == router_a.location_id

    async def test_update_name_only(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        updated = await h.service.update_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="Renamed VLAN",
        )
        assert updated.name == "Renamed VLAN"
        assert updated.vlan_id == 100

    async def test_update_to_duplicate_vlan_id_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_vlan(h, router, vlan_id=100)
        second = await _create_vlan(h, router, vlan_id=200)
        with pytest.raises(VlanIdAlreadyExistsError):
            await h.service.update_vlan(
                second.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                vlan_id=100,
            )

    async def test_update_with_invalid_cidr_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        with pytest.raises(InvalidCidrError):
            await h.service.update_vlan(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                cidr="bogus-cidr",
            )

    async def test_delete_soft_deletes(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        deleted = await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True

    async def test_recreate_vlan_id_after_delete_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, vlan_id=100)
        await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        recreated = await _create_vlan(h, router, vlan_id=100)
        assert recreated.vlan_id == 100
        assert recreated.id != vlan.id


# ============================================================================
# list_vlans_for_router -- the real read source Network Configuration
# Management composes to render a router's full VLAN config
# ============================================================================


class TestListVlansForRouter:
    async def test_returns_every_non_deleted_vlan_for_the_router(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        vlan_a = await _create_vlan(h, router, vlan_id=100)
        vlan_b = await _create_vlan(h, router, vlan_id=200)
        await h.service.delete_vlan(
            vlan_b.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        vlans = await h.service.list_vlans_for_router(
            router.id, requesting_organization_id=router.organization_id
        )

        assert [v.id for v in vlans] == [vlan_a.id]

    async def test_raises_for_a_router_outside_the_requesting_organization(
        self,
    ) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        with pytest.raises(RouterNotFoundError):
            await h.service.list_vlans_for_router(
                router.id, requesting_organization_id=uuid.uuid4()
            )


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_vlan_route_has_a_permission_dependency(self) -> None:
        # 7, not 6: GET /vlans/device-interfaces was added to back the VLAN
        # form's own interface picker. The count is asserted on purpose so a
        # new route cannot slip in unguarded -- bump it deliberately, having
        # checked the new route actually carries a permission dependency.
        assert len(vlan_router.routes) == 7
        for route in vlan_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"


# ============================================================================
# Device push and teardown. Neither had a service-level test: the push path
# shipped covered only by the gateway adapter's own tests, and delete never
# touched a device at all.
# ============================================================================


@dataclass
class FakeVlanAdapter:
    """Records what the service actually asked the device to do."""

    vendor: str = "mikrotik"
    calls: list[dict[str, object]] = field(default_factory=list)
    raises: Exception | None = None
    deletes: list[dict[str, object]] = field(default_factory=list)
    delete_raises: Exception | None = None
    nat_calls: list[dict[str, object]] = field(default_factory=list)
    nat_deletes: list[dict[str, object]] = field(default_factory=list)
    nat_raises: Exception | None = None
    hotspot_calls: list[dict[str, object]] = field(default_factory=list)
    hotspot_deletes: list[dict[str, object]] = field(default_factory=list)
    hotspot_raises: Exception | None = None
    #: What the preflight read sees. Defaults to a router carrying every
    #: interface the tests name and no addresses, so a test that is not
    #: about the preflight does not have to describe one.
    snapshot_interfaces: list[str] = field(
        default_factory=lambda: ["bridge", "ether1", "ether2", "ether3"]
    )
    snapshot_addresses: list[tuple] = field(default_factory=list)
    snapshot_raises: Exception | None = None
    snapshot_reads: int = 0

    async def read_network_snapshot(self, credentials) -> VlanNetworkSnapshot:
        self.snapshot_reads += 1
        if self.snapshot_raises is not None:
            raise self.snapshot_raises
        return VlanNetworkSnapshot(
            interfaces=[
                VlanDeviceInterface(
                    name=name,
                    type="ether",
                    running=True,
                    disabled=False,
                    bridge="bridge" if name.startswith("ether") else None,
                    is_bridge_port=name.startswith("ether"),
                    has_ip_address=False,
                )
                for name in self.snapshot_interfaces
            ],
            addresses=[
                # (address, interface) or (address, interface, disabled) --
                # disabled addresses are in no routing table and collide
                # with nothing, which the service relies on.
                VlanDeviceAddress(
                    address=row[0], interface=row[1],
                    disabled=bool(row[2]) if len(row) > 2 else False,
                    # 4th element: RouterOS's `invalid`, set when the
                    # interface this address names no longer exists. Such a
                    # row reserves no subnet.
                    invalid=bool(row[3]) if len(row) > 3 else False,
                )
                for row in self.snapshot_addresses
            ],
        )

    async def configure_hotspot(
        self,
        credentials,
        *,
        vlan_id: int,
        interface: str,
        cidr: str,
        gateway: str,
        dns_name: str,
        html_directory: str,
    ) -> None:
        self.hotspot_calls.append(
            {
                "vlan_id": vlan_id,
                "interface": interface,
                "cidr": cidr,
                "gateway": gateway,
                "dns_name": dns_name,
                "html_directory": html_directory,
            }
        )
        if self.hotspot_raises is not None:
            raise self.hotspot_raises

    async def delete_hotspot(
        self,
        credentials,
        *,
        vlan_id: int,
        interface: str,
        cidr: str,
        gateway: str,
        dns_name: str,
        html_directory: str,
    ) -> None:
        self.hotspot_deletes.append({"vlan_id": vlan_id, "interface": interface})

    async def configure_vlan(
        self,
        credentials,
        *,
        vlan_id: int,
        name: str,
        interface: str,
        ip_cidr: str | None,
        port_mode: str,
    ) -> None:
        self.calls.append(
            {
                "host": credentials.host,
                "vlan_id": vlan_id,
                "interface": interface,
                "ip_cidr": ip_cidr,
                "port_mode": port_mode,
            }
        )
        if self.raises is not None:
            raise self.raises

    async def delete_vlan(
        self,
        credentials,
        *,
        vlan_id: int,
        name: str,
        interface: str,
        ip_cidr: str | None,
        port_mode: str,
        previous_bridge: str | None = None,
    ) -> None:
        self.deletes.append(
            {
                "host": credentials.host,
                "vlan_id": vlan_id,
                "interface": interface,
                "ip_cidr": ip_cidr,
                "port_mode": port_mode,
                # Recorded so a test can assert the port goes back to the
                # bridge an access-mode push took it from.
                "previous_bridge": previous_bridge,
            }
        )
        if self.delete_raises is not None:
            raise self.delete_raises

    async def configure_nat_masquerade(
        self, credentials, *, vlan_id: int, src_cidr: str
    ) -> None:
        self.nat_calls.append(
            {"host": credentials.host, "vlan_id": vlan_id, "src_cidr": src_cidr}
        )
        if self.nat_raises is not None:
            raise self.nat_raises

    async def delete_nat_masquerade(self, credentials, *, vlan_id: int) -> None:
        self.nat_deletes.append({"host": credentials.host, "vlan_id": vlan_id})


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> FakeVlanAdapter:
    """Patched on ``service``'s own reference, not on ``device_adapters``:
    the service imported the name at module load, so patching the source
    module would leave the bound name untouched and the test would silently
    exercise the real adapter."""
    fake = FakeVlanAdapter()
    monkeypatch.setattr(
        "app.domains.vlan.service.get_vlan_adapter", lambda vendor: fake
    )
    return fake


class TestVlanDevicePush:
    async def test_push_sends_the_gateway_address_not_the_network_address(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The router's own address inside the subnet is the gateway.
        Sending ``cidr`` would put the router at ``.0``."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)

        pushed = await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls == [
            {
                "host": "10.0.0.1",
                "vlan_id": 100,
                "interface": "bridge",
                "ip_cidr": "192.168.10.1/24",
                "port_mode": "trunk",
            }
        ]
        assert pushed.device_push_status == VlanDevicePushStatus.ACTIVE.value
        assert pushed.device_push_error is None

    async def test_a_device_failure_is_recorded_committed_and_re_raised(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The commit is the point: ``GenericRepository.update`` only
        flushes and ``get_db_session`` rolls back on any exception, so
        without it the failure record is discarded and the row still reads
        "pending" with a NULL error after a real failure."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        adapter.raises = VlanDeviceOperationError(
            "configure_vlan", "already have such item"
        )

        with pytest.raises(VlanDeviceOperationError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert vlan.device_push_status == VlanDevicePushStatus.FAILED.value
        assert "already have such item" in (vlan.device_push_error or "")
        # Two, not one: the push commits PROVISIONING before it opens a
        # socket and the failure record after. Both have to survive the
        # session rollback -- the first so a concurrent reader sees work in
        # flight rather than the previous outcome, the second so the row
        # does not read "provisioning" forever after a real failure.
        assert h.repository.commits == 2

    async def test_a_vlan_with_no_interface_is_refused_before_connecting(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, interface=None)

        with pytest.raises(VlanMissingInterfaceError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []


class TestVlanDeleteReachesTheDevice:
    """Deleting a VLAN used to soft-delete the row and nothing else, so an
    interface this platform created went on carrying traffic afterwards."""

    async def _pushed_vlan(
        self, h: Harness, router: Router, adapter: FakeVlanAdapter
    ) -> Vlan:
        vlan = await _create_vlan(h, router)
        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        adapter.calls.clear()
        adapter.nat_calls.clear()
        adapter.nat_deletes.clear()
        return vlan

    async def test_deleting_a_pushed_vlan_removes_it_from_the_router(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await self._pushed_vlan(h, router, adapter)

        deleted = await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == [
            {
                "host": "10.0.0.1",
                "vlan_id": 100,
                "interface": "bridge",
                "ip_cidr": "192.168.10.1/24",
                "port_mode": "trunk",
                # A trunk VLAN never took a port, so there is no bridge to
                # give back -- see Vlan.previous_bridge.
                "previous_bridge": None,
            }
        ]
        assert deleted.is_deleted is True

    async def test_a_vlan_that_never_reached_a_device_skips_the_connection(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """Opening a connection to delete nothing would make every such
        delete fail whenever a router happened to be unreachable."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        assert vlan.device_push_status == VlanDevicePushStatus.PENDING.value

        deleted = await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == []
        assert deleted.is_deleted is True

    async def test_a_device_failure_aborts_the_delete_and_keeps_the_row(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """Removing the row while the interface is still live is exactly
        the drift this closes -- the operator would believe it was gone and
        nothing would ever reconcile it."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await self._pushed_vlan(h, router, adapter)
        adapter.delete_raises = VlanDeviceConnectionError("10.0.0.1", "timed out")

        with pytest.raises(VlanDeviceConnectionError):
            await h.service.delete_vlan(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert vlan.is_deleted is False
        assert await h.repository.get_vlan_by_id(vlan.id) is not None


class TestVlanNatIsPartOfThePush:
    """NAT / Internet Access. Without the masquerade rule a pushed VLAN is
    a complete *local* network and nothing more -- its guests get a lease,
    a gateway, and no route off the router, with no error anywhere to say
    so."""

    async def test_nat_is_applied_with_the_vlans_own_subnet(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The source subnet is the VLAN's ``cidr`` -- the network, not the
        ``_device_address`` gateway form the interface gets. Masquerading
        ``192.168.10.1/24`` would name a host where a subnet belongs."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, nat_enabled=True)

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.nat_calls == [
            {"host": "10.0.0.1", "vlan_id": 100, "src_cidr": "192.168.10.0/24"}
        ]
        assert adapter.nat_deletes == []

    async def test_the_service_never_names_a_wan_interface(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """Which port a site's uplink is in is not stored anywhere here.
        The adapter is called with the VLAN and its subnet only, so the
        vendor layer resolves the real WAN from the router itself."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, nat_enabled=True)

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert set(adapter.nat_calls[0]) == {"host", "vlan_id", "src_cidr"}

    async def test_nat_disabled_removes_the_rule_rather_than_doing_nothing(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """This is what makes "turning NAT off removes the rule" true. A
        no-op here would leave the last-pushed rule masquerading a network
        the operator has since decided must not reach the internet -- and
        the push would report success."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, nat_enabled=True)
        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        adapter.nat_calls.clear()

        await h.service.update_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            nat_enabled=False,
        )
        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.nat_calls == []
        assert adapter.nat_deletes == [{"host": "10.0.0.1", "vlan_id": 100}]

    async def test_a_vlan_that_never_wanted_nat_still_pushes_normally(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The removal is idempotent, so it is a harmless no-op on a VLAN
        that never had a rule -- the VLAN itself still reaches the device."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)

        pushed = await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.nat_calls == []
        assert adapter.nat_deletes == [{"host": "10.0.0.1", "vlan_id": 100}]
        assert len(adapter.calls) == 1
        assert pushed.device_push_status == VlanDevicePushStatus.ACTIVE.value

    async def test_nat_without_a_cidr_is_refused_before_connecting(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """NAT is a rule about a source subnet, and this row has none.
        Skipping the NAT step instead would report a successful push for a
        VLAN whose guests still have no internet."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, nat_enabled=True, cidr=None)

        with pytest.raises(VlanNatRequiresCidrError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert adapter.calls == []
        assert adapter.nat_calls == []

    async def test_a_nat_failure_is_recorded_committed_and_re_raised(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The NAT step is inside the same failure-recording block as the
        VLAN write: a push that put the interface up but could not give it
        internet access is a failed push, not a successful one."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, nat_enabled=True)
        adapter.nat_raises = VlanDeviceOperationError(
            "configure_nat_masquerade", "could not determine the WAN interface"
        )

        with pytest.raises(VlanDeviceOperationError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert vlan.device_push_status == VlanDevicePushStatus.FAILED.value
        assert "WAN interface" in (vlan.device_push_error or "")
        # PROVISIONING before the socket, FAILED after -- see
        # test_a_device_failure_is_recorded_committed_and_re_raised.
        assert h.repository.commits == 2

    async def test_deleting_a_vlan_takes_its_nat_rule_off_the_router(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, nat_enabled=True)
        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        adapter.nat_calls.clear()
        adapter.nat_deletes.clear()

        await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.nat_deletes == [{"host": "10.0.0.1", "vlan_id": 100}]
        assert len(adapter.deletes) == 1

    async def test_teardown_removes_nat_even_when_the_flag_is_now_off(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """``nat_enabled`` is current intent; the rule on the device is
        history. A VLAN pushed with NAT on and switched off without a
        re-push still has its rule, and gating the teardown on the flag
        would leave exactly that rule behind."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, nat_enabled=True)
        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        vlan.nat_enabled = False
        adapter.nat_deletes.clear()

        await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.nat_deletes == [{"host": "10.0.0.1", "vlan_id": 100}]

    async def test_nat_comes_off_before_the_interface_it_references(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The exact reverse of the push order: the rule goes while the
        interface it names is still there."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        order: list[str] = []
        vlan = await _create_vlan(h, router, nat_enabled=True)
        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        original_delete_nat = adapter.delete_nat_masquerade
        original_delete_vlan = adapter.delete_vlan

        async def _record_nat(*args: object, **kwargs: object) -> None:
            order.append("nat")
            await original_delete_nat(*args, **kwargs)

        async def _record_vlan(*args: object, **kwargs: object) -> None:
            order.append("vlan")
            await original_delete_vlan(*args, **kwargs)

        adapter.delete_nat_masquerade = _record_nat
        adapter.delete_vlan = _record_vlan

        await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert order == ["nat", "vlan"]

    async def test_a_vlan_that_never_reached_a_device_skips_nat_teardown_too(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """Opening a connection to delete nothing would make every such
        delete fail whenever a router happened to be unreachable."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, nat_enabled=True)

        await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.nat_deletes == []
        assert adapter.deletes == []


# ============================================================================
# Device preflight. Three questions -- is the router reachable, does the
# named interface exist on it, is this subnet already taken -- answered
# from one read, before anything is written.
# ============================================================================


class TestVlanDevicePreflight:
    async def test_a_parent_interface_the_router_does_not_have_is_refused(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, interface="bridgeLocal")
        adapter.snapshot_interfaces = ["bridge", "ether1", "ether2"]

        with pytest.raises(VlanParentInterfaceNotFoundError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_access_mode_gets_its_own_error_for_a_missing_port(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """"There is no such trunk" and "there is no such port on this
        hardware" are different problems with different fixes."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(
            h, router, interface="ether9", port_mode="access"
        )
        adapter.snapshot_interfaces = ["bridge", "ether1", "ether2"]

        with pytest.raises(VlanAccessPortNotFoundError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_a_dead_address_does_not_reserve_a_subnet(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """RouterOS marks an address invalid when the interface it names is
        gone. The lab router held `10.0.0.1/24` on a vanished interface
        `*C`, and every 10.0.0.0/24 VLAN was refused because of it -- a
        permanent rejection naming an interface the operator cannot find,
        over a range nothing was using.
        """
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        adapter.snapshot_interfaces = ["bridge", "ether1", "ether2"]
        adapter.snapshot_addresses = [("192.168.10.9/24", "*C", False, True)]

        pushed = await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert pushed.device_push_status == VlanDevicePushStatus.ACTIVE.value

    async def test_a_live_address_still_reserves_its_subnet(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The exclusion is for dead rows only -- a real overlapping address
        must still refuse, or two matching routes end up on the device."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        adapter.snapshot_interfaces = ["bridge", "ether1", "ether2"]
        adapter.snapshot_addresses = [("192.168.10.9/24", "ether1", False, False)]

        with pytest.raises(VlanSubnetConflictError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

    async def test_an_access_push_records_the_bridge_it_takes_the_port_from(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The incident this closes: an access VLAN took ether2 out of the
        bridge the guest portal is bound to, the access point went dark, and
        the product had no way to put the port back because it had never
        recorded where the port came from. An engineer restored it by hand.
        """
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, interface="ether2", port_mode="access")
        adapter.snapshot_interfaces = ["bridge", "ether1", "ether2"]

        pushed = await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert pushed.previous_bridge == "bridge"

    async def test_deleting_that_vlan_hands_the_recorded_bridge_to_the_device(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, interface="ether2", port_mode="access")
        adapter.snapshot_interfaces = ["bridge", "ether1", "ether2"]
        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        await h.service.delete_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes[-1]["previous_bridge"] == "bridge"

    async def test_a_trunk_push_records_no_previous_bridge(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """A trunk VLAN never takes a port, so there is nothing to give
        back -- and a value here would be a claim about a port this VLAN
        does not own."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, interface="bridge", port_mode="trunk")
        adapter.snapshot_interfaces = ["bridge", "ether1", "ether2"]

        pushed = await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert pushed.previous_bridge is None

    async def test_a_subnet_the_router_already_carries_is_refused(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """Compared against the device's live table, not other VLAN rows:
        the LAN bridge and the uplink have no row in this database, and it
        is the device's set that decides whether the push leaves two
        matching routes."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        adapter.snapshot_addresses = [("192.168.10.1/24", "ether7")]

        with pytest.raises(VlanSubnetConflictError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_a_vlan_does_not_conflict_with_its_own_address(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """Otherwise every re-push of an unchanged VLAN would refuse."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        adapter.snapshot_addresses = [("192.168.10.1/24", "vlan100")]

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert len(adapter.calls) == 1

    async def test_a_disabled_address_collides_with_nothing(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """A disabled address is in no routing table."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)
        adapter.snapshot_addresses = [("192.168.10.1/24", "ether7", True)]

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert len(adapter.calls) == 1

    async def test_the_preflight_costs_one_read_not_three(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """Three separate sessions would triple the wait on a validation
        failure and let the three answers disagree."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert adapter.snapshot_reads == 1


class TestCaptivePortalOnAVlan:
    async def _portal_vlan(self, h: Harness, router: Router) -> Vlan:
        vlan = await _create_vlan(h, router)
        return await h.service.update_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            enable_hotspot=True,
        )

    async def test_enabling_the_portal_pushes_it_to_the_bind_interface(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await self._portal_vlan(h, router)

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert len(adapter.hotspot_calls) == 1
        call = adapter.hotspot_calls[0]
        assert call["vlan_id"] == 100
        assert call["interface"] == "vlan100"
        assert call["gateway"] == "192.168.10.1"

    async def test_turning_the_portal_off_removes_it_rather_than_doing_nothing(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """A no-op would leave the last-pushed portal challenging guests on
        a network the operator has since decided must not have one -- and
        this push would report success."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router)

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.hotspot_calls == []
        assert len(adapter.hotspot_deletes) == 1

    async def test_a_portal_without_a_subnet_is_refused_before_connecting(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """A portal has to hand out addresses and answer DNS on a real
        address of its own."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await _create_vlan(h, router, cidr=None)
        vlan = await h.service.update_vlan(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            enable_hotspot=True,
        )

        with pytest.raises(VlanHotspotRequiresSubnetError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_a_portal_is_refused_when_a_dhcp_pool_already_serves_that_interface(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """Both features create an /ip dhcp-server, RouterOS permits one
        per interface, and a portal cannot go without. Refused from a
        database read, so it arrives before any connection rather than as
        an opaque device error halfway through a partial portal."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await self._portal_vlan(h, router)
        h.dhcp_pool_lookup.pools[router.id] = [
            FakeDhcpPool(name="Guest addresses", interface="vlan100")
        ]

        with pytest.raises(VlanHotspotDhcpPoolConflictError):
            await h.service.push_vlan_to_device(
                vlan.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []
        assert adapter.hotspot_calls == []

    async def test_a_disabled_pool_does_not_block_the_portal(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """A disabled pool row is intent this platform has not realized and
        will not realize, so it occupies no interface on the device."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await self._portal_vlan(h, router)
        h.dhcp_pool_lookup.pools[router.id] = [
            FakeDhcpPool(name="Off", interface="vlan100", is_enabled=False)
        ]

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert len(adapter.hotspot_calls) == 1

    async def test_a_pool_on_a_different_interface_does_not_block_the_portal(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        vlan = await self._portal_vlan(h, router)
        h.dhcp_pool_lookup.pools[router.id] = [
            FakeDhcpPool(name="Other", interface="vlan999")
        ]

        await h.service.push_vlan_to_device(
            vlan.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert len(adapter.hotspot_calls) == 1


class TestDeviceInterfacePicker:
    """`GET /vlans/device-interfaces`. An empty list has three different
    meanings and a picker that renders the same empty dropdown for all
    three teaches an operator the feature is broken -- so the method
    returns the sentence with the list."""

    async def test_it_returns_what_the_router_actually_has(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.snapshot_interfaces = ["bridge", "ether2", "ether3"]

        interfaces, message = await h.service.list_device_interfaces(
            router.id, requesting_organization_id=router.organization_id
        )

        assert [i.name for i in interfaces] == ["bridge", "ether2", "ether3"]
        assert message

    async def test_bridge_is_offered_unlike_the_router_domains_endpoint(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """`/routers/{id}/device-interfaces` drops every interface bound to
        an `/ip dhcp-server`, which on a real router removes `bridge` --
        confirmed on the lab device, where it was simply absent. `bridge`
        is the interface customers most need as a trunk parent."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.snapshot_interfaces = ["bridge", "ether2"]

        interfaces, _ = await h.service.list_device_interfaces(
            router.id, requesting_organization_id=router.organization_id
        )

        assert "bridge" in {i.name for i in interfaces}

    async def test_is_bridge_port_is_carried_through(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The form filters access-mode candidates on this. Deriving it
        from `bridge` being non-null is a convention a picker should not
        have to know."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.snapshot_interfaces = ["bridge", "ether2"]

        interfaces, _ = await h.service.list_device_interfaces(
            router.id, requesting_organization_id=router.organization_id
        )

        by_name = {i.name: i for i in interfaces}
        assert by_name["ether2"].is_bridge_port is True
        assert by_name["bridge"].is_bridge_port is False

    async def test_an_unreachable_router_is_an_empty_list_not_an_error(
        self, adapter: FakeVlanAdapter
    ) -> None:
        """The form is being filled in. Refusing to render it because a
        device is momentarily unreachable helps nobody, and the push path
        is where unreachability has to be fatal."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.snapshot_raises = VlanDeviceConnectionError("10.0.0.1", "timed out")

        interfaces, message = await h.service.list_device_interfaces(
            router.id, requesting_organization_id=router.organization_id
        )

        assert interfaces == []
        assert message  # says why, rather than an empty dropdown

    async def test_a_router_with_no_credentials_is_also_an_empty_list(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.router_lookup.secret = None

        interfaces, message = await h.service.list_device_interfaces(
            router.id, requesting_organization_id=router.organization_id
        )

        assert interfaces == []
        assert message

    async def test_another_organizations_router_is_not_readable(
        self, adapter: FakeVlanAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        with pytest.raises(RouterNotFoundError):
            await h.service.list_device_interfaces(
                router.id, requesting_organization_id=uuid.uuid4()
            )
