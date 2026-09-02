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
from app.domains.vlan.exceptions import (
    CrossOrganizationVlanAccessError,
    InvalidCidrError,
    InvalidGatewayIpAddressError,
    InvalidVlanIdError,
    VlanDeviceConnectionError,
    VlanDeviceOperationError,
    VlanIdAlreadyExistsError,
    VlanMissingInterfaceError,
    VlanNotFoundError,
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
class Harness:
    service: VlanService
    repository: FakeVlanRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeVlanRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = VlanService(repository, router_lookup, audit_writer=audit_writer)
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
    )


async def _create_vlan(
    h: Harness,
    router: Router,
    *,
    vlan_id: int = 100,
    interface: str | None = "bridge",
    port_mode: str = "trunk",
) -> Vlan:
    return await h.service.create_vlan(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        vlan_id=vlan_id,
        name="Guest VLAN",
        gateway_ip_address="192.168.10.1",
        cidr="192.168.10.0/24",
        interface=interface,
        port_mode=port_mode,
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
        # 6, not 5: POST /vlans/{vlan_pk}/push was added when this domain
        # gained a real device push. The count is asserted on purpose so a
        # new route cannot slip in unguarded -- bump it deliberately, having
        # checked the new route actually carries a permission dependency.
        assert len(vlan_router.routes) == 6
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
    ) -> None:
        self.deletes.append(
            {
                "host": credentials.host,
                "vlan_id": vlan_id,
                "interface": interface,
                "ip_cidr": ip_cidr,
                "port_mode": port_mode,
            }
        )
        if self.delete_raises is not None:
            raise self.delete_raises


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
        assert h.repository.commits == 1

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
