"""Unit tests for the DHCP Pool Management domain: pool CRUD (tenant
isolation), address-range validation (ordering, IP parseability),
gateway/DNS IP validation, range-conflict detection (overlap rejected on
the same router+interface, allowed across different interfaces or
different routers, re-checked on update excluding the pool itself), and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_vlan.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``DhcpService`` is exercised against small, hand-rolled
in-memory fakes for its own repository and the composed
``RouterLookupProtocol`` -- mirrors ``test_vlan.py``'s own identical "fake
the narrow Protocol boundary" precedent. This domain has no device I/O to
test (see ``service.py``'s own module docstring -- a pure rules/inventory
domain, no ``device_adapters.py`` in this pass).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.dhcp.constants import DhcpDevicePushStatus
from app.domains.dhcp.exceptions import (
    CrossOrganizationDhcpPoolAccessError,
    DhcpDeviceConnectionError,
    DhcpDeviceOperationError,
    DhcpMissingCredentialsError,
    DhcpPoolMissingGatewayError,
    DhcpPoolMissingInterfaceError,
    DhcpPoolNotEnabledError,
    DhcpPoolNotFoundError,
    DhcpPoolRangeConflictError,
    InvalidAddressRangeError,
    InvalidIpAddressError,
    UnsupportedDhcpVendorError,
)
from app.domains.dhcp.models import DhcpPool
from app.domains.dhcp.router import router as dhcp_router
from app.domains.dhcp.service import DhcpService
from app.domains.rbac.enums import AuditAction
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
class FakeDhcpRepository:
    pools: dict[uuid.UUID, DhcpPool] = field(default_factory=dict)

    async def create_pool(self, **fields: object) -> DhcpPool:
        pool = DhcpPool(**_base_fields(**fields))
        self.pools[pool.id] = pool
        return pool

    async def get_pool_by_id(
        self, pool_id: uuid.UUID, *, include_deleted: bool = False
    ) -> DhcpPool | None:
        pool = self.pools.get(pool_id)
        if pool is None or (pool.is_deleted and not include_deleted):
            return None
        return pool

    async def update_pool(self, pool: DhcpPool, data: dict[str, object]) -> DhcpPool:
        for key, value in data.items():
            if hasattr(pool, key):
                setattr(pool, key, value)
        pool.version += 1
        return pool

    async def soft_delete_pool(self, pool: DhcpPool) -> DhcpPool:
        pool.is_deleted = True
        pool.deleted_at = _now()
        return pool

    #: Counts the explicit commit ``push_pool_to_device`` issues before
    #: re-raising a device failure. Without it the failure record is
    #: discarded by the session rollback and the row still reads "pending".
    commits: int = 0

    async def commit(self) -> None:
        self.commits += 1

    async def list_pools(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.pools.values() if not v.is_deleted]
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if router_id is not None:
            values = [v for v in values if v.router_id == router_id]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_pools_for_router(self, router_id: uuid.UUID) -> list[DhcpPool]:
        return [
            v
            for v in self.pools.values()
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

    # Really part of the protocol -- the device-push path calls it. The
    # sentinel lets a test blank it out to exercise the missing-credentials
    # guard without hand-building a half-populated Router.
    secret: str | None = "s3cret"

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secret


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: DhcpService
    repository: FakeDhcpRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeDhcpRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = DhcpService(repository, router_lookup, audit_writer=audit_writer)
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
    )


async def _create_pool(
    h: Harness,
    router: Router,
    *,
    start: str = "192.168.10.10",
    end: str = "192.168.10.100",
    interface: str | None = "ether2",
) -> DhcpPool:
    return await h.service.create_pool(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name="Guest Pool",
        address_range_start=start,
        address_range_end=end,
        interface=interface,
        gateway_ip_address="192.168.10.1",
        dns_primary="8.8.8.8",
    )


# ============================================================================
# Pool CRUD
# ============================================================================


class TestDhcpPoolCrud:
    async def test_create_pool(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        assert pool.address_range_start == "192.168.10.10"
        assert pool.organization_id == router.organization_id
        assert pool.location_id == router.location_id
        assert len(h.audit_writer.entries) == 1

    async def test_create_with_reversed_range_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidAddressRangeError):
            await _create_pool(h, router, start="192.168.10.100", end="192.168.10.10")

    async def test_create_with_unparsable_range_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidAddressRangeError):
            await _create_pool(h, router, start="bogus", end="192.168.10.10")

    async def test_create_with_invalid_gateway_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidIpAddressError):
            await h.service.create_pool(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                name="Bad Pool",
                address_range_start="192.168.10.10",
                address_range_end="192.168.10.100",
                gateway_ip_address="bogus",
            )

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        with pytest.raises(CrossOrganizationDhcpPoolAccessError):
            await h.service.get_pool(pool.id, requesting_organization_id=uuid.uuid4())

    async def test_get_missing_pool_raises(self) -> None:
        h = make_harness()
        with pytest.raises(DhcpPoolNotFoundError):
            await h.service.get_pool(uuid.uuid4())

    async def test_list_pools_scoped_to_router(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_pool(h, router_a, interface="ether2")
        await _create_pool(h, router_b, interface="ether3")
        pools, meta = await h.service.list_pools(
            requesting_organization_id=router_a.organization_id, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert pools[0].router_id == router_a.id

    async def test_delete_soft_deletes(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        deleted = await h.service.delete_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True


# ============================================================================
# Range conflict detection
# ============================================================================


class TestDhcpPoolRangeConflict:
    async def test_overlapping_range_on_same_interface_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_pool(
            h, router, start="192.168.10.10", end="192.168.10.100", interface="ether2"
        )
        with pytest.raises(DhcpPoolRangeConflictError):
            await _create_pool(
                h,
                router,
                start="192.168.10.50",
                end="192.168.10.150",
                interface="ether2",
            )

    async def test_non_overlapping_range_on_same_interface_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_pool(
            h, router, start="192.168.10.10", end="192.168.10.100", interface="ether2"
        )
        second = await _create_pool(
            h, router, start="192.168.10.101", end="192.168.10.200", interface="ether2"
        )
        assert second.address_range_start == "192.168.10.101"

    async def test_overlapping_range_on_different_interface_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_pool(
            h, router, start="192.168.10.10", end="192.168.10.100", interface="ether2"
        )
        second = await _create_pool(
            h, router, start="192.168.10.10", end="192.168.10.100", interface="ether3"
        )
        assert second.interface == "ether3"

    async def test_overlapping_range_on_different_router_is_allowed(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_pool(
            h, router_a, start="192.168.10.10", end="192.168.10.100", interface="ether2"
        )
        second = await _create_pool(
            h, router_b, start="192.168.10.10", end="192.168.10.100", interface="ether2"
        )
        assert second.router_id == router_b.id

    async def test_update_range_rechecks_conflict_excluding_self(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(
            h, router, start="192.168.10.10", end="192.168.10.100", interface="ether2"
        )
        # Updating the pool's own range to itself (no real change) must
        # not conflict against itself.
        updated = await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            address_range_start="192.168.10.20",
            address_range_end="192.168.10.90",
        )
        assert updated.address_range_start == "192.168.10.20"

    async def test_update_range_to_overlap_another_pool_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_pool(
            h, router, start="192.168.10.10", end="192.168.10.100", interface="ether2"
        )
        second = await _create_pool(
            h, router, start="192.168.10.101", end="192.168.10.200", interface="ether2"
        )
        with pytest.raises(DhcpPoolRangeConflictError):
            await h.service.update_pool(
                second.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                address_range_start="192.168.10.50",
            )


# ============================================================================
# list_pools_for_router -- the real read source Network Configuration
# Management composes to render a router's full DHCP config
# ============================================================================


class TestListPoolsForRouter:
    async def test_returns_every_non_deleted_pool_for_the_router(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        pool_a = await _create_pool(h, router, interface="ether2")
        pool_b = await _create_pool(h, router, start="10.0.0.10", end="10.0.0.50")
        await h.service.delete_pool(
            pool_b.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        pools = await h.service.list_pools_for_router(
            router.id, requesting_organization_id=router.organization_id
        )

        assert [p.id for p in pools] == [pool_a.id]

    async def test_raises_for_a_router_outside_the_requesting_organization(
        self,
    ) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        with pytest.raises(RouterNotFoundError):
            await h.service.list_pools_for_router(
                router.id, requesting_organization_id=uuid.uuid4()
            )


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_dhcp_route_has_a_permission_dependency(self) -> None:
        assert len(dhcp_router.routes) == 6
        for route in dhcp_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"


# ============================================================================
# Device push -- the piece this domain never had. Creating a pool wrote a
# row and contacted nothing, so a guest joining the network got no address.
# ============================================================================


@dataclass
class FakeDhcpAdapter:
    """Records what the service actually asked the device to do."""

    vendor: str = "mikrotik"
    calls: list[dict[str, object]] = field(default_factory=list)
    raises: Exception | None = None
    deletes: list[dict[str, object]] = field(default_factory=list)
    delete_raises: Exception | None = None

    async def delete_dhcp_pool(
        self,
        credentials,
        *,
        interface: str,
        range_start: str,
        range_end: str,
    ) -> None:
        self.deletes.append(
            {
                "host": credentials.host,
                "interface": interface,
                "range_start": range_start,
                "range_end": range_end,
            }
        )
        if self.delete_raises is not None:
            raise self.delete_raises

    async def configure_dhcp_pool(
        self,
        credentials,
        *,
        interface: str,
        range_start: str,
        range_end: str,
        gateway: str,
        dns_servers: list[str],
        lease_time_seconds: int,
    ) -> None:
        self.calls.append(
            {
                "host": credentials.host,
                "username": credentials.username,
                "password": credentials.password,
                "interface": interface,
                "range_start": range_start,
                "range_end": range_end,
                "gateway": gateway,
                "dns_servers": dns_servers,
                "lease_time_seconds": lease_time_seconds,
            }
        )
        if self.raises is not None:
            raise self.raises


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> FakeDhcpAdapter:
    """Replaces the registry lookup the service performs.

    Patched on ``service``'s own reference, not on ``device_adapters`` --
    the service imported the name at module load, so patching the source
    module would leave the bound name untouched and the test would silently
    exercise the real adapter.
    """
    fake = FakeDhcpAdapter()
    monkeypatch.setattr(
        "app.domains.dhcp.service.get_dhcp_adapter", lambda vendor: fake
    )
    return fake


class TestDhcpPoolDevicePush:
    async def test_push_reaches_the_device_and_records_it(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        assert pool.device_push_status == DhcpDevicePushStatus.PENDING.value

        pushed = await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert len(adapter.calls) == 1
        call = adapter.calls[0]
        assert call["host"] == "10.0.0.1"
        assert call["username"] == "admin"
        assert call["password"] == "s3cret"
        assert call["interface"] == "ether2"
        assert call["range_start"] == "192.168.10.10"
        assert call["range_end"] == "192.168.10.100"
        assert call["gateway"] == "192.168.10.1"

        assert pushed.device_push_status == DhcpDevicePushStatus.ACTIVE.value
        assert pushed.device_push_error is None
        assert pushed.device_pushed_at is not None

    async def test_only_the_dns_servers_actually_set_are_advertised(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """An empty entry would reach RouterOS as a blank ``dns-server=``,
        which looks configured and resolves nothing."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)  # dns_primary only

        await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls[0]["dns_servers"] == ["8.8.8.8"]

    async def test_push_writes_a_real_audit_entry(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        before = len(h.audit_writer.entries)

        await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert len(h.audit_writer.entries) == before + 1
        assert (
            h.audit_writer.entries[-1]["action"]
            == AuditAction.DHCP_POOL_PUSHED.value
        )

    async def test_a_device_failure_is_recorded_committed_and_re_raised(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """The commit is the point. ``GenericRepository.update`` only
        flushes and ``get_db_session`` rolls back on any exception, so
        without an explicit commit the failure record is discarded and the
        row still reads "pending" with a NULL error after a real failure."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        adapter.raises = DhcpDeviceOperationError(
            "configure_dhcp_pool", "already have such item"
        )

        with pytest.raises(DhcpDeviceOperationError):
            await h.service.push_pool_to_device(
                pool.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert pool.device_push_status == DhcpDevicePushStatus.FAILED.value
        assert "already have such item" in (pool.device_push_error or "")
        assert h.repository.commits == 1

    async def test_a_disabled_pool_is_refused_before_any_connection(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )

        with pytest.raises(DhcpPoolNotEnabledError):
            await h.service.push_pool_to_device(
                pool.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_a_pool_with_no_interface_is_refused(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """``interface`` is nullable, and the adapter derives both RouterOS
        identifiers and the server's own binding from it."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router, interface=None)

        with pytest.raises(DhcpPoolMissingInterfaceError):
            await h.service.push_pool_to_device(
                pool.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_a_pool_with_no_gateway_is_refused(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """Guests would get an address and no route off the subnet.
        Defaulting to ``.1`` would be a fabricated network fact."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            gateway_ip_address=None,
        )

        with pytest.raises(DhcpPoolMissingGatewayError):
            await h.service.push_pool_to_device(
                pool.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_a_router_with_no_usable_credentials_is_refused(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        h.router_lookup.secret = None

        with pytest.raises(DhcpMissingCredentialsError):
            await h.service.push_pool_to_device(
                pool.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_another_organizations_pool_cannot_be_pushed(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)

        with pytest.raises(CrossOrganizationDhcpPoolAccessError):
            await h.service.push_pool_to_device(
                pool.id,
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
            )
        assert adapter.calls == []


class TestUnsupportedVendorIsATypedError:
    async def test_an_unknown_vendor_gets_a_400_not_a_gateway_error(self) -> None:
        """``Router.vendor`` is a free ``String(50)``, so a row carrying
        "MikroTik" or "mikrotik_routeros" must fail here, typed, rather than
        opaquely inside the gateway's own enum lookup."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        router.vendor = "ubiquiti"
        pool = await _create_pool(h, router)

        with pytest.raises(UnsupportedDhcpVendorError):
            await h.service.push_pool_to_device(
                pool.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )


class TestDhcpPoolDeleteReachesTheDevice:
    """Deleting a pool used to soft-delete the row and nothing else, so a
    DHCP server this platform created went on handing out addresses after
    the operator deleted it."""

    async def _pushed_pool(
        self, h: Harness, router: Router, adapter: FakeDhcpAdapter
    ) -> DhcpPool:
        pool = await _create_pool(h, router)
        await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        adapter.calls.clear()
        return pool

    async def test_deleting_a_pushed_pool_removes_it_from_the_router(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await self._pushed_pool(h, router, adapter)

        deleted = await h.service.delete_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == [
            {
                "host": "10.0.0.1",
                "interface": "ether2",
                "range_start": "192.168.10.10",
                "range_end": "192.168.10.100",
            }
        ]
        assert deleted.is_deleted is True

    async def test_a_pool_that_never_reached_a_device_skips_the_connection(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """Opening a connection to delete nothing would make every such
        delete fail whenever a router happened to be unreachable."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        assert pool.device_push_status == DhcpDevicePushStatus.PENDING.value

        deleted = await h.service.delete_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == []
        assert deleted.is_deleted is True

    async def test_a_device_failure_aborts_the_delete_and_keeps_the_row(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """Removing the row while the server is still live is exactly the
        drift this closes -- the operator would believe it was gone and
        nothing would ever reconcile it."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await self._pushed_pool(h, router, adapter)
        adapter.delete_raises = DhcpDeviceConnectionError("10.0.0.1", "timed out")

        with pytest.raises(DhcpDeviceConnectionError):
            await h.service.delete_pool(
                pool.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert pool.is_deleted is False
        assert await h.repository.get_pool_by_id(pool.id) is not None
