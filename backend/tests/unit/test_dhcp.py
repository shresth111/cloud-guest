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
from app.domains.dhcp.constants import DhcpDevicePushStatus, RogueDhcpAlertState
from app.domains.dhcp.device_adapters import RogueDhcpInterfaceReading
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
from app.domains.dhcp.models import DhcpPool, RouterRogueDhcpStatus
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

    # ------------------------------------------------------------------
    # Rogue-DHCP detection state.
    #
    # TAUGHT TO THIS FAKE BEFORE A SINGLE ASSERTION WAS WRITTEN AGAINST
    # IT, deliberately. ``DhcpService.run_rogue_dhcp_detection_for_router``
    # catches ``DhcpError`` and records UNKNOWN; a fake missing one of
    # these methods would raise ``AttributeError``, which is NOT a
    # ``DhcpError`` and so surfaces as a real test failure rather than
    # being silently recorded as an unreachable router. That narrowing is
    # itself a response to cloud-guest#131, where a blanket
    # ``except Exception`` in this domain swallowed exactly that
    # AttributeError and let untested wiring pass as green.
    # ------------------------------------------------------------------

    rogue_statuses: dict[tuple[uuid.UUID, str], RouterRogueDhcpStatus] = field(
        default_factory=dict
    )

    async def list_router_ids_serving_dhcp(self) -> list[uuid.UUID]:
        seen: dict[uuid.UUID, None] = {}
        for pool in self.pools.values():
            if pool.is_enabled and not pool.is_deleted:
                seen.setdefault(pool.router_id, None)
        return list(seen)

    async def list_rogue_dhcp_statuses(
        self, router_id: uuid.UUID
    ) -> list[RouterRogueDhcpStatus]:
        return [
            row
            for (rid, _iface), row in self.rogue_statuses.items()
            if rid == router_id
        ]

    async def upsert_rogue_dhcp_status(
        self, router_id: uuid.UUID, interface: str, data: dict[str, object]
    ) -> RouterRogueDhcpStatus:
        existing = self.rogue_statuses.get((router_id, interface))
        if existing is None:
            row = RouterRogueDhcpStatus(
                **_base_fields(router_id=router_id, interface=interface, **data)
            )
        else:
            row = existing
            for key, value in data.items():
                setattr(row, key, value)
        self.rogue_statuses[(router_id, interface)] = row
        return row

    async def delete_rogue_dhcp_statuses(
        self, router_id: uuid.UUID, interfaces: set[str]
    ) -> int:
        deleted = 0
        for interface in interfaces:
            if self.rogue_statuses.pop((router_id, interface), None) is not None:
                deleted += 1
        return deleted


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
    # The rogue-DHCP watch the service asks for after a successful push.
    # `alert_mac` is what the device would report as the trusted server;
    # None models an interface with no hardware address, where the alert
    # must be skipped rather than written with a guessed value.
    alerts: list[str] = field(default_factory=list)
    alert_mac: str | None = "04:F4:1C:25:EC:79"
    alert_raises: Exception | None = None
    delete_raises: Exception | None = None

    async def ensure_rogue_dhcp_alert(self, credentials, *, interface: str):
        if self.alert_raises is not None:
            raise self.alert_raises
        if self.alert_mac is None:
            return None
        self.alerts.append(interface)
        return self.alert_mac

    #: What ``read_rogue_dhcp_alerts`` reports back, and what it raises
    #: instead. Both default to the honest empty case rather than to a
    #: healthy one -- a fake that answers "all good" by default lets a
    #: wiring bug read as a pass.
    readings: list[RogueDhcpInterfaceReading] = field(default_factory=list)
    read_raises: Exception | None = None
    reads: int = 0

    async def read_rogue_dhcp_alerts(
        self, credentials
    ) -> list[RogueDhcpInterfaceReading]:
        """Taught to this fake before any assertion was written against it.

        Without it, ``get_dhcp_adapter`` would hand the service an object
        with no such attribute and the service would die on an
        ``AttributeError`` -- which is the failure cloud-guest#131 showed
        can hide inside a broad ``except``. Here it cannot: the service
        catches only ``DhcpError``.
        """
        self.reads += 1
        if self.read_raises is not None:
            raise self.read_raises
        return list(self.readings)

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

    async def test_a_pushed_pool_gets_a_rogue_dhcp_watch_on_its_interface(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """A DHCP server appearing on a segment is the moment it becomes
        worth guarding: a consumer router plugged in there answers leases
        too, and wins whenever it answers first."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)

        await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert adapter.alerts == ["ether2"]

    async def test_a_watch_that_cannot_be_set_does_not_fail_the_push(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """The alert is a guard around the feature, not the feature. A pool
        that reached the router must not be reported as failed because a
        watch could not be set beside it -- the operator would be told the
        addresses are not being handed out when they are."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        adapter.alert_raises = RuntimeError("device said no")

        pushed = await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert pushed.device_push_status == DhcpDevicePushStatus.ACTIVE.value
        assert pushed.device_push_error is None
        assert adapter.alerts == []

    async def test_an_interface_with_no_mac_is_left_unwatched(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """`valid-server` would have to be guessed, and a wrong trusted
        server makes every legitimate lease reply look rogue -- which is how
        a real one gets ignored. Skipped, not defaulted."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        adapter.alert_mac = None

        pushed = await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert adapter.alerts == []
        assert pushed.device_push_status == DhcpDevicePushStatus.ACTIVE.value

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


class TestDnsServerFallback:
    """A pool with no DNS configured must still point guests at this
    router, never past it.

    MikroTik documents that a DHCP server with no ``dns-server`` hands out
    the router's own *upstream* resolvers. Both DNS fields are optional and
    blank by default on the customer's screen, so the ordinary pool was the
    broken one -- and nobody had to touch a DNS setting to cause it.
    """

    async def test_a_pool_with_no_dns_advertises_the_gateway(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            dns_primary=None,
            dns_secondary=None,
        )

        await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        # Not [] -- an empty list makes the adapter omit dns-server=, which
        # is what sent guests to 8.8.8.8 and silently disabled every
        # feature built on this router's resolver.
        assert adapter.calls[0]["dns_servers"] == ["192.168.10.1"]

    async def test_configured_dns_still_wins_over_the_fallback(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)  # dns_primary=8.8.8.8

        await h.service.push_pool_to_device(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls[0]["dns_servers"] == ["8.8.8.8"]

    async def test_no_dns_and_no_gateway_advertises_nothing_rather_than_guessing(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """There is nothing truthful to advertise, and inventing an address
        would be worse than the gap. The push itself is refused earlier for
        a missing gateway, so this covers the helper directly."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, router)
        pool.dns_primary = None
        pool.dns_secondary = None
        pool.gateway_ip_address = None

        assert h.service._dns_servers(pool) == []


# ============================================================================
# Editing a pushed pool stops it claiming the router has the new values
# ============================================================================


class TestEditDemotesAnAppliedPool:
    """``active`` renders as a green "Applied" badge. An edit to anything
    the router actually carries makes that false the moment it is saved,
    and nothing used to say so -- the row went on reading ``active`` while
    the device handed out the *old* range."""

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

    async def test_widening_the_range_demotes_the_row(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await self._pushed_pool(h, router, adapter)
        assert pool.device_push_status == DhcpDevicePushStatus.ACTIVE.value

        updated = await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            address_range_end="192.168.10.200",
        )

        assert updated.device_push_status == DhcpDevicePushStatus.PENDING.value

    async def test_changing_dns_demotes_the_row(self, adapter: FakeDhcpAdapter) -> None:
        """A DNS server the router is not advertising is exactly the kind of
        edit whose effect a customer cannot see from the device."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await self._pushed_pool(h, router, adapter)

        updated = await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            dns_primary="1.1.1.1",
        )

        assert updated.device_push_status == DhcpDevicePushStatus.PENDING.value

    async def test_renaming_the_pool_does_not_demote(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """``name``/``description`` never leave the database. The device
        state still is exactly what the row describes, so demoting would
        nag the operator into a pointless re-push."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await self._pushed_pool(h, router, adapter)

        updated = await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="Lobby Pool",
            description="Renamed for clarity",
        )

        assert updated.device_push_status == DhcpDevicePushStatus.ACTIVE.value

    async def test_resubmitting_the_same_range_does_not_demote(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await self._pushed_pool(h, router, adapter)

        updated = await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            address_range_start=pool.address_range_start,
            address_range_end=pool.address_range_end,
            interface=pool.interface,
        )

        assert updated.device_push_status == DhcpDevicePushStatus.ACTIVE.value

    async def test_a_demoted_pool_is_still_torn_off_the_device_on_delete(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """The demotion says "the router has the old values", so the delete
        that follows must remove them. Reading ``pending`` as "nothing to
        remove" would orphan a live DHCP server -- which is why the delete
        guard keys on ``device_pushed_at``, not on the status."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        pool = await self._pushed_pool(h, router, adapter)
        await h.service.update_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            address_range_end="192.168.10.200",
        )

        await h.service.delete_pool(
            pool.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert len(adapter.deletes) == 1


# ============================================================================
# Rogue-DHCP detection -- the reader, which had zero callers.
#
# ``wyfy_device_gateway.mikrotik_adapter.read_rogue_dhcp_alerts`` was
# implemented, documented, and called from nowhere in ``app/``. The writer
# was wired on both config paths; the reader was not. A router that is not
# being watched has no alert row, raises no error and appears nowhere -- it
# is invisible precisely because it is unwatched.
#
# THE DISTINCTION UNDER TEST throughout this section is ``unknown`` vs
# ``unguarded``. A router we could not reach is not a router we know is
# unwatched. Every test below that produces one asserts it is not the other.
# ============================================================================


def _reading(
    interface: str = "ether2",
    *,
    serves_dhcp: bool = True,
    alert_present: bool = True,
    enabled: bool = True,
) -> RogueDhcpInterfaceReading:
    return RogueDhcpInterfaceReading(
        interface=interface,
        serves_dhcp=serves_dhcp,
        alert_present=alert_present,
        enabled=enabled,
    )


async def _detect(h: Harness, router: Router):  # noqa: ANN202 -- test helper
    return await h.service.run_rogue_dhcp_detection_for_router(router.id)


def _state(h: Harness, router: Router, interface: str = "ether2") -> str:
    return h.repository.rogue_statuses[(router.id, interface)].alert_state


class TestRogueDhcpDetection:
    async def test_a_watched_interface_reads_as_guarded(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.readings = [_reading(alert_present=True, enabled=True)]

        summary = await _detect(h, router)

        assert adapter.reads == 1
        assert _state(h, router) == RogueDhcpAlertState.GUARDED.value
        assert summary.guarded == 1
        assert summary.unguarded == 0
        assert summary.unknown == 0

    async def test_no_alert_row_at_all_reads_as_unguarded(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """An interface handing out addresses with nothing watching it.

        This is the finding the whole reader exists for, and it has no
        alert row of its own to be listed by -- the gateway's
        ``_build_rogue_dhcp_alert_statuses`` synthesises it from the set of
        DHCP-serving interfaces precisely so it cannot be a silence the
        caller has to notice.
        """
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.readings = [_reading(alert_present=False, enabled=False)]

        summary = await _detect(h, router)

        row = h.repository.rogue_statuses[(router.id, "ether2")]
        assert row.alert_state == RogueDhcpAlertState.UNGUARDED.value
        assert row.alert_present is False
        assert row.enabled is False
        assert summary.unguarded == 1
        # Not the same answer as "we could not check".
        assert summary.unknown == 0

    async def test_a_row_present_but_disabled_reads_as_unguarded(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """THE STATE ROUTEROS'S OWN DEFAULT PRODUCES.

        ``/ip dhcp-server alert`` rows are created **disabled**. Such a row
        appears in a ``/export`` looking exactly like a configured watch and
        observes nothing -- the first careful by-hand attempt on the lab
        router left three of them. A check that tested only for presence
        would certify this router as watched.

        ``alert_present`` and ``enabled`` stay legible as separate columns
        rather than collapsing into a bare ``unguarded``, so an operator can
        tell a switched-off watch from an interface nobody ever configured.
        """
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.readings = [_reading(alert_present=True, enabled=False)]

        await _detect(h, router)

        row = h.repository.rogue_statuses[(router.id, "ether2")]
        assert row.alert_state == RogueDhcpAlertState.UNGUARDED.value
        # Present, and switched off -- both facts survive.
        assert row.alert_present is True
        assert row.enabled is False
        assert "switched off" in (row.detail or "")

    async def test_an_unreachable_router_reads_as_unknown_not_unguarded(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """A router we could not reach is an unanswered question.

        Reporting it as ``unguarded`` would raise a finding on every
        offline router in the fleet that no operator could act on, while
        saying nothing true about rogue DHCP. Same posture
        ``monitoring.constants.HealthStatus.UNKNOWN`` documents.
        """
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_pool(h, router)
        adapter.read_raises = DhcpDeviceConnectionError(
            "10.0.0.1", "connection refused"
        )

        summary = await _detect(h, router)

        row = h.repository.rogue_statuses[(router.id, "ether2")]
        assert row.alert_state == RogueDhcpAlertState.UNKNOWN.value
        # THE ASSERTION THIS TEST EXISTS FOR: unknown is never unguarded.
        assert row.alert_state != RogueDhcpAlertState.UNGUARDED.value
        assert summary.unknown == 1
        assert summary.unguarded == 0
        assert summary.guarded == 0
        # And it says why, rather than leaving an unanswered question with
        # no reason attached.
        assert "connection refused" in (row.detail or "")

    async def test_an_unknown_row_does_not_keep_stale_liveness_booleans(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """A router that was watched, then became unreachable.

        ``enabled`` must not stay True beside an ``unknown`` state: a
        consumer glancing at the boolean would conclude the segment is
        watched, on evidence that is now of unknown age. ``alert_state`` is
        the only field carrying an answer here.
        """
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.readings = [_reading(alert_present=True, enabled=True)]
        await _detect(h, router)
        assert _state(h, router) == RogueDhcpAlertState.GUARDED.value

        adapter.read_raises = DhcpDeviceConnectionError("10.0.0.1", "timed out")
        await _detect(h, router)

        row = h.repository.rogue_statuses[(router.id, "ether2")]
        assert row.alert_state == RogueDhcpAlertState.UNKNOWN.value
        assert row.enabled is False
        assert row.alert_present is False

    async def test_missing_credentials_is_unknown_not_a_finding(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """Every way of failing to get an answer lands as ``unknown`` --
        not only a refused connection. A router with no API credentials was
        never asked, so nothing about it is known either way."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_pool(h, router)
        # No decryptable API secret -- ``_resolve_device_credentials``
        # raises rather than guessing, and the detector never opens a
        # connection at all.
        h.router_lookup.secret = None

        summary = await _detect(h, router)

        assert summary.unknown == 1
        assert summary.unguarded == 0
        assert _state(h, router) == RogueDhcpAlertState.UNKNOWN.value

    async def test_a_bug_in_the_reader_fails_loudly_rather_than_reading_unknown(
        self,
        adapter: FakeDhcpAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """cloud-guest#131, guarded against directly.

        The detector catches ``DhcpError`` and records UNKNOWN. It must NOT
        catch everything: an ``AttributeError`` from a collaborator that
        does not implement the reader is a bug in this code, and recording
        it as "router unreachable" is exactly how broken wiring passes as
        green. That precise failure -- a fake missing a new method, an
        ``except Exception`` swallowing the AttributeError -- already
        happened once in this domain's own test file.
        """

        class AdapterWithoutTheReader:
            vendor = "mikrotik"

        monkeypatch.setattr(
            "app.domains.dhcp.service.get_dhcp_adapter",
            lambda vendor: AdapterWithoutTheReader(),
        )
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        with pytest.raises(AttributeError):
            await _detect(h, router)

        # And nothing was recorded -- no fabricated "unknown" row papering
        # over a code defect.
        assert h.repository.rogue_statuses == {}

    async def test_every_dhcp_serving_interface_appears_even_with_no_row(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """The union, not the alert rows alone."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.readings = [
            _reading("ether2", alert_present=True, enabled=True),
            _reading("ether3", alert_present=False, enabled=False),
            _reading("vlan10", alert_present=True, enabled=False),
        ]

        summary = await _detect(h, router)

        assert summary.interfaces == 3
        assert summary.guarded == 1
        assert summary.unguarded == 2
        assert _state(h, router, "ether2") == RogueDhcpAlertState.GUARDED.value
        assert _state(h, router, "ether3") == RogueDhcpAlertState.UNGUARDED.value
        assert _state(h, router, "vlan10") == RogueDhcpAlertState.UNGUARDED.value

    async def test_an_interface_the_device_stops_reporting_is_retired(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """A stale ``unguarded`` row for an interface that no longer serves
        DHCP would fail the readiness item forever, with nothing an
        operator could do to clear it."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.readings = [
            _reading("ether2", alert_present=False, enabled=False),
            _reading("ether3", alert_present=False, enabled=False),
        ]
        await _detect(h, router)
        assert (router.id, "ether3") in h.repository.rogue_statuses

        adapter.readings = [_reading("ether2", alert_present=True, enabled=True)]
        await _detect(h, router)

        assert (router.id, "ether3") not in h.repository.rogue_statuses
        assert _state(h, router, "ether2") == RogueDhcpAlertState.GUARDED.value

    async def test_an_unreachable_router_never_retires_its_rows(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """Deleting on a failed read would turn "we could not reach this
        router" into "this router has nothing to report", which reads as
        fine."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.readings = [
            _reading("ether2", alert_present=False, enabled=False),
            _reading("ether3", alert_present=False, enabled=False),
        ]
        await _detect(h, router)

        adapter.read_raises = DhcpDeviceConnectionError("10.0.0.1", "no route to host")
        summary = await _detect(h, router)

        assert (router.id, "ether2") in h.repository.rogue_statuses
        assert (router.id, "ether3") in h.repository.rogue_statuses
        assert summary.unknown == 2

    async def test_get_rogue_dhcp_statuses_performs_no_device_io(
        self, adapter: FakeDhcpAdapter
    ) -> None:
        """The property that lets the readiness checklist compose this at
        all: ``get_checklist`` re-runs every AUTO item on every GET, so a
        device read here would put a RouterOS timeout behind a dashboard
        page load."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.readings = [_reading()]
        await _detect(h, router)
        reads_after_detection = adapter.reads

        rows = await h.service.get_rogue_dhcp_statuses(router.id)

        assert len(rows) == 1
        assert adapter.reads == reads_after_detection


class TestRogueDhcpSweepTargets:
    async def test_only_routers_with_an_enabled_pool_are_swept(self) -> None:
        """A disabled pool hands out nothing, so RouterOS's own alert would
        have no baseline either -- polling that router spends a real device
        round trip to learn nothing."""
        h = make_harness()
        serving = h.router_lookup.add(_make_router())
        idle = h.router_lookup.add(_make_router())
        pool = await _create_pool(h, serving)
        assert pool.is_enabled

        router_ids = await h.repository.list_router_ids_serving_dhcp()

        assert router_ids == [serving.id]
        assert idle.id not in router_ids

    async def test_a_router_with_many_pools_is_swept_once(self) -> None:
        """``read_rogue_dhcp_alerts`` answers for every interface in a
        single pass, so six pools is still one API read."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_pool(h, router, start="192.168.10.10", end="192.168.10.100")
        await _create_pool(
            h, router, start="192.168.11.10", end="192.168.11.100", interface="ether3"
        )

        assert await h.repository.list_router_ids_serving_dhcp() == [router.id]
