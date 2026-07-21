"""Unit tests for the DNS Management domain: record CRUD (tenant
isolation), name/address validation (A/AAAA/CNAME shape checks), and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_dhcp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``DnsService`` is exercised against small, hand-rolled in-memory
fakes for its own repository and the composed ``RouterLookupProtocol`` --
mirrors ``test_dhcp.py``'s own identical "fake the narrow Protocol
boundary" precedent. This domain has no device I/O to test (a pure
rules/inventory domain, no ``device_adapters.py`` in this pass).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.dns.constants import DnsRecordType
from app.domains.dns.exceptions import (
    CrossOrganizationDnsRecordAccessError,
    DnsRecordNotFoundError,
    InvalidDnsAddressError,
    InvalidDnsNameError,
)
from app.domains.dns.models import DnsRecord
from app.domains.dns.router import router as dns_router
from app.domains.dns.service import DnsService
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
class FakeDnsRepository:
    records: dict[uuid.UUID, DnsRecord] = field(default_factory=dict)

    async def create_record(self, **fields: object) -> DnsRecord:
        record = DnsRecord(**_base_fields(**fields))
        self.records[record.id] = record
        return record

    async def get_record_by_id(
        self, record_id: uuid.UUID, *, include_deleted: bool = False
    ) -> DnsRecord | None:
        record = self.records.get(record_id)
        if record is None or (record.is_deleted and not include_deleted):
            return None
        return record

    async def update_record(
        self, record: DnsRecord, data: dict[str, object]
    ) -> DnsRecord:
        for key, value in data.items():
            if hasattr(record, key):
                setattr(record, key, value)
        record.version += 1
        return record

    async def soft_delete_record(self, record: DnsRecord) -> DnsRecord:
        record.is_deleted = True
        record.deleted_at = _now()
        return record

    async def list_records(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.records.values() if not v.is_deleted]
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

    async def list_records_for_router(self, router_id: uuid.UUID) -> list[DnsRecord]:
        return [
            v
            for v in self.records.values()
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


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: DnsService
    repository: FakeDnsRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeDnsRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = DnsService(repository, router_lookup, audit_writer=audit_writer)
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
    )


async def _create_record(
    h: Harness,
    router: Router,
    *,
    name: str = "printer.local",
    address: str = "192.168.1.50",
    record_type: DnsRecordType = DnsRecordType.A,
) -> DnsRecord:
    return await h.service.create_record(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name=name,
        address=address,
        record_type=record_type,
    )


# ============================================================================
# Record CRUD
# ============================================================================


class TestDnsRecordCrud:
    async def test_create_record(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        record = await _create_record(h, router)
        assert record.name == "printer.local"
        assert record.organization_id == router.organization_id
        assert record.location_id == router.location_id
        assert len(h.audit_writer.entries) == 1

    async def test_create_with_invalid_a_address_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidDnsAddressError):
            await _create_record(h, router, address="not-an-ip")

    async def test_create_with_invalid_name_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidDnsNameError):
            await _create_record(h, router, name="bad name with spaces")

    async def test_create_cname_accepts_hostname_address(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        record = await _create_record(
            h,
            router,
            record_type=DnsRecordType.CNAME,
            address="target.local",
        )
        assert record.record_type == DnsRecordType.CNAME.value

    async def test_create_cname_rejects_non_hostname_address(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidDnsNameError):
            await _create_record(
                h, router, record_type=DnsRecordType.CNAME, address="not valid!"
            )

    async def test_create_aaaa_requires_ipv6(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidDnsAddressError):
            await _create_record(
                h, router, record_type=DnsRecordType.AAAA, address="192.168.1.1"
            )
        record = await _create_record(
            h, router, record_type=DnsRecordType.AAAA, address="fe80::1"
        )
        assert record.record_type == DnsRecordType.AAAA.value

    async def test_create_raises_for_unknown_router(self) -> None:
        h = make_harness()
        with pytest.raises(RouterNotFoundError):
            await _create_record(h, _make_router())

    async def test_get_record_cross_organization_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        record = await _create_record(h, router)
        with pytest.raises(CrossOrganizationDnsRecordAccessError):
            await h.service.get_record(
                record.id, requesting_organization_id=uuid.uuid4()
            )

    async def test_get_record_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(DnsRecordNotFoundError):
            await h.service.get_record(uuid.uuid4())

    async def test_update_record_revalidates_new_address(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        record = await _create_record(h, router)
        with pytest.raises(InvalidDnsAddressError):
            await h.service.update_record(
                record.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=router.organization_id,
                address="not-an-ip",
            )

    async def test_update_record_success(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        record = await _create_record(h, router)
        updated = await h.service.update_record(
            record.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            address="192.168.1.99",
        )
        assert updated.address == "192.168.1.99"
        assert len(h.audit_writer.entries) == 2

    async def test_delete_record(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        record = await _create_record(h, router)
        deleted = await h.service.delete_record(
            record.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True

    async def test_list_records_for_router(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_record(h, router, name="a.local")
        await _create_record(h, router, name="b.local")
        records = await h.service.list_records_for_router(
            router.id, requesting_organization_id=router.organization_id
        )
        assert len(records) == 2

    async def test_list_records_scopes_to_organization(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_record(h, router_a)
        await _create_record(h, router_b)
        records, meta = await h.service.list_records(
            requesting_organization_id=router_a.organization_id
        )
        assert meta.total_items == 1
        assert records[0].organization_id == router_a.organization_id


# ============================================================================
# Structural RBAC check
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_dns_route_has_a_permission_dependency(self) -> None:
        assert len(dns_router.routes) == 5
        for route in dns_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
