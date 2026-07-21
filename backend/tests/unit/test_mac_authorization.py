"""Unit tests for the MAC Authorization domain: entry CRUD (tenant
isolation), MAC address normalization/validation, expiry validation per
authorization type, uniqueness per organization, the required-
organization-context guard on create/import/export, bulk import (partial
success), CSV export, the ``is_mac_authorized`` read-model query, and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_vlan.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``MacAuthorizationService`` is exercised against a small,
hand-rolled in-memory fake for its own repository -- this domain composes
no cross-domain protocol at all (see ``service.py``'s own module
docstring: purely organization/location scoped, no router/device
concept).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.mac_authorization.constants import MacAuthorizationType
from app.domains.mac_authorization.exceptions import (
    CrossOrganizationMacAuthorizationAccessError,
    InvalidExpiryError,
    InvalidMacAddressError,
    MacAuthorizationAlreadyExistsError,
    MacAuthorizationEntryNotFoundError,
    OrganizationRequiredError,
)
from app.domains.mac_authorization.models import MacAuthorizationEntry
from app.domains.mac_authorization.router import router as mac_authorization_router
from app.domains.mac_authorization.service import MacAuthorizationService

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


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeMacAuthorizationRepository:
    entries: dict[uuid.UUID, MacAuthorizationEntry] = field(default_factory=dict)

    async def create_entry(self, **fields: object) -> MacAuthorizationEntry:
        entry = MacAuthorizationEntry(**_base_fields(**fields))
        self.entries[entry.id] = entry
        return entry

    async def get_entry_by_id(
        self, entry_id: uuid.UUID, *, include_deleted: bool = False
    ) -> MacAuthorizationEntry | None:
        entry = self.entries.get(entry_id)
        if entry is None or (entry.is_deleted and not include_deleted):
            return None
        return entry

    async def get_entry_by_org_and_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> MacAuthorizationEntry | None:
        for entry in self.entries.values():
            if (
                entry.organization_id == organization_id
                and entry.mac_address == mac_address
                and not entry.is_deleted
            ):
                return entry
        return None

    async def update_entry(
        self, entry: MacAuthorizationEntry, data: dict[str, object]
    ) -> MacAuthorizationEntry:
        for key, value in data.items():
            if hasattr(entry, key):
                setattr(entry, key, value)
        entry.version += 1
        return entry

    async def soft_delete_entry(
        self, entry: MacAuthorizationEntry
    ) -> MacAuthorizationEntry:
        entry.is_deleted = True
        entry.deleted_at = _now()
        return entry

    async def list_entries(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.entries.values() if not v.is_deleted]
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

    async def list_all_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[MacAuthorizationEntry]:
        return [
            v
            for v in self.entries.values()
            if v.organization_id == organization_id and not v.is_deleted
        ]


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: MacAuthorizationService
    repository: FakeMacAuthorizationRepository
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeMacAuthorizationRepository()
    audit_writer = FakeAuditLogWriter()
    service = MacAuthorizationService(repository, audit_writer=audit_writer)
    return Harness(service=service, repository=repository, audit_writer=audit_writer)


async def _create_entry(
    h: Harness,
    organization_id: uuid.UUID,
    *,
    mac_address: str = "aa:bb:cc:dd:ee:ff",
    authorization_type: MacAuthorizationType = MacAuthorizationType.PERMANENT,
    expires_at: datetime | None = None,
) -> MacAuthorizationEntry:
    return await h.service.create_entry(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=organization_id,
        mac_address=mac_address,
        authorization_type=authorization_type,
        expires_at=expires_at,
        comment="test device",
    )


# ============================================================================
# Entry CRUD
# ============================================================================


class TestMacAuthorizationEntryCrud:
    async def test_create_entry_normalizes_mac_address(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        entry = await _create_entry(h, org_id, mac_address="aa:bb:cc:dd:ee:ff")
        assert entry.mac_address == "AA:BB:CC:DD:EE:FF"
        assert entry.organization_id == org_id
        assert len(h.audit_writer.entries) == 1

    async def test_create_with_invalid_mac_raises(self) -> None:
        h = make_harness()
        with pytest.raises(InvalidMacAddressError):
            await _create_entry(h, uuid.uuid4(), mac_address="not-a-mac")

    async def test_create_temporary_without_expiry_raises(self) -> None:
        h = make_harness()
        with pytest.raises(InvalidExpiryError):
            await _create_entry(
                h, uuid.uuid4(), authorization_type=MacAuthorizationType.TEMPORARY
            )

    async def test_create_temporary_with_past_expiry_raises(self) -> None:
        h = make_harness()
        with pytest.raises(InvalidExpiryError):
            await _create_entry(
                h,
                uuid.uuid4(),
                authorization_type=MacAuthorizationType.TEMPORARY,
                expires_at=_now() - timedelta(days=1),
            )

    async def test_create_permanent_with_expiry_raises(self) -> None:
        h = make_harness()
        with pytest.raises(InvalidExpiryError):
            await _create_entry(
                h,
                uuid.uuid4(),
                authorization_type=MacAuthorizationType.PERMANENT,
                expires_at=_now() + timedelta(days=1),
            )

    async def test_create_without_organization_raises(self) -> None:
        h = make_harness()
        with pytest.raises(OrganizationRequiredError):
            await h.service.create_entry(
                actor_user_id=None,
                requesting_organization_id=None,
                mac_address="AA:BB:CC:DD:EE:FF",
            )

    async def test_create_duplicate_mac_in_same_org_raises(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        await _create_entry(h, org_id, mac_address="AA:BB:CC:DD:EE:01")
        with pytest.raises(MacAuthorizationAlreadyExistsError):
            await _create_entry(h, org_id, mac_address="aa:bb:cc:dd:ee:01")

    async def test_same_mac_in_different_orgs_is_allowed(self) -> None:
        h = make_harness()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        entry_a = await _create_entry(h, org_a, mac_address="AA:BB:CC:DD:EE:02")
        entry_b = await _create_entry(h, org_b, mac_address="AA:BB:CC:DD:EE:02")
        assert entry_a.organization_id != entry_b.organization_id

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        entry = await _create_entry(h, org_id)
        with pytest.raises(CrossOrganizationMacAuthorizationAccessError):
            await h.service.get_entry(entry.id, requesting_organization_id=uuid.uuid4())

    async def test_get_missing_entry_raises(self) -> None:
        h = make_harness()
        with pytest.raises(MacAuthorizationEntryNotFoundError):
            await h.service.get_entry(uuid.uuid4())

    async def test_list_entries_scoped_to_organization(self) -> None:
        h = make_harness()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await _create_entry(h, org_a, mac_address="AA:BB:CC:DD:EE:03")
        await _create_entry(h, org_b, mac_address="AA:BB:CC:DD:EE:04")
        entries, meta = await h.service.list_entries(requesting_organization_id=org_a)
        assert meta.total_items == 1
        assert entries[0].organization_id == org_a

    async def test_update_mac_address_renormalizes_and_rechecks_uniqueness(
        self,
    ) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        await _create_entry(h, org_id, mac_address="AA:BB:CC:DD:EE:05")
        second = await _create_entry(h, org_id, mac_address="AA:BB:CC:DD:EE:06")
        with pytest.raises(MacAuthorizationAlreadyExistsError):
            await h.service.update_entry(
                second.id,
                actor_user_id=None,
                requesting_organization_id=org_id,
                mac_address="aa:bb:cc:dd:ee:05",
            )

    async def test_update_authorization_type_revalidates_expiry(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        entry = await _create_entry(h, org_id)
        with pytest.raises(InvalidExpiryError):
            await h.service.update_entry(
                entry.id,
                actor_user_id=None,
                requesting_organization_id=org_id,
                authorization_type=MacAuthorizationType.TEMPORARY.value,
            )

    async def test_delete_soft_deletes(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        entry = await _create_entry(h, org_id)
        deleted = await h.service.delete_entry(
            entry.id, actor_user_id=None, requesting_organization_id=org_id
        )
        assert deleted.is_deleted is True


# ============================================================================
# Bulk import / export
# ============================================================================


class TestMacAuthorizationImportExport:
    async def test_import_partial_success(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        result = await h.service.import_entries(
            actor_user_id=None,
            requesting_organization_id=org_id,
            entries=[
                {"mac_address": "AA:BB:CC:DD:EE:10"},
                {"mac_address": "not-a-mac"},
                {"mac_address": "AA:BB:CC:DD:EE:11"},
            ],
        )
        assert result.imported_count == 2
        assert len(result.rejected) == 1
        assert result.rejected[0].mac_address == "not-a-mac"

    async def test_import_without_organization_raises(self) -> None:
        h = make_harness()
        with pytest.raises(OrganizationRequiredError):
            await h.service.import_entries(
                actor_user_id=None,
                requesting_organization_id=None,
                entries=[{"mac_address": "AA:BB:CC:DD:EE:12"}],
            )

    async def test_export_produces_csv_with_header_and_rows(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        await _create_entry(h, org_id, mac_address="AA:BB:CC:DD:EE:13")
        csv_text = await h.service.export_entries_csv(requesting_organization_id=org_id)
        lines = csv_text.strip().splitlines()
        assert lines[0].startswith("mac_address,")
        assert "AA:BB:CC:DD:EE:13" in lines[1]

    async def test_export_without_organization_raises(self) -> None:
        h = make_harness()
        with pytest.raises(OrganizationRequiredError):
            await h.service.export_entries_csv(requesting_organization_id=None)


# ============================================================================
# is_mac_authorized
# ============================================================================


class TestIsMacAuthorized:
    async def test_valid_enabled_entry_is_authorized(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        await _create_entry(h, org_id, mac_address="AA:BB:CC:DD:EE:20")
        assert await h.service.is_mac_authorized(
            "aa:bb:cc:dd:ee:20", organization_id=org_id
        )

    async def test_expired_temporary_entry_is_not_authorized(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        entry = await _create_entry(
            h,
            org_id,
            mac_address="AA:BB:CC:DD:EE:21",
            authorization_type=MacAuthorizationType.TEMPORARY,
            expires_at=_now() + timedelta(seconds=1),
        )
        # Force it into the past directly on the fake row (bypassing
        # validate_expiry, which only runs at write time).
        entry.expires_at = _now() - timedelta(days=1)
        assert not await h.service.is_mac_authorized(
            "AA:BB:CC:DD:EE:21", organization_id=org_id
        )

    async def test_disabled_entry_is_not_authorized(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        entry = await _create_entry(h, org_id, mac_address="AA:BB:CC:DD:EE:22")
        entry.is_enabled = False
        assert not await h.service.is_mac_authorized(
            "AA:BB:CC:DD:EE:22", organization_id=org_id
        )

    async def test_missing_entry_is_not_authorized(self) -> None:
        h = make_harness()
        assert not await h.service.is_mac_authorized(
            "AA:BB:CC:DD:EE:99", organization_id=uuid.uuid4()
        )

    async def test_malformed_mac_is_not_authorized_and_never_raises(self) -> None:
        h = make_harness()
        assert not await h.service.is_mac_authorized(
            "bogus", organization_id=uuid.uuid4()
        )


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_mac_authorization_route_has_a_permission_dependency(self) -> None:
        assert len(mac_authorization_router.routes) == 7
        for route in mac_authorization_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
