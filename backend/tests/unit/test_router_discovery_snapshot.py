"""Unit tests for Wave 1 router discovery snapshot collection and
compatibility evaluation.

Covers:

* collector sanitization / ``is_wyfy_managed`` detection from a canned
  ``ReadOnlyStateCapture``
* compatibility matrix cases (PASS / WARNING / BLOCKED)
* an optional ``DiscoveryService`` path with a mocked
  ``ReadOnlyDeviceReader``

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_readiness.py``); ``asyncio_mode = "auto"`` runs async
tests directly. No live device I/O.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest
from wyfy_device_gateway.mikrotik_adapter import MikroTikConnectionError
from wyfy_device_gateway.read_only_reader import ReadOnlyStateCapture

from app.domains.provisioning_engine.planner.collector import (
    collect_firewall_summary,
    collect_interfaces,
    collect_snapshot_fields,
    is_wyfy_managed,
    strip_secrets,
)
from app.domains.provisioning_engine.planner.compatibility import (
    evaluate_compatibility_from_fields,
)
from app.domains.provisioning_engine.planner.constants import (
    SNAPSHOT_SCHEMA_VERSION,
    CompatibilityCheckStatus,
    CompatibilityOverall,
    ManagedResourceStatus,
    SnapshotStatus,
    SnapshotTrigger,
)
from app.domains.provisioning_engine.planner.exceptions import (
    DiscoveryDeviceConnectionError,
)
from app.domains.provisioning_engine.planner.managed_resources import (
    build_managed_resource_backfill_rows,
)
from app.domains.provisioning_engine.planner.models import RouterSnapshot
from app.domains.provisioning_engine.planner.service import DiscoveryService
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


def _make_router() -> Router:
    return Router(
        **_base_fields(
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
            routeros_version="7.15.3",
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status="online",
            last_seen_at=_now(),
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


def _canned_capture(*, with_secrets: bool = True) -> ReadOnlyStateCapture:
    sections: dict[str, list[dict[str, Any]]] = {
        "system_resource": [
            {
                "version": "7.15.3 (stable)",
                "architecture-name": "arm",
                "total-memory": 1073741824,
                "free-memory": 536870912,
                "free-hdd-space": 10485760,
                "board-name": "RB4011iGS+",
            }
        ],
        "system_routerboard": [{"model": "RB4011iGS+", "board-name": "RB4011iGS+"}],
        "interfaces": [
            {
                "name": "ether1",
                "type": "ether",
                "running": True,
                "disabled": False,
                "comment": "WAN uplink",
            },
            {
                "name": "bridge-guest",
                "type": "bridge",
                "running": True,
                "disabled": False,
                "comment": "WYFYGUEST-guest-bridge",
            },
            {
                "name": "vlan100",
                "type": "vlan",
                "running": True,
                "disabled": False,
                "comment": "cloudguest-vlan-100",
            },
        ],
        "bridges": [
            {"name": "bridge-guest", "comment": "WYFYGUEST-guest-bridge"},
            {"name": "bridge-lan", "comment": "local"},
        ],
        "bridge_ports": [
            {"bridge": "bridge-guest", "interface": "ether2"},
            {"bridge": "bridge-lan", "interface": "ether3"},
        ],
        "ip_addresses": [
            {
                "address": "10.10.0.1/24",
                "interface": "bridge-guest",
                "comment": "WYFYGUEST-guest-ip",
            }
        ],
        "dhcp_clients": [{"interface": "ether1", "status": "bound", "comment": ""}],
        "dhcp_servers": [
            {
                "name": "guest-dhcp",
                "interface": "bridge-guest",
                "address-pool": "guest-pool",
                "comment": "WYFYGUEST-dhcp",
            }
        ],
        "routes": [
            {
                "dst-address": "0.0.0.0/0",
                "gateway": "203.0.113.1",
                "distance": 1,
                "active": True,
                "comment": "",
            }
        ],
        "dns": [{"servers": "1.1.1.1", "allow-remote-requests": True}],
        "firewall_filter": [
            {
                "comment": "WYFYGUEST-accept-guest",
                "disabled": False,
                "action": "accept",
            },
            {"comment": "drop-all", "disabled": False, "action": "drop"},
            {"comment": "legacy", "disabled": True, "action": "accept"},
        ],
        "firewall_nat": [
            {"comment": "WYFYGUEST-masq", "disabled": False, "action": "masquerade"},
            {"comment": "other", "disabled": False, "action": "src-nat"},
        ],
        "hotspot_servers": [
            {
                "name": "hs-guest",
                "interface": "bridge-guest",
                "profile": "hsprof1",
                "comment": "WYFYGUEST-hotspot",
            }
        ],
        "hotspot_profiles": [{"name": "hsprof1"}],
        "hotspot_walled_garden": [{"dst-host": "portal.example.com"}],
        "vlan_interfaces": [
            {
                "name": "vlan100",
                "vlan-id": 100,
                "interface": "bridge-lan",
                "comment": "cloudguest-vlan-100",
            }
        ],
        "ip_services": [{"name": "www", "port": 80, "disabled": False}],
        "system_packages": [
            {"name": "routeros", "version": "7.15.3", "disabled": False},
            {"name": "hotspot", "version": "7.15.3", "disabled": False},
        ],
    }
    if with_secrets:
        # Residual secret-shaped keys a buggy upstream might leave behind.
        sections["interfaces"].append(
            {
                "name": "wg1",
                "type": "wg",
                "running": True,
                "disabled": False,
                "comment": "",
                "private-key": "SHOULD_NEVER_PERSIST",
                "password": "also-secret",
            }
        )
    return ReadOnlyStateCapture(sections=sections, errors={})


# ============================================================================
# Collector
# ============================================================================


def test_is_wyfy_managed_detects_both_prefixes() -> None:
    assert is_wyfy_managed("WYFYGUEST-guest-bridge") is True
    assert is_wyfy_managed("cloudguest-vlan-100") is True
    assert is_wyfy_managed("local") is False
    assert is_wyfy_managed(None) is False
    assert is_wyfy_managed("") is False


def test_strip_secrets_removes_secret_keys() -> None:
    cleaned = strip_secrets(
        {
            "name": "wg1",
            "private-key": "abc",
            "password": "x",
            "comment": "ok",
            "nested": {"secret": "y", "port": 1},
        }
    )
    assert "private-key" not in cleaned
    assert "password" not in cleaned
    assert cleaned["has_private_key"] is True
    assert cleaned["has_password"] is True
    assert cleaned["comment"] == "ok"
    assert "secret" not in cleaned["nested"]
    assert cleaned["nested"]["has_secret"] is True
    assert cleaned["nested"]["port"] == 1


def test_collect_interfaces_marks_managed_and_strips_secrets() -> None:
    capture = _canned_capture(with_secrets=True)
    interfaces = collect_interfaces(capture)
    by_name = {row["name"]: row for row in interfaces}
    assert by_name["bridge-guest"]["is_wyfy_managed"] is True
    assert by_name["vlan100"]["is_wyfy_managed"] is True
    assert by_name["ether1"]["is_wyfy_managed"] is False
    # Secrets must never appear on the persisted interface shape.
    assert "private-key" not in by_name["wg1"]
    assert "password" not in by_name["wg1"]
    assert "SHOULD_NEVER_PERSIST" not in str(by_name["wg1"])
    assert "also-secret" not in str(by_name["wg1"])


def test_collect_firewall_summary_is_counts_only() -> None:
    capture = _canned_capture()
    summary = collect_firewall_summary(capture)
    assert summary == {
        "total_count": 3,
        "wyfy_tagged_count": 1,
        "disabled_count": 1,
    }
    # No rule bodies leaked into the summary.
    assert set(summary.keys()) == {
        "total_count",
        "wyfy_tagged_count",
        "disabled_count",
    }


def test_collect_snapshot_fields_builds_complete_payload() -> None:
    capture = _canned_capture()
    fields = collect_snapshot_fields(capture)
    assert fields["status"] == SnapshotStatus.COMPLETE.value
    assert fields["snapshot_version"] == SNAPSHOT_SCHEMA_VERSION
    assert fields["model"] == "RB4011iGS+"
    assert fields["routeros_version"] == "7.15.3 (stable)"
    assert fields["architecture"] == "arm"
    assert fields["total_memory_bytes"] == 1073741824
    assert fields["free_memory_bytes"] == 536870912
    assert fields["free_storage_bytes"] == 10485760
    assert fields["firewall_summary"]["wyfy_tagged_count"] == 1
    assert fields["nat_summary"]["total_count"] == 2
    assert fields["hotspot_state"]["server_count"] == 1
    assert any(p["name"] == "hotspot" for p in fields["packages"])
    assert fields["error_detail"] is None


def test_collect_snapshot_fields_partial_when_section_errors() -> None:
    capture = _canned_capture()
    capture.errors["hotspot_servers"] = "no such command prefix"
    fields = collect_snapshot_fields(capture)
    assert fields["status"] == SnapshotStatus.PARTIAL.value
    assert "hotspot_servers" in (fields["error_detail"] or "")


# ============================================================================
# Compatibility matrix
# ============================================================================


def test_compatibility_pass_healthy_routeros7() -> None:
    report = evaluate_compatibility_from_fields(
        routeros_version="7.15.3 (stable)",
        model="RB4011",
        free_memory_bytes=64 * 1024 * 1024,
        free_storage_bytes=20 * 1024 * 1024,
        packages=[{"name": "hotspot", "version": "7.15.3"}],
        hotspot_state={"server_count": 1},
    )
    assert report.overall == CompatibilityOverall.PASS
    assert all(c.status == CompatibilityCheckStatus.PASS for c in report.checks)


def test_compatibility_blocked_on_routeros6() -> None:
    report = evaluate_compatibility_from_fields(
        routeros_version="6.49.7",
        model="RB4011",
        free_memory_bytes=64 * 1024 * 1024,
        free_storage_bytes=20 * 1024 * 1024,
        packages=[{"name": "routeros"}],
        hotspot_state={},
    )
    assert report.overall == CompatibilityOverall.BLOCKED
    version_check = next(c for c in report.checks if c.name == "routeros_version")
    assert version_check.status == CompatibilityCheckStatus.BLOCKED


def test_compatibility_blocked_on_low_memory() -> None:
    report = evaluate_compatibility_from_fields(
        routeros_version="7.12",
        model="hAP",
        free_memory_bytes=4 * 1024 * 1024,  # < 8 MiB
        free_storage_bytes=20 * 1024 * 1024,
        packages=[{"name": "routeros"}],
        hotspot_state={},
    )
    assert report.overall == CompatibilityOverall.BLOCKED
    mem = next(c for c in report.checks if c.name == "free_memory")
    assert mem.status == CompatibilityCheckStatus.BLOCKED


def test_compatibility_warning_on_low_memory_band() -> None:
    report = evaluate_compatibility_from_fields(
        routeros_version="7.12",
        model="hAP",
        free_memory_bytes=12 * 1024 * 1024,  # 8–16 MiB
        free_storage_bytes=20 * 1024 * 1024,
        packages=[{"name": "routeros"}],
        hotspot_state={},
    )
    assert report.overall == CompatibilityOverall.WARNING
    mem = next(c for c in report.checks if c.name == "free_memory")
    assert mem.status == CompatibilityCheckStatus.WARNING


def test_compatibility_blocked_on_low_storage() -> None:
    report = evaluate_compatibility_from_fields(
        routeros_version="7.12",
        model="hAP",
        free_memory_bytes=64 * 1024 * 1024,
        free_storage_bytes=1 * 1024 * 1024,  # < 2 MiB
        packages=[{"name": "routeros"}],
        hotspot_state={},
    )
    assert report.overall == CompatibilityOverall.BLOCKED
    storage = next(c for c in report.checks if c.name == "free_storage")
    assert storage.status == CompatibilityCheckStatus.BLOCKED


def test_compatibility_warning_when_model_and_memory_missing() -> None:
    report = evaluate_compatibility_from_fields(
        routeros_version="7.12",
        model=None,
        free_memory_bytes=None,
        free_storage_bytes=None,
        packages=[{"name": "routeros"}],
        hotspot_state={},
    )
    assert report.overall == CompatibilityOverall.WARNING
    by_name = {c.name: c for c in report.checks}
    assert by_name["model"].status == CompatibilityCheckStatus.WARNING
    assert by_name["free_memory"].status == CompatibilityCheckStatus.WARNING
    assert by_name["free_storage"].status == CompatibilityCheckStatus.WARNING


def test_compatibility_warning_when_packages_empty() -> None:
    report = evaluate_compatibility_from_fields(
        routeros_version="7.12",
        model="RB4011",
        free_memory_bytes=64 * 1024 * 1024,
        free_storage_bytes=20 * 1024 * 1024,
        packages=[],
        hotspot_state={"server_count": 0},
    )
    assert report.overall == CompatibilityOverall.WARNING
    hotspot = next(c for c in report.checks if c.name == "hotspot_package")
    assert hotspot.status == CompatibilityCheckStatus.WARNING


# ============================================================================
# DiscoveryService with mocked reader
# ============================================================================


@dataclass
class FakeSnapshotRepository:
    rows: list[RouterSnapshot] = field(default_factory=list)

    async def create(self, data: dict[str, object]) -> RouterSnapshot:
        row = RouterSnapshot(**_base_fields(**data))
        self.rows.append(row)
        return row

    async def get_by_id(self, snapshot_id: uuid.UUID) -> RouterSnapshot | None:
        for row in self.rows:
            if row.id == snapshot_id:
                return row
        return None

    async def get_for_router(
        self, router_id: uuid.UUID, snapshot_id: uuid.UUID
    ) -> RouterSnapshot | None:
        for row in self.rows:
            if row.router_id == router_id and row.id == snapshot_id:
                return row
        return None

    async def list_for_router(
        self, router_id: uuid.UUID, *, limit: int = 10
    ) -> list[RouterSnapshot]:
        matched = [row for row in self.rows if row.router_id == router_id]
        matched.sort(key=lambda r: r.captured_at, reverse=True)
        return matched[:limit]

    async def get_latest_for_router(
        self, router_id: uuid.UUID
    ) -> RouterSnapshot | None:
        rows = await self.list_for_router(router_id, limit=1)
        return rows[0] if rows else None


@dataclass
class FakeRouterLookup:
    router: Router
    secret: str = "device-secret"

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Router:
        assert router_id == self.router.id
        return self.router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secret


class FakeReader:
    def __init__(self, creds: object, capture: ReadOnlyStateCapture) -> None:
        self.creds = creds
        self._capture = capture

    async def read_all(self, sections: object = None) -> ReadOnlyStateCapture:
        return self._capture


@pytest.mark.asyncio
async def test_discovery_service_persists_snapshot_and_compatibility() -> None:
    router = _make_router()
    capture = _canned_capture()
    repo = FakeSnapshotRepository()
    lookup = FakeRouterLookup(router=router)

    def reader_factory(creds: object) -> FakeReader:
        return FakeReader(creds, capture)

    service = DiscoveryService(repo, lookup, reader_factory=reader_factory)
    result = await service.discover_router(
        router.id, trigger=SnapshotTrigger.WIZARD_DISCOVERY
    )

    assert len(repo.rows) == 1
    assert result.snapshot.status == SnapshotStatus.COMPLETE
    assert repo.rows[0].snapshot_version == SNAPSHOT_SCHEMA_VERSION
    assert result.snapshot.snapshot_version == SNAPSHOT_SCHEMA_VERSION
    assert result.snapshot.model == "RB4011iGS+"
    assert result.compatibility.overall == CompatibilityOverall.PASS
    assert any(i.is_wyfy_managed for i in result.snapshot.interfaces)

    listed = await service.list_snapshots(router.id, limit=5)
    assert listed.total == 1
    assert listed.snapshots[0].id == result.snapshot.id

    compat = await service.get_compatibility(router.id)
    assert compat.overall == CompatibilityOverall.PASS


@pytest.mark.asyncio
async def test_discovery_service_stamps_version_on_failed_snapshot() -> None:
    """A connection failure still persists an audit-trail row -- and that
    row must carry the collector schema version like any other snapshot."""
    router = _make_router()
    repo = FakeSnapshotRepository()
    lookup = FakeRouterLookup(router=router)

    class ExplodingReader:
        def __init__(self, creds: object) -> None:
            self.creds = creds

        async def read_all(self, sections: object = None) -> ReadOnlyStateCapture:
            raise MikroTikConnectionError("203.0.113.7", "connection refused")

    service = DiscoveryService(repo, lookup, reader_factory=ExplodingReader)
    with pytest.raises(DiscoveryDeviceConnectionError):
        await service.discover_router(
            router.id, trigger=SnapshotTrigger.WIZARD_DISCOVERY
        )

    assert len(repo.rows) == 1
    failed = repo.rows[0]
    assert failed.status == SnapshotStatus.FAILED.value
    assert failed.snapshot_version == SNAPSHOT_SCHEMA_VERSION
    assert failed.error_detail


# ============================================================================
# Live-venue Phase B — managed resource backfill on discover
# ============================================================================


def test_build_managed_resource_backfill_rows_from_snapshot() -> None:
    capture = _canned_capture()
    fields = collect_snapshot_fields(capture)
    router_id = uuid.uuid4()
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    applied_at = _now()
    rows = build_managed_resource_backfill_rows(
        fields,
        capture,
        router_id=router_id,
        organization_id=org_id,
        location_id=loc_id,
        applied_at=applied_at,
    )
    tags = {row["comment_tag"] for row in rows}
    assert "WYFYGUEST-guest-bridge" in tags
    assert "cloudguest-vlan-100" in tags
    assert "WYFYGUEST-dhcp" in tags
    assert "WYFYGUEST-hotspot" in tags
    assert "WYFYGUEST-accept-guest" in tags
    assert "WYFYGUEST-masq" in tags
    assert all(row["plan_id"] is None for row in rows)
    assert all(row["status"] == ManagedResourceStatus.APPLIED.value for row in rows)
    assert all(row["router_id"] == router_id for row in rows)


@dataclass
class FakeManagedResourceRepository:
    replaced: list[tuple[uuid.UUID, list[dict[str, object]]]] = field(
        default_factory=list
    )

    async def replace_discovery_backfill(
        self, router_id: uuid.UUID, rows: list[dict[str, object]]
    ) -> list[object]:
        self.replaced.append((router_id, rows))
        return rows


@pytest.mark.asyncio
async def test_discovery_service_backfills_managed_resources_on_success() -> None:
    router = _make_router()
    capture = _canned_capture()
    repo = FakeSnapshotRepository()
    lookup = FakeRouterLookup(router=router)
    managed_repo = FakeManagedResourceRepository()

    def reader_factory(creds: object) -> FakeReader:
        return FakeReader(creds, capture)

    service = DiscoveryService(
        repo,
        lookup,
        managed_resource_repository=managed_repo,
        reader_factory=reader_factory,
    )
    await service.discover_router(router.id, trigger=SnapshotTrigger.MANUAL)

    assert len(managed_repo.replaced) == 1
    router_id, rows = managed_repo.replaced[0]
    assert router_id == router.id
    assert len(rows) >= 5
    assert all(row["plan_id"] is None for row in rows)
