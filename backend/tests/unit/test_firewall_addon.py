"""The Firewall add-on (``PlanFeatureKey.FIREWALL``).

* **Catalogue** -- a BOOLEAN add-on the Master console can switch, off by
  default, named for the add-on panel, needing no other add-on.
* **What it gates** -- every customer firewall route (rules, push, flood
  limit, guest isolation) and every Block Websites route (content filtering,
  DNS filtering), with the feature check before the permission check. Not
  the Master-only band routes, and not the read-only Security Check.
* **The guard** -- 402 ``feature_not_entitled`` naming ``firewall`` when off.
* **Grandfathering** -- migration 0178 writes an enabled override row, the
  same row the Master switch writes, for organizations already using it.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.routing import APIRoute

from app.domains.billing.constants import (
    ADDON_FEATURE_KEYS,
    BOOLEAN_FEATURE_KEYS,
    FEATURE_REQUIRES,
    PlanFeatureKey,
)
from app.domains.billing.exceptions import FeatureNotEntitledError

ORG = uuid.UUID("aaaaaaaa-0000-4000-8000-00000000000a")
KEY = PlanFeatureKey.FIREWALL
BAND = "/firewall-rules/routers/{router_id}/band"


def _closure(call: Any) -> list[Any]:
    return [c.cell_contents for c in (getattr(call, "__closure__", None) or ())]


def _is_addon_gate(call: Any) -> bool:
    return KEY in _closure(call)


def _calls(dependant: Any) -> list[Any]:
    found = [d.call for d in dependant.dependencies]
    for d in dependant.dependencies:
        found += _calls(d)
    return found


def _mounted() -> list[APIRoute]:
    from app.api.v1.router import api_v1_router

    return [r for r in api_v1_router.routes if isinstance(r, APIRoute)]


def _gated(route: APIRoute) -> bool:
    return any(_is_addon_gate(c) for c in _calls(route.dependant))


class _Checker:
    def __init__(self, *features: str) -> None:
        self.features = features

    async def get_snapshot(self, organization_id: uuid.UUID) -> Any:
        features = self.features
        return SimpleNamespace(has_feature=lambda key: key.value in features)


class TestCatalogue:
    def test_it_is_a_boolean_add_on_the_master_console_can_switch(self) -> None:
        assert KEY.value == "firewall"
        assert KEY in ADDON_FEATURE_KEYS and KEY in BOOLEAN_FEATURE_KEYS
        assert KEY not in FEATURE_REQUIRES
        assert KEY not in FEATURE_REQUIRES.values()

    async def test_off_by_default_and_named_for_the_panel(self) -> None:
        from app.domains.feature_entitlement.service import (
            FEATURE_META,
            FeatureEntitlementService,
        )

        listing = await FeatureEntitlementService(None, None).list_features()  # type: ignore[arg-type]
        (feature,) = [f for f in listing.features if f.key == "firewall"]
        assert feature.default_enabled is False and feature.type == "boolean"
        assert FEATURE_META[KEY][0] == "Firewall"


class TestWhatItGates:
    def test_every_firewall_route_but_the_band_is_gated(self) -> None:
        routes = [r for r in _mounted() if r.path.startswith("/firewall-rules")]
        assert len(routes) == 12
        for route in routes:
            assert _gated(route) is (route.path != BAND), (route.methods, route.path)

    def test_firewall_gate_runs_before_the_permission_check(self) -> None:
        from app.domains.firewall.router import router

        for route in router.routes:
            assert isinstance(route, APIRoute)
            if route.path == BAND:
                continue
            first = route.dependencies[0].dependency
            assert _is_addon_gate(first), route.path

    def test_every_block_websites_route_is_gated(self) -> None:
        prefixes = ("/content-filter-rules", "/dns-filtering")
        routes = [r for r in _mounted() if r.path.startswith(prefixes)]
        assert len(routes) >= 15
        for route in routes:
            assert _gated(route), (route.methods, route.path)

    def test_security_check_is_not_gated(self) -> None:
        routes = [r for r in _mounted() if r.path.startswith("/security")]
        assert routes
        for route in routes:
            assert not _gated(route), route.path

    def test_nothing_outside_the_section_is_gated(self) -> None:
        section = ("/firewall-rules", "/content-filter-rules", "/dns-filtering")
        stray = [
            r.path
            for r in _mounted()
            if _gated(r) and not r.path.startswith(section)
        ]
        assert stray == []


class TestGuard:
    def _guard(self) -> Any:
        from app.domains.firewall.router import _FIREWALL_ADDON

        return _FIREWALL_ADDON.dependency

    async def test_off_is_a_402_naming_the_feature(self) -> None:
        with pytest.raises(FeatureNotEntitledError) as exc:
            await self._guard()(organization_id=ORG, checker=_Checker("reports"))
        assert exc.value.status_code == 402
        assert exc.value.data == {
            "error_code": "feature_not_entitled",
            "feature_key": "firewall",
        }

    async def test_on_passes(self) -> None:
        guard = self._guard()
        assert await guard(organization_id=ORG, checker=_Checker("firewall")) == ORG

    async def test_no_organization_context_passes(self) -> None:
        assert await self._guard()(organization_id=None, checker=_Checker()) is None


class TestGrandfatherMigration:
    def _module(self) -> Any:
        versions = Path(__file__).resolve().parents[2] / "alembic" / "versions"
        path = versions / "0178_grandfather_firewall_addon.py"
        spec = importlib.util.spec_from_file_location("m0178", path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_it_writes_the_master_switch_row_for_this_key_only(self) -> None:
        module = self._module()
        assert KEY.value == module.FEATURE_KEY
        assert module.REASON.startswith("Grandfathered")
        assert len(module.REASON) <= 500  # organization_feature_overrides.reason

    def test_evidence_covers_rules_websites_and_router_switches(self) -> None:
        from app.domains.rbac.enums import AuditAction

        module = self._module()
        values = {a.value for a in AuditAction}
        assert set(module.AUDIT_ACTIONS) <= values
        for action in (
            AuditAction.FIREWALL_FLOOD_LIMIT_CHANGED,
            AuditAction.FIREWALL_GUEST_ISOLATION_CHANGED,
            AuditAction.DNS_FILTERING_BYPASS_HARDENING_CHANGED,
            AuditAction.CONTENT_FILTER_RULE_CREATED,
            AuditAction.FIREWALL_RULE_CREATED,
        ):
            assert action.value in module.AUDIT_ACTIONS

    def test_upgrade_reads_every_usage_table_and_skips_existing_overrides(self) -> None:
        module = self._module()
        executed: list[tuple[str, dict[str, Any]]] = []

        class _Bind:
            def execute(self, statement: Any, params: dict[str, Any]) -> None:
                executed.append((str(statement), params))

        module.op = SimpleNamespace(get_bind=lambda: _Bind())
        module.upgrade()
        ((sql, params),) = executed
        for table in (
            "firewall_rules",
            "content_filter_rules",
            "dns_filtering_policies",
            "dns_filtering_router_locations",
            "audit_log_entries",
        ):
            assert f"FROM {table}" in sql, table
        assert "NOT EXISTS" in sql and "f.deleted_at IS NULL" in sql
        assert params == {"feature_key": "firewall", "reason": module.REASON}

        executed.clear()
        module.downgrade()
        ((sql, params),) = executed
        assert sql.startswith("DELETE FROM organization_feature_overrides")
        assert "reason = :reason" in sql
        assert params == {"feature_key": "firewall", "reason": module.REASON}
