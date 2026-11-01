"""Batch B4 venue twins (ADDENDUM_04: Security, Fix a Problem, Devices).

The generic structural tests (guards, gate parity, body ids, handler fit,
header resolution) already walk these rows through ``VENUE_TWINS``. This file
pins what is specific to B4:

1. the Wyfy firewall band is never twinned (GLOBAL, Master-only);
2. the two DNS policy originals that read the tenant id from the PATH are
   twinned with NO id in the path, the org/location injected instead;
3. the location filter of the list endpoints that would otherwise fall back to
   "every location of the org" is always injected, never exposed;
4. the per-ISP-user diagnostics limit (10 runs a minute; reads are free);
5. every B4 row is gated by a B4 key, at the right action;
6. the rows really are mounted on the app.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.firewall import router as firewall_routes
from app.domains.isp_partner import twins_security_ops as b4
from app.domains.isp_partner.twins_all import ALL_TWINS as VENUE_TWINS

B4 = b4.SECURITY_OPS_TWINS


def _row(method: str, path: str):
    return next(s for s in B4 if s.method == method and s.path == path)


def test_b4_rows_are_part_of_venue_twins() -> None:
    assert all(any(s is v for v in VENUE_TWINS) for s in B4)  # ALL_TWINS
    assert len(B4) == 49


def test_the_wyfy_firewall_band_is_never_twinned() -> None:
    band_handlers = {
        firewall_routes.install_firewall_band,
        firewall_routes.get_firewall_band_status,
    }
    for spec in VENUE_TWINS:
        assert spec.handler not in band_handlers, spec.path
        assert "/band" not in spec.path, spec.path


@pytest.mark.parametrize(
    ("method", "path", "inject_key", "source"),
    [
        ("GET", "/venue/dns-filtering/organization-policy", "organization_id", "org"),
        ("PUT", "/venue/dns-filtering/organization-policy", "organization_id", "org"),
        ("GET", "/venue/dns-filtering/location-policy", "location_id", "location"),
        ("PUT", "/venue/dns-filtering/location-policy", "location_id", "location"),
    ],
)
def test_path_scoped_dns_policies_take_no_id(method, path, inject_key, source) -> None:
    spec = _row(method, path)
    assert "{" not in spec.path, "a tenant id in the path is the path-id defect"
    assert spec.target == "header_location"
    assert spec.inject[inject_key] == (source,)
    assert not [p for p in spec.params if p.source == "path"]


@pytest.mark.parametrize(
    "path", ["/venue/connected-devices", "/venue/monitored-hardware"]
)
def test_list_location_filter_is_injected_not_exposed(path: str) -> None:
    spec = _row("GET", path)
    assert spec.inject["location_id"] == ("location",)
    exposed = {p.name for p in spec.params} | {e.name for e in spec.extras}
    assert "location_id" not in exposed and "isp_location_id" not in exposed


def test_monitored_hardware_register_forces_the_header_location() -> None:
    spec = _row("POST", "/venue/monitored-hardware")
    modes = {b.field: b.mode for b in spec.body_ids}
    assert modes == {"location_id": "force_location", "router_id": "router"}


_EXPECTED_GROUP = {
    "security": "isp_security",
    "content-filter-rules": "isp_security",
    "dns-filtering": "isp_security",
    "firewall-rules": "isp_security",
    "network-diagnostics": "isp_ops",
    "connected-devices": "isp_monitor",
    "monitored-hardware": "isp_monitor",
}


@pytest.mark.parametrize("spec", B4, ids=[f"{s.method} {s.path}" for s in B4])
def test_every_b4_row_uses_its_b4_group(spec) -> None:
    feature = spec.path.split("/")[2]
    group, action = spec.permission_key.split(".")
    assert group == _EXPECTED_GROUP[feature]
    if spec.method == "GET" and group != "isp_ops":
        assert action == "read"
    if spec.method != "GET":
        assert action != "read"


class _FakeRedis:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.ttl: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.ttl[key] = seconds


def _req(method: str):
    return SimpleNamespace(method=method)


async def test_diagnostics_limit_per_isp_user() -> None:
    redis = _FakeRedis()
    service = object()
    alice = SimpleNamespace(id=str(uuid.uuid4()))
    bob = SimpleNamespace(id=str(uuid.uuid4()))
    limit = b4.DIAGNOSTICS_PER_USER_PER_MINUTE
    assert limit == 10
    for _ in range(limit):
        got = await b4.get_isp_rate_limited_diagnostics_service(
            _req("POST"), service, redis, alice
        )
        assert got is service
    with pytest.raises(b4.IspDiagnosticsRateLimitedError) as exc:
        await b4.get_isp_rate_limited_diagnostics_service(
            _req("POST"), service, redis, alice
        )
    assert exc.value.status_code == 429
    # another ISP user has their own budget, and reads are never counted
    assert (
        await b4.get_isp_rate_limited_diagnostics_service(
            _req("POST"), service, redis, bob
        )
        is service
    )
    assert (
        await b4.get_isp_rate_limited_diagnostics_service(
            _req("GET"), service, redis, alice
        )
        is service
    )
    assert all(ttl > 60 for ttl in redis.ttl.values())


def test_diagnostic_runs_use_the_rate_limited_service() -> None:
    for path in (
        "/venue/network-diagnostics/routers/{isp_router_id}/ping",
        "/venue/network-diagnostics/routers/{isp_router_id}/traceroute",
    ):
        spec = _row("POST", path)
        assert spec.deps["service"] is b4.get_isp_rate_limited_diagnostics_service
        assert spec.inject["scope_location_id"] == ("location",)


def test_b4_rows_are_mounted() -> None:
    from app.main import create_app

    mounted = {
        (m, r.path)
        for r in create_app().routes
        for m in (getattr(r, "methods", None) or ())
    }
    for spec in B4:
        assert (spec.method, f"/api/v1/isp{spec.path}") in mounted, spec.path
