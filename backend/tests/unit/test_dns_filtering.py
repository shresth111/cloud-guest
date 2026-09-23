"""Cloudflare Gateway DNS filtering: client, profiles, ceilings, the router
switch and its rollback, disable, controller refusal, and pinned scopes.

Nothing here reaches Cloudflare, a router or a database:

* Cloudflare is ``httpx.MockTransport`` (client tests) or an in-memory fake
  implementing ``GatewayClientProtocol`` (service tests).
* The router is a fake ``librouteros`` connection patched into the vendored
  gateway, so the end-to-end tests run the real ``device_adapters`` ->
  ``wyfy_device_gateway.mikrotik_dns_filtering`` path, rollback included.
* The repository is an in-memory fake of ``DnsFilteringRepositoryProtocol``.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from librouteros.exceptions import LibRouterosError
from pydantic import SecretStr

from app.domains.dns_filtering.cloudflare_client import (
    REDACTED,
    CloudflareApiError,
    CloudflareGatewayClient,
    GatewayCategory,
    GatewayLocation,
    GatewayRule,
)
from app.domains.dns_filtering.constants import (
    RouterFilteringState,
    build_rule_traffic,
    doh_url,
    gateway_location_name,
    profile_fingerprint,
)
from app.domains.dns_filtering.exceptions import (
    CategoryNotSelectableError,
    CloudflareGatewayCeilingError,
    CloudflareNotConfiguredError,
    CrossLocationDnsFilteringAccessError,
    DnsFilteringDeviceOperationError,
    DnsFilteringNoCategoriesError,
    UnknownCategoryError,
)
from app.domains.dns_filtering.models import (
    DnsFilteringPolicy,
    DnsFilteringProfile,
    DnsFilteringRouterLocation,
)
from app.domains.dns_filtering.router import router as dns_filtering_router
from app.domains.dns_filtering.service import CategoryCache, DnsFilteringService
from app.domains.rbac.enums import AuditAction, ScopeType
from app.domains.router.device_domain_gate import (
    ControllerManagedFeatureUnavailableError,
)
from app.domains.router.exceptions import RouterNotFoundError

_TOKEN = "cf-test-token-7f3a9c1e2b4d"
_ACCOUNT = "acc123"


# ============================================================================
# 1. The Cloudflare client
# ============================================================================


def _client(handler) -> CloudflareGatewayClient:
    return CloudflareGatewayClient(
        api_token=SecretStr(_TOKEN),
        account_id=_ACCOUNT,
        transport=httpx.MockTransport(handler),
    )


class TestClient:
    async def test_sends_the_bearer_token_and_the_documented_shapes(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if request.url.path.endswith("/locations"):
                return httpx.Response(
                    200,
                    json={
                        "success": True,
                        "result": {"id": "loc1", "name": "n", "doh_subdomain": "abc"},
                    },
                )
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "result": {"id": "rule1", "name": "r", "traffic": "t"},
                },
            )

        client = _client(handler)
        location = await client.create_location("wyfy-router-x")
        rule = await client.create_rule(
            name="wyfy-profile-p", description="d", traffic="t", precedence=10000
        )
        await client.aclose()

        assert location == GatewayLocation(id="loc1", name="n", doh_subdomain="abc")
        assert rule.id == "rule1"
        assert seen[0].headers["Authorization"] == f"Bearer {_TOKEN}"
        assert seen[0].url.path == f"/client/v4/accounts/{_ACCOUNT}/gateway/locations"
        loc_body = json.loads(seen[0].content)
        assert loc_body["endpoints"]["doh"]["enabled"] is True
        assert loc_body["endpoints"]["ipv4"]["enabled"] is False
        rule_body = json.loads(seen[1].content)
        assert rule_body["action"] == "block"
        assert rule_body["filters"] == ["dns"]
        assert rule_body["precedence"] == 10000

    async def test_an_error_body_echoing_the_token_is_redacted(self, caplog) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403,
                json={
                    "success": False,
                    "errors": [
                        {"code": 10000, "message": f"Authentication error for {_TOKEN}"}
                    ],
                },
            )

        client = _client(handler)
        with caplog.at_level(logging.DEBUG), pytest.raises(CloudflareApiError) as exc:
            await client.list_categories()
        await client.aclose()

        assert _TOKEN not in str(exc.value)
        assert REDACTED in str(exc.value)
        assert exc.value.status_code == 403
        assert exc.value.codes == (10000,)
        assert _TOKEN not in caplog.text

    async def test_a_transport_error_is_redacted(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"boom {request.headers['Authorization']}")

        client = _client(handler)
        with pytest.raises(CloudflareApiError) as exc:
            await client.list_locations()
        await client.aclose()
        assert _TOKEN not in str(exc.value)
        assert exc.value.__cause__ is None  # the raw exception is not chained

    def test_the_token_is_not_in_the_repr(self) -> None:
        client = _client(lambda r: httpx.Response(200))
        assert _TOKEN not in repr(client)

    def test_the_token_is_a_secret_in_settings(self) -> None:
        from app.core.config import Settings

        settings = Settings(cloudflare_api_token=_TOKEN)
        assert _TOKEN not in repr(settings)
        assert _TOKEN not in str(settings.model_dump())

    async def test_deleting_something_already_gone_is_success(self) -> None:
        client = _client(lambda r: httpx.Response(404, json={"success": False}))
        await client.delete_location("gone")
        await client.delete_rule("gone")
        await client.aclose()


def test_rule_traffic_expression() -> None:
    traffic = build_rule_traffic(
        content_ids=[7, 2], security_ids=[117], location_ids=["b", "a"]
    )
    assert traffic == (
        "(any(dns.content_category[*] in {2 7}) or "
        'any(dns.security_category[*] in {117})) and dns.location in {"a" "b"}'
    )
    assert build_rule_traffic(content_ids=[2], security_ids=[], location_ids=["a"]) == (
        'any(dns.content_category[*] in {2}) and dns.location in {"a"}'
    )


def test_profile_fingerprint_ignores_order_and_duplicates() -> None:
    assert profile_fingerprint([3, 1, 2]) == profile_fingerprint([1, 2, 3, 3])
    assert profile_fingerprint([1, 2]) != profile_fingerprint([1, 2, 3])


def test_location_name_is_keyed_on_the_router_uuid_only() -> None:
    rid = uuid.uuid4()
    assert gateway_location_name(rid) == f"wyfy-router-{rid}"


# ============================================================================
# Fakes
# ============================================================================


def _base(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


_ROW_DEFAULTS = {
    "cf_location_id": None,
    "doh_subdomain": None,
    "applied_profile_id": None,
    "dns_snapshot": None,
    "routeros_version": None,
    "device_push_error": None,
    "device_pushed_at": None,
    "bypass_hardening_enabled": False,
    "bypass_hardening_status": "off",
    "bypass_hardening_error": None,
}


@dataclass
class FakeRepo:
    profiles: dict[uuid.UUID, DnsFilteringProfile] = field(default_factory=dict)
    policies: dict[uuid.UUID, DnsFilteringPolicy] = field(default_factory=dict)
    rows: dict[uuid.UUID, DnsFilteringRouterLocation] = field(default_factory=dict)
    extra_cf_locations: int = 0
    commits: int = 0

    async def get_profile(self, profile_id):
        return self.profiles.get(profile_id)

    async def get_profile_by_fingerprint(self, fingerprint):
        return next(
            (p for p in self.profiles.values() if p.fingerprint == fingerprint), None
        )

    async def create_profile(self, **fields):
        fields.setdefault("cf_rule_id", None)
        profile = DnsFilteringProfile(**_base(**fields))
        self.profiles[profile.id] = profile
        return profile

    async def next_rule_precedence(self):
        return 10_000 + len(self.profiles)

    async def lock_profile(self, profile_id):
        return self.profiles.get(profile_id)

    async def update_profile(self, profile, data):
        for k, v in data.items():
            setattr(profile, k, v)
        return profile

    async def count_profiles_with_rule(self):
        return sum(1 for p in self.profiles.values() if p.cf_rule_id)

    async def get_policy(self, organization_id, location_id):
        return next(
            (
                p
                for p in self.policies.values()
                if p.organization_id == organization_id and p.location_id == location_id
            ),
            None,
        )

    async def create_policy(self, **fields):
        policy = DnsFilteringPolicy(**_base(**fields))
        self.policies[policy.id] = policy
        return policy

    async def update_policy(self, policy, data):
        for k, v in data.items():
            setattr(policy, k, v)
        return policy

    async def get_router_location(self, router_id):
        return next((r for r in self.rows.values() if r.router_id == router_id), None)

    async def create_router_location(self, **fields):
        row = DnsFilteringRouterLocation(**_base(**{**_ROW_DEFAULTS, **fields}))
        self.rows[row.id] = row
        return row

    async def update_router_location(self, row, data):
        for k, v in data.items():
            setattr(row, k, v)
        return row

    async def count_cloudflare_locations(self):
        return self.extra_cf_locations + sum(
            1 for r in self.rows.values() if r.cf_location_id
        )

    async def list_profile_members(self, profile_id):
        return [
            r
            for r in self.rows.values()
            if r.applied_profile_id == profile_id and r.cf_location_id
        ]

    async def list_enabled_in_scope(self, organization_id, location_id):
        return [
            r
            for r in self.rows.values()
            if r.organization_id == organization_id
            and r.state != RouterFilteringState.DISABLED.value
            and (location_id is None or r.location_id == location_id)
        ]

    async def commit(self):
        self.commits += 1


_CATALOGUE = [
    GatewayCategory(
        2,
        "Adult Themes",
        "",
        "free",
        False,
        (GatewayCategory(133, "Pornography", "", "free", False, ()),),
    ),
    GatewayCategory(7, "Gambling", "", "free", False, ()),
    GatewayCategory(
        21,
        "Security threats",
        "",
        "free",
        False,
        (
            GatewayCategory(117, "Malware", "", "free", False, ()),
            GatewayCategory(131, "Phishing", "", "free", False, ()),
        ),
    ),
    GatewayCategory(99, "Legacy", "", "removalPending", False, ()),
]


@dataclass
class FakeGateway:
    locations: dict[str, GatewayLocation] = field(default_factory=dict)
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    fail: dict[str, CloudflareApiError] = field(default_factory=dict)

    def _maybe_fail(self, op: str) -> None:
        self.calls.append(op)
        if op in self.fail:
            raise self.fail[op]

    async def list_categories(self):
        self._maybe_fail("list_categories")
        return _CATALOGUE

    async def list_locations(self):
        self._maybe_fail("list_locations")
        return list(self.locations.values())

    async def create_location(self, name):
        self._maybe_fail("create_location")
        loc = GatewayLocation(
            id=f"cf-{uuid.uuid4().hex[:8]}",
            name=name,
            doh_subdomain=uuid.uuid4().hex[:10],
        )
        self.locations[loc.id] = loc
        return loc

    async def delete_location(self, location_id):
        self._maybe_fail("delete_location")
        self.locations.pop(location_id, None)

    async def create_rule(self, **body):
        self._maybe_fail("create_rule")
        rule_id = f"rule-{uuid.uuid4().hex[:8]}"
        self.rules[rule_id] = body
        return GatewayRule(id=rule_id, name=body["name"], traffic=body["traffic"])

    async def update_rule(self, rule_id, **body):
        self._maybe_fail("update_rule")
        self.rules[rule_id] = body
        return GatewayRule(id=rule_id, name=body["name"], traffic=body["traffic"])

    async def delete_rule(self, rule_id):
        self._maybe_fail("delete_rule")
        self.rules.pop(rule_id, None)


def _router(*, org=None, loc=None, vendor="mikrotik"):
    return SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=org or uuid.uuid4(),
        location_id=loc or uuid.uuid4(),
        name="Lobby router",
        vendor=vendor,
        management_ip_address="10.20.0.5",
        public_ip_address=None,
        api_username="wyfy",
    )


@dataclass
class FakeRouters:
    routers: dict[uuid.UUID, Any] = field(default_factory=dict)

    def add(self, router):
        self.routers[router.id] = router
        return router

    async def get_router(
        self, router_id, *, requesting_organization_id=None, include_deleted=False
    ):
        router = self.routers.get(router_id)
        if router is None or (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router

    def get_decrypted_api_secret(self, router):
        return "router-api-secret"


@dataclass
class FakeLocations:
    async def get_location(
        self, location_id, *, requesting_organization_id=None, include_deleted=False
    ):
        org = FakeLocations.owners[location_id]
        if requesting_organization_id is not None and requesting_organization_id != org:
            raise RouterNotFoundError(location_id)
        return SimpleNamespace(id=location_id, organization_id=org)

    owners: dict = None  # type: ignore[assignment]


FakeLocations.owners = {}


@dataclass
class FakeAudit:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields):
        self.entries.append(fields)


@dataclass
class FakeAdapter:
    vendor: str = "mikrotik"
    calls: list[tuple[str, dict]] = field(default_factory=list)
    apply_error: Exception | None = None

    async def apply_doh(self, credentials, **kw):
        self.calls.append(("apply_doh", kw))
        if self.apply_error:
            raise self.apply_error
        from wyfy_device_gateway.mikrotik_dns_filtering import (
            DnsResolverSnapshot,
            DohApplyResult,
        )

        return DohApplyResult(
            snapshot=DnsResolverSnapshot(use_doh_server="", verify_doh_cert=False),
            changed=True,
            probe_address="1.2.3.4",
            routeros_version="7.23.3 (stable)",
        )

    async def restore_dns(self, credentials, **kw):
        self.calls.append(("restore_dns", kw))
        from wyfy_device_gateway.mikrotik_dns_filtering import DnsRestoreResult

        return DnsRestoreResult(changed=True, probe_ok=True, probe_error=None)

    async def apply_bypass_hardening(self, credentials):
        self.calls.append(("apply_bypass_hardening", {}))

    async def remove_bypass_hardening(self, credentials):
        self.calls.append(("remove_bypass_hardening", {}))


@dataclass
class Harness:
    repo: FakeRepo
    routers: FakeRouters
    gateway: FakeGateway | None
    audit: FakeAudit
    service: DnsFilteringService

    def add_location(self, org: uuid.UUID) -> uuid.UUID:
        loc = uuid.uuid4()
        FakeLocations.owners[loc] = org
        return loc


def _harness(*, gateway=True, scope=None, max_locations=250, max_rules=500) -> Harness:
    repo = FakeRepo()
    routers = FakeRouters()
    gw = FakeGateway() if gateway else None
    audit = FakeAudit()
    service = DnsFilteringService(
        repo,
        routers,
        FakeLocations(),
        gateway=gw,
        audit_writer=audit,
        caller_location_scope=scope,
        max_locations=max_locations,
        max_dns_rules=max_rules,
        category_cache=CategoryCache(),
    )
    return Harness(repo, routers, gw, audit, service)


@pytest.fixture
def adapter(monkeypatch) -> FakeAdapter:
    fake = FakeAdapter()
    monkeypatch.setattr(
        "app.domains.dns_filtering.service.get_dns_filtering_adapter",
        lambda vendor: fake,
    )
    return fake


async def _venue_with_router(h: Harness, categories: list[int], org=None):
    org = org or uuid.uuid4()
    loc = h.add_location(org)
    await h.service.set_location_policy(
        loc,
        category_ids=categories,
        actor_user_id=None,
        requesting_organization_id=None,
    )
    router = h.routers.add(_router(org=org, loc=loc))
    return org, loc, router


# ============================================================================
# 2. Profiles are shared, not per venue
# ============================================================================


class TestProfiles:
    async def test_same_categories_in_two_orgs_share_one_rule(self, adapter) -> None:
        h = _harness()
        _, _, r1 = await _venue_with_router(h, [7, 2])
        _, _, r2 = await _venue_with_router(h, [2, 7, 7])

        await h.service.enable_router(
            r1.id, actor_user_id=None, requesting_organization_id=None
        )
        await h.service.enable_router(
            r2.id, actor_user_id=None, requesting_organization_id=None
        )

        assert len(h.repo.profiles) == 1
        assert len(h.gateway.rules) == 1
        (rule,) = h.gateway.rules.values()
        for row in h.repo.rows.values():
            assert f'"{row.cf_location_id}"' in rule["traffic"]
        assert "any(dns.content_category[*] in {2 7})" in rule["traffic"]

    async def test_a_different_set_gets_its_own_rule_with_security_selector(
        self, adapter
    ) -> None:
        h = _harness()
        _, _, r1 = await _venue_with_router(h, [7])
        _, _, r2 = await _venue_with_router(h, [117, 131, 2])
        for r in (r1, r2):
            await h.service.enable_router(
                r.id, actor_user_id=None, requesting_organization_id=None
            )

        assert len(h.gateway.rules) == 2
        traffic = {body["traffic"] for body in h.gateway.rules.values()}
        assert any(
            "any(dns.content_category[*] in {2})" in t
            and "any(dns.security_category[*] in {117 131})" in t
            for t in traffic
        )

    async def test_changing_a_venue_moves_it_between_rules_and_frees_the_empty_one(
        self, adapter
    ) -> None:
        h = _harness()
        org, loc, r1 = await _venue_with_router(h, [7])
        await h.service.enable_router(
            r1.id, actor_user_id=None, requesting_organization_id=None
        )
        (old_rule,) = h.gateway.rules

        await h.service.set_location_policy(
            loc, category_ids=[2], actor_user_id=None, requesting_organization_id=None
        )

        assert old_rule not in h.gateway.rules  # the 500-slot budget got one back
        (body,) = h.gateway.rules.values()
        assert "{2}" in body["traffic"]
        # New rule written before the old one was deleted: never unfiltered.
        assert h.gateway.calls.index("create_rule", 1) < h.gateway.calls.index(
            "delete_rule"
        )

    async def test_org_default_applies_until_the_venue_overrides(self, adapter) -> None:
        h = _harness()
        org = uuid.uuid4()
        loc = h.add_location(org)
        await h.service.set_organization_policy(
            org, category_ids=[7], actor_user_id=None
        )
        router = h.routers.add(_router(org=org, loc=loc))

        _, _, effective = await h.service.get_router_status(
            router.id, requesting_organization_id=None
        )
        assert effective.source == "organization"
        assert effective.category_ids == [7]

    async def test_unknown_and_unselectable_categories_are_refused(self) -> None:
        h = _harness()
        loc = h.add_location(uuid.uuid4())
        with pytest.raises(UnknownCategoryError):
            await h.service.set_location_policy(
                loc,
                category_ids=[4242],
                actor_user_id=None,
                requesting_organization_id=None,
            )
        with pytest.raises(CategoryNotSelectableError):
            await h.service.set_location_policy(
                loc,
                category_ids=[99],
                actor_user_id=None,
                requesting_organization_id=None,
            )

    async def test_categories_are_cached(self) -> None:
        h = _harness()
        await h.service.list_categories()
        await h.service.list_categories()
        assert h.gateway.calls.count("list_categories") == 1


# ============================================================================
# 3. Ceilings
# ============================================================================


class TestCeilings:
    async def test_the_250th_location_is_the_last(self, adapter) -> None:
        h = _harness(max_locations=250)
        h.repo.extra_cf_locations = 250
        _, _, router = await _venue_with_router(h, [7])

        with pytest.raises(CloudflareGatewayCeilingError) as exc:
            await h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            )

        assert exc.value.status_code == 409
        assert "250" in exc.value.message
        assert "create_location" not in h.gateway.calls
        assert adapter.calls == []

    async def test_the_249th_still_fits(self, adapter) -> None:
        h = _harness(max_locations=250)
        h.repo.extra_cf_locations = 249
        _, _, router = await _venue_with_router(h, [7])
        await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        assert "create_location" in h.gateway.calls

    async def test_the_rule_ceiling_refuses_a_new_profile(self, adapter) -> None:
        h = _harness(max_rules=1)
        _, _, r1 = await _venue_with_router(h, [7])
        _, _, r2 = await _venue_with_router(h, [2])
        await h.service.enable_router(
            r1.id, actor_user_id=None, requesting_organization_id=None
        )
        with pytest.raises(CloudflareGatewayCeilingError):
            await h.service.enable_router(
                r2.id, actor_user_id=None, requesting_organization_id=None
            )


# ============================================================================
# 4. Enable / disable lifecycle (fake adapter)
# ============================================================================


class TestLifecycle:
    async def test_enable_records_the_snapshot_and_audits(self, adapter) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])

        row = await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )

        assert row.state == "active"
        assert row.dns_snapshot == {
            "use_doh_server": "",
            "verify_doh_cert": False,
            "trust_setting": None,
            "trust_setting_value": None,
        }
        assert row.cf_location_name == f"wyfy-router-{router.id}"
        (call,) = adapter.calls
        assert call[1]["doh_url"] == doh_url(row.doh_subdomain)
        assert AuditAction.DNS_FILTERING_ENABLED.value in [
            e["action"] for e in h.audit.entries
        ]

    async def test_a_crashed_create_is_adopted_not_duplicated(self, adapter) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        orphan = GatewayLocation(
            id="cf-orphan", name=gateway_location_name(router.id), doh_subdomain="zzz"
        )
        h.gateway.locations[orphan.id] = orphan

        row = await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )

        assert row.cf_location_id == "cf-orphan"
        assert "create_location" not in h.gateway.calls

    async def test_a_failed_switch_is_committed_then_raised(self, adapter) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        error = DnsFilteringDeviceOperationError(
            "apply_doh",
            "DOH_PROBE_FAILED: x; previous DNS settings restored",
            code="DOH_PROBE_FAILED",
            rolled_back=True,
        )
        adapter.apply_error = error

        with pytest.raises(DnsFilteringDeviceOperationError):
            await h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            )

        row = await h.repo.get_router_location(router.id)
        assert row.state == "failed"
        assert "DOH_PROBE_FAILED" in row.device_push_error
        assert error.data["rolled_back"] is True

    async def test_repush_keeps_the_original_snapshot(self, adapter) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        row = await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        row.dns_snapshot = {
            "use_doh_server": "https://isp.example/dns-query",
            "verify_doh_cert": True,
        }

        await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )

        assert (
            adapter.calls[-1][1]["rollback_to"]["use_doh_server"]
            == "https://isp.example/dns-query"
        )
        assert row.dns_snapshot["use_doh_server"] == "https://isp.example/dns-query"
        assert h.gateway.calls.count("create_location") == 1

    async def test_no_categories_is_refused_before_anything(self, adapter) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [])
        with pytest.raises(DnsFilteringNoCategoriesError):
            await h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            )
        assert h.gateway.calls == []

    async def test_disable_restores_the_router_first_then_releases_cloudflare(
        self, adapter
    ) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        h.gateway.calls.clear()

        row = await h.service.disable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )

        assert adapter.calls[-1][0] == "restore_dns"
        assert row.state == "disabled"
        assert row.cf_location_id is None
        assert h.gateway.locations == {}
        assert h.gateway.rules == {}
        assert row.dns_snapshot is None

    async def test_disable_with_cloudflare_down_still_restores_the_router(
        self, adapter
    ) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        h.gateway.fail["delete_rule"] = CloudflareApiError(
            "delete_rule", "down", status_code=500
        )

        with pytest.raises(Exception):  # noqa: B017 -- CloudflareSyncError
            await h.service.disable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            )

        row = await h.repo.get_router_location(router.id)
        assert adapter.calls[-1][0] == "restore_dns"
        assert row.state == "disabled"

        # Retrying finishes Cloudflare only; the router is not touched again.
        h.gateway.fail.clear()
        restores = sum(1 for c in adapter.calls if c[0] == "restore_dns")
        await h.service.disable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        assert sum(1 for c in adapter.calls if c[0] == "restore_dns") == restores
        assert row.cf_location_id is None

    async def test_bypass_hardening_is_opt_in_and_needs_an_active_router(
        self, adapter
    ) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        from app.domains.dns_filtering.exceptions import DnsFilteringNotEnabledError

        with pytest.raises(DnsFilteringNotEnabledError):
            await h.service.set_bypass_hardening(
                router.id,
                enabled=True,
                actor_user_id=None,
                requesting_organization_id=None,
            )
        row = await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        assert row.bypass_hardening_enabled is False
        assert not any(c[0] == "apply_bypass_hardening" for c in adapter.calls)

        row = await h.service.set_bypass_hardening(
            router.id, enabled=True, actor_user_id=None, requesting_organization_id=None
        )
        assert row.bypass_hardening_status == "active"
        # Disable removes it before restoring DNS.
        await h.service.disable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        names = [c[0] for c in adapter.calls]
        assert names.index("remove_bypass_hardening") < names.index("restore_dns")

    async def test_not_configured_is_503(self, adapter) -> None:
        h = _harness(gateway=False)
        org = uuid.uuid4()
        loc = h.add_location(org)
        router = h.routers.add(_router(org=org, loc=loc))
        await h.repo.create_policy(
            organization_id=org,
            location_id=loc,
            category_ids=[7],
            profile_id=uuid.uuid4(),
        )
        with pytest.raises(CloudflareNotConfiguredError) as exc:
            await h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            )
        assert exc.value.status_code == 503


# ============================================================================
# 5. Tenancy and the controller refusal
# ============================================================================


class TestIsolation:
    async def test_a_controller_managed_venue_is_refused_before_anything(
        self, adapter
    ) -> None:
        h = _harness()
        org = uuid.uuid4()
        router = h.routers.add(_router(org=org, vendor="tplink_omada"))

        for call in (
            h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            ),
            h.service.disable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            ),
            h.service.set_bypass_hardening(
                router.id,
                enabled=True,
                actor_user_id=None,
                requesting_organization_id=None,
            ),
        ):
            with pytest.raises(ControllerManagedFeatureUnavailableError) as exc:
                await call
            assert "Category filtering" in exc.value.message

        assert h.gateway.calls == []
        assert adapter.calls == []
        assert h.repo.rows == {}

    async def test_another_orgs_router_is_not_found(self, adapter) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        with pytest.raises(RouterNotFoundError):
            await h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=uuid.uuid4()
            )

    async def test_a_location_confined_caller_cannot_reach_another_site(
        self, adapter
    ) -> None:
        h = _harness(scope=frozenset({uuid.uuid4()}))
        org = uuid.uuid4()
        loc = h.add_location(org)
        router = h.routers.add(_router(org=org, loc=loc))
        with pytest.raises(CrossLocationDnsFilteringAccessError):
            await h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            )
        with pytest.raises(CrossLocationDnsFilteringAccessError):
            await h.service.set_location_policy(
                loc,
                category_ids=[7],
                actor_user_id=None,
                requesting_organization_id=None,
            )

    async def test_policy_org_comes_from_the_location_row_not_the_caller(
        self, adapter
    ) -> None:
        h = _harness()
        owner = uuid.uuid4()
        loc = h.add_location(owner)
        await h.service.set_location_policy(
            loc, category_ids=[7], actor_user_id=None, requesting_organization_id=None
        )
        (policy,) = h.repo.policies.values()
        assert policy.organization_id == owner


# ============================================================================
# 6. End to end through the real gateway writer, fake RouterOS
# ============================================================================


class _FakeRouterOS:
    """Just enough of librouteros for mikrotik_dns_filtering."""

    def __init__(self, *, probe_ok: bool = True, doh: str = "") -> None:
        self.menus: dict[tuple[str, ...], list[dict[str, Any]]] = {
            ("system", "resource"): [{"version": "7.23.3 (stable)"}],
            ("ip", "dns"): [
                {
                    "servers": "8.8.8.8",
                    "dynamic-servers": "",
                    "use-doh-server": doh,
                    "verify-doh-cert": False,
                }
            ],
            ("certificate", "settings"): [{"builtin-trust-store": "default"}],
            ("ip", "dns", "static"): [{".id": "*S1", "name": "facebook.com"}],
        }
        self.probe_ok = probe_ok
        self.writes: list[tuple[tuple[str, ...], dict]] = []

    def path(self, *segments):
        rows = self.menus.setdefault(segments, [])
        api = self

        class _Path:
            def __iter__(self):
                return iter(rows)

            def update(self, **fields):
                api.writes.append((segments, fields))
                for row in rows:
                    row.update(fields)

        return _Path()

    def __call__(self, cmd, **kwargs):
        if cmd == "/execute":
            if not self.probe_ok:
                raise LibRouterosError("failure: dns server failure")
            return iter([{"ret": "104.16.132.229"}])
        return iter([])

    def close(self):
        pass


@pytest.fixture
def fake_routeros(monkeypatch):
    import wyfy_device_gateway.mikrotik_adapter as mikrotik_adapter

    holder: dict[str, _FakeRouterOS] = {}

    def install(api: _FakeRouterOS) -> _FakeRouterOS:
        holder["api"] = api
        return api

    monkeypatch.setattr(
        mikrotik_adapter.librouteros, "connect", lambda **kw: holder["api"]
    )
    monkeypatch.setattr(
        "wyfy_device_gateway.mikrotik_dns_filtering.time.sleep", lambda s: None
    )
    return install


class TestEndToEnd:
    async def test_probe_failure_rolls_the_router_back(self, fake_routeros) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        api = fake_routeros(_FakeRouterOS(probe_ok=False, doh=""))

        with pytest.raises(DnsFilteringDeviceOperationError) as exc:
            await h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            )

        assert exc.value.status_code == 502
        assert exc.value.data["code"] == "DOH_PROBE_FAILED"
        assert exc.value.data["rolled_back"] is True
        assert api.menus[("ip", "dns")][0]["use-doh-server"] == ""
        row = await h.repo.get_router_location(router.id)
        assert row.state == "failed"
        assert "previous DNS settings restored" in row.device_push_error
        # Static DNS (the content-filter sinkhole) never written.
        assert all(seg != ("ip", "dns", "static") for seg, _ in api.writes)

    async def test_enable_then_disable_restores_the_original(
        self, fake_routeros
    ) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        api = fake_routeros(_FakeRouterOS(doh="https://isp.example/dns-query"))

        row = await h.service.enable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        assert api.menus[("ip", "dns")][0]["use-doh-server"] == doh_url(
            row.doh_subdomain
        )
        assert row.dns_snapshot["use_doh_server"] == "https://isp.example/dns-query"

        await h.service.disable_router(
            router.id, actor_user_id=None, requesting_organization_id=None
        )
        assert (
            api.menus[("ip", "dns")][0]["use-doh-server"]
            == "https://isp.example/dns-query"
        )

    async def test_old_routeros_is_a_409_with_nothing_written(
        self, fake_routeros
    ) -> None:
        h = _harness()
        _, _, router = await _venue_with_router(h, [7])
        api = _FakeRouterOS()
        api.menus[("system", "resource")] = [{"version": "7.16.2 (stable)"}]
        fake_routeros(api)

        with pytest.raises(DnsFilteringDeviceOperationError) as exc:
            await h.service.enable_router(
                router.id, actor_user_id=None, requesting_organization_id=None
            )
        assert exc.value.status_code == 409
        assert exc.value.data["code"] == "ROUTEROS_TOO_OLD"
        assert api.writes == []


# ============================================================================
# 7. Routes: every permission pinned to an explicit scope
# ============================================================================


def _permission_of(route) -> set[object]:
    for dep in route.dependant.dependencies:
        call = dep.call
        if getattr(call, "__qualname__", "").startswith("RequirePermission"):
            return {c.cell_contents for c in (call.__closure__ or ())}
    raise AssertionError(f"{route.path} has no RequirePermission")


_EXPECTED = {
    ("GET", "/dns-filtering/categories"): (
        "content_filtering.read",
        ScopeType.LOCATION,
    ),
    ("GET", "/dns-filtering/organizations/{organization_id}/policy"): (
        "content_filtering.read",
        ScopeType.ORGANIZATION,
    ),
    ("PUT", "/dns-filtering/organizations/{organization_id}/policy"): (
        "content_filtering.update",
        ScopeType.ORGANIZATION,
    ),
    ("GET", "/dns-filtering/locations/{location_id}/policy"): (
        "content_filtering.read",
        ScopeType.LOCATION,
    ),
    ("PUT", "/dns-filtering/locations/{location_id}/policy"): (
        "content_filtering.update",
        ScopeType.LOCATION,
    ),
    ("GET", "/dns-filtering/routers/{router_id}"): (
        "content_filtering.read",
        ScopeType.ROUTER,
    ),
    ("POST", "/dns-filtering/routers/{router_id}/enable"): (
        "content_filtering.execute",
        ScopeType.ROUTER,
    ),
    ("POST", "/dns-filtering/routers/{router_id}/disable"): (
        "content_filtering.execute",
        ScopeType.ROUTER,
    ),
    ("PUT", "/dns-filtering/routers/{router_id}/bypass-hardening"): (
        "content_filtering.execute",
        ScopeType.ROUTER,
    ),
}


class TestRoutes:
    def test_every_route_is_listed_and_pinned(self) -> None:
        seen = {}
        for route in dns_filtering_router.routes:
            for method in route.methods:
                seen[(method, route.path)] = _permission_of(route)
        assert set(seen) == set(_EXPECTED)
        for key, (permission, scope) in _EXPECTED.items():
            cells = seen[key]
            assert permission in cells, key
            assert scope in cells, f"{key} is not pinned to {scope}"
            assert None not in cells, f"{key} leaves the scope to inference"

    def test_the_reused_actions_are_seeded(self) -> None:
        from app.domains.rbac.enums import PermissionAction, PermissionModule
        from app.domains.rbac.seed import MODULE_ACTIONS

        actions = MODULE_ACTIONS[PermissionModule.CONTENT_FILTERING]
        for action in (
            PermissionAction.READ,
            PermissionAction.UPDATE,
            PermissionAction.EXECUTE,
        ):
            assert action in actions
