"""Speed tiers by WiFi network (SSID) at Aruba Instant On venues.

Covers: the SSID parse out of Called-Station-Id (incl. no SSID and odd
spellings), the entitlement matrix, the RADIUS authorize gate on a NAS-only
venue, MikroTik/Omada untouched, the input validation, the portal answer, the
Instant On sync (manual steps when off, preview/apply through the #348 client
shape when on), and the route scoping declarations.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.guest.ssid_tier_instant_on import (
    SyncReason,
    SyncStatus,
    match_network_ids,
    sync_ssid_tiers_to_instant_on,
)
from app.domains.guest.ssid_tier_service import (
    SsidTierInput,
    SsidTierService,
    SsidTierValidationError,
    instant_on_manual_steps,
    validate_inputs,
)
from app.domains.guest.ssid_tiers import (
    NO_ENTITLEMENT,
    GuestEntitlement,
    SsidDecisionReason,
    SsidTierRule,
    decide_ssid_access,
    entitles,
    ssid_from_called_station_id,
    upgrade_networks,
)
from app.domains.guest.validators import canonicalize_calling_station_id
from tests.unit.test_aruba_access_rules import (
    _ARUBA_CSID,
    _PHONE,
    _fixture,
    _register_nas,
    _sign_in,
)

PLAN_GOLD = uuid.UUID("00000000-0000-0000-0000-00000000a001")
PLAN_DAY = uuid.UUID("00000000-0000-0000-0000-00000000a002")
TIER = uuid.UUID("00000000-0000-0000-0000-00000000b001")

FREE = SsidTierRule("WYFY_FREE", "Free", False, download_mbps=5, upload_mbps=2)
PREMIUM = SsidTierRule(
    "WYFY_PREMIUM", "Premium", True, download_mbps=50, upload_mbps=20
)
PREMIUM_GOLD_ONLY = SsidTierRule(
    "WYFY_GOLD", "Gold", True, policy_id=TIER, voucher_plan_ids=(PLAN_GOLD,)
)
RULES = [FREE, PREMIUM]


# ============================================================================
# SSID out of Called-Station-Id
# ============================================================================


class TestSsidParse:
    @pytest.mark.parametrize(
        ("raw", "ssid"),
        [
            ("54-F0-B1-C8-A9-0A:WYFY_ARUBA", "WYFY_ARUBA"),  # measured on the AP21
            ("54-f0-b1-c8-a9-0a:WYFY_PREMIUM", "WYFY_PREMIUM"),
            ("54:F0:B1:C8:A9:0A:WYFY_FREE", "WYFY_FREE"),
            ("54F0B1C8A90A:WYFY_FREE", "WYFY_FREE"),
            ("54f0.b1c8.a90a:WYFY_FREE", "WYFY_FREE"),
            ("54-F0-B1-C8-A9-0A:Cafe:Guest", "Cafe:Guest"),  # ':' inside the SSID
            ("54-F0-B1-C8-A9-0A:My Cafe WiFi", "My Cafe WiFi"),  # spaces
            ("  54-F0-B1-C8-A9-0A:WYFY_FREE \r\n", "WYFY_FREE"),  # padding
            ("54-F0-B1-C8-A9-0A:कैफ़े", "कैफ़े"),  # non-ASCII
            ("54-F0-B1-C8-A9-0A:" + "x" * 32, "x" * 32),  # 32 = the 802.11 max
        ],
    )
    def test_ssid(self, raw: str, ssid: str) -> None:
        assert ssid_from_called_station_id(raw) == ssid

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "",
            "   ",
            "54-F0-B1-C8-A9-0A",  # bare MAC, no SSID
            "54F0B1C8A90A",
            "54-F0-B1-C8-A9-0A:",  # empty SSID
            "54-F0-B1-C8-A9-0A:   ",
            "WYFY_FREE",  # no MAC in front
            "54-F0-B1-C8-A9:WYFY_FREE",  # 5-octet MAC
            "54-F0-B1-C8-A9-0A-11:WYFY",  # 7 octets
            "54-F0-B1-C8-A9-0A;WYFY_FREE",  # wrong separator
            "54-F0-B1-C8-A9-0A:" + "x" * 33,  # longer than any SSID
        ],
    )
    def test_no_ssid(self, raw: str | None) -> None:
        assert ssid_from_called_station_id(raw) is None


# ============================================================================
# Entitlement matrix
# ============================================================================

FREE_GUEST = NO_ENTITLEMENT
VOUCHER_ANY = GuestEntitlement(voucher_plan_ids=frozenset({None}))
VOUCHER_GOLD = GuestEntitlement(voucher_plan_ids=frozenset({PLAN_GOLD}))
VOUCHER_DAY = GuestEntitlement(voucher_plan_ids=frozenset({PLAN_DAY}))
TIER_GUEST = GuestEntitlement(tier_policy_ids=frozenset({TIER}))


class TestEntitlementMatrix:
    @pytest.mark.parametrize(
        ("rule", "entitlement", "allowed"),
        [
            # the free network: everyone signed in
            (FREE, FREE_GUEST, True),
            (FREE, VOUCHER_ANY, True),
            (FREE, TIER_GUEST, True),
            # premium, any voucher
            (PREMIUM, FREE_GUEST, False),
            (PREMIUM, VOUCHER_ANY, True),
            (PREMIUM, VOUCHER_GOLD, True),
            (PREMIUM, TIER_GUEST, False),  # tier not linked to this SSID
            # premium restricted to the Gold plan or the Access Tier
            (PREMIUM_GOLD_ONLY, FREE_GUEST, False),
            (PREMIUM_GOLD_ONLY, VOUCHER_ANY, False),  # planless voucher
            (PREMIUM_GOLD_ONLY, VOUCHER_DAY, False),
            (PREMIUM_GOLD_ONLY, VOUCHER_GOLD, True),
            (PREMIUM_GOLD_ONLY, TIER_GUEST, True),
        ],
    )
    def test_entitles(
        self, rule: SsidTierRule, entitlement: GuestEntitlement, allowed: bool
    ) -> None:
        assert entitles(rule, entitlement) is allowed

    def test_free_guest_refused_on_premium_with_reason(self) -> None:
        d = decide_ssid_access(RULES, "WYFY_PREMIUM", FREE_GUEST)
        assert (d.allowed, d.reason, d.rule) == (
            False,
            SsidDecisionReason.NOT_ENTITLED,
            PREMIUM,
        )

    def test_premium_guest_allowed_on_both(self) -> None:
        assert decide_ssid_access(RULES, "WYFY_PREMIUM", VOUCHER_ANY).allowed
        d = decide_ssid_access(RULES, "WYFY_FREE", VOUCHER_ANY)
        assert d.allowed and d.reason == SsidDecisionReason.OPEN_NETWORK

    @pytest.mark.parametrize(
        ("ssid", "reason"),
        [
            (None, SsidDecisionReason.NO_SSID),
            ("WYFY_ARUBA", SsidDecisionReason.SSID_NOT_MAPPED),
        ],
    )
    def test_fail_open_cases(self, ssid: str | None, reason: str) -> None:
        d = decide_ssid_access(RULES, ssid, FREE_GUEST)
        assert d.allowed and d.reason == reason

    def test_case_insensitive_fallback(self) -> None:
        assert not decide_ssid_access(RULES, "wyfy_premium", FREE_GUEST).allowed

    def test_upgrade_hint_lists_only_paid_networks_the_pass_opens(self) -> None:
        rules = [FREE, PREMIUM, PREMIUM_GOLD_ONLY]
        hint = upgrade_networks(rules, VOUCHER_ANY, current_ssid="WYFY_FREE")
        assert [r.ssid for r in hint] == ["WYFY_PREMIUM"]
        assert upgrade_networks(rules, FREE_GUEST, current_ssid="WYFY_FREE") == []
        # never "join the network you are on"
        assert (
            upgrade_networks(rules, VOUCHER_ANY, current_ssid="WYFY_PREMIUM") == []
        )


# ============================================================================
# The RADIUS authorize gate
# ============================================================================


@dataclass
class FakeTierLookup:
    rules: list[SsidTierRule] = field(default_factory=list)
    by_guest: dict[uuid.UUID, GuestEntitlement] = field(default_factory=dict)
    raises: Exception | None = None
    entitlement_calls: int = 0

    async def rules_for_location(self, *, organization_id, location_id):  # noqa: ANN001, ANN201
        if self.raises:
            raise self.raises
        return list(self.rules)

    async def entitlement_for(  # noqa: ANN201
        self,
        *,
        guest_id,  # noqa: ANN001
        organization_id,  # noqa: ANN001
        location_id,  # noqa: ANN001
        now=None,  # noqa: ANN001
    ):
        self.entitlement_calls += 1
        return self.by_guest.get(guest_id, NO_ENTITLEMENT)


def _csid(ssid: str | None) -> str:
    return "54-F0-B1-C8-A9-0A" + (f":{ssid}" if ssid is not None else "")


async def _authorize_on(fx, nas, ssid: str | None):  # noqa: ANN001, ANN202
    return await fx.radius_service.authorize(
        nas_client=nas,
        username=_PHONE,
        calling_station_id=_ARUBA_CSID,
        called_station_id=_csid(ssid),
    )


class TestRadiusGate:
    async def _venue(self, *, vendor: str = "aruba_instant_on", **lookup: Any):  # noqa: ANN202
        fx = _fixture(vendor=vendor)
        nas = await _register_nas(fx)
        signed = await _sign_in(fx)
        tier_lookup = FakeTierLookup(rules=list(RULES), **lookup)
        fx.radius_service.ssid_tier_lookup = tier_lookup
        return fx, nas, signed, tier_lookup

    async def test_free_guest_is_rejected_on_premium(self, caplog) -> None:  # noqa: ANN001
        fx, nas, _, _ = await self._venue()
        caplog.set_level("INFO")
        assert (await _authorize_on(fx, nas, "WYFY_PREMIUM")).authorized is False
        assert any(
            r.getMessage() == "radius_authorize_ssid_not_entitled"
            and getattr(r, "event_ssid", None) == "WYFY_PREMIUM"
            for r in caplog.records
        )

    async def test_free_guest_is_accepted_on_free(self) -> None:
        fx, nas, _, lookup = await self._venue()
        result = await _authorize_on(fx, nas, "WYFY_FREE")
        assert result.authorized is True
        assert result.session_timeout_seconds  # the normal reply, unchanged
        assert lookup.entitlement_calls == 0  # open SSID: nothing to look up

    async def test_premium_guest_is_accepted_on_both(self) -> None:
        fx, nas, signed, _ = await self._venue()
        fx.radius_service.ssid_tier_lookup.by_guest[signed.session.guest_id] = (
            VOUCHER_ANY
        )
        assert (await _authorize_on(fx, nas, "WYFY_PREMIUM")).authorized is True
        assert (await _authorize_on(fx, nas, "WYFY_FREE")).authorized is True

    @pytest.mark.parametrize("ssid", [None, "WYFY_ARUBA"])
    async def test_no_ssid_or_unmapped_ssid_decides_as_before(
        self, ssid: str | None
    ) -> None:
        fx, nas, _, _ = await self._venue()
        assert (await _authorize_on(fx, nas, ssid)).authorized is True

    async def test_no_rows_at_the_venue_is_unchanged(self) -> None:
        fx, nas, _, lookup = await self._venue()
        lookup.rules = []
        assert (await _authorize_on(fx, nas, "WYFY_PREMIUM")).authorized is True

    async def test_a_broken_tier_lookup_does_not_lock_the_venue_out(self) -> None:
        fx, nas, _, _ = await self._venue(raises=RuntimeError("db down"))
        assert (await _authorize_on(fx, nas, "WYFY_PREMIUM")).authorized is True

    async def test_without_called_station_id_there_is_no_gate(self) -> None:
        """The per-venue (address-keyed) route passes no Called-Station-Id."""
        fx, nas, _, _ = await self._venue()
        result = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_ARUBA_CSID
        )
        assert result.authorized is True

    async def test_without_a_lookup_there_is_no_gate(self) -> None:
        fx, nas, _, _ = await self._venue()
        fx.radius_service.ssid_tier_lookup = None
        assert (await _authorize_on(fx, nas, "WYFY_PREMIUM")).authorized is True

    @pytest.mark.parametrize("vendor", ["mikrotik", "omada"])
    async def test_mikrotik_and_omada_are_untouched(self, vendor: str) -> None:
        fx, nas, _, lookup = await self._venue(vendor=vendor)
        result = await fx.radius_service.authorize(
            nas_client=nas,
            username=_PHONE,
            calling_station_id=canonicalize_calling_station_id("60f4450b2866"),
            called_station_id=_csid("WYFY_PREMIUM"),
        )
        assert result.authorized is True
        assert lookup.entitlement_calls == 0


# ============================================================================
# Input validation and the manual Instant On steps
# ============================================================================


class TestValidation:
    def test_clean_input_passes_trimmed(self) -> None:
        out = validate_inputs(
            [SsidTierInput(" WYFY_FREE ", " Free ", download_mbps=5, upload_mbps=2)]
        )
        assert (out[0].ssid, out[0].tier_name) == ("WYFY_FREE", "Free")

    @pytest.mark.parametrize(
        "items",
        [
            [SsidTierInput("", "Free")],
            [SsidTierInput("x" * 33, "Free")],
            [SsidTierInput("BAD\x00SSID", "Free")],
            [SsidTierInput("WYFY_FREE", "")],
            [SsidTierInput("A", "t"), SsidTierInput("a", "t")],  # dup, any case
            [SsidTierInput("A", "t", download_mbps=0)],
            [SsidTierInput("A", "t", upload_mbps=1001)],
            [SsidTierInput("A", "t", policy_id=TIER)],  # open + tier: contradiction
            [SsidTierInput(f"S{i}", "t") for i in range(9)],
        ],
    )
    def test_refusals(self, items: list[SsidTierInput]) -> None:
        with pytest.raises(SsidTierValidationError):
            validate_inputs(items)

    def test_manual_steps_name_the_ssid_and_speed(self) -> None:
        steps = instant_on_manual_steps([FREE, SsidTierRule("OPEN", "Open", False)])
        assert "WYFY_FREE" in steps[0] and "download 5 Mbps" in steps[0]
        assert "upload 2 Mbps" in steps[0] and "Per client" in steps[0]
        assert "no speed cap" in steps[1]


class FakeRepo:
    def __init__(self, rules, entitlement, session) -> None:  # noqa: ANN001
        self.rules = rules
        self.entitlement = entitlement
        self.session = session
        self.foreign_policies: set = set()
        self.foreign_plans: set = set()
        self.replaced: list = []

    async def rules_for_location(self, **kw):  # noqa: ANN003, ANN201
        return list(self.rules)

    async def entitlement_for(self, **kw):  # noqa: ANN003, ANN201
        return self.entitlement

    async def get_session(self, session_id):  # noqa: ANN001, ANN201
        return self.session if self.session and self.session.id == session_id else None

    async def foreign_policy_ids(self, *, organization_id, policy_ids):  # noqa: ANN001, ANN201
        return policy_ids & self.foreign_policies

    async def foreign_voucher_plan_ids(self, *, organization_id, plan_ids):  # noqa: ANN001, ANN201
        return plan_ids & self.foreign_plans

    async def replace_rows(self, *, organization_id, location_id, items, actor_user_id):  # noqa: ANN001, ANN201
        self.replaced = list(items)
        return [
            SimpleNamespace(
                ssid=i.ssid,
                tier_name=i.tier_name,
                requires_entitlement=i.requires_entitlement,
                policy_id=i.policy_id,
                voucher_plan_ids=[str(p) for p in i.voucher_plan_ids],
                download_mbps=i.download_mbps,
                upload_mbps=i.upload_mbps,
            )
            for i in items
        ]


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        guest_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        status="active",
    )


class TestService:
    async def test_replace_refuses_another_tenants_access_tier(self) -> None:
        repo = FakeRepo([], NO_ENTITLEMENT, None)
        repo.foreign_policies = {TIER}
        with pytest.raises(SsidTierValidationError):
            await SsidTierService(repo).replace(
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                items=[SsidTierInput("P", "Premium", True, policy_id=TIER)],
                actor_user_id=None,
            )
        assert repo.replaced == []

    async def test_replace_refuses_another_tenants_voucher_plan(self) -> None:
        repo = FakeRepo([], NO_ENTITLEMENT, None)
        repo.foreign_plans = {PLAN_GOLD}
        with pytest.raises(SsidTierValidationError):
            await SsidTierService(repo).replace(
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                items=[
                    SsidTierInput("P", "Premium", True, voucher_plan_ids=(PLAN_GOLD,))
                ],
                actor_user_id=None,
            )

    async def test_replace_round_trips(self) -> None:
        repo = FakeRepo([], NO_ENTITLEMENT, None)
        out = await SsidTierService(repo).replace(
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            items=[SsidTierInput("WYFY_FREE", "Free", download_mbps=5)],
            actor_user_id=None,
        )
        assert out[0].ssid == "WYFY_FREE" and out[0].download_mbps == 5

    async def test_portal_free_guest_on_premium_gets_the_paid_path(self) -> None:
        s = _session()
        repo = FakeRepo(RULES, NO_ENTITLEMENT, s)
        a = await SsidTierService(repo).guest_access(
            session_id=s.id, ssid="WYFY_PREMIUM"
        )
        assert a.requires_entitlement and not a.entitled
        assert a.tier_name == "Premium" and a.download_mbps == 50

    async def test_portal_after_voucher_on_free_hints_premium(self) -> None:
        s = _session()
        repo = FakeRepo(RULES, VOUCHER_ANY, s)
        a = await SsidTierService(repo).guest_access(session_id=s.id, ssid="WYFY_FREE")
        assert a.entitled and not a.requires_entitlement
        assert [r.ssid for r in a.upgrade_networks] == ["WYFY_PREMIUM"]

    async def test_portal_unknown_session_is_none(self) -> None:
        repo = FakeRepo(RULES, NO_ENTITLEMENT, _session())
        assert (
            await SsidTierService(repo).guest_access(
                session_id=uuid.uuid4(), ssid="WYFY_FREE"
            )
            is None
        )

    async def test_portal_venue_without_tiers(self) -> None:
        s = _session()
        a = await SsidTierService(FakeRepo([], NO_ENTITLEMENT, s)).guest_access(
            session_id=s.id, ssid="WYFY_ARUBA"
        )
        assert a.entitled and not a.mapped and a.paid_networks == []


# ============================================================================
# Instant On sync -- through the cloud-control client (#348), flag OFF default
# ============================================================================


def _settings(**over: Any) -> SimpleNamespace:
    base = {"instant_on_ssid_tier_push_enabled": False}
    base.update(over)
    return SimpleNamespace(**base)


@dataclass
class _Limit:
    download_mbps: int | None
    upload_mbps: int | None


class FakeControlClient:
    def __init__(self, networks: list[dict], limits: dict[str, _Limit]) -> None:
        self.networks = networks
        self.limits = limits
        self.writes: list[tuple] = []

    async def list_networks(self, site_id: str) -> list[dict]:
        return self.networks

    async def get_guest_network_rate_limit(self, site_id: str, network_id: str):  # noqa: ANN201
        return self.limits[network_id]

    async def set_guest_network_rate_limit(  # noqa: ANN201
        self, site_id: str, network_id: str, *, download_mbps, upload_mbps  # noqa: ANN001
    ):
        self.writes.append((site_id, network_id, download_mbps, upload_mbps))
        self.limits[network_id] = _Limit(download_mbps, upload_mbps)
        return self.limits[network_id]


def _factory(client: FakeControlClient):  # noqa: ANN202
    @asynccontextmanager
    async def factory(target):  # noqa: ANN001, ANN202
        yield client

    return factory


@pytest.fixture
def control_open(monkeypatch):  # noqa: ANN001, ANN201
    """The #348 module's resolver, answering a target (all gates open)."""
    from app.domains.guest import ssid_tier_instant_on as mod

    target = SimpleNamespace(site_id="site-1", secret_arn="arn")

    async def _resolve(db, **kw):  # noqa: ANN001, ANN003, ANN202
        return target

    monkeypatch.setattr(
        mod,
        "_control_module",
        lambda: SimpleNamespace(resolve_control_target=_resolve),
    )
    return target


class TestInstantOnSync:
    async def _run(self, settings, dry_run=True, client=None):  # noqa: ANN001, ANN202
        return await sync_ssid_tiers_to_instant_on(
            None,
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            rules=RULES,
            dry_run=dry_run,
            settings=settings,
            client_factory=_factory(client) if client else None,
        )

    async def test_flag_off_by_default_gives_manual_steps(self) -> None:
        result = await self._run(_settings())
        assert result.status == SyncStatus.MANUAL
        assert result.reason == SyncReason.PUSH_DISABLED
        assert len(result.manual_steps) == 2 and result.items == []

    async def test_cloud_control_gates_closed_gives_manual_steps(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.guest import ssid_tier_instant_on as mod

        async def _none(db, **kw):  # noqa: ANN001, ANN003, ANN202
            return None

        monkeypatch.setattr(
            mod,
            "_control_module",
            lambda: SimpleNamespace(resolve_control_target=_none),
        )
        result = await self._run(_settings(instant_on_ssid_tier_push_enabled=True))
        assert result.status == SyncStatus.MANUAL
        assert result.reason == SyncReason.CLOUD_CONTROL_NOT_ENABLED

    async def test_build_without_cloud_control_gives_manual_steps(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.guest import ssid_tier_instant_on as mod

        monkeypatch.setattr(mod, "_control_module", lambda: None)
        result = await self._run(_settings(instant_on_ssid_tier_push_enabled=True))
        assert result.reason == SyncReason.CLOUD_CONTROL_UNAVAILABLE

    async def test_preview_writes_nothing(self, control_open) -> None:  # noqa: ANN001
        client = FakeControlClient(
            [
                {"id": "n-free", "networkName": "WYFY_FREE"},
                {"id": "n-prem", "networkName": "WYFY_PREMIUM"},
            ],
            {"n-free": _Limit(None, None), "n-prem": _Limit(50, 20)},
        )
        result = await self._run(
            _settings(instant_on_ssid_tier_push_enabled=True), True, client
        )
        assert result.status == SyncStatus.PREVIEW
        assert [(i.ssid, i.status) for i in result.items] == [
            ("WYFY_FREE", "preview"),
            ("WYFY_PREMIUM", "unchanged"),
        ]
        assert client.writes == []

    async def test_apply_writes_each_changed_ssid_once(self, control_open) -> None:  # noqa: ANN001
        client = FakeControlClient(
            [
                {"id": "n-free", "networkName": "WYFY_FREE"},
                {"id": "n-prem", "networkName": "wyfy_premium"},  # case differs
            ],
            {"n-free": _Limit(None, None), "n-prem": _Limit(None, None)},
        )
        result = await self._run(
            _settings(instant_on_ssid_tier_push_enabled=True), False, client
        )
        assert result.status == SyncStatus.APPLIED
        assert client.writes == [
            ("site-1", "n-free", 5, 2),
            ("site-1", "n-prem", 50, 20),
        ]

    async def test_a_missing_ssid_is_partial_with_the_create_step(
        self, control_open
    ) -> None:  # noqa: ANN001
        client = FakeControlClient(
            [{"id": "n-free", "networkName": "WYFY_FREE"}],
            {"n-free": _Limit(None, None)},
        )
        result = await self._run(
            _settings(instant_on_ssid_tier_push_enabled=True), False, client
        )
        assert result.status == SyncStatus.PARTIAL
        missing = [i for i in result.items if i.status == "missing"]
        assert missing[0].ssid == "WYFY_PREMIUM"
        assert "Networks > Add" in missing[0].message

    def test_match_network_ids(self) -> None:
        ids = match_network_ids(
            RULES, [{"id": 1, "networkName": "WYFY_FREE"}, {"networkName": "x"}]
        )
        assert ids == {"WYFY_FREE": "1", "WYFY_PREMIUM": None}


# ============================================================================
# Routes: scoping declarations
# ============================================================================


def _route(path: str, method: str):  # noqa: ANN202
    from app.domains.guest.ssid_tier_router import (
        ssid_tier_guest_router,
        ssid_tier_router,
    )

    for router in (ssid_tier_router, ssid_tier_guest_router):
        for route in router.routes:
            if route.path == path and method in route.methods:
                return route
    raise AssertionError(f"{method} {path} not mounted")


class TestRoutes:
    @pytest.mark.parametrize(
        ("path", "method"),
        [
            ("/locations/{location_id}/ssid-tiers", "GET"),
            ("/locations/{location_id}/ssid-tiers", "PUT"),
        ],
    )
    def test_location_routes_declare_org_and_location_scope(
        self, path: str, method: str
    ) -> None:
        from app.domains.rbac.dependencies import CurrentLocation, CurrentOrganization

        calls = {d.call for d in _route(path, method).dependant.dependencies}
        assert CurrentOrganization in calls and CurrentLocation in calls

    def test_instant_on_sync_is_master_only(self) -> None:
        from app.domains.rbac.enums import ScopeType

        route = _route("/locations/{location_id}/ssid-tiers/instant-on-sync", "POST")
        closures = [
            {
                type(cell.cell_contents): cell.cell_contents
                for cell in (getattr(d.dependency, "__closure__", None) or ())
            }
            for d in route.dependencies
        ]
        pinned = [c for c in closures if ScopeType in c]
        assert pinned and pinned[0][ScopeType] == ScopeType.GLOBAL
        assert pinned[0][str] == "network_integrations.update"

    def test_mounted_under_v1(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        assert "/locations/{location_id}/ssid-tiers" in paths
        assert "/locations/{location_id}/ssid-tiers/instant-on-sync" in paths
        assert "/guest/ssid-access" in paths

    async def test_location_routes_refuse_a_sibling_location(self) -> None:
        """Header location A, path location B: refused before any read."""
        from app.domains.guest import ssid_tier_router as mod
        from app.domains.location.exceptions import CrossLocationScopeAccessError

        class _NoLocations:
            async def get_location(self, *a, **kw):  # noqa: ANN002, ANN003, ANN201
                raise AssertionError("must not be reached")

        with pytest.raises(CrossLocationScopeAccessError):
            await mod._scoped_location(
                uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _NoLocations()
            )
