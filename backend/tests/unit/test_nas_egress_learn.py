"""NAS-only egress auto-learn (``app.domains.guest.nas_egress``).

An Aruba Instant On venue on a dynamic public IP: the guest portal reports
"traffic from this venue currently leaves from the address this request came
from", and the learner adds that address to the hub as an ADDITIONAL
client{} stanza for the venue's NAS (same secret, same shortname).

Pinned here: the trusted-client-IP rule behind nginx, the matching rules
(vendor, active NAS, nas-id, AP MAC), the address rules (public only; never
another NAS's), never replacing the registered address, the per-NAS rate
limit and cap, TTL (never the most recent), old-agent and push-failure
honesty, the public endpoint's uninformative 202, and that a rotation
carries learned addresses over with the new secret.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.guest import nas_egress
from app.domains.guest.nas_egress import (
    REFRESH_INTERVAL,
    EgressHint,
    EgressPolicy,
    LearnOutcome,
    NasEgressLearner,
    active_rows,
    canonical_mac,
    learnable_address,
    trusted_client_ip,
)
from app.domains.guest.radius_bridge import RadiusBridgePushError
from app.domains.rbac.enums import ScopeType

_ARUBA = "aruba_instant_on"
PRIMARY = "103.84.202.195"
SECOND = "111.223.3.241"
THIRD = "8.8.4.4"
FOURTH = "1.1.1.1"
AP_MAC = "54:f0:b1:c8:a9:0a"
T0 = datetime(2026, 10, 3, 5, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _Row(SimpleNamespace):
    pass


class FakeStore:
    def __init__(self, routers=(), nases=()) -> None:  # noqa: ANN001
        self.routers = {r.id: r for r in routers}
        self.nases = {n.id: n for n in nases}
        self.rows: list[_Row] = []
        self.used_elsewhere: set[str] = set()
        self.locks: list[uuid.UUID] = []

    async def get_router(self, router_id):  # noqa: ANN001, ANN201
        return self.routers.get(router_id)

    async def get_nas_for_router(self, router_id):  # noqa: ANN001, ANN201
        return next((n for n in self.nases.values() if n.router_id == router_id), None)

    async def get_nas(self, nas_client_id):  # noqa: ANN001, ANN201
        return self.nases.get(nas_client_id)

    async def lock_nas(self, nas_client_id) -> None:  # noqa: ANN001
        self.locks.append(nas_client_id)

    async def list_for_nas(self, nas_client_id):  # noqa: ANN001, ANN201
        return sorted(
            (r for r in self.rows if r.nas_client_id == nas_client_id),
            key=lambda r: r.last_seen_at,
            reverse=True,
        )

    async def address_used_elsewhere(self, address, nas_client_id) -> bool:  # noqa: ANN001
        return address in self.used_elsewhere

    async def learned_by_other_router(self, address, router_id) -> bool:  # noqa: ANN001
        return any(
            r.ip_address == address and r.router_id != router_id for r in self.rows
        )

    async def add(self, *, nas_client_id, router_id, address, source, now):  # noqa: ANN001, ANN201
        row = _Row(
            id=uuid.uuid4(),
            nas_client_id=nas_client_id,
            router_id=router_id,
            ip_address=address,
            source=source,
            first_seen_at=now,
            last_seen_at=now,
            hit_count=1,
            hub_confirmed_at=None,
        )
        self.rows.append(row)
        return row

    async def delete_rows(self, rows) -> None:  # noqa: ANN001
        ids = {r.id for r in rows}
        self.rows = [r for r in self.rows if r.id not in ids]

    async def nas_ids_with_learned(self):  # noqa: ANN201
        return list({r.nas_client_id for r in self.rows})

    async def flush(self) -> None:
        return None

    def ips(self) -> list[str]:
        return sorted(r.ip_address for r in self.rows)


class FakePush:
    """Stands in for ``push_nas_address_set``: records every set, answers
    like the new agent unless told to act old or fail."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.mode = "new"

    async def __call__(self, **kw: Any) -> list[str] | None:
        self.calls.append(kw)
        if self.mode == "fail":
            raise RadiusBridgePushError(
                "agent said no", transport=False, status_code=500
            )
        if self.mode == "old":
            return None
        return [kw["primary_ip"], *kw["additional_addresses"]]


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _router(vendor: str = _ARUBA, mac: str | None = AP_MAC) -> SimpleNamespace:
    return SimpleNamespace(id=uuid.uuid4(), vendor=vendor, mac_address=mac)


def _nas(router, status: str = "active", ip: str = PRIMARY) -> SimpleNamespace:  # noqa: ANN001
    return SimpleNamespace(
        id=uuid.uuid4(),
        router_id=router.id,
        nas_identifier=f"cg-aruba-{str(router.id)[:8]}",
        status=status,
        ip_address=ip,
        hub_client_synced_ip=ip,
        shared_secret_encrypted="enc:" + "S" * 32,
    )


def _policy(**kw: Any) -> EgressPolicy:
    base = dict(
        enabled=True,
        ttl=timedelta(days=14),
        max_addresses=6,
        max_new_per_hour=3,
    )
    base.update(kw)
    return EgressPolicy(**base)


class Venue:
    """One Aruba venue wired to a learner over fakes."""

    def __init__(self, vendor: str = _ARUBA, mac: str | None = AP_MAC, **policy: Any):
        self.router = _router(vendor, mac)
        self.nas = _nas(self.router)
        self.store = FakeStore([self.router], [self.nas])
        self.push = FakePush()
        self.clock = Clock()
        self.learner = NasEgressLearner(
            self.store,
            _policy(**policy),
            push=self.push,
            decrypt=lambda c: c.removeprefix("enc:"),
            clock=self.clock,
        )

    def hint(self, ip: str = SECOND, **kw: Any) -> EgressHint:
        fields = dict(
            router_id=self.router.id,
            client_ip=ip,
            nas_id=self.nas.nas_identifier,
            ap_mac=AP_MAC,
        )
        fields.update(kw)
        return EgressHint(**fields)

    async def learn(self, ip: str = SECOND, **kw: Any) -> LearnOutcome:
        return await self.learner.learn(self.hint(ip, **kw))


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

_TRUSTED = "127.0.0.1/32,::1/128,172.16.0.0/12"


class TestTrustedClientIp:
    def test_behind_nginx_the_real_ip_header_is_believed(self) -> None:
        # Staging, measured: every request reaches the api from 172.18.0.1.
        got = trusted_client_ip(
            peer="172.18.0.1",
            headers={"x-real-ip": SECOND, "x-forwarded-for": f"6.6.6.6, {SECOND}"},
            trusted_proxy_cidrs=_TRUSTED,
        )
        assert got == SECOND

    def test_a_direct_untrusted_peer_is_its_own_address_headers_ignored(
        self,
    ) -> None:
        got = trusted_client_ip(
            peer="9.9.9.9",
            headers={"x-real-ip": PRIMARY},
            trusted_proxy_cidrs=_TRUSTED,
        )
        assert got == "9.9.9.9"

    def test_forwarded_for_fallback_uses_the_entry_nginx_added_not_the_first(
        self,
    ) -> None:
        got = trusted_client_ip(
            peer="172.18.0.1",
            headers={"x-forwarded-for": f"{PRIMARY}, {SECOND}"},
            trusted_proxy_cidrs=_TRUSTED,
        )
        assert got == SECOND

    @pytest.mark.parametrize("headers", [{}, {"x-real-ip": "not-an-ip"}])
    def test_trusted_peer_without_a_usable_header_yields_nothing(
        self, headers: dict
    ) -> None:
        assert (
            trusted_client_ip(
                peer="172.18.0.1", headers=headers, trusted_proxy_cidrs=_TRUSTED
            )
            is None
        )

    def test_no_peer(self) -> None:
        assert trusted_client_ip(peer=None, headers={}, trusted_proxy_cidrs="") is None


class TestAddressAndMacRules:
    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.20",  # the guest's LAN address
            "10.0.0.1",
            "172.18.0.1",  # the docker bridge
            "100.64.1.1",  # CGNAT
            "127.0.0.1",
            "169.254.1.1",
            "10.20.0.7",  # WireGuard overlay
            "::1",
            "fe80::1",
            "garbage",
            "",
            None,
        ],
    )
    def test_never_learnable(self, ip: str | None) -> None:
        assert learnable_address(ip) is None

    @pytest.mark.parametrize("ip", [PRIMARY, SECOND, "2001:4860:4860::8888"])
    def test_public_is_learnable(self, ip: str) -> None:
        assert learnable_address(ip) == ip

    @pytest.mark.parametrize(
        "raw",
        ["54:f0:b1:c8:a9:0a", "54-F0-B1-C8-A9-0A", "54f0b1c8a90a", "54F0.B1C8.A90A"],
    )
    def test_mac_spellings(self, raw: str) -> None:
        assert canonical_mac(raw) == "54:F0:B1:C8:A9:0A"

    @pytest.mark.parametrize("raw", [None, "", "54:f0", "zz:zz:zz:zz:zz:zz"])
    def test_bad_macs(self, raw: str | None) -> None:
        assert canonical_mac(raw) is None


# ---------------------------------------------------------------------------
# Matching and gating
# ---------------------------------------------------------------------------


class TestGating:
    async def test_disabled_does_nothing(self) -> None:
        v = Venue(enabled=False)
        assert await v.learn() == LearnOutcome.DISABLED
        assert v.push.calls == [] and v.store.rows == []

    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_mikrotik_and_omada_never_learn(self, vendor: str) -> None:
        v = Venue(vendor=vendor)
        assert await v.learn() == LearnOutcome.NOT_ARUBA
        assert v.push.calls == [] and v.store.rows == [] and v.store.locks == []

    async def test_unknown_router(self) -> None:
        v = Venue()
        assert (
            await v.learner.learn(v.hint(router_id=uuid.uuid4()))
            == LearnOutcome.UNKNOWN_ROUTER
        )

    async def test_no_nas(self) -> None:
        v = Venue()
        v.store.nases.clear()
        assert await v.learn() == LearnOutcome.NO_ACTIVE_NAS

    async def test_disabled_nas(self) -> None:
        v = Venue()
        v.nas.status = "disabled"
        assert await v.learn() == LearnOutcome.NO_ACTIVE_NAS
        assert v.push.calls == []

    @pytest.mark.parametrize("nas_id", [None, "", "cg-aruba-deadbeef"])
    async def test_nas_id_must_match(self, nas_id: str | None) -> None:
        v = Venue()
        assert await v.learn(nas_id=nas_id) == LearnOutcome.NAS_ID_MISMATCH
        assert v.store.rows == []

    @pytest.mark.parametrize("ap_mac", [None, "garbage", "AA:BB:CC:DD:EE:FF"])
    async def test_ap_mac_must_match_the_recorded_mac(self, ap_mac: str | None) -> None:
        v = Venue()
        assert await v.learn(ap_mac=ap_mac) == LearnOutcome.AP_MAC_MISMATCH
        assert v.store.rows == []

    async def test_ap_mac_any_spelling(self) -> None:
        v = Venue()
        assert await v.learn(ap_mac="54F0B1C8A90A") == LearnOutcome.LEARNED

    async def test_no_recorded_mac_means_any_well_formed_ap_mac(self) -> None:
        v = Venue(mac=None)
        assert await v.learn(ap_mac="AA:BB:CC:DD:EE:FF") == LearnOutcome.LEARNED

    @pytest.mark.parametrize("ip", ["192.168.1.20", "100.64.0.9", "127.0.0.1", None])
    async def test_private_cgnat_loopback_never_learned(self, ip: str | None) -> None:
        v = Venue()
        outcome = await v.learn(ip)
        assert outcome in (LearnOutcome.NOT_PUBLIC, LearnOutcome.NO_CLIENT_ADDRESS)
        assert v.push.calls == [] and v.store.rows == []

    async def test_the_registered_address_is_not_a_learned_one(self) -> None:
        v = Venue()
        assert await v.learn(PRIMARY) == LearnOutcome.PRIMARY
        assert v.push.calls == [] and v.store.rows == []


# ---------------------------------------------------------------------------
# Learning
# ---------------------------------------------------------------------------


class TestLearn:
    async def test_a_new_address_is_added_beside_the_registered_one(self) -> None:
        v = Venue()
        assert await v.learn(SECOND) == LearnOutcome.LEARNED
        assert v.push.calls == [
            {
                "primary_ip": PRIMARY,
                "additional_addresses": [SECOND],
                "nas_identifier": v.nas.nas_identifier,
                "secret": "S" * 32,
            }
        ]
        assert v.store.locks == [v.nas.id]
        (row,) = v.store.rows
        assert row.ip_address == SECOND
        assert row.source == "portal_hint"
        assert row.hub_confirmed_at == T0
        # Never replaces: the NAS row's registered address is untouched.
        assert v.nas.ip_address == PRIMARY and v.nas.hub_client_synced_ip == PRIMARY

    async def test_a_second_learned_address_keeps_the_first(self) -> None:
        v = Venue()
        await v.learn(SECOND)
        v.clock.now += timedelta(minutes=1)
        assert await v.learn(THIRD) == LearnOutcome.LEARNED
        last = v.push.calls[-1]
        assert last["primary_ip"] == PRIMARY
        assert sorted(last["additional_addresses"]) == sorted([SECOND, THIRD])

    async def test_a_repeat_within_the_refresh_interval_is_free(self) -> None:
        v = Venue()
        await v.learn(SECOND)
        v.clock.now += timedelta(minutes=1)
        assert await v.learn(SECOND) == LearnOutcome.REFRESHED
        assert len(v.push.calls) == 1
        assert v.store.rows[0].last_seen_at == T0

    async def test_a_repeat_after_the_interval_refreshes_without_a_push(self) -> None:
        v = Venue()
        await v.learn(SECOND)
        v.clock.now += REFRESH_INTERVAL + timedelta(seconds=1)
        assert await v.learn(SECOND) == LearnOutcome.REFRESHED
        assert len(v.push.calls) == 1
        assert v.store.rows[0].last_seen_at == v.clock.now
        assert v.store.rows[0].hit_count == 2

    async def test_an_old_agent_is_reported_not_believed(self) -> None:
        v = Venue()
        v.push.mode = "old"
        assert await v.learn(SECOND) == LearnOutcome.LEARNED_UNCONFIRMED
        assert v.store.rows[0].hub_confirmed_at is None

    async def test_a_failed_push_keeps_the_row_unconfirmed_and_retries_later(
        self,
    ) -> None:
        v = Venue()
        v.push.mode = "fail"
        assert await v.learn(SECOND) == LearnOutcome.PUSH_FAILED
        assert v.store.rows[0].hub_confirmed_at is None
        # Retried on a later sighting, not on every page load.
        v.push.mode = "new"
        v.clock.now += timedelta(minutes=1)
        assert await v.learn(SECOND) == LearnOutcome.LEARNED
        assert len(v.push.calls) == 2
        assert v.store.rows[0].hub_confirmed_at == v.clock.now

    async def test_an_address_another_nas_uses_is_refused(self) -> None:
        v = Venue()
        v.store.used_elsewhere.add(SECOND)
        assert await v.learn(SECOND) == LearnOutcome.ADDRESS_IN_USE
        assert v.push.calls == [] and v.store.rows == []


class TestLimits:
    async def test_rate_limit_per_nas_per_hour(self) -> None:
        v = Venue(max_new_per_hour=2)
        assert await v.learn(SECOND) == LearnOutcome.LEARNED
        assert await v.learn(THIRD) == LearnOutcome.LEARNED
        assert await v.learn(FOURTH) == LearnOutcome.RATE_LIMITED
        assert len(v.push.calls) == 2
        v.clock.now += timedelta(hours=1, seconds=1)
        assert await v.learn(FOURTH) == LearnOutcome.LEARNED

    async def test_rate_limit_is_per_nas(self) -> None:
        v = Venue(max_new_per_hour=1)
        other = _router()
        other_nas = _nas(other, ip="9.9.9.9")
        v.store.routers[other.id] = other
        v.store.nases[other_nas.id] = other_nas
        assert await v.learn(SECOND) == LearnOutcome.LEARNED
        hint = EgressHint(
            router_id=other.id,
            client_ip=THIRD,
            nas_id=other_nas.nas_identifier,
            ap_mac=AP_MAC,
        )
        assert await v.learner.learn(hint) == LearnOutcome.LEARNED

    async def test_cap_evicts_the_least_recently_seen_learned_address(self) -> None:
        v = Venue(max_addresses=2, max_new_per_hour=10)
        await v.learn(SECOND)
        v.clock.now += timedelta(minutes=1)
        await v.learn(THIRD)
        v.clock.now += REFRESH_INTERVAL + timedelta(minutes=1)
        await v.learn(SECOND)  # SECOND now more recent than THIRD
        v.clock.now += timedelta(minutes=1)
        assert await v.learn(FOURTH) == LearnOutcome.LEARNED
        assert v.store.ips() == sorted([SECOND, FOURTH])
        last = v.push.calls[-1]
        assert last["primary_ip"] == PRIMARY  # the registered one is never evicted
        assert sorted(last["additional_addresses"]) == sorted([SECOND, FOURTH])


class TestTtl:
    def _row(self, ip: str, seen: datetime) -> _Row:
        return _Row(id=uuid.uuid4(), ip_address=ip, last_seen_at=seen)

    def test_expired_rows_go_but_never_the_most_recent(self) -> None:
        now = T0 + timedelta(days=30)
        rows = [self._row(SECOND, T0), self._row(THIRD, T0 + timedelta(days=1))]
        keep, expired = active_rows(rows, now=now, ttl=timedelta(days=14))
        assert [r.ip_address for r in keep] == [THIRD]
        assert [r.ip_address for r in expired] == [SECOND]

    def test_a_lone_ancient_row_is_kept(self) -> None:
        rows = [self._row(SECOND, T0)]
        keep, expired = active_rows(
            rows, now=T0 + timedelta(days=365), ttl=timedelta(days=14)
        )
        assert keep == rows and expired == []

    async def test_prune_all_drops_expired_and_repushes_only_changed_nas(
        self,
    ) -> None:
        v = Venue(max_new_per_hour=10)
        await v.learn(SECOND)
        v.clock.now += timedelta(days=10)
        await v.learn(THIRD)
        pushes_before = len(v.push.calls)

        v.clock.now += timedelta(days=1)
        assert await v.learner.prune_all() == {"pruned": 0, "pushed": 0}
        assert len(v.push.calls) == pushes_before

        v.clock.now += timedelta(days=10)  # SECOND unseen 21d, THIRD 11d
        assert await v.learner.prune_all() == {"pruned": 1, "pushed": 1}
        assert v.store.ips() == [THIRD]
        assert v.push.calls[-1]["additional_addresses"] == [THIRD]

    async def test_prune_all_never_removes_the_last_learned_address(self) -> None:
        v = Venue()
        await v.learn(SECOND)
        v.clock.now += timedelta(days=400)
        assert await v.learner.prune_all() == {"pruned": 0, "pushed": 0}
        assert v.store.ips() == [SECOND]


class TestOperatorPaths:
    async def test_remove_one_learned_address_repushes_without_it(self) -> None:
        v = Venue(max_new_per_hour=10)
        await v.learn(SECOND)
        await v.learn(THIRD)
        assert await v.learner.remove(v.nas, SECOND) is True
        assert v.store.ips() == [THIRD]
        assert v.push.calls[-1]["additional_addresses"] == [THIRD]
        assert await v.learner.remove(v.nas, "4.4.4.4") is False

    async def test_rotation_carries_learned_addresses_except_a_promoted_one(
        self,
    ) -> None:
        v = Venue(max_new_per_hour=10)
        await v.learn(SECOND)
        await v.learn(THIRD)
        # Operator re-registers the venue AT the learned SECOND address.
        carried = await v.learner.learned_addresses_for_push(v.nas, primary_ip=SECOND)
        assert carried == [THIRD]
        assert v.store.ips() == [THIRD]

    async def test_disabled_learner_carries_nothing(self) -> None:
        v = Venue()
        await v.learn(SECOND)
        v.learner.policy = _policy(enabled=False)
        assert (
            await v.learner.learned_addresses_for_push(v.nas, primary_ip=PRIMARY) == []
        )


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------


class _Db:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def _http_request(peer: str = "172.18.0.1", **headers: str) -> SimpleNamespace:
    return SimpleNamespace(
        client=SimpleNamespace(host=peer),
        headers={k.replace("_", "-"): v for k, v in headers.items()},
        state=SimpleNamespace(request_id="req-1"),
    )


def _settings(enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        nas_egress_learning_enabled=enabled,
        nas_egress_ttl_days=14,
        nas_egress_max_addresses=6,
        nas_egress_max_new_per_hour=3,
        trusted_proxy_cidrs=_TRUSTED,
        hub_radius_public_address="",
        api_public_base_url="https://api.wyfyguest.com",
    )


def _body(response) -> dict:  # noqa: ANN001
    import json

    return response if isinstance(response, dict) else json.loads(response.body)


class TestHintEndpoint:
    async def _call(self, monkeypatch, learn, enabled=True, **headers):  # noqa: ANN001, ANN202
        from app.domains.guest import router as guest_router
        from app.domains.guest.schemas import NasEgressHintRequest

        seen: list[EgressHint] = []

        class _Learner:
            async def learn(self, hint: EgressHint) -> LearnOutcome:
                seen.append(hint)
                return await learn(hint)

        monkeypatch.setattr(guest_router, "get_settings", lambda: _settings(enabled))
        monkeypatch.setattr(
            guest_router, "learner_for_session", lambda db, settings: _Learner()
        )
        db = _Db()
        rid = uuid.uuid4()
        response = await guest_router.portal_nas_egress_hint(
            _http_request(**headers),
            NasEgressHintRequest(router_id=rid, nas_id="cg-aruba-x", ap_mac=AP_MAC),
            db=db,
        )
        return _body(response), seen, db

    async def test_reads_the_venue_address_from_nginx_and_always_answers_202(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        async def _learn(hint: EgressHint) -> LearnOutcome:
            return LearnOutcome.LEARNED

        body, seen, db = await self._call(monkeypatch, _learn, x_real_ip=SECOND)
        assert body["data"] == {"accepted": True}
        assert seen[0].client_ip == SECOND
        assert seen[0].nas_id == "cg-aruba-x" and seen[0].ap_mac == AP_MAC
        assert db.commits == 1

    @pytest.mark.parametrize(
        "outcome", [LearnOutcome.UNKNOWN_ROUTER, LearnOutcome.NOT_ARUBA]
    )
    async def test_a_refusal_looks_identical_to_success(
        self, monkeypatch, outcome: LearnOutcome
    ) -> None:  # noqa: ANN001
        async def _learn(hint: EgressHint) -> LearnOutcome:
            return outcome

        body, _seen, _db = await self._call(monkeypatch, _learn, x_real_ip=SECOND)
        assert body["data"] == {"accepted": True}

    async def test_an_exception_never_reaches_the_guest(self, monkeypatch) -> None:  # noqa: ANN001
        async def _learn(hint: EgressHint) -> LearnOutcome:
            raise RuntimeError("database fell over")

        body, _seen, db = await self._call(monkeypatch, _learn, x_real_ip=SECOND)
        assert body["data"] == {"accepted": True}
        assert db.rollbacks == 1

    async def test_disabled_never_builds_a_learner(self, monkeypatch) -> None:  # noqa: ANN001
        async def _learn(hint: EgressHint) -> LearnOutcome:
            raise AssertionError("must not be called")

        body, seen, _db = await self._call(
            monkeypatch, _learn, enabled=False, x_real_ip=SECOND
        )
        assert body["data"] == {"accepted": True} and seen == []

    def test_the_route_is_public_and_mounted(self) -> None:
        from app.domains.guest.router import guest_router

        route = next(
            r for r in guest_router.routes if r.path == "/guest/portal/nas-egress-hint"
        )
        assert route.methods == {"POST"}
        assert route.dependencies == []


class TestRemoveLearnedRouteIsPlatformOnly:
    def test_pinned_global_radius_execute(self) -> None:
        from app.domains.guest.router import nas_platform_router

        route = next(
            r
            for r in nas_platform_router.routes
            if r.path.endswith("/public/{router_id}/learned/{ip_address}")
        )
        closures = [
            {
                type(cell.cell_contents): cell.cell_contents
                for cell in (getattr(d.dependency, "__closure__", None) or ())
            }
            for d in route.dependencies
        ]
        pinned = [c for c in closures if ScopeType in c]
        assert pinned and pinned[0][ScopeType] == ScopeType.GLOBAL
        assert pinned[0][str] == "radius.execute"


class TestRotationCarriesLearnedAddresses:
    async def test_push_helper_writes_the_whole_set_with_the_new_secret(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.guest import router as guest_router

        v = Venue(max_new_per_hour=10)
        await v.learn(SECOND)
        sets: list[dict] = []
        singles: list[dict] = []

        async def _set(**kw: Any) -> list[str]:
            sets.append(kw)
            return [kw["primary_ip"], *kw["additional_addresses"]]

        async def _single(**kw: Any) -> str:
            singles.append(kw)
            return kw["controller_ip"]

        monkeypatch.setattr(guest_router, "push_nas_address_set", _set)
        monkeypatch.setattr(guest_router, "push_controller_nas_client", _single)
        await guest_router._push_nas_only_set(
            v.learner,
            v.nas,
            nas_ip=PRIMARY,
            nas_identifier=v.nas.nas_identifier,
            secret="N" * 32,
        )
        assert singles == []
        assert sets == [
            {
                "primary_ip": PRIMARY,
                "additional_addresses": [SECOND],
                "nas_identifier": v.nas.nas_identifier,
                "secret": "N" * 32,
            }
        ]

    async def test_without_learned_addresses_it_is_the_old_single_push(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.guest import router as guest_router

        singles: list[dict] = []

        async def _single(**kw: Any) -> str:
            singles.append(kw)
            return kw["controller_ip"]

        monkeypatch.setattr(guest_router, "push_controller_nas_client", _single)
        await guest_router._push_nas_only_set(
            None, None, nas_ip=PRIMARY, nas_identifier="cg-aruba-1", secret="N" * 32
        )
        assert singles == [
            {
                "controller_ip": PRIMARY,
                "nas_identifier": "cg-aruba-1",
                "secret": "N" * 32,
            }
        ]

    async def test_registering_an_address_learned_by_another_venue_is_refused(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.guest import router as guest_router
        from app.domains.guest.exceptions import PublicNasRegistrationRefusedError
        from app.domains.guest.schemas import PublicNasRegistrationRequest

        v = Venue()
        await v.learn(SECOND)
        newcomer = _router()

        class _Svc:
            router_lookup = SimpleNamespace(get_router=None)

            async def nas_clients_at_address(self, address: str) -> list:
                return []

        async def _get_router(router_id):  # noqa: ANN001, ANN202
            return SimpleNamespace(**vars(newcomer), name="x", serial_number=None)

        svc = _Svc()
        svc.router_lookup = SimpleNamespace(get_router=_get_router)
        monkeypatch.setattr(
            guest_router, "learner_for_radius_service", lambda s, st: v.learner
        )
        with pytest.raises(PublicNasRegistrationRefusedError) as exc:
            await guest_router.register_public_radius_nas(
                SimpleNamespace(state=SimpleNamespace(request_id="r")),
                newcomer.id,
                PublicNasRegistrationRequest(nas_ip=SECOND),
                user=SimpleNamespace(id=str(uuid.uuid4())),
                service=svc,
            )
        assert "auto-learned" in exc.value.message


class TestSettingsDefaults:
    def test_off_by_default(self) -> None:
        from app.core.config import Settings

        fields = Settings.model_fields
        assert fields["nas_egress_learning_enabled"].default is False
        assert fields["nas_egress_ttl_days"].default == 14
        assert "172.16.0.0/12" in fields["trusted_proxy_cidrs"].default


def test_module_exports_the_public_surface() -> None:
    for name in nas_egress.__all__:
        assert hasattr(nas_egress, name)
