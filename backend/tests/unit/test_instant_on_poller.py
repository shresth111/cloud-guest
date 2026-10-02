"""The Instant On poller: cadence, per-venue isolation, failure recording.

In-memory repository and a scripted provider; no network, no database.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import Settings
from app.domains.network_integration import instant_on_tasks
from app.domains.network_integration.instant_on_service import InstantOnKind
from app.domains.network_integration.instant_on_tasks import (
    _payload_hash,
    due_kinds,
    run_instant_on_poll,
)
from app.domains.network_integration.providers.aruba_instant_on import (
    InstantOnHealth,
    map_access_point,
    map_alert,
    map_client,
    map_client_usage,
    map_network,
)
from app.domains.network_integration.providers.aruba_instant_on_client import (
    InstantOnApiDriftError,
    InstantOnAuthError,
    InstantOnForbiddenError,
    InstantOnRateLimitedError,
    InstantOnUpstreamError,
)
from tests.unit import instant_on_fixtures as fx

T0 = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)

ALL_KINDS = [k.value for k in InstantOnKind]


def _settings(**overrides: Any) -> Settings:
    values = {"instant_on_poller_enabled": True, **overrides}
    return Settings(**values)


def _site(**fields: Any) -> SimpleNamespace:
    base = {
        "id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "router_id": uuid.uuid4(),
        "site_id": fx.SITE_ID,
        "poll_enabled": True,
        "customer_visible": False,
        "api_state": "never_polled",
        "last_poll_at": None,
        "last_success_at": None,
        "last_error_code": None,
        "last_error_message": None,
        "last_error_at": None,
        "consecutive_failures": 0,
        "backoff_until": None,
    }
    base.update(fields)
    return SimpleNamespace(**base)


class FakeRepo:
    def __init__(self, sites: list[SimpleNamespace]) -> None:
        self.sites = sites
        self.snapshots: dict[tuple[uuid.UUID, str], SimpleNamespace] = {}
        self.fail_update_for: set[uuid.UUID] = set()

    async def list_pollable_sites(self, *, limit: int) -> list[SimpleNamespace]:
        return [s for s in self.sites if s.poll_enabled][:limit]

    async def get_snapshots(self, site: SimpleNamespace) -> dict[str, SimpleNamespace]:
        return {k: v for (sid, k), v in self.snapshots.items() if sid == site.id}

    async def update_site(self, site: SimpleNamespace, data: dict) -> SimpleNamespace:
        if site.id in self.fail_update_for:
            raise RuntimeError("db exploded")
        for key, value in data.items():
            setattr(site, key, value)
        return site

    async def record_snapshot_success(self, site, *, kind, payload, payload_hash, at):  # noqa: ANN001, ANN201
        self.snapshots[(site.id, kind)] = SimpleNamespace(
            kind=kind,
            payload=payload,
            payload_hash=payload_hash,
            fetched_at=at,
            last_attempt_at=at,
            last_attempt_ok=True,
            error_code=None,
            error_message=None,
        )

    async def record_snapshot_failure(
        self, site, *, kind, error_code, error_message, at
    ):  # noqa: ANN001, ANN201
        prev = self.snapshots.get((site.id, kind))
        self.snapshots[(site.id, kind)] = SimpleNamespace(
            kind=kind,
            payload=prev.payload if prev else None,
            payload_hash=prev.payload_hash if prev else None,
            fetched_at=prev.fetched_at if prev else None,
            last_attempt_at=at,
            last_attempt_ok=False,
            error_code=error_code,
            error_message=error_message,
        )

    def snap(self, site: SimpleNamespace, kind: str) -> SimpleNamespace:
        return self.snapshots[(site.id, kind)]


class ScriptedProvider:
    """Returns fixture data; ``errors[(site_id, kind)]`` raises instead."""

    def __init__(self, errors: dict[tuple[str, str], Exception] | None = None) -> None:
        self.errors = errors or {}
        self.calls: list[tuple[str, str]] = []

    def _maybe_raise(self, site_id: str, kind: str) -> None:
        self.calls.append((site_id, kind))
        error = self.errors.get((site_id, kind)) or self.errors.get(("*", kind))
        if error is not None:
            raise error

    async def read_access_points(self, site_id: str):  # noqa: ANN201
        self._maybe_raise(site_id, "access_points")
        return [map_access_point(e) for e in fx.INVENTORY["elements"]]

    async def read_clients(self, site_id: str):  # noqa: ANN201
        self._maybe_raise(site_id, "clients")
        return [map_client(e) for e in fx.CLIENT_SUMMARY["elements"]]

    async def read_networks(self, site_id: str):  # noqa: ANN201
        self._maybe_raise(site_id, "ssids")
        return [map_network(e) for e in fx.NETWORKS_SUMMARY["elements"]]

    async def read_alerts(self, site_id: str):  # noqa: ANN201
        self._maybe_raise(site_id, "alerts")
        return [map_alert(e) for e in fx.ALERTS["elements"]]

    async def read_health(self, site_id: str):  # noqa: ANN201
        self._maybe_raise(site_id, "health")
        return InstantOnHealth(score=100, status="good")

    async def read_client_usage_24h(self, site_id: str):  # noqa: ANN201
        self._maybe_raise(site_id, "client_usage")
        return [map_client_usage(e) for e in fx.CLIENT_USAGE["elements"]]


class Tx:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


async def _run(
    repo: FakeRepo,
    provider: Any,
    *,
    at: datetime = T0,
    settings: Settings | None = None,
):  # noqa: ANN202
    tx = Tx()
    built: list[Any] = []

    def factory() -> Any:
        built.append(provider)
        return provider

    summary = await run_instant_on_poll(
        repository=repo,
        provider_factory=factory,
        settings=settings or _settings(),
        commit=tx.commit,
        rollback=tx.rollback,
        clock=lambda: at,
    )
    return summary, tx, built


class TestGating:
    async def test_globally_disabled_contacts_nobody(self) -> None:
        repo = FakeRepo([_site()])
        summary, _tx, built = await _run(
            repo,
            ScriptedProvider(),
            settings=_settings(instant_on_poller_enabled=False),
        )
        assert summary.skipped_reason == "poller_disabled"
        assert built == [] and repo.snapshots == {}

    async def test_disabled_venue_is_not_polled(self) -> None:
        repo = FakeRepo([_site(poll_enabled=False)])
        _summary, _tx, built = await _run(repo, ScriptedProvider())
        assert built == []

    async def test_the_settings_default_is_off(self) -> None:
        assert Settings().instant_on_poller_enabled is False
        assert Settings().instant_on_api_version == 28
        assert Settings().instant_on_service_account_secret_arn == ""


class TestCadence:
    async def test_first_tick_reads_every_kind(self) -> None:
        site = _site()
        repo = FakeRepo([site])
        provider = ScriptedProvider()
        summary, tx, _ = await _run(repo, provider)
        assert sorted(k for _, k in provider.calls) == sorted(ALL_KINDS)
        assert summary.sites_ok == 1 and summary.kinds_read == 6
        assert site.api_state == "ok" and site.last_success_at == T0
        assert tx.commits == 1
        snap = repo.snap(site, "clients")
        assert snap.last_attempt_ok and snap.fetched_at == T0
        assert [c["mac"] for c in snap.payload] == [
            "02:11:22:33:44:55",
            "02:AA:BB:CC:DD:EE",
        ]
        assert repo.snap(site, "health").payload == [{"score": 100, "status": "good"}]

    async def test_one_minute_later_only_the_fast_kinds_are_due(self) -> None:
        site = _site()
        repo = FakeRepo([site])
        await _run(repo, ScriptedProvider())
        provider = ScriptedProvider()
        await _run(repo, provider, at=T0 + timedelta(seconds=60))
        assert sorted(k for _, k in provider.calls) == ["access_points", "clients"]

    async def test_five_and_fifteen_minutes(self) -> None:
        site = _site()
        repo = FakeRepo([site])
        await _run(repo, ScriptedProvider())
        p5 = ScriptedProvider()
        await _run(repo, p5, at=T0 + timedelta(minutes=5))
        assert sorted(k for _, k in p5.calls) == sorted(
            ["access_points", "clients", "health", "ssids", "alerts"]
        )
        p15 = ScriptedProvider()
        await _run(repo, p15, at=T0 + timedelta(minutes=15))
        assert "client_usage" in [k for _, k in p15.calls]

    def test_due_kinds_counts_a_slightly_early_tick(self) -> None:
        snaps = {
            "access_points": SimpleNamespace(last_attempt_at=T0),
            "clients": SimpleNamespace(last_attempt_at=T0),
        }
        due = due_kinds(snaps, now=T0 + timedelta(seconds=57), settings=_settings())
        assert InstantOnKind.ACCESS_POINTS in due

    def test_payload_hash_is_order_independent_for_keys(self) -> None:
        assert _payload_hash([{"a": 1, "b": 2}]) == _payload_hash([{"b": 2, "a": 1}])


class TestFailureIsolation:
    async def test_drift_on_one_kind_does_not_stop_the_others(self) -> None:
        site = _site()
        repo = FakeRepo([site])
        provider = ScriptedProvider(
            {("*", "alerts"): InstantOnApiDriftError("x", reason="shape_alerts")}
        )
        await _run(repo, provider)
        assert repo.snap(site, "alerts").last_attempt_ok is False
        assert repo.snap(site, "alerts").error_code == "incompatible"
        assert repo.snap(site, "client_usage").last_attempt_ok is True
        assert site.api_state == "incompatible"
        assert site.last_success_at is None
        assert site.consecutive_failures == 1

    async def test_failure_keeps_the_last_good_payload_but_marks_the_attempt(
        self,
    ) -> None:
        site = _site()
        repo = FakeRepo([site])
        await _run(repo, ScriptedProvider())
        good = repo.snap(site, "clients").payload
        await _run(
            repo,
            ScriptedProvider({("*", "clients"): InstantOnUpstreamError("down")}),
            at=T0 + timedelta(minutes=1),
        )
        snap = repo.snap(site, "clients")
        assert snap.last_attempt_ok is False and snap.error_code == "upstream_error"
        assert snap.payload == good and snap.fetched_at == T0

    async def test_not_invited_stops_that_site_only(self) -> None:
        a, b = _site(site_id="site-a"), _site(site_id="site-b")
        repo = FakeRepo([a, b])
        provider = ScriptedProvider(
            {("site-a", "access_points"): InstantOnForbiddenError("403")}
        )
        summary, _tx, _ = await _run(repo, provider)
        assert [c for c in provider.calls if c[0] == "site-a"] == [
            ("site-a", "access_points")
        ]
        assert all(repo.snap(a, k).error_code == "not_invited" for k in ALL_KINDS)
        assert a.api_state == "not_invited"
        assert b.api_state == "ok"
        assert summary.sites_ok == 1 and summary.sites_failed == 1

    async def test_auth_failure_marks_every_remaining_site_without_calling_out(
        self,
    ) -> None:
        a, b, c = _site(site_id="a"), _site(site_id="b"), _site(site_id="c")
        repo = FakeRepo([a, b, c])
        provider = ScriptedProvider(
            {("a", "access_points"): InstantOnAuthError("no", reason="login_rejected")}
        )
        summary, tx, _ = await _run(repo, provider)
        assert provider.calls == [("a", "access_points")]
        for site in (a, b, c):
            assert site.api_state == "auth_failed"
            assert all(
                repo.snap(site, k).error_code == "auth_failed" for k in ALL_KINDS
            )
        assert summary.sites_failed == 3
        assert tx.commits == 3

    async def test_rate_limit_backs_off_the_site_and_ends_the_tick(self) -> None:
        a, b = _site(site_id="a"), _site(site_id="b")
        repo = FakeRepo([a, b])
        provider = ScriptedProvider(
            {
                ("a", "clients"): InstantOnRateLimitedError(
                    "slow", retry_after_seconds=120
                )
            }
        )
        await _run(repo, provider)
        assert a.backoff_until == T0 + timedelta(seconds=120)
        assert a.api_state == "rate_limited"
        assert not [c for c in provider.calls if c[0] == "b"]
        assert b.api_state == "never_polled"
        # Still backing off a minute later: not contacted.
        later = ScriptedProvider()
        summary, _tx, _ = await _run(repo, later, at=T0 + timedelta(seconds=60))
        assert not [c for c in later.calls if c[0] == "a"]
        assert summary.sites_skipped >= 1

    async def test_an_unexpected_error_in_one_kind_is_contained(self) -> None:
        site = _site()
        repo = FakeRepo([site])
        provider = ScriptedProvider({("*", "ssids"): KeyError("boom")})
        await _run(repo, provider)
        assert repo.snap(site, "ssids").error_code == "internal_error"
        assert repo.snap(site, "alerts").last_attempt_ok is True

    async def test_a_database_error_on_one_venue_rolls_back_only_that_venue(
        self,
    ) -> None:
        a, b = _site(site_id="a"), _site(site_id="b")
        repo = FakeRepo([a, b])
        repo.fail_update_for.add(a.id)
        summary, tx, _ = await _run(repo, ScriptedProvider())
        assert tx.rollbacks == 1
        assert b.api_state == "ok"
        assert summary.sites_failed == 1 and summary.sites_ok == 1


class TestGuestDataStaysWithRadius:
    def test_the_poller_never_writes_guest_usage(self) -> None:
        source = inspect.getsource(instant_on_tasks)
        assert "record_usage(" not in source
        assert "GuestService" not in source.replace("``GuestService.record_usage``", "")

    @pytest.mark.parametrize("name", ["poll_site", "run_instant_on_poll"])
    def test_no_guest_collaborator_is_accepted(self, name: str) -> None:
        params = inspect.signature(getattr(instant_on_tasks, name)).parameters
        assert not any("guest" in p for p in params)


class TestProviderCannotBeBuilt:
    async def test_every_site_is_marked_and_nothing_is_called(self) -> None:
        from app.domains.network_integration.providers.aruba_instant_on_client import (
            InstantOnNotConfiguredError,
        )

        a, b = _site(site_id="a"), _site(site_id="b")
        repo = FakeRepo([a, b])
        attempts: list[int] = []

        def factory() -> Any:
            attempts.append(1)
            raise InstantOnNotConfiguredError(
                "no key", reason="encryption_key_not_configured"
            )

        tx = Tx()
        summary = await run_instant_on_poll(
            repository=repo,
            provider_factory=factory,
            settings=_settings(),
            commit=tx.commit,
            rollback=tx.rollback,
            clock=lambda: T0,
        )
        assert attempts == [1]
        assert a.api_state == b.api_state == "not_configured"
        assert summary.sites_failed == 2

    def test_the_live_wiring_refuses_the_public_encryption_key(self) -> None:
        from app.domains.network_integration.instant_on_tasks import (
            build_live_provider,
        )
        from app.domains.network_integration.providers.aruba_instant_on_client import (
            InstantOnNotConfiguredError,
        )

        settings = _settings(environment="production")
        if not settings.uses_public_network_integration_key():
            pytest.skip("environment supplies a real key")
        with pytest.raises(InstantOnNotConfiguredError):
            build_live_provider(http=None, settings=settings)
