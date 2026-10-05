"""Instant On read API: freshness/unavailable rules, tenant scoping, route
scope pinning, and the Master site mapping."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.domains.network_integration.exceptions import (
    CrossLocationNetworkIntegrationAccessError,
    InstantOnSiteNotConfigurableError,
)
from app.domains.network_integration.instant_on_schemas import (
    InstantOnSiteConfigRequest,
)
from app.domains.network_integration.instant_on_service import (
    InstantOnKind,
    InstantOnReadService,
    build_view,
)
from app.domains.rbac.enums import ScopeType

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
ORG = uuid.uuid4()
OTHER_ORG = uuid.uuid4()
LOC = uuid.uuid4()
SIBLING_LOC = uuid.uuid4()
CLIENT = {
    "mac": "02:11:22:33:44:55",
    "connection": "wireless",
    "ssid": "WYFY_ARUBA",
    "snr_db": 38,
    "signal_dbm": None,
    "bands": ["fiveGHz"],
}


def _settings(**overrides: Any) -> Settings:
    return Settings(**{"instant_on_poller_enabled": True, **overrides})


def _site(**fields: Any) -> SimpleNamespace:
    base = {
        "id": uuid.uuid4(),
        "organization_id": ORG,
        "location_id": LOC,
        "router_id": uuid.uuid4(),
        "site_id": "3f6c2a10-7b1d-4c9e-9a55-0d2e8b7c4f11",
        "site_name": "test-site",
        "poll_enabled": True,
        "customer_visible": True,
        "api_state": "ok",
        "last_poll_at": NOW,
        "last_success_at": NOW,
        "last_error_code": None,
        "last_error_message": None,
        "last_error_at": None,
        "consecutive_failures": 0,
        "backoff_until": None,
    }
    base.update(fields)
    return SimpleNamespace(**base)


def _snap(
    *, age: int = 10, ok: bool = True, payload: Any = None, error: str | None = None
):  # noqa: ANN202
    fetched = NOW - timedelta(seconds=age)
    return SimpleNamespace(
        payload=[dict(CLIENT)] if payload is None else payload,
        fetched_at=fetched,
        last_attempt_at=NOW - timedelta(seconds=5) if not ok else fetched,
        last_attempt_ok=ok,
        error_code=error,
    )


# ---------------------------------------------------------------------------
# build_view: the honesty rules
# ---------------------------------------------------------------------------


class TestBuildView:
    def _view(self, snapshot, site=None, kind=InstantOnKind.CLIENTS, settings=None):  # noqa: ANN001, ANN202
        return build_view(
            kind=kind,
            site=site if site is not None else _site(),
            snapshot=snapshot,
            now=NOW,
            settings=settings or _settings(),
        )

    def test_fresh_data_is_served_with_source_and_as_of(self) -> None:
        view = self._view(_snap(age=30))
        assert view.status == "ok" and view.source == "instant_on"
        assert view.as_of == NOW - timedelta(seconds=30)
        assert view.items == [CLIENT]
        assert view.stale_after_seconds == 180

    def test_data_older_than_three_periods_is_unavailable_not_current(self) -> None:
        view = self._view(_snap(age=181))
        assert view.status == "unavailable" and view.unavailable_reason == "stale"
        assert view.items is None and view.as_of is None
        assert view.last_success_at == NOW - timedelta(seconds=181)

    def test_stale_threshold_follows_the_kind(self) -> None:
        view = self._view(
            _snap(age=600, payload=[{"name": "x"}]), kind=InstantOnKind.SSIDS
        )
        assert view.status == "ok"  # 5-minute kind: stale only after 15 min
        assert view.stale_after_seconds == 900

    def test_a_failed_last_poll_hides_even_a_recent_good_read(self) -> None:
        view = self._view(_snap(age=20, ok=False, error="upstream_error"))
        assert view.status == "unavailable"
        assert view.unavailable_reason == "poll_failed"
        assert view.items is None
        assert view.error_code == "upstream_error"
        assert view.last_success_at == NOW - timedelta(seconds=20)

    def test_never_polled(self) -> None:
        assert self._view(None).unavailable_reason == "never_polled"

    def test_no_site_is_not_configured(self) -> None:
        view = build_view(
            kind=InstantOnKind.CLIENTS,
            site=None,
            snapshot=None,
            now=NOW,
            settings=_settings(),
        )
        assert view.unavailable_reason == "not_configured" and view.items is None

    def test_polling_off_globally_or_per_venue(self) -> None:
        assert (
            self._view(
                _snap(), settings=_settings(instant_on_poller_enabled=False)
            ).unavailable_reason
            == "polling_disabled"
        )
        assert self._view(
            _snap(), site=_site(poll_enabled=False)
        ).unavailable_reason == ("polling_disabled")

    def test_an_empty_list_is_served_only_when_it_was_really_read(self) -> None:
        assert self._view(_snap(payload=[])).items == []
        for snapshot in (None, _snap(ok=False, payload=[])):
            assert self._view(snapshot).items is None


# ---------------------------------------------------------------------------
# Service: tenancy
# ---------------------------------------------------------------------------


class FakeRepo:
    def __init__(self, *sites: SimpleNamespace) -> None:
        self.sites = list(sites)
        self.snapshots: dict[uuid.UUID, dict[str, Any]] = {}
        self.location_queries: list[tuple[uuid.UUID, uuid.UUID]] = []
        self.created: list[dict] = []

    async def get_site_for_location(self, *, location_id, organization_id):  # noqa: ANN001, ANN201
        self.location_queries.append((location_id, organization_id))
        return next(
            (
                s
                for s in self.sites
                if s.location_id == location_id and s.organization_id == organization_id
            ),
            None,
        )

    async def get_site_for_router(self, router_id):  # noqa: ANN001, ANN201
        return next((s for s in self.sites if s.router_id == router_id), None)

    async def list_sites(self, *, limit):  # noqa: ANN001, ANN201
        return self.sites[:limit]

    async def get_snapshots(self, site):  # noqa: ANN001, ANN201
        return self.snapshots.get(site.id, {})

    async def create_site(self, data):  # noqa: ANN001, ANN201
        site = _site(**{**data, "api_state": "never_polled"})
        self.sites.append(site)
        self.created.append(data)
        return site

    async def update_site(self, site, data):  # noqa: ANN001, ANN201
        for k, v in data.items():
            setattr(site, k, v)
        return site


class FakeGuestMacs:
    def __init__(self, macs: set[str]) -> None:
        self.macs = macs
        self.calls: list[tuple] = []

    async def active_guest_macs(self, *, router_id, organization_id):  # noqa: ANN001, ANN201
        self.calls.append((router_id, organization_id))
        return self.macs


def _service(repo: FakeRepo, *, scope=None, guest_macs=None, audit=None):  # noqa: ANN001, ANN202
    return InstantOnReadService(
        repo,
        caller_location_scope=scope,
        guest_mac_lookup=guest_macs,
        audit_writer=audit,
        settings=_settings(),
        clock=lambda: NOW,
    )


def _with_clients(repo: FakeRepo, site: SimpleNamespace) -> None:
    repo.snapshots[site.id] = {"clients": _snap()}


class TestCustomerScoping:
    async def test_own_location_is_served(self) -> None:
        site = _site()
        repo = FakeRepo(site)
        _with_clients(repo, site)
        view = await _service(repo).customer_view(
            location_id=LOC, organization_id=ORG, kind=InstantOnKind.CLIENTS
        )
        assert (
            view.status == "ok" and view.items and view.items[0]["mac"] == CLIENT["mac"]
        )
        assert repo.location_queries == [(LOC, ORG)]

    async def test_another_tenants_location_reads_exactly_like_no_site(self) -> None:
        site = _site()
        repo = FakeRepo(site)
        _with_clients(repo, site)
        service = _service(repo)
        foreign = await service.customer_view(
            location_id=LOC, organization_id=OTHER_ORG, kind=InstantOnKind.CLIENTS
        )
        nothing = await service.customer_view(
            location_id=uuid.uuid4(), organization_id=ORG, kind=InstantOnKind.CLIENTS
        )
        assert foreign == nothing
        assert foreign.unavailable_reason == "not_configured" and foreign.items is None
        # The org is in the query, not compared afterwards.
        assert (LOC, OTHER_ORG) in repo.location_queries

    async def test_not_customer_visible_reads_like_no_site(self) -> None:
        site = _site(customer_visible=False)
        repo = FakeRepo(site)
        _with_clients(repo, site)
        view = await _service(repo).customer_view(
            location_id=LOC, organization_id=ORG, kind=InstantOnKind.CLIENTS
        )
        assert view.unavailable_reason == "not_configured" and view.items is None

    async def test_no_organization_resolves_nothing(self) -> None:
        site = _site()
        repo = FakeRepo(site)
        _with_clients(repo, site)
        view = await _service(repo).customer_view(
            location_id=LOC, organization_id=None, kind=InstantOnKind.CLIENTS
        )
        assert view.unavailable_reason == "not_configured"
        assert repo.location_queries == []

    async def test_a_location_confined_user_cannot_read_a_sibling_site(self) -> None:
        site = _site()
        repo = FakeRepo(site)
        _with_clients(repo, site)
        service = _service(repo, scope=frozenset({SIBLING_LOC}))
        with pytest.raises(CrossLocationNetworkIntegrationAccessError):
            await service.customer_view(
                location_id=LOC, organization_id=ORG, kind=InstantOnKind.CLIENTS
            )

    async def test_a_location_confined_user_reads_their_own_site(self) -> None:
        site = _site()
        repo = FakeRepo(site)
        _with_clients(repo, site)
        view = await _service(repo, scope=frozenset({LOC})).customer_view(
            location_id=LOC, organization_id=ORG, kind=InstantOnKind.CLIENTS
        )
        assert view.status == "ok"

    async def test_customer_view_carries_no_error_text_or_api_state(self) -> None:
        site = _site(api_state="auth_failed")
        repo = FakeRepo(site)
        repo.snapshots[site.id] = {"clients": _snap(ok=False, error="auth_failed")}
        view = await _service(repo).customer_view(
            location_id=LOC, organization_id=ORG, kind=InstantOnKind.CLIENTS
        )
        assert view.unavailable_reason == "poll_failed"
        assert view.error_code is None and view.api_state is None

    async def test_master_only_kinds_are_refused_on_the_customer_path(self) -> None:
        with pytest.raises(ValueError):
            await _service(FakeRepo()).customer_view(
                location_id=LOC, organization_id=ORG, kind=InstantOnKind.CLIENT_USAGE
            )

    async def test_signed_in_guests_are_flagged_by_mac(self) -> None:
        site = _site()
        repo = FakeRepo(site)
        repo.snapshots[site.id] = {
            "clients": _snap(
                payload=[dict(CLIENT), {**CLIENT, "mac": "02:00:00:00:00:01"}]
            )
        }
        macs = FakeGuestMacs({"02:11:22:33:44:55"})
        view = await _service(repo, guest_macs=macs).customer_view(
            location_id=LOC, organization_id=ORG, kind=InstantOnKind.CLIENTS
        )
        assert [i["is_signed_in_guest"] for i in view.items or []] == [True, False]
        assert macs.calls == [(site.router_id, ORG)]

    async def test_platform_view_keeps_error_code_and_api_state(self) -> None:
        site = _site(api_state="incompatible")
        repo = FakeRepo(site)
        repo.snapshots[site.id] = {"alerts": _snap(ok=False, error="incompatible")}
        view = await _service(repo).platform_view(
            router_id=site.router_id, kind=InstantOnKind.ALERTS
        )
        assert view.error_code == "incompatible" and view.api_state == "incompatible"


# ---------------------------------------------------------------------------
# Master: mapping a router to a site
# ---------------------------------------------------------------------------


class FakeRouterLookup:
    def __init__(self, router: SimpleNamespace) -> None:
        self.router = router

    async def get_router(self, router_id):  # noqa: ANN001, ANN201
        return self.router


class FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    async def create_audit_log_entry(self, **fields: Any) -> None:
        self.entries.append(fields)


def _router(vendor: str = "aruba_instant_on", **fields: Any) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        vendor=vendor,
        organization_id=fields.get("organization_id", ORG),
        location_id=fields.get("location_id", LOC),
    )


class TestConfigureSite:
    async def test_org_and_location_come_from_the_router(self) -> None:
        repo = FakeRepo()
        audit = FakeAudit()
        router = _router()
        site = await _service(repo, audit=audit).configure_site(
            router_id=router.id,
            site_id="3f6c2a10-7b1d-4c9e-9a55-0d2e8b7c4f11",
            site_name="test-site",
            poll_enabled=True,
            customer_visible=False,
            router_lookup=FakeRouterLookup(router),
        )
        assert site.organization_id == ORG and site.location_id == LOC
        assert repo.created[0]["router_id"] == router.id
        assert audit.entries[0]["action"] == "instant_on_site.create"
        assert audit.entries[0]["organization_id"] == ORG

    @pytest.mark.parametrize(
        ("router", "site_id", "reason"),
        [
            (_router(vendor="mikrotik"), "abc", "not_nas_only_vendor"),
            (_router(vendor="omada"), "abc", "not_nas_only_vendor"),
            (_router(location_id=None), "abc", "no_location"),
            (_router(), "../../sites", "invalid_site_id"),
        ],
    )
    async def test_refusals(self, router, site_id, reason) -> None:  # noqa: ANN001
        with pytest.raises(InstantOnSiteNotConfigurableError) as caught:
            await _service(FakeRepo()).configure_site(
                router_id=router.id,
                site_id=site_id,
                site_name=None,
                poll_enabled=True,
                customer_visible=True,
                router_lookup=FakeRouterLookup(router),
            )
        assert caught.value.reason == reason
        assert caught.value.status_code == 422

    async def test_switching_site_resets_the_previous_sites_state(self) -> None:
        router = _router()
        site = _site(
            router_id=router.id, api_state="auth_failed", consecutive_failures=4
        )
        repo = FakeRepo(site)
        await _service(repo).configure_site(
            router_id=router.id,
            site_id="another-site",
            site_name=None,
            poll_enabled=True,
            customer_visible=True,
            router_lookup=FakeRouterLookup(router),
        )
        assert site.site_id == "another-site"
        assert site.api_state == "never_polled" and site.consecutive_failures == 0

    def test_the_body_cannot_name_an_organization_or_location(self) -> None:
        for extra in ({"organization_id": str(ORG)}, {"location_id": str(LOC)}):
            with pytest.raises(ValidationError):
                InstantOnSiteConfigRequest(site_id="abc", **extra)


# ---------------------------------------------------------------------------
# Routes: scope pinning, shapes
# ---------------------------------------------------------------------------


def _permission_closures(route) -> list[dict]:  # noqa: ANN001
    out = []
    for dependency in route.dependencies:
        cells = getattr(dependency.dependency, "__closure__", None) or ()
        out.append({type(c.cell_contents): c.cell_contents for c in cells})
    return [c for c in out if ScopeType in c]


class TestRoutes:
    def test_every_platform_route_is_pinned_to_global(self) -> None:
        from app.domains.network_integration.instant_on_router import (
            instant_on_platform_router,
        )

        assert len(instant_on_platform_router.routes) == 11
        for route in instant_on_platform_router.routes:
            (closure,) = _permission_closures(route)
            assert closure[ScopeType] == ScopeType.GLOBAL, route.path
            expected = (
                "network_integrations.update"
                if "PUT" in route.methods
                else "network_integrations.read"
            )
            assert closure[str] == expected, route.path

    def test_every_customer_route_is_organization_scoped_and_location_keyed(
        self,
    ) -> None:
        from app.domains.network_integration.instant_on_router import (
            instant_on_customer_router,
        )

        # 4 reads + the guest network speed (GET + PUT).
        assert len(instant_on_customer_router.routes) == 6
        for route in instant_on_customer_router.routes:
            (closure,) = _permission_closures(route)
            assert closure[ScopeType] == ScopeType.ORGANIZATION
            if route.methods == {"PUT"}:
                # The one write: the guest network's speed. Its body names an
                # Instant On network, which is only ever looked up inside the
                # site resolved from the caller's organization + location
                # (``set_venue_guest_speed``), never read unscoped.
                assert route.path.endswith("/instant-on/guest-speed")
                assert closure[str] == "bandwidth.update"
                assert [p.name for p in route.dependant.path_params] == [
                    "location_id"
                ]
                continue
            assert closure[str] == "locations.read"
            assert route.methods == {"GET"}
            assert route.path.startswith(
                "/network-integrations/locations/{location_id}/"
            )
            # No body, and no other id the handler could read unscoped.
            assert route.dependant.body_params == []
            assert [p.name for p in route.dependant.path_params] == ["location_id"]

    def test_the_customer_read_service_resolves_the_strict_location_scope(self) -> None:
        import inspect

        from app.domains.network_integration.dependencies import (
            get_instant_on_read_service,
        )
        from app.domains.rbac.location_scope import CallerLocationScope

        param = inspect.signature(get_instant_on_read_service).parameters[
            "caller_location_scope"
        ]
        assert param.default.dependency is CallerLocationScope

    async def test_customer_endpoint_returns_null_items_when_unavailable(self) -> None:
        from app.domains.network_integration.instant_on_router import (
            instant_on_customer_router,
        )

        route = next(
            r for r in instant_on_customer_router.routes if r.path.endswith("/clients")
        )
        repo = FakeRepo(_site())  # site exists, never polled
        request = SimpleNamespace(
            headers={"X-Request-ID": "r-1"}, state=SimpleNamespace()
        )
        response = await route.endpoint(
            location_id=LOC,
            request=request,
            requesting_organization_id=ORG,
            service=_service(repo),
        )
        data = response["data"]
        assert data["source"] == "instant_on"
        assert data["status"] == "unavailable"
        assert data["unavailable_reason"] == "never_polled"
        assert data["items"] is None
        assert "error_code" not in data and "api_state" not in data
        json.dumps(response, default=str)

    async def test_customer_endpoint_serves_typed_items(self) -> None:
        from app.domains.network_integration.instant_on_router import (
            instant_on_customer_router,
        )

        route = next(
            r for r in instant_on_customer_router.routes if r.path.endswith("/clients")
        )
        site = _site()
        repo = FakeRepo(site)
        _with_clients(repo, site)
        request = SimpleNamespace(headers={}, state=SimpleNamespace(request_id="r-2"))
        response = await route.endpoint(
            location_id=LOC,
            request=request,
            requesting_organization_id=ORG,
            service=_service(repo, guest_macs=FakeGuestMacs(set())),
        )
        data = response["data"]
        assert data["status"] == "ok" and data["as_of"]
        item = data["items"][0]
        assert item["mac"] == CLIENT["mac"] and item["signal_dbm"] is None
        assert item["is_signed_in_guest"] is False

    async def test_platform_endpoint_includes_state(self) -> None:
        from app.domains.network_integration.instant_on_router import (
            instant_on_platform_router,
        )

        site = _site(api_state="not_invited")
        repo = FakeRepo(site)
        repo.snapshots[site.id] = {
            "access_points": _snap(ok=False, error="not_invited")
        }
        route = next(
            r
            for r in instant_on_platform_router.routes
            if r.path.endswith("/access-points")
        )
        response = await route.endpoint(
            router_id=site.router_id,
            request=SimpleNamespace(headers={}, state=SimpleNamespace()),
            service=_service(repo),
        )
        data = response["data"]
        assert data["status"] == "unavailable"
        assert (
            data["error_code"] == "not_invited" and data["api_state"] == "not_invited"
        )
