"""Aruba Instant On multi-AP sites (DASHBOARD_PLAN P0-A1 / P0-A2).

Pinned here:

* the resolver accepts any APPROVED AP of the site's router, beside the
  router's own MAC; an unknown MAC is still refused (``ap_mac_mismatch``)
  and handed to ``record_unknown`` (pending, never approved); without a
  registry the check is byte-for-byte the old single-MAC comparison;
* the shared accounting route stamps ``guest_sessions.ap_mac``/``ap_ssid``
  from Called-Station-Id, and only that route does;
* Called-Station-Id SSID parsing;
* the Master registry routes are GLOBAL-pinned; the customer route is
  ORGANIZATION-pinned and declares CurrentOrganization + location scope;
* the customer per-AP view: counts per AP, online/no-recent-activity, a
  MikroTik/Omada location (or a None organization) is ``applicable: false``;
* ``/guest-sessions``: ``ap_*`` fields are None for non-Aruba sessions, the
  name lookup issues no query when a page has no ``ap_mac``, and the
  ``ap_mac`` filter reaches the repository only when given.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.guest import aruba_shared
from app.domains.guest.aruba_shared import (
    ArubaSharedRequestRejected,
    ArubaSharedSecretStore,
    SharedRejectReason,
    backend_secret_for,
    resolve_shared_nas,
)
from app.domains.network_integration.aruba_access_points import (
    ApSessionStats,
    ArubaAccessPointService,
    ssid_from_called_station_id,
)
from app.domains.rbac.enums import ScopeType

SECRET = "A" * 16 + "b" * 16
AGENT = "hub-agent-secret-" + "x" * 23
BACKEND = backend_secret_for(SECRET, AGENT)
AP1 = "54:F0:B1:C8:A9:0A"
AP2 = "54:F0:B1:C8:A9:0B"
NAS_ID = "cg-aruba-9e6069de"
ROUTER_ID = uuid.UUID("9e6069de-f7a7-409f-8e4e-68d1cba75687")
ORG = uuid.UUID("711495a5-c9f7-44d5-a302-12b3cd92b6ae")
LOC = uuid.UUID("4d5f309c-b225-4615-a2f8-480b656e66bc")


@pytest.fixture(autouse=True)
def _hub_agent_secret(monkeypatch):  # noqa: ANN001, ANN202
    monkeypatch.setattr(
        aruba_shared,
        "get_settings",
        lambda: SimpleNamespace(
            hub_radius_agent_secret=AGENT,
            hub_radius_aruba_shared_agent_url="http://agent/radius/shared-client",
        ),
    )


class _SettingsRepo:
    def __init__(self) -> None:
        from app.domains.guest.nas_number_generator import secret_fingerprint
        from app.domains.router.crypto import encrypt_secret

        self.values = {
            ArubaSharedSecretStore.KEY: {
                "secret_encrypted": encrypt_secret(SECRET),
                "hub_fingerprint": secret_fingerprint(SECRET),
            }
        }

    async def get_value(self, key: str) -> Any:
        return self.values.get(key)


def _router(vendor: str = "aruba_instant_on", mac: str | None = AP1):  # noqa: ANN202
    return SimpleNamespace(
        id=ROUTER_ID,
        vendor=vendor,
        mac_address=mac,
        name="Aruba AP21",
        organization_id=ORG,
        location_id=LOC,
    )


def _service(router):  # noqa: ANN001, ANN202
    nas = SimpleNamespace(
        id=uuid.uuid4(), router_id=router.id, nas_identifier=NAS_ID, status="active"
    )

    async def by_ident(ident: str):  # noqa: ANN202
        return nas if ident == NAS_ID else None

    async def get_router(router_id, **_: Any):  # noqa: ANN001, ANN202
        return router

    return SimpleNamespace(
        nas=nas,
        repository=SimpleNamespace(get_nas_client_by_identifier=by_ident),
        router_lookup=SimpleNamespace(get_router=get_router),
    )


class FakeRegistry:
    def __init__(self, approved: set[str] | None = None) -> None:
        self.approved = approved or set()
        self.unknown: list[str] = []
        self.touched: list[str] = []

    async def approved_macs(self, router_id: uuid.UUID) -> set[str]:
        return set(self.approved)

    async def touch(self, router_id: uuid.UUID, mac: str) -> None:
        self.touched.append(mac)

    async def record_unknown(self, router: Any, mac: str) -> None:
        self.unknown.append(mac)


async def _resolve(csid: str, *, router=None, registry=None):  # noqa: ANN001, ANN202
    router = router or _router()
    return await resolve_shared_nas(
        presented_secret=BACKEND,
        nas_identifier=NAS_ID,
        called_station_id=csid,
        store=ArubaSharedSecretStore(_SettingsRepo()),
        radius_service=_service(router),
        ap_registry=registry,
    )


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class TestResolverMultiAp:
    async def test_primary_still_accepted_and_touched(self) -> None:
        reg = FakeRegistry()
        nas = await _resolve("54-F0-B1-C8-A9-0A:WYFY", registry=reg)
        assert nas.nas_identifier == NAS_ID
        assert reg.touched == [AP1] and reg.unknown == []

    async def test_approved_second_ap_accepted(self) -> None:
        reg = FakeRegistry({AP2})
        nas = await _resolve("54-F0-B1-C8-A9-0B:WYFY", registry=reg)
        assert nas.nas_identifier == NAS_ID
        assert reg.touched == [AP2]

    async def test_unknown_ap_rejected_and_recorded_pending(self) -> None:
        reg = FakeRegistry()
        with pytest.raises(ArubaSharedRequestRejected) as exc:
            await _resolve("54-F0-B1-C8-A9-0B:WYFY", registry=reg)
        assert exc.value.reason == SharedRejectReason.AP_MAC_MISMATCH
        assert reg.unknown == [AP2] and reg.touched == []

    async def test_without_registry_second_ap_still_rejected(self) -> None:
        """No registry = the pre-multi-AP behaviour, unchanged."""
        with pytest.raises(ArubaSharedRequestRejected) as exc:
            await _resolve("54-F0-B1-C8-A9-0B:WYFY")
        assert exc.value.reason == SharedRejectReason.AP_MAC_MISMATCH
        assert (await _resolve("54-F0-B1-C8-A9-0A")).nas_identifier == NAS_ID

    async def test_router_without_mac_accepts_approved_ap(self) -> None:
        router = _router(mac="02:00:00:00:00:01")  # minted placeholder
        with pytest.raises(ArubaSharedRequestRejected) as exc:
            await _resolve("54-F0-B1-C8-A9-0B", router=router, registry=FakeRegistry())
        assert exc.value.reason == SharedRejectReason.ROUTER_HAS_NO_AP_MAC
        nas = await _resolve(
            "54-F0-B1-C8-A9-0B", router=router, registry=FakeRegistry({AP2})
        )
        assert nas.nas_identifier == NAS_ID

    async def test_non_aruba_nas_never_reaches_registry(self) -> None:
        reg = FakeRegistry({AP2})
        for vendor in ("mikrotik", "tplink_omada"):
            with pytest.raises(ArubaSharedRequestRejected) as exc:
                await _resolve(
                    "54-F0-B1-C8-A9-0B", router=_router(vendor), registry=reg
                )
            assert exc.value.reason == SharedRejectReason.NOT_ARUBA
        assert reg.touched == [] and reg.unknown == []


@pytest.mark.parametrize(
    ("raw", "ssid"),
    [
        ("54-F0-B1-C8-A9-0A:WYFY_ARUBA", "WYFY_ARUBA"),
        ("54:f0:b1:c8:a9:0a:Guest WiFi", "Guest WiFi"),
        ("54f0b1c8a90a:X", "X"),
        ("54f0.b1c8.a90a:Y", "Y"),
        ("54-F0-B1-C8-A9-0A", None),
        ("54-F0-B1-C8-A9-0A:", None),
        ("garbage", None),
        (None, None),
    ],
)
def test_ssid_from_called_station_id(raw: str | None, ssid: str | None) -> None:
    assert ssid_from_called_station_id(raw) == ssid


# ---------------------------------------------------------------------------
# Shared accounting stamps the AP on the session
# ---------------------------------------------------------------------------


class _Http:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


class TestAccountingStampsAp:
    async def test_stamps_ap_mac_and_ssid(self, monkeypatch) -> None:  # noqa: ANN001
        from app.domains.guest import router as guest_router
        from app.domains.guest.schemas import RadiusAccountingResponse
        from app.domains.network_integration import aruba_access_points as mod

        calls: list[dict] = []

        async def fake_set(session, **kw):  # noqa: ANN001, ANN003, ANN202
            calls.append(kw)

        monkeypatch.setattr(mod, "set_session_ap", fake_set)
        sid = uuid.uuid4()
        service = SimpleNamespace(repository=SimpleNamespace(session=object()))
        await guest_router._record_session_ap(
            _Http({"X-RADIUS-Called-Station-Id": "54-F0-B1-C8-A9-0B:WYFY_ARUBA"}),
            service,
            RadiusAccountingResponse(session_id=str(sid), status="active"),
        )
        assert calls == [
            {"guest_session_id": sid, "ap_mac": AP2, "ap_ssid": "WYFY_ARUBA"}
        ]

    async def test_real_ap_shape_ssid_from_vsa_header(self, monkeypatch) -> None:  # noqa: ANN001
        """The real AP21 sends bare-hex Called-Station-Id and the SSID only
        in Aruba-Essid-Name (forwarded as a header by the shared listener)."""
        from app.domains.guest import router as guest_router
        from app.domains.guest.schemas import RadiusAccountingResponse
        from app.domains.network_integration import aruba_access_points as mod

        calls: list[dict] = []

        async def fake_set(session, **kw):  # noqa: ANN001, ANN003, ANN202
            calls.append(kw)

        monkeypatch.setattr(mod, "set_session_ap", fake_set)
        sid = uuid.uuid4()
        service = SimpleNamespace(repository=SimpleNamespace(session=object()))
        resp = RadiusAccountingResponse(session_id=str(sid), status="active")
        await guest_router._record_session_ap(
            _Http(
                {
                    "X-RADIUS-Called-Station-Id": "54f0b1c8a90a",
                    "X-RADIUS-Aruba-Essid-Name": "WYFY_ARUBA",
                }
            ),
            service,
            resp,
        )
        # Interim: no VSA, no suffix -> ssid None (kept by set_session_ap).
        await guest_router._record_session_ap(
            _Http({"X-RADIUS-Called-Station-Id": "54f0b1c8a90a"}), service, resp
        )
        assert [c["ap_ssid"] for c in calls] == ["WYFY_ARUBA", None]
        assert {c["ap_mac"] for c in calls} == {AP1}

    async def test_set_session_ap_keeps_ssid_when_none(self) -> None:
        from app.domains.network_integration.aruba_access_points import (
            set_session_ap,
        )

        stmts: list[Any] = []

        class _Db:
            async def execute(self, stmt):  # noqa: ANN001, ANN202
                stmts.append(stmt)

        await set_session_ap(
            _Db(), guest_session_id=uuid.uuid4(), ap_mac=AP1, ap_ssid=None
        )
        await set_session_ap(
            _Db(), guest_session_id=uuid.uuid4(), ap_mac=AP1, ap_ssid="X"
        )
        keep, write = (set(s.compile().params) for s in stmts)
        assert "ap_ssid" not in keep and "ap_mac" in keep
        assert "ap_ssid" in write

    async def test_no_session_or_no_mac_is_a_noop(self, monkeypatch) -> None:  # noqa: ANN001
        from app.domains.guest import router as guest_router
        from app.domains.guest.schemas import RadiusAccountingResponse
        from app.domains.network_integration import aruba_access_points as mod

        async def boom(*a, **k):  # noqa: ANN002, ANN003, ANN202
            raise AssertionError("must not be called")

        monkeypatch.setattr(mod, "set_session_ap", boom)
        db = SimpleNamespace(repository=SimpleNamespace(session=object()))
        ok = RadiusAccountingResponse(session_id=str(uuid.uuid4()), status="active")
        nas_event = RadiusAccountingResponse(session_id=None, status="accounting-on")
        await guest_router._record_session_ap(_Http({}), db, ok)
        await guest_router._record_session_ap(
            _Http({"X-RADIUS-Called-Station-Id": "AA"}), db, ok
        )
        await guest_router._record_session_ap(
            _Http({"X-RADIUS-Called-Station-Id": AP1}), db, nas_event
        )

    def test_only_the_shared_route_stamps(self) -> None:
        """The per-venue /radius/accounting (MikroTik, Omada, address-keyed
        Aruba) never writes ap_mac."""
        import inspect

        from app.domains.guest import router as guest_router

        assert "_record_session_ap" in inspect.getsource(
            guest_router.radius_aruba_shared_accounting
        )
        assert "_record_session_ap" not in inspect.getsource(
            guest_router.radius_accounting
        )
        assert "_record_session_ap" not in inspect.getsource(
            guest_router._radius_accounting
        )


# ---------------------------------------------------------------------------
# Route scoping
# ---------------------------------------------------------------------------


def _pins(router, path_suffix: str, method: str) -> dict:  # noqa: ANN001
    route = next(
        r for r in router.routes if r.path.endswith(path_suffix) and method in r.methods
    )
    closures = [
        {
            type(cell.cell_contents): cell.cell_contents
            for cell in (getattr(d.dependency, "__closure__", None) or ())
        }
        for d in route.dependencies
    ]
    pinned = [c for c in closures if ScopeType in c]
    assert pinned, closures
    return pinned[0]


class TestRouteScoping:
    @pytest.mark.parametrize(
        ("suffix", "method", "perm"),
        [
            ("/ap-registry", "GET", "network_integrations.read"),
            ("/ap-registry", "POST", "network_integrations.update"),
            ("/ap-registry/{ap_id}", "PATCH", "network_integrations.update"),
            ("/ap-registry/{ap_id}", "DELETE", "network_integrations.update"),
        ],
    )
    def test_master_routes_global_pinned(
        self, suffix: str, method: str, perm: str
    ) -> None:
        from app.domains.network_integration.aruba_ap_router import (
            aruba_ap_platform_router,
        )

        pin = _pins(aruba_ap_platform_router, suffix, method)
        assert pin[ScopeType] == ScopeType.GLOBAL and pin[str] == perm

    def test_customer_route_org_pinned_with_org_and_location_scope(self) -> None:
        from app.domains.network_integration.aruba_ap_router import (
            aruba_ap_customer_router,
        )
        from app.domains.rbac.dependencies import CurrentOrganization
        from app.domains.rbac.location_scope import CallerLocationScope

        pin = _pins(aruba_ap_customer_router, "/access-points", "GET")
        assert pin[ScopeType] == ScopeType.ORGANIZATION
        route = next(
            r
            for r in aruba_ap_customer_router.routes
            if r.path.endswith("/access-points")
        )
        calls = {d.call for d in route.dependant.dependencies}
        assert CurrentOrganization in calls
        assert CallerLocationScope in calls

    def test_mounted(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        assert "/locations/{location_id}/access-points" in paths
        assert "/platform/instant-on/routers/{router_id}/ap-registry" in paths
        # The existing Instant On inventory read is untouched.
        assert "/platform/instant-on/routers/{router_id}/access-points" in paths


# ---------------------------------------------------------------------------
# Customer per-AP view
# ---------------------------------------------------------------------------

NOW = datetime(2026, 10, 4, 6, 30, tzinfo=UTC)


def _ap(mac: str, name: str | None, *, router_id=ROUTER_ID, last_seen=None):  # noqa: ANN001, ANN202
    return SimpleNamespace(
        id=uuid.uuid4(),
        router_id=router_id,
        mac=mac,
        name=name,
        serial=None,
        model=None,
        source="manual",
        status="approved",
        first_seen_at=None,
        last_seen_at=last_seen,
    )


def _ap_service(*, routers, aps, stats, unattributed=0):  # noqa: ANN001, ANN202
    svc = ArubaAccessPointService(session=SimpleNamespace(), clock=lambda: NOW)
    seen: dict[str, Any] = {}

    async def aruba_routers_at(*, organization_id, location_id):  # noqa: ANN001, ANN202
        seen["routers"] = (organization_id, location_id)
        return routers

    async def list_approved(*, organization_id, location_id):  # noqa: ANN001, ANN202
        seen["aps"] = (organization_id, location_id)
        return aps

    async def session_stats(*, organization_id, location_id, router_ids, since):  # noqa: ANN001, ANN202
        seen["stats"] = (organization_id, location_id, set(router_ids), since)
        return stats, unattributed

    svc._aruba_routers_at = aruba_routers_at  # type: ignore[method-assign]
    svc.repository = SimpleNamespace(
        list_approved_for_location=list_approved, session_stats=session_stats
    )
    return svc, seen


class TestLocationAccessPoints:
    async def test_two_aps_counts_and_status(self) -> None:
        svc, seen = _ap_service(
            routers=[_router()],
            aps=[_ap(AP2, "Lobby")],
            stats={
                (ROUTER_ID, AP1): ApSessionStats(
                    clients_now=2,
                    sessions_today=5,
                    download_bytes_today=1000,
                    upload_bytes_today=100,
                    last_activity_at=NOW - timedelta(minutes=4),
                ),
                (ROUTER_ID, AP2): ApSessionStats(
                    clients_now=0,
                    sessions_today=1,
                    download_bytes_today=10,
                    upload_bytes_today=1,
                    last_activity_at=NOW - timedelta(hours=2),
                ),
            },
            unattributed=3,
        )
        body = await svc.location_access_points(
            organization_id=ORG, location_id=LOC, tz_offset_minutes=330
        )
        assert body["applicable"] is True
        assert body["unattributed_clients_now"] == 3
        # 06:30Z = 12:00 IST; IST midnight = 18:30Z the day before.
        assert body["day_start"] == datetime(2026, 10, 3, 18, 30, tzinfo=UTC)
        assert seen["stats"][:3] == (ORG, LOC, {ROUTER_ID})
        assert seen["routers"] == (ORG, LOC) and seen["aps"] == (ORG, LOC)
        by_mac = {i["mac"]: i for i in body["items"]}
        assert set(by_mac) == {AP1, AP2}
        primary, lobby = by_mac[AP1], by_mac[AP2]
        assert primary["is_primary"] and primary["id"] is None
        assert (primary["clients_now"], primary["sessions_today"]) == (2, 5)
        assert primary["status"] == "online" and primary["status_source"] == "radius"
        assert lobby["name"] == "Lobby" and lobby["clients_now"] == 0
        assert lobby["status"] == "no_recent_activity"
        assert lobby["status_source"] is None
        assert lobby["download_bytes_today"] == 10

    async def test_instant_on_online_when_radius_silent(self) -> None:
        svc, _ = _ap_service(routers=[_router()], aps=[_ap(AP2, None)], stats={})
        body = await svc.location_access_points(
            organization_id=ORG,
            location_id=LOC,
            instant_on_items=[
                {"mac": "54f0b1c8a90b", "status": "online", "name": "IO name",
                 "model": "AP21", "serial_number": "VNV5"},
            ],
        )
        lobby = next(i for i in body["items"] if i["mac"] == AP2)
        assert lobby["status"] == "online" and lobby["status_source"] == "instant_on"
        assert (lobby["name"], lobby["model"], lobby["serial"]) == (
            "IO name", "AP21", "VNV5"
        )
        primary = next(i for i in body["items"] if i["mac"] == AP1)
        assert primary["status"] == "no_recent_activity"
        assert primary["instant_on_status"] is None

    async def test_registry_last_seen_counts_as_radius_evidence(self) -> None:
        svc, _ = _ap_service(
            routers=[_router()],
            aps=[_ap(AP2, None, last_seen=NOW - timedelta(minutes=1))],
            stats={},
        )
        body = await svc.location_access_points(organization_id=ORG, location_id=LOC)
        lobby = next(i for i in body["items"] if i["mac"] == AP2)
        assert lobby["status"] == "online" and lobby["status_source"] == "radius"

    async def test_non_aruba_location_not_applicable(self) -> None:
        """MikroTik / Omada venue, or another tenant's location: no NAS-only
        router matches (org AND location in the WHERE) -> empty."""
        svc, seen = _ap_service(routers=[], aps=[_ap(AP2, "x")], stats={})
        body = await svc.location_access_points(organization_id=ORG, location_id=LOC)
        assert body["applicable"] is False and body["items"] == []
        assert "aps" not in seen and "stats" not in seen

    async def test_no_organization_never_reads(self) -> None:
        svc, seen = _ap_service(routers=[_router()], aps=[], stats={})
        body = await svc.location_access_points(organization_id=None, location_id=LOC)
        assert body["applicable"] is False and seen == {}


# ---------------------------------------------------------------------------
# Master registry service
# ---------------------------------------------------------------------------


class _Repo:
    def __init__(self, rows=None) -> None:  # noqa: ANN001
        self.rows = list(rows or [])
        self.created: list[dict] = []

    async def list_for_router(self, router_id):  # noqa: ANN001, ANN202
        return [r for r in self.rows if r.router_id == router_id]

    async def get_by_mac(self, router_id, mac):  # noqa: ANN001, ANN202
        return next((r for r in self.rows if r.mac == mac), None)

    async def get_for_router(self, router_id, ap_id):  # noqa: ANN001, ANN202
        return next((r for r in self.rows if r.id == ap_id), None)

    async def create(self, data):  # noqa: ANN001, ANN202
        self.created.append(data)
        row = _ap(data["mac"], data.get("name"))
        row.source, row.status = data["source"], data["status"]
        self.rows.append(row)
        return row

    async def update(self, ap, data):  # noqa: ANN001, ANN202
        for k, v in data.items():
            setattr(ap, k, v)
        return ap

    async def soft_delete(self, ap):  # noqa: ANN001, ANN202
        self.rows.remove(ap)


def _registry_service(rows=None):  # noqa: ANN001, ANN202
    svc = ArubaAccessPointService(session=SimpleNamespace(), clock=lambda: NOW)
    svc.repository = _Repo(rows)  # type: ignore[assignment]
    return svc


class TestRegistryService:
    async def test_list_synthesizes_primary(self) -> None:
        svc = _registry_service([_ap(AP2, "Lobby")])
        records = await svc.list_registry(_router())
        assert [r["mac"] for r in records] == [AP1, AP2]
        assert records[0]["is_primary"] and records[0]["id"] is None

    async def test_add_approves_and_copies_tenant_from_router(self) -> None:
        svc = _registry_service()
        rec = await svc.add(
            _router(), mac="54-f0-b1-c8-a9-0b", name="Lobby", actor_user_id=uuid.uuid4()
        )
        assert rec["mac"] == AP2 and rec["status"] == "approved"
        created = svc.repository.created[0]
        assert (created["organization_id"], created["location_id"]) == (ORG, LOC)

    @pytest.mark.parametrize(
        "mac", ["nonsense", "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF"]
    )
    async def test_add_refuses_bad_mac(self, mac: str) -> None:
        from app.domains.network_integration.exceptions import (
            ArubaAccessPointInvalidError,
        )

        with pytest.raises(ArubaAccessPointInvalidError) as exc:
            await _registry_service().add(
                _router(), mac=mac, name=None, actor_user_id=uuid.uuid4()
            )
        assert exc.value.reason == "invalid_mac"

    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_refuses_non_aruba_router(self, vendor: str) -> None:
        from app.domains.network_integration.exceptions import (
            ArubaAccessPointInvalidError,
        )

        with pytest.raises(ArubaAccessPointInvalidError) as exc:
            await _registry_service().list_registry(_router(vendor))
        assert exc.value.reason == "not_nas_only_vendor"

    async def test_pending_add_approves_existing(self) -> None:
        row = _ap(AP2, None)
        row.status, row.source = "pending", "discovered"
        svc = _registry_service([row])
        rec = await svc.add(
            _router(), mac=AP2, name="Lobby", actor_user_id=uuid.uuid4()
        )
        assert rec["status"] == "approved" and rec["name"] == "Lobby"
        assert svc.repository.created == []

    async def test_cannot_reject_or_delete_primary(self) -> None:
        from app.domains.network_integration.exceptions import (
            ArubaAccessPointInvalidError,
        )

        row = _ap(AP1, "primary")
        svc = _registry_service([row])
        with pytest.raises(ArubaAccessPointInvalidError):
            await svc.update(
                _router(), row.id, status="rejected", name=None,
                actor_user_id=uuid.uuid4(),
            )
        with pytest.raises(ArubaAccessPointInvalidError):
            await svc.delete(_router(), row.id)

    async def test_reject_secondary(self) -> None:
        row = _ap(AP2, None)
        svc = _registry_service([row])
        rec = await svc.update(
            _router(), row.id, status="rejected", name="X", actor_user_id=uuid.uuid4()
        )
        assert rec["status"] == "rejected" and rec["name"] == "X"


# ---------------------------------------------------------------------------
# /guest-sessions: MikroTik / Omada payloads unchanged
# ---------------------------------------------------------------------------


def _session(**kw: Any):  # noqa: ANN202
    base = dict(
        id=uuid.uuid4(),
        guest_id=uuid.uuid4(),
        device_id=None,
        router_id=uuid.uuid4(),
        location_id=LOC,
        organization_id=ORG,
        auth_method="otp",
        voucher_id=None,
        status="active",
        started_at=NOW,
        ended_at=None,
        last_activity_at=NOW,
        ip_address="10.0.0.2",
        bytes_uploaded=1,
        bytes_downloaded=2,
        data_limit_mb=None,
        session_timeout_minutes=None,
        disconnect_reason=None,
        disconnect_enforced=None,
        user_agent=None,
        created_at=NOW,
    )
    base.update(kw)
    return SimpleNamespace(**base)


class TestGuestSessionsPayload:
    def test_non_aruba_session_has_null_ap_fields(self) -> None:
        from app.domains.guest.router import _session_responses

        (resp,) = _session_responses([_session(ap_mac=None, ap_ssid=None)], {})
        dumped = resp.model_dump()
        assert dumped["ap_mac"] is None and dumped["ap_ssid"] is None
        assert dumped["ap_name"] is None
        # A row from before the column existed (no attribute at all) too.
        (old,) = _session_responses([_session()], {})
        assert old.ap_mac is None

    def test_aruba_session_carries_ap(self) -> None:
        from app.domains.guest.router import _session_responses

        s = _session(ap_mac=AP2, ap_ssid="WYFY")
        (resp,) = _session_responses(
            [s], {}, ap_names={(s.router_id, AP2): "Lobby"}
        )
        assert (resp.ap_mac, resp.ap_ssid, resp.ap_name) == (AP2, "WYFY", "Lobby")

    async def test_name_lookup_skipped_without_ap(self) -> None:
        from app.domains.guest.router import _resolve_ap_names

        class Boom:
            def __getattr__(self, name: str):  # noqa: ANN204
                raise AssertionError("no query expected")

        service = SimpleNamespace(repository=SimpleNamespace(session=Boom()))
        assert await _resolve_ap_names([_session(ap_mac=None)], service=service) == {}

    async def test_ap_mac_filter_only_when_given(self) -> None:
        from app.domains.guest.service import GuestService

        captured: list[dict] = []

        async def list_sessions(*, page, page_size, filters):  # noqa: ANN001, ANN202
            captured.append(filters)
            return [], None

        svc = GuestService.__new__(GuestService)
        svc.repository = SimpleNamespace(list_sessions=list_sessions)
        svc._confined_location_filter = lambda loc: loc  # type: ignore[method-assign]
        await svc.list_sessions(requesting_organization_id=ORG, location_id=LOC)
        await svc.list_sessions(
            requesting_organization_id=ORG, location_id=LOC, ap_mac=AP2
        )
        assert captured[0] == {"organization_id": ORG, "location_id": LOC}
        assert captured[1] == {
            "organization_id": ORG, "location_id": LOC, "ap_mac": AP2
        }
