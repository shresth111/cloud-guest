"""The shared Aruba Instant On RADIUS listener (UDP 1912/1913).

Venue identity comes from INSIDE the packet -- NAS-Identifier plus the AP MAC
in Called-Station-Id -- never from the source address, so a venue on a
dynamic public IP keeps working. Pinned here:

* the resolver: shared secret first (constant-time), then an ACTIVE
  ``aruba_instant_on`` NAS by identifier, then the AP MAC; every refusal has
  its own logged reason, and MikroTik / Omada NAS rows are unreachable;
* Called-Station-Id parsing across the spellings APs use;
* the RADIUS routes: a refusal on authorize is an Access-Reject (never a
  500), on accounting a 401; a match runs exactly the per-venue decision;
* the per-venue path (``/radius/authorize`` + ``CurrentNas``) is unchanged;
* the shared secret: minted by the platform, pushed to the hub FIRST and
  confirmed by fingerprint, stored encrypted, shown once, never in the
  platform-settings read;
* the Master routes are GLOBAL-pinned; register-shared needs an AP MAC.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.guest import aruba_shared
from app.domains.guest.aruba_shared import (
    ArubaSharedRequestRejected,
    ArubaSharedSecretStore,
    SharedRejectReason,
    ap_mac_from_called_station_id,
    resolve_shared_nas,
    rotate_shared_secret,
)
from app.domains.guest.radius_bridge import RadiusBridgePushError
from app.domains.rbac.enums import ScopeType

SECRET = "A" * 16 + "b" * 16
AP = "54:F0:B1:C8:A9:0A"
NAS_ID = "cg-aruba-9e6069de"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeSettingsRepo:
    def __init__(self) -> None:
        self.values: dict[str, Any] = {}
        self.upserts: list[tuple[str, Any]] = []

    async def get_value(self, key: str) -> Any:
        return self.values.get(key)

    async def upsert(self, key: str, value: Any, *, actor_user_id=None) -> None:  # noqa: ANN001
        self.values[key] = value
        self.upserts.append((key, value))


def _store_with(secret: str | None) -> ArubaSharedSecretStore:
    from app.domains.guest.nas_number_generator import secret_fingerprint
    from app.domains.router.crypto import encrypt_secret

    repo = FakeSettingsRepo()
    if secret is not None:
        repo.values[ArubaSharedSecretStore.KEY] = {
            "secret_encrypted": encrypt_secret(secret),
            "rotated_at": "2026-10-03T08:00:00+00:00",
            "hub_fingerprint": secret_fingerprint(secret),
        }
    return ArubaSharedSecretStore(repo)


def _router(vendor: str = "aruba_instant_on", mac: str | None = AP):  # noqa: ANN202
    return SimpleNamespace(
        id=uuid.UUID("9e6069de-f7a7-409f-8e4e-68d1cba75687"),
        vendor=vendor,
        mac_address=mac,
        name="Aruba AP21",
    )


def _nas(router, status: str = "active", ident: str = NAS_ID):  # noqa: ANN001, ANN202
    return SimpleNamespace(
        id=uuid.uuid4(),
        router_id=router.id,
        nas_identifier=ident,
        status=status,
        ip_address=None,
        hub_client_synced_ip=None,
    )


class FakeRadiusService:
    def __init__(self, router=None, nas=None) -> None:  # noqa: ANN001
        self.router = router or _router()
        self.nas = nas if nas is not None else _nas(self.router)
        self.lookups: list[str] = []

        async def get_nas_client_by_identifier(ident: str):  # noqa: ANN202
            self.lookups.append(ident)
            return self.nas if self.nas and self.nas.nas_identifier == ident else None

        async def get_router(router_id, **_: Any):  # noqa: ANN001, ANN202
            if router_id != self.router.id:
                raise LookupError("no such router")
            return self.router

        self.repository = SimpleNamespace(
            get_nas_client_by_identifier=get_nas_client_by_identifier
        )
        self.router_lookup = SimpleNamespace(get_router=get_router)


async def _resolve(
    *,
    secret: str | None = SECRET,
    stored: str | None = SECRET,
    nas_id: str | None = NAS_ID,
    csid: str | None = "54-F0-B1-C8-A9-0A:WYFY_ARUBA",
    service: FakeRadiusService | None = None,
):  # noqa: ANN202
    return await resolve_shared_nas(
        presented_secret=secret,
        nas_identifier=nas_id,
        called_station_id=csid,
        store=_store_with(stored),
        radius_service=service or FakeRadiusService(),
    )


async def _reason(**kw: Any) -> str:
    with pytest.raises(ArubaSharedRequestRejected) as exc:
        await _resolve(**kw)
    return exc.value.reason


# ---------------------------------------------------------------------------
# Called-Station-Id
# ---------------------------------------------------------------------------


class TestCalledStationId:
    @pytest.mark.parametrize(
        "raw",
        [
            "54-F0-B1-C8-A9-0A:WYFY_ARUBA",  # RFC 3580 s3.20
            "54-f0-b1-c8-a9-0a",
            "54:f0:b1:c8:a9:0a",
            "54:F0:B1:C8:A9:0A:WYFY_ARUBA",
            "54f0b1c8a90a",
            "54F0B1C8A90A:WYFY_ARUBA",
            "54f0.b1c8.a90a",
            " 54-F0-B1-C8-A9-0A:Guest WiFi ",
        ],
    )
    def test_spellings(self, raw: str) -> None:
        assert ap_mac_from_called_station_id(raw) == AP

    @pytest.mark.parametrize(
        "raw",
        [None, "", "WYFY_ARUBA", "54-F0-B1", "54f0b1c8a90a0b", "zz-zz-zz-zz-zz-zz"],
    )
    def test_unparseable(self, raw: str | None) -> None:
        assert ap_mac_from_called_station_id(raw) is None


# ---------------------------------------------------------------------------
# The resolver
# ---------------------------------------------------------------------------


class TestResolver:
    async def test_match(self) -> None:
        service = FakeRadiusService()
        assert await _resolve(service=service) is service.nas

    @pytest.mark.parametrize(
        "csid", ["54f0b1c8a90a", "54:F0:B1:C8:A9:0A", "54-f0-b1-c8-a9-0a:SSID"]
    )
    async def test_match_any_spelling(self, csid: str) -> None:
        assert await _resolve(csid=csid) is not None

    async def test_no_secret_configured(self) -> None:
        assert await _reason(stored=None) == SharedRejectReason.SECRET_NOT_CONFIGURED

    @pytest.mark.parametrize("presented", [None, "", "B" * 32, SECRET[:-1]])
    async def test_wrong_secret_is_checked_before_any_lookup(
        self, presented: str | None
    ) -> None:
        service = FakeRadiusService()
        assert (
            await _reason(secret=presented, service=service)
            == SharedRejectReason.SECRET_MISMATCH
        )
        assert service.lookups == []

    @pytest.mark.parametrize("ident", [None, "", "  "])
    async def test_missing_nas_identifier(self, ident: str | None) -> None:
        assert await _reason(nas_id=ident) == SharedRejectReason.NAS_IDENTIFIER_MISSING

    @pytest.mark.parametrize(
        "ident",
        [
            "cg-5d3a509e",  # a MikroTik NAS identifier
            "cg-omada-1234abcd",  # an Omada controller's
            "cg-aruba-9E6069DE",  # wrong case
            "cg-aruba-9e6069de-x",
            "wyfy-aruba-shared",
        ],
    )
    async def test_only_aruba_identifiers_are_even_looked_up(self, ident: str) -> None:
        service = FakeRadiusService()
        assert (
            await _reason(nas_id=ident, service=service)
            == SharedRejectReason.NAS_IDENTIFIER_MALFORMED
        )
        assert service.lookups == []

    async def test_unknown_nas(self) -> None:
        assert (
            await _reason(nas_id="cg-aruba-00000000") == SharedRejectReason.NAS_UNKNOWN
        )

    @pytest.mark.parametrize("status", ["disabled", "pending"])
    async def test_inactive_nas(self, status: str) -> None:
        router = _router()
        service = FakeRadiusService(router, _nas(router, status=status))
        assert await _reason(service=service) == SharedRejectReason.NAS_INACTIVE

    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_a_non_aruba_router_behind_an_aruba_shaped_id_is_refused(
        self, vendor: str
    ) -> None:
        router = _router(vendor=vendor)
        service = FakeRadiusService(router, _nas(router))
        assert await _reason(service=service) == SharedRejectReason.NOT_ARUBA

    async def test_a_missing_fleet_row_is_an_unknown_nas(self) -> None:
        router = _router()
        nas = _nas(router)
        nas.router_id = uuid.uuid4()
        service = FakeRadiusService(router, nas)
        assert await _reason(service=service) == SharedRejectReason.NAS_UNKNOWN

    async def test_router_without_ap_mac(self) -> None:
        router = _router(mac=None)
        service = FakeRadiusService(router, _nas(router))
        assert await _reason(service=service) == SharedRejectReason.ROUTER_HAS_NO_AP_MAC

    @pytest.mark.parametrize("csid", [None, "", "   "])
    async def test_missing_called_station_id(self, csid: str | None) -> None:
        assert await _reason(csid=csid) == SharedRejectReason.CALLED_STATION_ID_MISSING

    async def test_unparseable_called_station_id(self) -> None:
        with pytest.raises(ArubaSharedRequestRejected) as exc:
            await _resolve(csid="WYFY_ARUBA")
        assert exc.value.reason == SharedRejectReason.CALLED_STATION_ID_UNPARSEABLE
        assert exc.value.context["called_station_id"] == "WYFY_ARUBA"

    async def test_ap_mac_mismatch_records_what_was_sent(self) -> None:
        with pytest.raises(ArubaSharedRequestRejected) as exc:
            await _resolve(csid="AA-BB-CC-00-00-01:WYFY_ARUBA")
        assert exc.value.reason == SharedRejectReason.AP_MAC_MISMATCH
        assert exc.value.context == {
            "nas_identifier": NAS_ID,
            "called_station_id": "AA-BB-CC-00-00-01:WYFY_ARUBA",
            "expected_ap_mac": AP,
        }

    def test_rejection_log_never_carries_the_secret(self, caplog) -> None:  # noqa: ANN001
        exc = ArubaSharedRequestRejected(
            SharedRejectReason.AP_MAC_MISMATCH, nas_identifier=NAS_ID
        )
        with caplog.at_level("WARNING"):
            aruba_shared.log_rejection(exc, kind="authorize")
        record = caplog.records[-1]
        assert record.getMessage() == "radius_aruba_shared_rejected"
        assert record.reason == "ap_mac_mismatch"
        assert SECRET not in str(record.__dict__)


# ---------------------------------------------------------------------------
# RADIUS routes
# ---------------------------------------------------------------------------


def _http(headers: dict[str, str]) -> SimpleNamespace:
    return SimpleNamespace(headers=headers, state=SimpleNamespace(request_id="r"))


def _shared_headers(**over: str) -> dict[str, str]:
    h = {
        "X-RADIUS-Shared-Secret": SECRET,
        "X-RADIUS-Packet-NAS-Identifier": NAS_ID,
        "X-RADIUS-Called-Station-Id": "54-F0-B1-C8-A9-0A:WYFY_ARUBA",
    }
    h.update(over)
    return h


@pytest.fixture
def wired(monkeypatch):  # noqa: ANN001, ANN201
    """Route module with the store pinned to a known secret and the
    per-venue decision recorded instead of run."""
    from app.domains.guest import router as guest_router

    calls: list[tuple[str, Any]] = []

    async def _authorize_reply(payload, nas_client, service):  # noqa: ANN001, ANN202
        calls.append(("authorize", nas_client))
        return {"control:Auth-Type": "Accept"}

    async def _accounting(payload, nas_client, service):  # noqa: ANN001, ANN202
        calls.append(("accounting", nas_client))
        return "acct-ok"

    monkeypatch.setattr(guest_router, "_radius_authorize_reply", _authorize_reply)
    monkeypatch.setattr(guest_router, "_radius_accounting", _accounting)
    monkeypatch.setattr(
        guest_router, "_aruba_shared_store", lambda service: _store_with(SECRET)
    )
    return guest_router, calls


class TestRadiusRoutes:
    async def test_authorize_match_runs_the_per_venue_decision(self, wired) -> None:  # noqa: ANN001
        guest_router, calls = wired
        from app.domains.guest.schemas import RadiusAuthorizeRequest

        service = FakeRadiusService()
        reply = await guest_router.radius_aruba_shared_authorize(
            _http(_shared_headers()),
            RadiusAuthorizeRequest(username="+919999900077"),
            service=service,
        )
        assert reply == {"control:Auth-Type": "Accept"}
        assert calls == [("authorize", service.nas)]

    @pytest.mark.parametrize(
        "over",
        [
            {"X-RADIUS-Shared-Secret": "nope"},
            {"X-RADIUS-Packet-NAS-Identifier": "cg-aruba-00000000"},
            {"X-RADIUS-Called-Station-Id": "AA-BB-CC-00-00-01:WYFY_ARUBA"},
            {"X-RADIUS-Called-Station-Id": ""},
        ],
    )
    async def test_authorize_refusal_is_an_access_reject_with_a_logged_reason(
        self, wired, over: dict, caplog
    ) -> None:  # noqa: ANN001
        guest_router, calls = wired
        from app.domains.guest.schemas import RadiusAuthorizeRequest

        with caplog.at_level("WARNING"):
            reply = await guest_router.radius_aruba_shared_authorize(
                _http(_shared_headers(**over)),
                RadiusAuthorizeRequest(username="+919999900077"),
                service=FakeRadiusService(),
            )
        assert reply == {"control:Auth-Type": "Reject"}
        assert calls == []
        assert any(
            r.getMessage() == "radius_aruba_shared_rejected" for r in caplog.records
        )

    async def test_accounting_match_and_refusal(self, wired) -> None:  # noqa: ANN001
        guest_router, calls = wired
        from app.domains.guest.exceptions import RadiusNasAuthenticationError
        from app.domains.guest.schemas import RadiusAccountingRequest

        payload = RadiusAccountingRequest(
            status_type="start", username="+919999900077", session_id="S1"
        )
        service = FakeRadiusService()
        assert (
            await guest_router.radius_aruba_shared_accounting(
                _http(_shared_headers()), payload, service=service
            )
            == "acct-ok"
        )
        with pytest.raises(RadiusNasAuthenticationError):
            await guest_router.radius_aruba_shared_accounting(
                _http(
                    _shared_headers(
                        **{"X-RADIUS-Called-Station-Id": "AA-BB-CC-00-00-01"}
                    )
                ),
                payload,
                service=service,
            )
        assert calls == [("accounting", service.nas)]

    def test_per_venue_routes_still_use_current_nas(self) -> None:
        """The shared listener must not have widened the existing path."""
        from app.domains.guest.dependencies import CurrentNas
        from app.domains.guest.router import radius_router

        for path in ("/radius/authorize", "/radius/accounting"):
            route = next(r for r in radius_router.routes if r.path == path)
            deps = [d.call for d in route.dependant.dependencies]
            assert CurrentNas in deps, path
        for path in (
            "/radius/aruba-shared/authorize",
            "/radius/aruba-shared/accounting",
        ):
            route = next(r for r in radius_router.routes if r.path == path)
            deps = [d.call for d in route.dependant.dependencies]
            assert CurrentNas not in deps, path


# ---------------------------------------------------------------------------
# The shared secret
# ---------------------------------------------------------------------------


class TestSharedSecret:
    async def test_rotate_pushes_first_confirms_fingerprint_then_stores(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.guest.nas_number_generator import secret_fingerprint

        pushed: list[str] = []

        async def _push(secret: str) -> str:
            pushed.append(secret)
            return secret_fingerprint(secret)

        monkeypatch.setattr(aruba_shared, "push_shared_secret", _push)
        store = _store_with(None)
        secret, fp = await rotate_shared_secret(store, actor_user_id="u1")
        assert pushed == [secret]
        assert len(secret) == 32 and secret.isalnum() and secret.isascii()
        assert fp == secret_fingerprint(secret)
        stored = store.repository.values[ArubaSharedSecretStore.KEY]
        assert secret not in json.dumps(stored)  # encrypted at rest
        assert await store.secret() == secret
        state = await store.state()
        assert state.configured and state.hub_confirmed and state.fingerprint == fp

    async def test_a_refusing_hub_leaves_the_old_secret(self, monkeypatch) -> None:  # noqa: ANN001
        async def _push(secret: str) -> str:
            raise RadiusBridgePushError("no", transport=False, status_code=409)

        monkeypatch.setattr(aruba_shared, "push_shared_secret", _push)
        store = _store_with(SECRET)
        with pytest.raises(RadiusBridgePushError):
            await rotate_shared_secret(store, actor_user_id="u1")
        assert await store.secret() == SECRET
        assert store.repository.upserts == []

    async def test_a_hub_reporting_another_fingerprint_stores_nothing(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        async def _push(secret: str) -> str:
            return "000000000000"

        monkeypatch.setattr(aruba_shared, "push_shared_secret", _push)
        store = _store_with(SECRET)
        with pytest.raises(RadiusBridgePushError):
            await rotate_shared_secret(store, actor_user_id="u1")
        assert store.repository.upserts == []

    async def test_push_needs_an_agent_url(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.setattr(
            aruba_shared,
            "get_settings",
            lambda: SimpleNamespace(
                hub_radius_aruba_shared_agent_url="", hub_radius_agent_secret="x"
            ),
        )
        with pytest.raises(aruba_shared.ArubaSharedNotConfiguredError):
            await aruba_shared.push_shared_secret(SECRET)

    async def test_state_of_an_unset_secret(self) -> None:
        state = await _store_with(None).state()
        assert not state.configured and state.fingerprint is None

    def test_never_part_of_the_platform_settings_read(self) -> None:
        from app.domains.system_settings.schemas import PlatformSettingsResponse

        assert "aruba_shared_radius" not in PlatformSettingsResponse.model_fields


# ---------------------------------------------------------------------------
# Master routes
# ---------------------------------------------------------------------------


def _pinned(router, path_suffix: str, method: str) -> dict:  # noqa: ANN001
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


class TestMasterRoutes:
    def test_global_pins(self) -> None:
        from app.domains.guest.router import (
            aruba_shared_platform_router,
            nas_platform_router,
        )

        rot = _pinned(aruba_shared_platform_router, "/rotate", "POST")
        assert rot[ScopeType] == ScopeType.GLOBAL and rot[str] == "radius.execute"
        read = _pinned(aruba_shared_platform_router, "/aruba-shared", "GET")
        assert read[ScopeType] == ScopeType.GLOBAL and read[str] == "radius.read"
        reg = _pinned(nas_platform_router, "/register-shared/{router_id}", "POST")
        assert reg[ScopeType] == ScopeType.GLOBAL and reg[str] == "radius.create"

    def test_mounted_under_v1(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        assert "/platform/radius/aruba-shared" in paths
        assert "/platform/radius/aruba-shared/rotate" in paths
        assert "/radius/aruba-shared/authorize" in paths
        assert "/radius/aruba-shared/accounting" in paths

    async def test_register_shared_needs_an_ap_mac(self, monkeypatch) -> None:  # noqa: ANN001
        from app.domains.guest import router as guest_router
        from app.domains.guest.exceptions import PublicNasRegistrationRefusedError

        router = _router(mac=None)
        service = FakeRadiusService(router, None)

        async def _nas_only(svc, rid):  # noqa: ANN001, ANN202
            return router

        monkeypatch.setattr(guest_router, "_nas_only_router", _nas_only)
        with pytest.raises(PublicNasRegistrationRefusedError) as exc:
            await guest_router.register_shared_radius_nas(
                _http({}),
                router.id,
                user=SimpleNamespace(id=str(uuid.uuid4())),
                service=service,
            )
        assert "AP MAC" in exc.value.message

    async def test_register_shared_creates_an_addressless_nas_once(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.guest import router as guest_router

        router = _router()
        registered: list[dict] = []
        rows: list[Any] = []

        class Svc(FakeRadiusService):
            async def list_nas_clients(self, **_: Any):  # noqa: ANN202
                return rows, None

            async def register_nas(self, **kw: Any):  # noqa: ANN202
                registered.append(kw)
                nas = _nas(router, ident=kw["nas_identifier"])
                rows.append(nas)
                return SimpleNamespace(
                    nas_client=nas, shared_secret=kw["shared_secret"]
                )

        service = Svc(router, None)

        async def _nas_only(svc, rid):  # noqa: ANN001, ANN202
            return router

        monkeypatch.setattr(guest_router, "_nas_only_router", _nas_only)
        monkeypatch.setattr(
            guest_router, "_aruba_shared_store", lambda s: _store_with(SECRET)
        )
        monkeypatch.setattr(
            guest_router,
            "get_settings",
            lambda: SimpleNamespace(
                hub_radius_aruba_shared_agent_url="http://agent/radius/shared-client",
                hub_radius_public_address="13.207.123.212",
                aruba_shared_radius_auth_port=1912,
                aruba_shared_radius_acct_port=1913,
            ),
        )
        for _ in range(2):
            resp = await guest_router.register_shared_radius_nas(
                _http({}),
                router.id,
                user=SimpleNamespace(id=str(uuid.uuid4())),
                service=service,
            )
        assert len(registered) == 1
        assert registered[0]["nas_identifier"] == NAS_ID
        assert registered[0]["ip_address"] is None
        data = json.loads(resp.body)["data"] if hasattr(resp, "body") else resp["data"]
        assert data["available"] is True, data["gaps"]
        assert data["nas_identifier"] == NAS_ID
        assert data["ap_mac"] == AP
        assert data["auth_port"] == 1912 and data["accounting_port"] == 1913
        assert data["radius_server"] == {
            "host": "13.207.123.212",
            "auth_port": 1912,
            "accounting_port": 1913,
        }
        assert SECRET not in json.dumps(data)


def test_module_exports() -> None:
    for name in aruba_shared.__all__:
        assert hasattr(aruba_shared, name)
