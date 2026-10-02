"""Aruba Instant On as a NAS-only vendor ("Aruba RADIUS mode").

An Instant On access point is managed only from Aruba's cloud, which this
platform has no API to. It reaches us as a RADIUS NAS and nothing else:
its guest network sends the browser to our portal, the portal form-POSTs the
guest's identifier back to the AP, and the AP asks our FreeRADIUS.

These tests pin four things:

1. the vendor decision in ``vendor_capabilities`` (the module's own
   docstring says this is where it gets recorded);
2. that MikroTik and Omada answers are unchanged by it;
3. the RADIUS boundary: Aruba's bare-hex Calling-Station-Id is understood,
   other vendors' spellings are byte-identical, and no MikroTik VSA is
   sent to an Aruba NAS;
4. the public-address NAS registration route: GLOBAL-pinned, refuses
   anything but a NAS-only device and anything but a public literal IP,
   pushes a controller-shaped stanza and returns the portal URL.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.exceptions import PublicNasRegistrationRefusedError
from app.domains.guest.schemas import (
    PublicNasRegistrationRequest,
    RadiusAccountingRequest,
    RadiusAuthorizeRequest,
)
from app.domains.guest.validators import canonicalize_calling_station_id
from app.domains.rbac.enums import ScopeType
from app.domains.router.device_domain_gate import (
    ControllerManagedFeatureUnavailableError,
    ensure_not_controller_managed,
)
from app.domains.router.vendor_capabilities import (
    ARUBA_INSTANT_ON_VENDOR,
    CONTROLLER_MANAGED_VENDORS,
    NAS_ONLY_VENDORS,
    SUPPORTED_ROUTER_VENDORS,
    ControllerState,
    controller_state_for,
    has_controller_api,
    is_agent_managed,
    is_controller_managed,
    is_controller_managed_row,
    is_nas_only,
    supports_zero_touch_provisioning,
)

_ARUBA = ARUBA_INSTANT_ON_VENDOR
_OMADA = "tplink_omada"
_MIKROTIK = "mikrotik"


def _row(vendor: str, **evidence: object) -> SimpleNamespace:
    fields: dict[str, object] = {
        "vendor": vendor,
        "last_seen_at": None,
        "routeros_version": None,
        "last_health_check_at": None,
        "api_credentials_encrypted": None,
    }
    fields.update(evidence)
    return SimpleNamespace(**fields)


# ============================================================================
# 1. The vendor decision
# ============================================================================


class TestArubaInstantOnIsANasOnlyVendor:
    def test_the_vendor_string(self) -> None:
        """Not the ``aruba`` stub: that is Aruba Instant / AOS, a different
        product, and it stays a stub."""
        assert _ARUBA == "aruba_instant_on"
        assert "aruba" not in CONTROLLER_MANAGED_VENDORS

    def test_it_is_controller_managed_so_every_no_agent_gate_applies(self) -> None:
        assert is_controller_managed(_ARUBA) is True
        assert is_agent_managed(_ARUBA) is False
        assert supports_zero_touch_provisioning(_ARUBA) is False

    def test_it_is_nas_only_and_has_no_controller_api(self) -> None:
        assert is_nas_only(_ARUBA) is True
        assert has_controller_api(_ARUBA) is False

    def test_nas_only_is_a_subset_of_controller_managed(self) -> None:
        """A NAS-only vendor outside CONTROLLER_MANAGED_VENDORS would read as
        an agent-managed MikroTik everywhere -- heartbeats, WireGuard,
        RouterOS writes -- which is the exact failure the module exists to
        prevent."""
        assert NAS_ONLY_VENDORS <= CONTROLLER_MANAGED_VENDORS

    def test_it_can_be_recorded_on_a_fleet_row(self) -> None:
        assert _ARUBA in SUPPORTED_ROUTER_VENDORS

    def test_controller_state_is_no_controller_api_not_not_registered(self) -> None:
        """`not_registered` would tell an operator to register a controller
        integration that cannot exist for this vendor."""
        assert controller_state_for(_row(_ARUBA), None) == (
            ControllerState.NO_CONTROLLER_API.value,
            "vendor_has_no_api",
        )

    def test_the_state_ignores_any_integration_it_is_handed(self) -> None:
        integration = SimpleNamespace(
            is_enabled=False, last_error_code="OMADA_TIMEOUT", external_site_id=None
        )
        state, _reason = controller_state_for(_row(_ARUBA), integration)  # type: ignore[misc]
        assert state == ControllerState.NO_CONTROLLER_API.value

    def test_evidence_still_beats_the_label(self) -> None:
        """A MikroTik mislabelled as Aruba that has checked in is still
        agent-managed -- the 2026-09-10 rule applies to every
        controller-managed vendor, this one included."""
        row = _row(_ARUBA, last_seen_at="2026-10-01T00:00:00Z")
        assert is_controller_managed_row(row) is False
        assert controller_state_for(row, None) is None

    def test_device_domain_writes_are_refused_naming_the_product(self) -> None:
        router = SimpleNamespace(vendor=_ARUBA, name="Lobby AP21")
        with pytest.raises(ControllerManagedFeatureUnavailableError) as exc:
            ensure_not_controller_managed(router, feature="Port Forwarding")
        assert "Aruba Instant On cloud" in exc.value.message

    def test_wireguard_is_refused(self) -> None:
        """No agent, so no peer -- and a peer minted for one leaks a hub
        address forever (the hub agent has no delete verb)."""
        from app.domains.wireguard.exceptions import WireGuardVendorNotSupportedError
        from app.domains.wireguard.validators import (
            validate_router_eligible_for_wireguard,
        )

        router = SimpleNamespace(id=uuid.uuid4(), vendor=_ARUBA, status="online")
        with pytest.raises(WireGuardVendorNotSupportedError):
            validate_router_eligible_for_wireguard(router)


class TestOtherVendorsAreUnchanged:
    def test_omada_still_has_a_controller_api(self) -> None:
        assert is_controller_managed(_OMADA) is True
        assert is_nas_only(_OMADA) is False
        assert has_controller_api(_OMADA) is True

    def test_omada_state_without_an_integration_is_still_not_registered(self) -> None:
        assert controller_state_for(_row(_OMADA), None) == (
            ControllerState.NOT_REGISTERED.value,
            "no_integration",
        )

    def test_mikrotik_is_still_agent_managed_with_no_controller(self) -> None:
        assert is_agent_managed(_MIKROTIK) is True
        assert is_nas_only(_MIKROTIK) is False
        assert has_controller_api(_MIKROTIK) is False
        assert controller_state_for(_row(_MIKROTIK), None) is None


# ============================================================================
# 3. The RADIUS boundary
# ============================================================================


class TestCallingStationIdCanonicalisation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"),
            ("60F4450B2866", "60:F4:45:0B:28:66"),
            (" 60f4450b2866 ", "60:F4:45:0B:28:66"),
        ],
    )
    def test_bare_hex_from_an_aruba_ap_becomes_colon_form(
        self, raw: str, expected: str
    ) -> None:
        assert canonicalize_calling_station_id(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "AA:BB:CC:DD:EE:FF",  # MikroTik
            "aa:bb:cc:dd:ee:ff",
            "B8-FB-B3-5D-64-3E",  # Omada
            "26-79-94-B5-24-D9",
            "",
            "not-a-mac",
            "aabbccddeeff00",  # 14 hex digits: not a MAC, left alone
        ],
    )
    def test_every_other_spelling_is_byte_identical(self, raw: str) -> None:
        assert canonicalize_calling_station_id(raw) is raw

    def test_none_stays_none(self) -> None:
        assert canonicalize_calling_station_id(None) is None

    def test_the_authorize_body_is_canonicalised(self) -> None:
        body = RadiusAuthorizeRequest(
            username="+919800000000", calling_station_id="60f4450b2866"
        )
        assert body.calling_station_id == "60:F4:45:0B:28:66"

    def test_the_accounting_body_is_canonicalised(self) -> None:
        body = RadiusAccountingRequest(
            status_type="start",
            username="+919800000000",
            calling_station_id="60f4450b2866",
        )
        assert body.calling_station_id == "60:F4:45:0B:28:66"

    def test_a_mikrotik_authorize_body_is_unchanged(self) -> None:
        body = RadiusAuthorizeRequest(
            username="+919800000000", calling_station_id="FA:42:FE:9E:29:03"
        )
        assert body.calling_station_id == "FA:42:FE:9E:29:03"


class _FixedQueueLookup:
    async def get_rate_limit_reply_for_session(self, session_id: uuid.UUID) -> str:
        return "1000k/5000k"


class _QueueHook:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def resolve_and_assign_queue(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


async def _login_and_authorize(fx, *, username: str = "+919811122233"):  # noqa: ANN001, ANN202
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="cg-aruba-test",
        shared_secret="supersecret123",
    )
    await fx.guest_service.login_via_otp(
        identifier=username,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac="60:f4:45:0b:28:66",
        ip_address="192.168.1.50",
    )
    nas_client = await fx.radius_service.authenticate_nas(
        nas_identifier="cg-aruba-test", shared_secret="supersecret123"
    )
    return await fx.radius_service.authorize(
        nas_client=nas_client,
        username=username,
        calling_station_id=canonicalize_calling_station_id("60f4450b2866"),
    )


class TestRadiusAuthorizeForAnArubaNas:
    async def test_a_signed_in_guest_is_accepted(self) -> None:
        from tests.unit.test_guest import make_fixture

        fx = make_fixture()
        fx.router.vendor = _ARUBA
        authz = await _login_and_authorize(fx)
        assert authz.authorized is True
        assert authz.session_timeout_seconds is not None

    async def test_an_unknown_identifier_is_rejected(self) -> None:
        from tests.unit.test_guest import make_fixture

        fx = make_fixture()
        fx.router.vendor = _ARUBA
        await _login_and_authorize(fx)
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="cg-aruba-test", shared_secret="supersecret123"
        )
        authz = await fx.radius_service.authorize(
            nas_client=nas_client, username="+910000000000"
        )
        assert authz.authorized is False

    async def test_no_mikrotik_rate_limit_is_sent_to_an_aruba_nas(self) -> None:
        from tests.unit.test_guest import make_fixture

        fx = make_fixture(queue_lookup=_FixedQueueLookup())
        fx.router.vendor = _ARUBA
        authz = await _login_and_authorize(fx)
        assert authz.authorized is True
        assert authz.rate_limit is None

    async def test_a_mikrotik_nas_still_gets_its_rate_limit(self) -> None:
        """The same fixture with the vendor left alone: byte-identical."""
        from tests.unit.test_guest import make_fixture

        fx = make_fixture(queue_lookup=_FixedQueueLookup())
        authz = await _login_and_authorize(fx)
        assert authz.rate_limit == "1000k/5000k"

    async def test_no_queue_is_assigned_at_an_aruba_venue(self) -> None:
        """There is no device-side write a speed could reach, so nothing is
        assigned -- rather than a controller-hook failure per login."""
        from tests.unit.test_guest import make_fixture

        hook = _QueueHook()
        fx = make_fixture(queue_assignment_hook=hook)
        fx.router.vendor = _ARUBA
        await _login_and_authorize(fx)
        assert hook.calls == []

    async def test_a_mikrotik_venue_still_assigns_its_queue_by_ip(self) -> None:
        from tests.unit.test_guest import make_fixture

        hook = _QueueHook()
        fx = make_fixture(queue_assignment_hook=hook)
        await _login_and_authorize(fx)
        assert [c["device_target"] for c in hook.calls] == ["192.168.1.50"]


# ============================================================================
# 4. Public-address NAS registration
# ============================================================================


class _NasRow(SimpleNamespace):
    pass


_ENC = "enc:"


class _FakeRadiusService:
    """Just the surface the NAS-only routes touch."""

    def __init__(
        self,
        router: SimpleNamespace,
        existing: list | None = None,
        at_address: list | None = None,
    ) -> None:
        self.router_lookup = self
        self._router = router
        self._existing = existing or []
        self._at_address = at_address or []
        self.registered: list[dict] = []
        self.rotated: list[dict] = []
        self.synced: list[str] = []
        self._row = _NasRow(
            id=uuid.uuid4(),
            router_id=router.id,
            nas_identifier="",
            hub_client_synced_ip=None,
            ip_address=None,
            status="active",
            shared_secret_encrypted=None,
        )

    async def get_router(self, router_id, **_: object):  # noqa: ANN001, ANN201
        assert router_id == self._router.id
        return self._router

    async def list_nas_clients(self, **_: object):  # noqa: ANN201
        return self._existing, None

    async def nas_clients_at_address(self, address: str) -> list:
        return [n for n in self._at_address if n.ip_address == address]

    def shared_secret_fingerprint(self, nas_client) -> tuple[str, int]:  # noqa: ANN001
        from app.domains.guest.nas_number_generator import secret_fingerprint

        plain = nas_client.shared_secret_encrypted.removeprefix(_ENC)
        return secret_fingerprint(plain), len(plain)

    async def get_nas_client(self, nas_id, **_: object):  # noqa: ANN001, ANN201
        return self._existing[0]

    async def register_nas(self, **kwargs: object):  # noqa: ANN201
        self.registered.append(kwargs)
        self._row.nas_identifier = str(kwargs["nas_identifier"])
        self._row.ip_address = kwargs.get("ip_address")
        secret = str(kwargs["shared_secret"])
        self._row.shared_secret_encrypted = _ENC + secret
        return SimpleNamespace(nas_client=self._row, shared_secret=secret)

    async def regenerate_secret(  # noqa: ANN201
        self,
        *,
        nas_id,
        push_secret,
        new_secret=None,
        **_: object,  # noqa: ANN001
    ):
        secret = new_secret or "urlsafe-default"
        await push_secret(secret)
        self.rotated.append({"nas_id": nas_id, "secret": secret})
        row = self._existing[0]
        row.shared_secret_encrypted = _ENC + secret
        return SimpleNamespace(nas_client=row, shared_secret=secret)

    async def record_hub_client_sync(self, *, nas_id, tunnel_ip_address, **_: object):  # noqa: ANN001, ANN201, E501
        self.synced.append(tunnel_ip_address)
        row = self._existing[0] if self._existing else self._row
        row.hub_client_synced_ip = tunnel_ip_address
        row.ip_address = tunnel_ip_address
        return row


def _aruba_router(vendor: str = _ARUBA) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        vendor=vendor,
        name="Lobby AP21",
        serial_number="SERIAL0001",
        mac_address="AA:BB:CC:00:00:01",
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
    )


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(request_id="req-1"))


def _user() -> SimpleNamespace:
    return SimpleNamespace(id=str(uuid.uuid4()))


def _data(response) -> dict:  # noqa: ANN001
    if isinstance(response, dict):
        return response["data"]
    import json

    return json.loads(response.body)["data"]


def _pinned(path_suffix: str, method: str) -> dict:
    from app.domains.guest.router import nas_platform_router

    route = next(
        r
        for r in nas_platform_router.routes
        if r.path.endswith(path_suffix) and method in r.methods
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


@pytest.fixture
def pushes(monkeypatch):  # noqa: ANN001, ANN201
    from app.domains.guest import router as guest_router

    sent: list[dict] = []

    async def _push(**kw: object) -> str:
        sent.append(kw)
        return str(kw["controller_ip"])

    monkeypatch.setattr(guest_router, "push_controller_nas_client", _push)
    return sent


class TestRoutesArePinnedToGlobalScope:
    """Introspect the mounted routes, so deleting `scope=` fails here."""

    def test_register(self) -> None:
        dep = _pinned("/register-public/{router_id}", "POST")
        assert dep[ScopeType] == ScopeType.GLOBAL
        assert dep[str] == "radius.create"

    def test_status(self) -> None:
        dep = _pinned("/public/{router_id}", "GET")
        assert dep[ScopeType] == ScopeType.GLOBAL
        assert dep[str] == "radius.read"


class TestRegisterPublicNasRoute:
    async def _register(self, router, ip: str, service=None):  # noqa: ANN001, ANN202
        from app.domains.guest import router as guest_router

        return await guest_router.register_public_radius_nas(
            _request(),
            router.id,
            PublicNasRegistrationRequest(nas_ip=ip),
            user=_user(),
            service=service or _FakeRadiusService(router),
        )

    @pytest.mark.parametrize("vendor", [_MIKROTIK, _OMADA])
    async def test_a_non_nas_only_vendor_is_refused_422(
        self, pushes: list, vendor: str
    ) -> None:
        with pytest.raises(PublicNasRegistrationRefusedError) as exc:
            await self._register(_aruba_router(vendor=vendor), "1.1.1.1")
        assert exc.value.status_code == 422
        assert exc.value.data == {"code": "PUBLIC_NAS_REGISTRATION_REFUSED"}
        assert pushes == []

    @pytest.mark.parametrize(
        "address",
        [
            "192.168.1.1",  # private
            "100.64.0.1",  # CGNAT
            "127.0.0.1",  # loopback
            "10.20.0.7",  # WireGuard overlay
            "wifi.example.com",  # hostname
            "1.2.3.0/24",  # prefix
        ],
    )
    async def test_a_non_public_address_is_refused_before_anything_is_written(
        self, pushes: list, address: str
    ) -> None:
        router = _aruba_router()
        service = _FakeRadiusService(router)
        with pytest.raises(PublicNasRegistrationRefusedError) as exc:
            await self._register(router, address, service)
        assert exc.value.status_code == 422
        assert service.registered == []
        assert pushes == []

    async def test_an_ip_another_venue_uses_is_refused(self, pushes: list) -> None:
        router = _aruba_router()
        other = _NasRow(router_id=uuid.uuid4(), ip_address="1.1.1.1")
        service = _FakeRadiusService(router, at_address=[other])
        with pytest.raises(PublicNasRegistrationRefusedError) as exc:
            await self._register(router, "1.1.1.1", service)
        assert "share RADIUS" in exc.value.message
        assert service.registered == []
        assert pushes == []

    async def test_a_fresh_registration(self, pushes: list) -> None:
        router = _aruba_router()
        service = _FakeRadiusService(router)
        data = _data(await self._register(router, " 1.1.1.1 ", service))

        secret = data["shared_secret"]
        assert len(secret) == 32 and secret.isalnum() and secret.isascii()
        assert pushes == [
            {
                "controller_ip": "1.1.1.1",
                "nas_identifier": f"cg-aruba-{str(router.id)[:8]}",
                "secret": secret,
            }
        ]
        assert service.registered[0]["ip_address"] == "1.1.1.1"
        assert service.registered[0]["shared_secret"] == secret
        from app.domains.guest.nas_number_generator import secret_fingerprint

        assert data["secret_fingerprint"] == secret_fingerprint(secret)
        assert data["secret_length"] == 32
        assert data["nas_ip"] == "1.1.1.1"
        assert data["hub_confirmed"] is True
        assert data["rotated"] is False
        assert data["vendor"] == _ARUBA

        portal = data["portal_url"]
        assert portal["server_host"] == "auth.wyfyguest.com"
        assert portal["server_port"] == 443
        assert portal["use_https"] is True
        assert (
            portal["url"]
            == "https://" + portal["server_host"] + portal["server_url_path"]
        )
        url = urlsplit(portal["url"])
        assert url.path == "/portal"
        query = parse_qs(url.query)
        assert query["netProvider"] == [_ARUBA]
        assert query["portalMode"] == ["radius"]
        assert query["routerId"] == [str(router.id)]
        assert query["locationId"] == [str(router.location_id)]
        assert query["organizationId"] == [str(router.organization_id)]

    async def test_a_re_registration_rotates_pushes_first_and_moves_the_ip(
        self, pushes: list
    ) -> None:
        router = _aruba_router()
        existing = _NasRow(
            id=uuid.uuid4(),
            router_id=router.id,
            nas_identifier="cg-aruba-0000abcd",
            hub_client_synced_ip="1.1.1.1",
            ip_address="1.1.1.1",
            shared_secret_encrypted=_ENC + "old",
        )
        # Its own row at the old address is not "another venue".
        service = _FakeRadiusService(router, existing=[existing], at_address=[existing])
        data = _data(await self._register(router, "8.8.4.4", service))

        assert service.registered == []
        secret = service.rotated[0]["secret"]
        assert len(secret) == 32 and secret.isalnum()
        assert pushes == [
            {
                "controller_ip": "8.8.4.4",
                "nas_identifier": "cg-aruba-0000abcd",
                "secret": secret,
            }
        ]
        assert service.synced == ["8.8.4.4"]
        assert data["rotated"] is True
        assert data["nas_ip"] == "8.8.4.4"
        assert data["hub_confirmed"] is True


class TestPublicNasStatusRoute:
    async def _status(self, router, service, monkeypatch, hub: str = ""):  # noqa: ANN001, ANN202
        from app.domains.guest import router as guest_router

        settings = SimpleNamespace(
            hub_radius_public_address=hub,
            api_public_base_url="https://api.wyfyguest.com",
        )
        monkeypatch.setattr(guest_router, "get_settings", lambda: settings)
        return _data(
            await guest_router.get_public_radius_nas_status(
                _request(), router.id, service=service
            )
        )

    async def test_unregistered_shows_gaps_and_no_url(self, monkeypatch) -> None:  # noqa: ANN001
        router = _aruba_router()
        data = await self._status(router, _FakeRadiusService(router), monkeypatch)
        assert data["registered"] is False
        assert data["portal_url"] is None
        assert set(data["gaps"]) == {
            "nas_not_registered",
            "radius_server_address_not_configured",
        }
        assert data["vendor_label"] == "Aruba Instant On"
        assert data["allowed_domains"] == ["auth.wyfyguest.com", "api.wyfyguest.com"]

    async def test_registered_shows_fingerprint_never_the_secret(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        router = _aruba_router()
        existing = _NasRow(
            id=uuid.uuid4(),
            router_id=router.id,
            nas_identifier="cg-aruba-0000abcd",
            hub_client_synced_ip="1.1.1.1",
            ip_address="1.1.1.1",
            status="active",
            shared_secret_encrypted=_ENC + "S" * 32,
        )
        data = await self._status(
            router,
            _FakeRadiusService(router, existing=[existing]),
            monkeypatch,
            hub="radius.example.net",
        )
        assert data["gaps"] == []
        assert data["registered"] is True
        assert data["hub_confirmed"] is True
        assert data["secret_length"] == 32
        assert len(data["secret_fingerprint"]) == 12
        assert "S" * 32 not in str(data)
        assert data["radius_server"] == {
            "host": "radius.example.net",
            "auth_port": 1812,
            "accounting_port": 1813,
        }
        assert parse_qs(urlsplit(data["portal_url"]["url"]).query)["netProvider"] == [
            _ARUBA
        ]

    async def test_a_stanza_the_hub_never_confirmed_is_a_gap(self, monkeypatch) -> None:  # noqa: ANN001
        router = _aruba_router()
        existing = _NasRow(
            id=uuid.uuid4(),
            router_id=router.id,
            nas_identifier="cg-aruba-0000abcd",
            hub_client_synced_ip=None,
            ip_address="1.1.1.1",
            status="active",
            shared_secret_encrypted=_ENC + "x" * 32,
        )
        data = await self._status(
            router,
            _FakeRadiusService(router, existing=[existing]),
            monkeypatch,
            hub="h",
        )
        assert data["gaps"] == ["hub_not_confirmed"]
        assert data["portal_url"] is None

    async def test_a_mikrotik_row_is_a_gap_not_a_url(self, monkeypatch) -> None:  # noqa: ANN001
        router = _aruba_router(vendor=_MIKROTIK)
        data = await self._status(router, _FakeRadiusService(router), monkeypatch)
        assert "not_nas_only_vendor" in data["gaps"]
        assert data["portal_url"] is None


class TestGenericRotateForANasOnlyDevice:
    async def test_rotates_against_the_public_ip_without_a_wireguard_peer(
        self, pushes: list, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.guest import router as guest_router

        router = _aruba_router()
        existing = _NasRow(
            id=uuid.uuid4(),
            router_id=router.id,
            nas_identifier="cg-aruba-0000abcd",
            hub_client_synced_ip="1.1.1.1",
            ip_address="1.1.1.1",
            status="active",
            shared_secret_encrypted=_ENC + "old",
        )
        service = _FakeRadiusService(router, existing=[existing])

        class _NoPeers:
            async def get_peer(self, **_: object):  # noqa: ANN201
                raise AssertionError("a NAS-only device has no WireGuard peer")

        class _Echo:
            """Stands in for the NAS-row serializer and the rotated-response
            schema, which need a full ORM row this fake does not carry."""

            def __init__(self, **fields: object) -> None:
                self.fields = fields

            def model_dump(self) -> dict:
                return dict(self.fields)

        monkeypatch.setattr(guest_router, "_nas_response", lambda row: _Echo())
        monkeypatch.setattr(guest_router, "RadiusNasSecretRotatedResponse", _Echo)
        response = await guest_router.regenerate_radius_nas_secret(
            _request(),
            existing.id,
            user=_user(),
            service=service,
            wireguard_service=_NoPeers(),
        )
        secret = service.rotated[0]["secret"]
        assert len(secret) == 32 and secret.isalnum()
        assert pushes == [
            {
                "controller_ip": "1.1.1.1",
                "nas_identifier": "cg-aruba-0000abcd",
                "secret": secret,
            }
        ]
        assert service.synced == ["1.1.1.1"]
        body = _data(response)
        assert body["shared_secret"] == secret
        assert "Instant On" in body["device_action"]


# ============================================================================
# 5. Customer capabilities: a declaration, not a 404
# ============================================================================


class TestClientCapabilitiesAtAnArubaVenue:
    def _service(self):  # noqa: ANN202
        from tests.unit.test_network_integration import FakeRepository
        from tests.unit.test_omada_client_management import _service

        repo = FakeRepository()
        return _service(repo), repo

    async def test_an_aruba_venue_declares_everything_unsupported(self) -> None:
        service, repo = self._service()
        org, loc = uuid.uuid4(), uuid.uuid4()
        repo.nas_only_rows[(loc, org)] = _ARUBA
        report = await service.get_client_capabilities(
            location_id=loc, organization_id=org
        )
        assert {k: v["supported"] for k, v in report.capabilities.items()} == {
            "set_rate_limit": False,
            "clear_rate_limit": False,
            "block": False,
            "unblock": False,
            "list_blocked": False,
            "disconnect": False,
            "client_stats": False,
        }
        assert all(v["reason"] for v in report.capabilities.values())
        assert "Instant On" in report.capabilities["set_rate_limit"]["reason"]
        assert report.controller.reachable is None
        assert "Instant On" in (report.controller.reason or "")
        for entry in report.capabilities.values():
            for word in ("RADIUS", "NAS", "controller"):
                assert word not in entry["reason"]

    async def test_another_tenants_aruba_location_is_still_not_found(self) -> None:
        from app.domains.network_integration.exceptions import (
            LocationHasNoControllerError,
        )

        service, repo = self._service()
        org, loc = uuid.uuid4(), uuid.uuid4()
        repo.nas_only_rows[(loc, org)] = _ARUBA
        with pytest.raises(LocationHasNoControllerError):
            await service.get_client_capabilities(
                location_id=loc, organization_id=uuid.uuid4()
            )

    async def test_a_location_with_nothing_still_404s(self) -> None:
        from app.domains.network_integration.exceptions import (
            LocationHasNoControllerError,
        )

        service, _repo = self._service()
        with pytest.raises(LocationHasNoControllerError):
            await service.get_client_capabilities(
                location_id=uuid.uuid4(), organization_id=uuid.uuid4()
            )


class TestNasOnlyPortalUrl:
    def test_it_is_the_omada_radius_url_with_this_vendor(self) -> None:
        from app.domains.network_integration.validators import (
            build_external_portal_url,
            build_nas_only_portal_url,
        )

        ids = {
            "organization_id": uuid.uuid4(),
            "location_id": uuid.uuid4(),
            "router_id": uuid.uuid4(),
        }
        aruba = build_nas_only_portal_url(**ids, vendor=_ARUBA)
        omada = build_external_portal_url(**ids, provider="omada", portal_mode="radius")
        assert aruba is not None and omada is not None
        assert aruba.scheme == omada.scheme == "https"
        assert aruba.host_and_query == omada.host_and_query.replace(
            "netProvider=omada", f"netProvider={_ARUBA}"
        )

    def test_no_location_means_no_url(self) -> None:
        from app.domains.network_integration.validators import (
            build_nas_only_portal_url,
        )

        assert (
            build_nas_only_portal_url(
                organization_id=uuid.uuid4(),
                location_id=None,
                router_id=uuid.uuid4(),
                vendor=_ARUBA,
            )
            is None
        )
