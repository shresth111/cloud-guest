# ruff: noqa: E501 -- snapshot strings and SQL are kept verbatim
"""BE-10 pure parts: curated params (no passwords, ever), the RouterOS
script, the NBI client against GenieACS-shaped JSON fixtures, ACS
credentials, and the nginx ``acs-auth`` endpoint."""

from __future__ import annotations

import base64
import json
import pathlib
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from app.domains.tr069 import credentials, internal_router
from app.domains.tr069 import params as P
from app.domains.tr069.config import Tr069Settings
from app.domains.tr069.exceptions import Tr069AcsUnavailableError
from app.domains.tr069.nbi_client import NbiClient
from app.domains.tr069.script import render_tr069_script, ros_quote
from app.domains.tr069.sync import apply_facts, username_query

FIX = pathlib.Path(__file__).parent / "fixtures" / "genieacs"
TR181 = json.loads((FIX / "device_tr181.json").read_text())[0]
TR098 = json.loads((FIX / "device_tr098.json").read_text())[0]
LEAKS = (
    "acs-secret-leak",
    "pppoe-secret-leak",
    "wifi-secret-leak",
    "psk-leak",
    "ppp-leak",
    "wlan-leak",
)


class TestParams:
    def test_tr181_curated_shape(self) -> None:
        cache = P.curate(TR181)
        assert cache == {
            "uptime_s": 123456,
            "wan_ip": "203.0.113.10",
            "wan_connection_type": "pppoe",
            "pppoe_username": "cafe-x@isp",
            "wifi": [
                {
                    "index": 1,
                    "ssid": "Cafe X",
                    "band": "2.4GHz",
                    "enabled": True,
                    "clients": 7,
                },
                {
                    "index": 2,
                    "ssid": "Cafe X 5G",
                    "band": "5GHz",
                    "enabled": False,
                    "clients": 0,
                },
            ],
            "lan_hosts": 12,
            "hardware_version": "r3",
            "software_version": "7.18.2",
        }

    def test_tr098_fallback(self) -> None:
        cache = P.curate(TR098)
        assert cache["wan_ip"] == "198.51.100.4"
        assert cache["pppoe_username"] == "sub001"
        assert cache["wifi"][0]["ssid"] == "Home" and cache["wifi"][0]["clients"] == 2
        assert P.data_model(TR098) == "tr098" and P.data_model(TR181) == "tr181"

    @pytest.mark.parametrize("doc", [TR181, TR098], ids=["tr181", "tr098"])
    def test_no_password_reaches_params_cache(self, doc) -> None:
        """KeyPassphrase / PreSharedKey / *Password* are in the fixture and
        must not appear anywhere in what we store or ask for."""
        row = SimpleNamespace(product_class=None, params_cache={})
        apply_facts(row, doc)
        stored = json.dumps(row.params_cache) + json.dumps(vars(row), default=str)
        for leak in LEAKS:
            assert leak not in stored
        for model in ("tr181", "tr098"):
            names = P.refresh_parameter_names(model)
            assert names and not any(P.is_denied(n) for n in names)
            assert not any("KeyPassphrase" in n or "Password" in n for n in names)
        assert not any(P.is_denied(p) for p in P.projection())

    def test_resolver_refuses_denied_paths(self) -> None:
        assert (
            P.resolve(TR181, "Device.WiFi.AccessPoint.1.Security.KeyPassphrase") is None
        )
        assert P.resolve(TR181, "Device.ManagementServer.Password") is None
        assert P.resolve(TR181, "Device.ManagementServer.Username") == "cust-1a2b3c4d"

    def test_username_query_matches_both_data_models(self) -> None:
        q = username_query(["isp-1", "cust-2"])
        assert {"Device.ManagementServer.Username._value": "cust-2"} in q["$or"]
        assert {"InternetGatewayDevice.ManagementServer.Username._value": "isp-1"} in q[
            "$or"
        ]


class TestScript:
    def test_quoting_escapes_quotes_backslash_and_dollar(self) -> None:
        assert ros_quote('a"b\\c$d') == '"a\\"b\\\\c\\$d"'
        with pytest.raises(ValueError):
            ros_quote("a\nb")

    def test_snapshot(self) -> None:
        script = render_tr069_script(
            acs_url="https://acs.example.com/",
            username="cust-1a2b3c4d",
            password='pa"ss$word\\x',
            interval_s=300,
            enabled=True,
            now=datetime(2026, 10, 22, 6, 0, tzinfo=UTC),
        )
        assert script == (
            "# Wyfy Guest Network: TR-069 management\n"
            "# Paste into a RouterOS terminal. Needs the tr069-client package.\n"
            ':if ([:len [/system package find name="tr069-client"]] = 0) do={ :error '
            '"WYFY-TR069: install the tr069-client package for this RouterOS version and '
            'architecture, reboot, then paste this again" }\n'
            ':if ([:len [/certificate find name="wyfy-acs-root"]] = 0) do={ /tool fetch '
            'url="https://letsencrypt.org/certs/isrgrootx1.pem" dst-path="wyfy-acs-root.pem"; '
            ':delay 2s; /certificate import file-name="wyfy-acs-root.pem" name="wyfy-acs-root" '
            'passphrase="" }\n'
            ':if ([:len [/certificate find name="wyfy-acs-root"]] = 0) do={ :error '
            '"WYFY-TR069: could not import the ACS root certificate" }\n'
            '/tr069-client set acs-url="https://acs.example.com/" username="cust-1a2b3c4d" '
            'password="pa\\"ss\\$word\\\\x" periodic-inform-enabled=yes '
            "periodic-inform-interval=300s enabled=yes\n"
            ":delay 10s\n"
            ":local st [/tr069-client get status]\n"
            ':if ($st = "running") do={ :put "WYFY-TR069: PASS (status=running)" } else={ '
            ':error ("WYFY-TR069: status=" . $st . " " . [/tr069-client get last-session-error]) }\n'
            '/system note set note="wyfy-tr069 2026-10-22T06:00:00Z"\n'
        )

    def test_disabled_location_still_renders_with_enabled_no(self) -> None:
        script = render_tr069_script(
            acs_url="https://acs.example.com/",
            username="u",
            password="p",
            interval_s=600,
            enabled=False,
        )
        assert "enabled=no" in script and "periodic-inform-interval=600s" in script
        assert "PASS" not in script


def _client(handler) -> NbiClient:
    return NbiClient(
        Tr069Settings(nbi_url="http://nbi.test:7557", nbi_timeout_s=1),
        transport=httpx.MockTransport(handler),
    )


class TestNbiClient:
    async def test_device_query_sends_json_query_and_projection(self) -> None:
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["path"] = request.url.path
            seen["query"] = json.loads(request.url.params["query"])
            seen["projection"] = request.url.params["projection"]
            return httpx.Response(200, json=[TR181])

        docs = await _client(handler).query_devices(
            username_query(["cust-1"]), ["_id", "_lastInform"]
        )
        assert docs[0]["_id"] == TR181["_id"]
        assert seen["path"] == "/devices/" and "$or" in seen["query"]
        assert seen["projection"] == "_id,_lastInform"

    @pytest.mark.parametrize("code", [200, 202])
    async def test_task_200_and_202(self, code) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/devices/E48D8C-RB750Gr3-HG3XXXX/tasks"
            assert "connection_request" in request.url.params
            assert json.loads(request.content) == {"name": "reboot"}
            return httpx.Response(
                code, json=json.loads((FIX / "task_202.json").read_text())
            )

        status, body = await _client(handler).post_task(
            "E48D8C-RB750Gr3-HG3XXXX", {"name": "reboot"}
        )
        assert status == code and body["_id"] == "6717a1f0c3b4a2001234abcd"

    async def test_device_id_is_url_encoded(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.raw_path.startswith(b"/devices/A%2FB%20C/tasks")
            return httpx.Response(202, json={})

        await _client(handler).post_task("A/B C", {"name": "reboot"})

    async def test_faults(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/faults/"
            return httpx.Response(
                200, json=json.loads((FIX / "faults.json").read_text())
            )

        faults = await _client(handler).get_faults(
            {"device": "E48D8C-RB750Gr3-HG3XXXX"}
        )
        assert faults[0]["code"] == "cwmp.9002"

    @pytest.mark.parametrize(
        "handler",
        [
            lambda r: httpx.Response(503, text="down"),
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r)),
            lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=r)),
        ],
        ids=["5xx", "connect", "timeout"],
    )
    async def test_unreachable_is_502(self, handler) -> None:
        with pytest.raises(Tr069AcsUnavailableError) as err:
            await _client(handler).query_devices({})
        assert err.value.status_code == 502
        assert err.value.data["code"] == "TR069_ACS_UNAVAILABLE"
        assert "nbi.test" not in err.value.message


class TestCredentials:
    def test_generated_credentials(self) -> None:
        assert credentials.generate_username("isp").startswith("isp-")
        assert len(credentials.generate_username("cust")) == len("cust-") + 8
        password = credentials.generate_password()
        assert len(password) == 24 and password.isalnum()
        hashed = credentials.hash_password(password)
        assert credentials.verify_password(password, hashed)
        assert not credentials.verify_password(password + "x", hashed)
        assert not credentials.verify_password(password, "not-a-hash")


# -- acs-auth -----------------------------------------------------------------

SECRET = "edge-s3cret"


@pytest.fixture
def edge(monkeypatch):
    from functools import lru_cache

    from app.database.session import get_db_session
    from app.domains.isp_partner import config as isp_config
    from app.domains.tr069 import config as tr_config

    settings = Tr069Settings(enabled=True, edge_shared_secret=SECRET)
    monkeypatch.setattr(tr_config, "get_tr069_settings", lambda: settings)
    monkeypatch.setattr(internal_router, "get_tr069_settings", lambda: settings)
    monkeypatch.setattr(
        isp_config,
        "get_isp_partner_settings",
        lambda: isp_config.IspPartnerSettings(enabled=True),
    )
    password = "AbcdEfgh1234IjklMnop5678"
    cred = SimpleNamespace(
        username="cust-1a2b3c4d",
        password_hash=credentials.hash_password(password),
        enabled=True,
        isp_organization_id=uuid.uuid4(),
        customer_organization_id=uuid.uuid4(),
    )
    state = SimpleNamespace(cred=cred, password=password, owner_ok=True, lookups=0)

    class Store:
        def __init__(self, session):
            pass

        async def get_by_username(self, username):
            state.lookups += 1
            return state.cred if username == state.cred.username else None

    async def owner_active(session, credential):
        return state.owner_ok

    monkeypatch.setattr(internal_router, "CredentialStore", Store)
    monkeypatch.setattr(internal_router, "_owner_active", owner_active)
    internal_router.positive_cache.clear()

    @lru_cache(maxsize=1)
    def app():
        from app.main import create_app

        return create_app()

    async def _db():
        class NoWrites:
            def add(self, *a):
                raise AssertionError("acs-auth must not write")

            async def commit(self):
                return None

            async def rollback(self):
                return None

        yield NoWrites()

    application = app()
    application.dependency_overrides[get_db_session] = _db
    state.client = TestClient(application, raise_server_exceptions=False)
    yield state
    application.dependency_overrides.clear()
    internal_router.positive_cache.clear()


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _call(state, *, gate=SECRET, auth=None):
    headers = {}
    if gate is not None:
        headers["X-Wyfy-Acs-Gate"] = gate
    if auth is not None:
        headers["Authorization"] = auth
    return state.client.get("/api/v1/internal/tr069/acs-auth", headers=headers)


def test_acs_auth_good_credential_is_204_with_user_header(edge) -> None:
    r = _call(edge, auth=_basic(edge.cred.username, edge.password))
    assert r.status_code == 204 and r.content == b""
    assert r.headers["X-Wyfy-Acs-User"] == edge.cred.username


def _count_verifies(monkeypatch) -> list[int]:
    calls = [0]
    real = internal_router.verify_password

    def counting(password, password_hash):
        calls[0] += 1
        return real(password, password_hash)

    monkeypatch.setattr(internal_router, "verify_password", counting)
    return calls


def test_acs_auth_positive_result_is_cached(edge, monkeypatch) -> None:
    """The cache skips only the Argon2id verify. The credential row is read
    on every request (that read is what makes "off" immediate)."""
    verifies = _count_verifies(monkeypatch)
    for _ in range(3):
        assert (
            _call(edge, auth=_basic(edge.cred.username, edge.password)).status_code
            == 204
        )
    assert verifies[0] == 1
    assert edge.lookups == 3


def _ok(state, password=None) -> int:
    return _call(
        state, auth=_basic(state.cred.username, password or state.password)
    ).status_code


def test_acs_auth_off_toggle_applies_on_the_next_request(edge) -> None:
    """PUT /isp/tr069/customers/{id} {"enabled": false} flips the row. A CPE
    whose positive answer is cached must get 401 on its very next request,
    not up to 60 s later (measured on wyfy-isp-test before this fix)."""
    assert _ok(edge) == 204  # now cached
    edge.cred.enabled = False
    assert _ok(edge) == 401
    edge.cred.enabled = True
    assert _ok(edge) == 204


def test_acs_auth_suspended_owner_applies_on_the_next_request(edge) -> None:
    """ISP suspended or customer disabled after a cached positive -> 401 next."""
    assert _ok(edge) == 204
    edge.owner_ok = False
    assert _ok(edge) == 401


def test_acs_auth_rotation_applies_on_the_next_request(edge) -> None:
    """Rotate writes a new hash (same username). The old password, cached a
    moment ago, must fail on the next request; the new one must work."""
    old = edge.password
    assert _ok(edge, old) == 204
    new = credentials.generate_password()
    edge.cred.password_hash = credentials.hash_password(new)
    assert _ok(edge, old) == 401
    assert _ok(edge, new) == 204
    assert _ok(edge, old) == 401


@pytest.mark.parametrize(
    "auth",
    [
        None,
        "Bearer x",
        "Basic !!!",
        _basic("cust-1a2b3c4d", "wrong"),
        _basic("nobody", "x"),
    ],
    ids=["none", "bearer", "garbage", "wrong-password", "unknown-user"],
)
def test_acs_auth_bad_credential_is_401(edge, auth) -> None:
    assert _call(edge, auth=auth).status_code == 401


def test_acs_auth_disabled_credential_or_inactive_owner_is_401(edge) -> None:
    edge.cred.enabled = False
    assert (
        _call(edge, auth=_basic(edge.cred.username, edge.password)).status_code == 401
    )
    edge.cred.enabled = True
    edge.owner_ok = False  # suspended ISP or disabled customer
    assert (
        _call(edge, auth=_basic(edge.cred.username, edge.password)).status_code == 401
    )


@pytest.mark.parametrize("gate", [None, "", "wrong"], ids=["absent", "empty", "wrong"])
def test_acs_auth_without_the_gate_secret_is_404(edge, gate) -> None:
    r = _call(edge, gate=gate, auth=_basic(edge.cred.username, edge.password))
    assert r.status_code == 404
    assert edge.lookups == 0


async def test_owner_active_rules() -> None:
    """Disabled customer or suspended ISP -> not active (no 204)."""
    from app.domains.tr069.internal_router import _owner_active

    isp_id, cust_id = uuid.uuid4(), uuid.uuid4()
    profile = SimpleNamespace(status="active")
    isp_org = SimpleNamespace(id=isp_id, org_type="msp", status="active")
    customer = SimpleNamespace(
        id=cust_id, parent_organization_id=isp_id, status="active"
    )

    class Repo:
        def __init__(self, session):
            pass

        async def get_profile(self, org_id):
            return profile

        async def get_organization(self, org_id):
            return isp_org if org_id == isp_id else customer

    import app.domains.isp_partner.repository as repo_mod

    original = repo_mod.IspRepository
    repo_mod.IspRepository = Repo  # type: ignore[misc]
    try:
        cred = SimpleNamespace(
            isp_organization_id=isp_id, customer_organization_id=cust_id
        )
        assert await _owner_active(None, cred)
        customer.status = "suspended"
        assert not await _owner_active(None, cred)
        customer.status = "active"
        profile.status = "suspended"
        assert not await _owner_active(None, cred)
        profile.status = "active"
        isp_org.status = "suspended"
        assert not await _owner_active(
            None,
            SimpleNamespace(isp_organization_id=isp_id, customer_organization_id=None),
        )
    finally:
        repo_mod.IspRepository = original  # type: ignore[misc]
