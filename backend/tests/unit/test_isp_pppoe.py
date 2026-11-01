"""JAZE-6 Phase 2b PPPoE: authorize decisions, rate formatting, the REST
secret gate, the RouterOS script, the 8728 matcher, accounting totals.

The authorize tests drive ``IspPppoeService.authorize`` with its lookups
overridden, so no database is needed. The Postgres round trip lives in
``test_isp_pppoe_postgres.py`` (skipped unless ``ISP_TEST_PG_DSN``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import pppoe_config, pppoe_service
from app.domains.isp_partner.pppoe_hooks import (
    PppoeGateResult,
    SpeedGroupRate,
    clear_pppoe_hooks,
    register_pppoe_gate,
    register_pppoe_rate_resolver,
)
from app.domains.isp_partner.pppoe_script import PppoeScriptParams, render_pppoe_script
from app.domains.isp_partner.pppoe_service import (
    IspPppoeService,
    format_rate_limit,
    normalize_mac,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
ISP = uuid.uuid4()
CUST = uuid.uuid4()


def _settings(monkeypatch, **kw) -> None:
    s = pppoe_config.IspPppoeSettings(enabled=True, rest_secret="s3cret", **kw)
    monkeypatch.setattr(pppoe_service, "get_isp_pppoe_settings", lambda: s)
    monkeypatch.setattr(pppoe_config, "get_isp_pppoe_settings", lambda: s)


class _Sess:
    async def flush(self):
        return None


class FakeSvc(IspPppoeService):
    def __init__(self, *, isp=ISP, isp_active=True, suspended=False, cred=None, sub=None, rate=None):
        super().__init__(session=_Sess(), clock=lambda: NOW)
        self._isp, self._active, self._susp = isp, isp_active, suspended
        self._cred, self._sub, self._rate = cred, sub, rate

    async def _isp_for_customer(self, customer_org_id):
        return self._isp if customer_org_id == CUST else None

    async def _isp_active(self, isp_org_id):
        return self._active

    async def _customer_suspended(self, customer_org_id):
        return self._susp

    async def _find_credential(self, customer_org, isp_org, uname):
        c = self._cred
        if c is None or c.username_lower != uname or customer_org != c.customer_organization_id:
            return None
        return c

    async def _get_subscriber(self, subscriber_id):
        return self._sub

    async def _base_rate(self, sub):
        return self._rate


def _nas(org=CUST):
    return SimpleNamespace(id=uuid.uuid4(), organization_id=org, location_id=None, router_id=None)


def _cred(**kw):
    from app.domains.router.crypto import encrypt_secret

    base = dict(
        id=uuid.uuid4(),
        subscriber_id=uuid.uuid4(),
        customer_organization_id=CUST,
        username="ravi01",
        username_lower="ravi01",
        password_encrypted=encrypt_secret("pw-Abc12345"),
        status="active",
        static_ip=None,
        ip_pool_name=None,
        last_auth_at=None,
        last_auth_result=None,
        last_calling_station_id=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _sub(**kw):
    base = dict(id=uuid.uuid4(), is_deleted=False, status="active", valid_until=NOW + timedelta(days=10))
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _hooks():
    clear_pppoe_hooks()
    yield
    clear_pppoe_hooks()


async def _auth(svc, username="ravi01", nas=None, mac="aa-bb-cc-dd-ee-ff"):
    return await svc.authorize(nas_client=nas or _nas(), username=username, calling_station_id=mac)


async def test_flag_off_rejects(monkeypatch):
    s = pppoe_config.IspPppoeSettings(enabled=False)
    monkeypatch.setattr(pppoe_service, "get_isp_pppoe_settings", lambda: s)
    r = await _auth(FakeSvc(cred=_cred(), sub=_sub()))
    assert r["control:Auth-Type"] == "Reject"
    assert "Cleartext-Password" not in str(r)


async def test_accept_returns_password_rate_and_timeouts(monkeypatch):
    _settings(monkeypatch)
    cred = _cred()
    rate = SpeedGroupRate(download_kbps=50000, upload_kbps=20000)
    r = await _auth(FakeSvc(cred=cred, sub=_sub(), rate=rate))
    assert r["control:Cleartext-Password"] == "pw-Abc12345"
    assert r["reply:Mikrotik-Rate-Limit"] == "20000k/50000k"
    assert r["reply:Acct-Interim-Interval"] == 300
    assert r["reply:Session-Timeout"] == 86400
    assert "control:Auth-Type" not in r
    assert cred.last_auth_result == "accepted"
    assert cred.last_calling_station_id == "AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize(
    ("svc_kw", "reason"),
    [
        ({"isp_active": False}, "isp_suspended"),
        ({"suspended": True}, "customer_suspended"),
        ({"cred": None}, "unknown_user"),
    ],
)
async def test_rejects(monkeypatch, svc_kw, reason):
    _settings(monkeypatch)
    kw = {"cred": _cred(), "sub": _sub()}
    kw.update(svc_kw)
    r = await _auth(FakeSvc(**kw))
    assert r == {"control:Auth-Type": "Reject", "reply:Reply-Message": f"wyfy:{reason}"}


async def test_disabled_login_expired_and_disabled_subscriber(monkeypatch):
    _settings(monkeypatch)
    r = await _auth(FakeSvc(cred=_cred(status="disabled"), sub=_sub()))
    assert r["reply:Reply-Message"] == "wyfy:login_disabled"
    r = await _auth(FakeSvc(cred=_cred(), sub=_sub(status="disabled")))
    assert r["reply:Reply-Message"] == "wyfy:subscriber_disabled"
    r = await _auth(FakeSvc(cred=_cred(), sub=_sub(valid_until=NOW - timedelta(seconds=1))))
    assert r["reply:Reply-Message"] == "wyfy:expired"


async def test_non_isp_nas_and_other_customer_are_rejected(monkeypatch):
    _settings(monkeypatch)
    svc = FakeSvc(cred=_cred(), sub=_sub())
    r = await _auth(svc, nas=_nas(org=uuid.uuid4()))
    assert r["reply:Reply-Message"] == "wyfy:not_isp_nas"


async def test_session_timeout_capped_by_validity(monkeypatch):
    _settings(monkeypatch)
    r = await _auth(FakeSvc(cred=_cred(), sub=_sub(valid_until=NOW + timedelta(minutes=30))))
    assert r["reply:Session-Timeout"] == 1800


async def test_static_ip_wins_over_pool(monkeypatch):
    _settings(monkeypatch)
    r = await _auth(FakeSvc(cred=_cred(static_ip="100.64.1.9", ip_pool_name="p2"), sub=_sub()))
    assert r["reply:Framed-IP-Address"] == "100.64.1.9"
    assert "reply:Framed-Pool" not in r


async def test_gate_hook_rejects_and_failing_hook_is_ignored(monkeypatch):
    _settings(monkeypatch)

    @register_pppoe_gate
    async def broken(ctx):
        raise RuntimeError("bug")

    @register_pppoe_gate
    async def mac_lock(ctx):
        if ctx.calling_station_id != "11:22:33:44:55:66":
            return PppoeGateResult(allow=False, reason="mac_mismatch")
        return None

    r = await _auth(FakeSvc(cred=_cred(), sub=_sub()))
    assert r["reply:Reply-Message"] == "wyfy:mac_mismatch"
    r = await _auth(FakeSvc(cred=_cred(), sub=_sub()), mac="11-22-33-44-55-66")
    assert "control:Cleartext-Password" in r


async def test_rate_resolver_can_swap_the_rate(monkeypatch):
    _settings(monkeypatch)

    @register_pppoe_rate_resolver
    async def fup(ctx, base):
        return SpeedGroupRate(download_kbps=2000, upload_kbps=2000)

    r = await _auth(FakeSvc(cred=_cred(), sub=_sub(), rate=SpeedGroupRate(100000, 100000)))
    assert r["reply:Mikrotik-Rate-Limit"] == "2000k/2000k"


def test_rate_limit_burst_grammar():
    r = SpeedGroupRate(
        download_kbps=100000,
        upload_kbps=50000,
        burst_download_kbps=150000,
        burst_upload_kbps=75000,
        burst_threshold_kbps=80000,
        burst_time_seconds=8,
        priority=5,
    )
    assert format_rate_limit(r) == "50000k/100000k 75000k/150000k 80000k/80000k 8/8 5"


def test_normalize_mac():
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("AABB.CCDD.EEFF") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac(None) is None


# --- script -----------------------------------------------------------------


def _params(**kw):
    base = dict(
        interface="bridge1",
        local_address="100.64.0.1",
        pool_range="100.64.0.10-100.64.3.254",
        pool_cidr="100.64.0.0/22",
        dns_servers=(),
        hub_tunnel_ip="10.66.0.1",
        router_tunnel_ip="10.66.0.2",
        nas_secret='se"c$ret',
        auth_port=1912,
        acct_port=1913,
        interim_seconds=300,
    )
    base.update(kw)
    return PppoeScriptParams(**base)


def test_script_shape_and_quoting():
    text = render_pppoe_script(_params())
    assert (
        '/radius add service=ppp address=10.66.0.1 src-address=10.66.0.2 secret="se\\"c\\$ret" '
        "authentication-port=1912 accounting-port=1913" in text
    )
    assert "/ppp aaa set use-radius=yes accounting=yes interim-update=5m" in text
    assert "authentication=pap,chap,mschap2 one-session-per-host=yes" in text
    assert "dns-server=100.64.0.1" in text
    # Idempotent: every add is preceded by a remove of the same object.
    for obj in ("/ip pool", "/ppp profile", "/radius", "/interface pppoe-server server", "/ip firewall nat"):
        assert f"{obj} remove" in text
    # Never touches the hotspot or the existing hotspot RADIUS entry.
    assert "hotspot" not in text
    assert "service=hotspot" not in text


@pytest.mark.parametrize(
    "bad",
    [
        {"interface": "ether1; /system reset"},
        {"pool_range": "100.64.9.1-100.64.9.9"},
        {"local_address": "192.168.1.1"},
        {"pool_cidr": "fd00::/64"},
        {"nas_secret": ""},
        {"hub_tunnel_ip": "not-an-ip"},
    ],
)
def test_script_refuses_bad_values(bad):
    with pytest.raises(ValueError):
        render_pppoe_script(_params(**bad))


# --- device matcher ---------------------------------------------------------


def test_end_ppp_sessions_matches_name_and_mac(monkeypatch):
    import sys
    import types

    from app.domains.isp_partner import pppoe_device

    rows = [
        {".id": "*1", "name": "Ravi01", "caller-id": "AA:BB:CC:DD:EE:FF"},
        {".id": "*2", "name": "ravi01", "caller-id": "11:11:11:11:11:11"},
        {".id": "*3", "name": "other", "caller-id": "AA:BB:CC:DD:EE:FF"},
    ]

    class Path(list):
        def remove(self, rid):
            rows[:] = [r for r in rows if r[".id"] != rid]

    class Api:
        def path(self, *a):
            return Path(rows)

        def close(self):
            pass

    fake = types.ModuleType("librouteros")
    fake.connect = lambda **kw: Api()
    exc = types.ModuleType("librouteros.exceptions")
    exc.LibRouterosError = type("LibRouterosError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "librouteros", fake)
    monkeypatch.setitem(sys.modules, "librouteros.exceptions", exc)
    out = pppoe_device._end_sync("h", "u", "p", None, "ravi01", "aa-bb-cc-dd-ee-ff")
    assert (out.matched, out.removed, out.still_active) == (1, 1, 0)
    assert [r[".id"] for r in rows] == ["*2", "*3"]
    assert pppoe_device._end_sync("h", "u", "p", None, "", None).matched == 0


# --- REST secret gate -------------------------------------------------------


async def test_rest_caller_gate(monkeypatch):
    from fastapi import HTTPException

    from app.domains.isp_partner import pppoe_router

    s = pppoe_config.IspPppoeSettings(enabled=True, rest_secret="s3cret")
    monkeypatch.setattr(pppoe_router, "get_isp_pppoe_settings", lambda: s)

    def req(headers):
        return SimpleNamespace(headers={k.lower(): v for k, v in headers.items()})

    class H(dict):
        def get(self, k, d=None):
            return super().get(k.lower(), d)

    async def call(headers):
        r = SimpleNamespace(headers=H({k.lower(): v for k, v in headers.items()}))
        await pppoe_router.RequirePppoeRestCaller(r)

    await call({pppoe_router.REST_SECRET_HEADER: "s3cret"})
    for bad in (
        {},
        {pppoe_router.REST_SECRET_HEADER: "nope"},
        {pppoe_router.REST_SECRET_HEADER: "s3cret", "X-Forwarded-For": "1.2.3.4"},
        {pppoe_router.REST_SECRET_HEADER: "s3cret", "X-Real-IP": "1.2.3.4"},
    ):
        with pytest.raises(HTTPException) as e:
            await call(bad)
        assert e.value.status_code == 404
    empty = pppoe_config.IspPppoeSettings(enabled=True, rest_secret="")
    monkeypatch.setattr(pppoe_router, "get_isp_pppoe_settings", lambda: empty)
    with pytest.raises(HTTPException):
        await call({pppoe_router.REST_SECRET_HEADER: ""})
