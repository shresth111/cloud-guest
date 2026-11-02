"""ENFORCE-1 unit tests (no DB): the JAZE-2 PPPoE hooks are registered, a
no-op with the flag off, and encode timeouts / queue priority the way
RouterOS reads them. The end-to-end rules run on Postgres in
``test_isp_enforce_pppoe_postgres.py``."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import enforcement_pppoe as ep
from app.domains.isp_partner.config import get_isp_partner_settings
from app.domains.isp_partner.pppoe_hooks import (
    PppoeAuthorizeContext,
    SpeedGroupRate,
)
from app.domains.isp_partner.pppoe_service import format_rate_limit

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("ISP_PARTNER_ENABLED", "true")
    monkeypatch.delenv("ISP_PARTNER_ENFORCEMENT_ENABLED", raising=False)
    get_isp_partner_settings.cache_clear()
    yield
    get_isp_partner_settings.cache_clear()


def _ctx(session=None):  # noqa: ANN001, ANN202
    return PppoeAuthorizeContext(
        session=session,
        now=NOW,
        isp_organization_id=uuid.uuid4(),
        customer_organization_id=uuid.uuid4(),
        location_id=None,
        router_id=None,
        nas_client_id=uuid.uuid4(),
        subscriber=SimpleNamespace(id=uuid.uuid4(), package_id=uuid.uuid4()),
        credential=None,
        calling_station_id="aa:00:00:00:00:01",
        nas_port_id=None,
    )


class _Boom:
    async def execute(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("flag off must not touch the DB")

    async def get(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("flag off must not touch the DB")


def test_hooks_register_on_import():
    # test_isp_pppoe clears the global registry, so prove the import-time
    # registration on a clean registry instead of relying on test order.
    import importlib

    from app.domains.isp_partner import pppoe_hooks

    gates, rates = list(pppoe_hooks._gates), list(pppoe_hooks._rates)
    try:
        pppoe_hooks.clear_pppoe_hooks()
        mod = importlib.reload(ep)
        assert pppoe_hooks._gates == [mod.jaze2_pppoe_gate]
        assert pppoe_hooks._rates == [mod.jaze2_pppoe_rate]
    finally:
        pppoe_hooks.clear_pppoe_hooks()
        pppoe_hooks._gates.extend(gates)
        pppoe_hooks._rates.extend(rates)


def test_models_import_pulls_the_hooks_in():
    import app.domains.isp_partner.models as m

    assert m._enforcement_pppoe_hooks is ep


async def test_flag_off_is_a_no_op_without_db():
    base = SpeedGroupRate(download_kbps=20480, upload_kbps=20480)
    assert await ep.jaze2_pppoe_gate(_ctx(_Boom())) is None
    assert await ep.jaze2_pppoe_rate(_ctx(_Boom()), base) is base
    assert await ep.jaze2_pppoe_rate(_ctx(_Boom()), None) is None


async def test_flag_on_but_isp_master_off_is_a_no_op(monkeypatch):
    monkeypatch.setenv("ISP_PARTNER_ENABLED", "false")
    monkeypatch.setenv("ISP_PARTNER_ENFORCEMENT_ENABLED", "true")
    get_isp_partner_settings.cache_clear()
    assert await ep.jaze2_pppoe_gate(_ctx(_Boom())) is None


def _pol(**kw):  # noqa: ANN003, ANN202
    return SimpleNamespace(**{"hard_timeout_s": None, "idle_timeout_s": None, **kw})


def test_timeout_reply_only_shortens():
    assert (
        ep.timeout_reply(_pol(), now=NOW, valid_until=None, max_session_s=86400) == {}
    )
    out = ep.timeout_reply(
        _pol(hard_timeout_s=3600, idle_timeout_s=600),
        now=NOW,
        valid_until=None,
        max_session_s=86400,
    )
    assert out == {"reply:Session-Timeout": 3600, "reply:Idle-Timeout": 600}
    # validity ends sooner than the hard timeout -> validity wins
    out = ep.timeout_reply(
        _pol(hard_timeout_s=3600),
        now=NOW,
        valid_until=NOW + timedelta(minutes=20),
        max_session_s=86400,
    )
    assert out == {"reply:Session-Timeout": 1200}
    # configured maximum smaller than the hard timeout -> maximum wins
    out = ep.timeout_reply(
        _pol(hard_timeout_s=90000), now=NOW, valid_until=None, max_session_s=86400
    )
    assert out == {"reply:Session-Timeout": 86400}


def test_priority_needs_zero_burst_fields():
    plain = SpeedGroupRate(download_kbps=20480, upload_kbps=10240)
    assert format_rate_limit(plain) == "10240k/20480k"
    with_prio = SpeedGroupRate(
        download_kbps=20480,
        upload_kbps=10240,
        burst_download_kbps=0,
        burst_upload_kbps=0,
        burst_threshold_kbps=0,
        burst_time_seconds=0,
        priority=3,
    )
    assert format_rate_limit(with_prio) == "10240k/20480k 0k/0k 0k/0k 0/0 3"


def test_reasons_fit_reply_message():
    for r in (ep.R_MAC, ep.R_IP, ep.R_CONCURRENCY):
        assert len(r) <= 32


def test_pppoe_script_only_one_token():
    """ENFORCE-3: the default render is JAZE-6's (only-one=yes); only_one
    False changes that one token and nothing else."""
    from dataclasses import replace

    from app.domains.isp_partner.pppoe_script import (
        PppoeScriptParams,
        render_pppoe_script,
    )

    p = PppoeScriptParams(
        interface="ether2",
        local_address="10.78.0.1",
        pool_range="10.78.0.10-10.78.0.100",
        pool_cidr="10.78.0.0/24",
        dns_servers=(),
        hub_tunnel_ip="10.66.0.1",
        router_tunnel_ip="10.66.0.5",
        nas_secret="s3cret",
        auth_port=1922,
        acct_port=1923,
        interim_seconds=300,
    )
    default = render_pppoe_script(p)
    assert default == render_pppoe_script(replace(p, only_one=True))
    assert default.count(" only-one=yes ") == 1
    multi = render_pppoe_script(replace(p, only_one=False))
    assert multi == default.replace(" only-one=yes ", " only-one=no ")
