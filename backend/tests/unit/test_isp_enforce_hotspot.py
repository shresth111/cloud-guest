"""ENFORCE-2 unit tests (no DB) for ``isp_partner.hotspot_hooks``, the one
call the old hotspot Authorize makes. The rules themselves, and the
byte-identical reply for regular tenants, run on Postgres in
``test_isp_enforce_hotspot_postgres.py``."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.guest.service import RadiusAuthorizeResult
from app.domains.isp_partner import hotspot_hooks as hh
from app.domains.isp_partner.config import get_isp_partner_settings
from app.domains.isp_partner.rate_limit import _isp_customer_cache


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ISP_PARTNER_ENABLED", "true")
    monkeypatch.delenv("ISP_PARTNER_ENFORCEMENT_ENABLED", raising=False)
    get_isp_partner_settings.cache_clear()
    saved = list(hh._gates)
    hh.clear_hotspot_gates()
    _isp_customer_cache.clear()
    yield
    hh.clear_hotspot_gates()
    hh._gates.extend(saved)
    _isp_customer_cache.clear()
    get_isp_partner_settings.cache_clear()


class _Boom:
    """A DB that fails the test if anything touches it."""

    def __getattr__(self, name):  # noqa: ANN001, ANN204
        raise AssertionError(f"DB touched: {name}")


class _Nested:
    async def __aenter__(self):  # noqa: ANN204
        return self

    async def __aexit__(self, *a):  # noqa: ANN002, ANN204
        return False


class _Db:
    def begin_nested(self):  # noqa: ANN201
        return _Nested()


def _gs(org=None):  # noqa: ANN001, ANN202
    return SimpleNamespace(id=uuid.uuid4(), organization_id=org or uuid.uuid4())


def _accept(st=3600, it=1800):  # noqa: ANN001, ANN202
    return RadiusAuthorizeResult(
        authorized=True,
        session_timeout_seconds=st,
        idle_timeout_seconds=it,
        data_limit_mb=None,
        rate_limit="10240k/10240k",
    )


async def _allow(_ctx):  # noqa: ANN001, ANN202
    return hh.HotspotGateResult(allow=True, session_timeout_cap=60)


async def test_flag_off_no_db_touch_even_with_gates():
    hh.register_hotspot_gate(_allow)
    out = await hh.run_hotspot_gates(
        db=_Boom(), guest_session=_gs(), router=None, calling_station_id="aa"
    )
    assert out is None


async def test_no_gates_no_db_touch_flag_on(monkeypatch):
    monkeypatch.setenv("ISP_PARTNER_ENFORCEMENT_ENABLED", "true")
    get_isp_partner_settings.cache_clear()
    assert (
        await hh.run_hotspot_gates(
            db=_Boom(), guest_session=_gs(), router=None, calling_station_id=None
        )
        is None
    )


async def test_flag_on_non_isp_org_cached_skips_gates(monkeypatch):
    import time

    monkeypatch.setenv("ISP_PARTNER_ENFORCEMENT_ENABLED", "true")
    get_isp_partner_settings.cache_clear()
    called = []

    async def gate(ctx):  # noqa: ANN001, ANN202
        called.append(ctx)
        return hh.HotspotGateResult(allow=False, reason="x")

    hh.register_hotspot_gate(gate)
    org = uuid.uuid4()
    _isp_customer_cache[org] = (False, time.monotonic() + 60)
    out = await hh.run_hotspot_gates(
        db=_Boom(), guest_session=_gs(org), router=None, calling_station_id=None
    )
    assert out is None and called == []


async def test_failing_gate_is_ignored_and_refusal_wins(monkeypatch):
    import time

    monkeypatch.setenv("ISP_PARTNER_ENFORCEMENT_ENABLED", "true")
    get_isp_partner_settings.cache_clear()
    org = uuid.uuid4()
    _isp_customer_cache[org] = (True, time.monotonic() + 60)

    async def broken(_ctx):  # noqa: ANN001, ANN202
        raise RuntimeError("bug")

    async def refuse(_ctx):  # noqa: ANN001, ANN202
        return hh.HotspotGateResult(allow=False, reason="mac_not_bound")

    hh.register_hotspot_gate(broken)
    hh.register_hotspot_gate(_allow)
    out = await hh.run_hotspot_gates(
        db=_Db(), guest_session=_gs(org), router=None, calling_station_id=None
    )
    assert out == hh.HotspotGateResult(allow=True, session_timeout_cap=60)
    hh.register_hotspot_gate(refuse)
    out = await hh.run_hotspot_gates(
        db=_Db(), guest_session=_gs(org), router=None, calling_station_id=None
    )
    assert out is not None and not out.allow and out.reason == "mac_not_bound"


def test_apply_is_identity_without_verdict():
    r = _accept()
    assert hh.apply_hotspot_verdict(None, r) is r
    assert hh.apply_hotspot_verdict(hh.HotspotGateResult(), r) is r
    big = hh.HotspotGateResult(session_timeout_cap=99999, idle_timeout_cap=99999)
    assert hh.apply_hotspot_verdict(big, r) is r  # never lengthens


def test_apply_only_shortens():
    r = _accept(st=3600, it=1800)
    out = hh.apply_hotspot_verdict(
        hh.HotspotGateResult(session_timeout_cap=600, idle_timeout_cap=300), r
    )
    assert (out.session_timeout_seconds, out.idle_timeout_seconds) == (600, 300)
    assert out.rate_limit == r.rate_limit and out.authorized
    # an absent old value takes the cap; 0 is never sent
    r = _accept(st=None, it=None)
    out = hh.apply_hotspot_verdict(
        hh.HotspotGateResult(session_timeout_cap=0, idle_timeout_cap=120), r
    )
    assert (out.session_timeout_seconds, out.idle_timeout_seconds) == (1, 120)


def test_apply_leaves_a_reject_alone():
    rej = RadiusAuthorizeResult(
        authorized=False,
        session_timeout_seconds=None,
        idle_timeout_seconds=None,
        data_limit_mb=None,
    )
    v = hh.HotspotGateResult(session_timeout_cap=5)
    assert hh.apply_hotspot_verdict(v, rej) is rej


def test_gate_registered_from_models_import():
    import importlib

    import app.domains.isp_partner.models as m
    from app.domains.isp_partner import enforcement_hotspot as eh

    assert m._enforcement_hotspot_hooks is eh
    hh.clear_hotspot_gates()
    mod = importlib.reload(eh)
    assert hh._gates == [mod.jaze2_hotspot_gate]


def test_reasons_short():
    from app.domains.isp_partner import enforcement_hotspot as eh

    for r in (eh.R_HARD, eh.R_MAC, eh.R_NO_IP, eh.R_IP, eh.R_CONCURRENCY):
        assert len(r) <= 32
