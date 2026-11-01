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
    """Fake gate session (ENFORCE-4: the gate opens its own session)."""

    def __init__(self) -> None:
        self.committed = 0
        self.rolled_back = 0

    def begin_nested(self):  # noqa: ANN201
        return _Nested()

    async def execute(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
        return None

    async def get(self, _model, ident):  # noqa: ANN001, ANN202
        return SimpleNamespace(id=ident, organization_id=None)

    async def commit(self) -> None:
        self.committed += 1

    async def rollback(self) -> None:
        self.rolled_back += 1

    async def __aenter__(self):  # noqa: ANN204
        return self

    async def __aexit__(self, *a):  # noqa: ANN002, ANN204
        return False


@pytest.fixture(autouse=True)
def _gate_sessions(monkeypatch):
    db = _Db()
    monkeypatch.setattr(hh, "_session_factory", lambda: db)
    saved = list(hh._timeout_hooks)
    hh._timeout_hooks.clear()
    yield db
    hh._timeout_hooks.clear()
    hh._timeout_hooks.extend(saved)


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


def _isp_org_cached():  # noqa: ANN202
    import time

    org = uuid.uuid4()
    _isp_customer_cache[org] = (True, time.monotonic() + 60)
    return org


async def test_slow_gate_cannot_hold_a_login_past_the_budget(
    monkeypatch, _gate_sessions
):
    """ENFORCE-4: a gate stuck for 0.6 s; the Authorize gets None (fail-open)
    within the budget, and the late verdict is thrown away (rolled back,
    timeout hook told)."""
    import asyncio
    import time

    monkeypatch.setenv("ISP_PARTNER_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ISP_PARTNER_HOTSPOT_GATE_BUDGET_MS", "150")
    get_isp_partner_settings.cache_clear()
    told = []

    async def slow(_ctx):  # noqa: ANN001, ANN202
        await asyncio.sleep(0.6)
        return hh.HotspotGateResult(allow=False, reason="mac_not_bound")

    async def hook(db, gs, now, budget):  # noqa: ANN001, ANN202
        told.append(budget)

    hh.register_hotspot_gate(slow)
    hh.register_hotspot_timeout_hook(hook)
    t0 = time.monotonic()
    out = await hh.run_hotspot_gates(
        db=_Db(),
        guest_session=_gs(_isp_org_cached()),
        router=None,
        calling_station_id=None,
    )
    took = time.monotonic() - t0
    assert out is None
    assert took < 0.15 + 0.08, took
    await asyncio.sleep(0.7)  # let the background task finish
    assert told == [150]
    assert _gate_sessions.rolled_back == 1  # its refusal is never kept


async def test_fast_gate_is_unaffected_by_the_budget(monkeypatch, _gate_sessions):
    monkeypatch.setenv("ISP_PARTNER_ENFORCEMENT_ENABLED", "true")
    get_isp_partner_settings.cache_clear()

    async def refuse(_ctx):  # noqa: ANN001, ANN202
        return hh.HotspotGateResult(allow=False, reason="concurrency")

    hh.register_hotspot_gate(refuse)
    out = await hh.run_hotspot_gates(
        db=_Db(),
        guest_session=_gs(_isp_org_cached()),
        router=None,
        calling_station_id=None,
    )
    assert out is not None and out.reason == "concurrency"
    assert _gate_sessions.committed == 1 and _gate_sessions.rolled_back == 0


async def test_regular_tenant_flag_on_no_task_no_session(monkeypatch):
    """A regular tenant's org cached as not-ISP: no gate task, no DB session
    (the factory would fail the test), nothing awaited."""
    import time

    monkeypatch.setenv("ISP_PARTNER_ENFORCEMENT_ENABLED", "true")
    get_isp_partner_settings.cache_clear()

    def boom():  # noqa: ANN202
        raise AssertionError("gate session opened for a regular tenant")

    monkeypatch.setattr(hh, "_session_factory", boom)
    hh.register_hotspot_gate(_allow)
    org = uuid.uuid4()
    _isp_customer_cache[org] = (False, time.monotonic() + 60)
    tasks_before = len(asyncio_all_tasks())
    out = await hh.run_hotspot_gates(
        db=_Boom(), guest_session=_gs(org), router=None, calling_station_id=None
    )
    assert out is None and len(asyncio_all_tasks()) == tasks_before


def asyncio_all_tasks():  # noqa: ANN201
    import asyncio

    return asyncio.all_tasks()
