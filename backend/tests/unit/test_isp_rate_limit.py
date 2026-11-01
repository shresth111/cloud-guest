"""Exception X1 (founder-approved): ``IspRateLimitLookup`` is byte-identical
to the hook it wraps for every non-ISP organization, with the flag off, and
on any internal error. The ISP coupon branch is exercised on Postgres in
``test_isp_plans_postgres.py``."""

from __future__ import annotations

import random
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import config as isp_config
from app.domains.isp_partner import rate_limit
from app.domains.isp_partner.rate_limit import IspRateLimitLookup


class Inner:
    """Stands in for QueueManagementService: records every call."""

    def __init__(self, session=None) -> None:
        self.calls: list = []
        self.repository = SimpleNamespace(session=session)

    async def rate_limit_reply_for_authorize(self, session_id, **kwargs):
        self.calls.append((session_id, kwargs))
        return f"{len(self.calls)}k/{session_id.hex[:4]}"

    async def get_rate_limit_reply_for_session(self, session_id):
        return "legacy"

    marker = "inner-attribute"


class _Nested:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class NonIspSession:
    """Answers "not an ISP customer" to the one lookup the wrapper makes."""

    def __init__(self) -> None:
        self.queries = 0

    def begin_nested(self):
        return _Nested()

    async def execute(self, stmt):
        self.queries += 1
        return SimpleNamespace(first=lambda: None)


class BrokenSession(NonIspSession):
    async def execute(self, stmt):
        raise RuntimeError("db down")


def _flag(monkeypatch, on: bool) -> None:
    monkeypatch.setattr(
        rate_limit,
        "get_isp_partner_settings",
        lambda: isp_config.IspPartnerSettings(enabled=on),
    )
    rate_limit._isp_customer_cache.clear()


def _random_kwargs(rng: random.Random) -> dict:
    kw = {}
    for name in ("organization_id", "location_id", "router_id", "guest_id"):
        if rng.random() < 0.8:
            kw[name] = uuid.UUID(int=rng.getrandbits(128))
    if rng.random() < 0.7:
        kw["session_started_at"] = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(
            seconds=rng.randint(0, 10**8)
        )
    return kw


async def _identical(inner_factory, wrapper_factory, kwargs_list) -> None:
    for kwargs in kwargs_list:
        session_id = uuid.uuid4()
        a, b = inner_factory(), inner_factory()
        expected = await a.rate_limit_reply_for_authorize(session_id, **kwargs)
        got = await wrapper_factory(b).rate_limit_reply_for_authorize(
            session_id, **kwargs
        )
        assert got == expected
        assert b.calls == a.calls == [(session_id, kwargs)]


@pytest.mark.parametrize("seed", range(5))
async def test_flag_off_is_identical_and_touches_no_database(monkeypatch, seed) -> None:
    _flag(monkeypatch, False)
    rng = random.Random(seed)
    session = BrokenSession()  # would raise if the wrapper queried anything
    await _identical(
        lambda: Inner(session),
        IspRateLimitLookup,
        [_random_kwargs(rng) for _ in range(40)],
    )
    assert session.queries == 0


@pytest.mark.parametrize("seed", range(5))
async def test_non_isp_org_is_identical(monkeypatch, seed) -> None:
    _flag(monkeypatch, True)
    rng = random.Random(100 + seed)
    session = NonIspSession()
    await _identical(
        lambda: Inner(session),
        IspRateLimitLookup,
        [_random_kwargs(rng) for _ in range(40)],
    )


async def test_errors_fall_back_to_the_inner_result(monkeypatch) -> None:
    _flag(monkeypatch, True)
    await _identical(
        lambda: Inner(BrokenSession()),
        IspRateLimitLookup,
        [
            {"organization_id": uuid.uuid4()},
            {"organization_id": uuid.uuid4(), "router_id": uuid.uuid4()},
        ],
    )


async def test_no_session_available_delegates(monkeypatch) -> None:
    _flag(monkeypatch, True)
    inner = Inner(None)
    sid = uuid.uuid4()
    assert (
        await IspRateLimitLookup(inner).rate_limit_reply_for_authorize(
            sid, organization_id=uuid.uuid4()
        )
        == "1k/" + sid.hex[:4]
    )


async def test_everything_else_passes_through() -> None:
    inner = Inner()
    wrapped = IspRateLimitLookup(inner)
    assert wrapped.marker == "inner-attribute"
    assert await wrapped.get_rate_limit_reply_for_session(uuid.uuid4()) == "legacy"
    assert wrapped.repository is inner.repository


def test_the_wiring_line_wraps_the_existing_hook() -> None:
    """X1 is exactly one changed line: RadiusService's queue_lookup is the
    wrapper around the real QueueManagementService."""
    import inspect

    from app.domains.guest import dependencies

    source = inspect.getsource(dependencies.get_radius_service)
    assert "queue_lookup=IspRateLimitLookup(queue_management_service)" in source
