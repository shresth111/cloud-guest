"""P1-2: billing cycle linked to the subscriber's anchor day.

The hook in ``plans_service.recharge`` must be byte-identical (and must not
even query) unless the flag is on; then it snaps only for a ``subscriber``
package of >= 28 days and a subscriber with an anchor day.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.domains.isp_partner import p1_cycle, p1_cycle_hook
from app.domains.isp_partner.p1_config import get_p1_settings
from app.domains.isp_partner.p1_cycle_hook import (
    cycle_end,
    prorate_line,
    prorated_paise,
    snap_to_anchor,
)

IST = "Asia/Kolkata"


class _NoDb:
    async def execute(self, *_a, **_k):  # pragma: no cover - must not happen
        raise AssertionError("the hook queried with the flag off")


class _Db:
    """execute() answers the basis lookup first, then the anchor lookup."""

    def __init__(self, basis, anchor):
        self.answers = [basis, anchor]
        self.calls = 0

    async def execute(self, *_a, **_k):
        value = self.answers[self.calls]
        self.calls += 1
        return SimpleNamespace(scalar_one_or_none=lambda: value)


@pytest.fixture
def flag_on(monkeypatch):
    monkeypatch.setenv("ISP_CYCLE_BASIS_ENABLED", "true")
    get_p1_settings.cache_clear()
    yield
    get_p1_settings.cache_clear()


def _ist(y, m, d, hh=10, mm=0):
    from zoneinfo import ZoneInfo

    return datetime(y, m, d, hh, mm, tzinfo=ZoneInfo(IST)).astimezone(UTC)


def _isp():
    return SimpleNamespace(organization=SimpleNamespace(timezone=IST))


def _pkg(days=30):
    return SimpleNamespace(id=uuid.uuid4(), validity_days=days)


def _sub():
    return SimpleNamespace(id=uuid.uuid4())


@pytest.mark.parametrize(
    ("end", "anchor", "want"),
    [
        (_ist(2026, 12, 10), 1, _ist(2026, 12, 1)),  # 9 days back beats 22 forward
        (_ist(2026, 12, 20), 1, _ist(2027, 1, 1)),  # year rolls over
        (_ist(2026, 12, 5), 5, _ist(2026, 12, 5)),  # already on the anchor
        (_ist(2027, 1, 3), 28, _ist(2026, 12, 28)),  # back across a year
        (_ist(2027, 2, 14, 10), 28, _ist(2027, 2, 28)),  # Feb has a 28th
    ],
)
def test_snap_to_nearest_anchor_same_local_time(end, anchor, want) -> None:
    got = snap_to_anchor(end, anchor, IST)
    assert got == want
    assert got.tzinfo is not None


def test_snap_tie_goes_later() -> None:
    # 16 Mar 10:00 IST is 15 days after 1 Mar... and 16 days before 1 Apr:
    # not a tie. A real tie: anchor 15, end on the 30th of a 30-day month
    # midway -> pick the later one.
    end = _ist(2026, 4, 30)  # 15 Apr is 15 d back, 15 May is 15 d forward
    assert snap_to_anchor(end, 15, IST) == _ist(2026, 5, 15)


async def test_identity_and_no_query_with_flag_off(monkeypatch) -> None:
    monkeypatch.delenv("ISP_CYCLE_BASIS_ENABLED", raising=False)
    get_p1_settings.cache_clear()
    start = _ist(2026, 11, 10)
    end = start + timedelta(days=30)
    assert await cycle_end(_NoDb(), _isp(), _sub(), _pkg(), start, end) is end


async def test_short_packs_never_snap(flag_on) -> None:
    start = _ist(2026, 11, 10)
    end = start + timedelta(days=7)
    assert await cycle_end(_NoDb(), _isp(), _sub(), _pkg(7), start, end) is end


@pytest.mark.parametrize(
    ("basis", "anchor"), [(None, 1), ("package", 1), ("subscriber", None)]
)
async def test_identity_unless_package_and_subscriber_opt_in(
    flag_on, basis, anchor
) -> None:
    start = _ist(2026, 11, 10)
    end = start + timedelta(days=30)
    assert (
        await cycle_end(_Db(basis, anchor), _isp(), _sub(), _pkg(), start, end) is end
    )


async def test_snaps_when_everything_opts_in(flag_on) -> None:
    start = _ist(2026, 11, 10)
    end = start + timedelta(days=30)  # 10 Dec
    got = await cycle_end(_Db("subscriber", 1), _isp(), _sub(), _pkg(), start, end)
    assert got == _ist(2026, 12, 1)
    # on-time renewal from the anchor stays on the anchor
    start2 = got
    end2 = start2 + timedelta(days=30)  # 31 Dec
    assert await cycle_end(
        _Db("subscriber", 1), _isp(), _sub(), _pkg(), start2, end2
    ) == _ist(2027, 1, 1)


async def test_quarterly_pack_snaps_near_its_own_end(flag_on) -> None:
    start = _ist(2026, 11, 10)
    end = start + timedelta(days=90)  # 8 Feb 2027
    got = await cycle_end(_Db("subscriber", 1), _isp(), _sub(), _pkg(90), start, end)
    assert got == _ist(2027, 2, 1)


async def test_router_flag_off_is_404(monkeypatch) -> None:
    monkeypatch.delenv("ISP_CYCLE_BASIS_ENABLED", raising=False)
    get_p1_settings.cache_clear()
    with pytest.raises(HTTPException) as exc:
        await p1_cycle.RequireCycleBasisEnabled()
    assert exc.value.status_code == 404


def test_only_two_bases() -> None:
    p1_cycle.CycleBasisRequest(basis="package")
    p1_cycle.CycleBasisRequest(basis="subscriber")
    with pytest.raises(ValidationError):
        p1_cycle.CycleBasisRequest(basis="calendar")
    with pytest.raises(ValidationError):
        p1_cycle.CycleBasisRequest(basis="package", anchor_day=3)


def test_recharge_calls_the_hook_once_right_after_the_old_end() -> None:
    import inspect

    from app.domains.isp_partner import plans_service

    src = inspect.getsource(plans_service.IspPlansService.recharge)
    old = "end = start + timedelta(days=package.validity_days * cycles)\n"
    assert src.count(old) == 1
    after = src.split(old, 1)[1].lstrip()
    assert after.startswith(
        "end = await _p1_cycle_end(self.session, isp, s, package, start, end)"
    )
    assert plans_service._p1_cycle_end is p1_cycle_hook.cycle_end


# -- DECISIONS-1 (2026-11-10): pro-rate the first snapped period -------------


def _line(amount=50_000, cycles=1):
    return {"description": "Home 30", "amount_paise": amount, "quantity": cycles}


def _named(days=30):
    return SimpleNamespace(id=uuid.uuid4(), validity_days=days, name="Home 30")


def test_prorate_rounds_to_whole_rupees() -> None:
    assert prorated_paise(50_000, 21, 30) == 35_000
    assert prorated_paise(49_900, 21, 30) == 34_900  # 349.30 -> 349
    assert prorated_paise(49_950, 21, 30) == 35_000  # 349.65 -> 350
    assert prorated_paise(59_900, 42, 30) == 83_900  # 838.60 -> 839
    assert prorated_paise(100, 1, 30) == 100  # never below one rupee


def test_prorate_identity_with_flag_off(monkeypatch) -> None:
    monkeypatch.delenv("ISP_CYCLE_BASIS_ENABLED", raising=False)
    get_p1_settings.cache_clear()
    line = _line()
    start = _ist(2026, 11, 10)
    assert prorate_line(_isp(), _named(), start, _ist(2026, 12, 1), line) is line


async def test_shorter_first_period_is_prorated(flag_on) -> None:
    start = _ist(2026, 11, 10)
    end = await cycle_end(
        _Db("subscriber", 1),
        _isp(),
        _sub(),
        _named(),
        start,
        start + timedelta(days=30),
    )
    assert end == _ist(2026, 12, 1)  # 21 days, shorter than 30
    line = _line()
    got = prorate_line(_isp(), _named(), start, end, line)
    assert got is not line
    assert got["amount_paise"] == 35_000  # 500 x 21 / 30
    assert got["quantity"] == 1
    assert got["description"] == "Home 30 (pro-rated 21 days)"
    assert line["amount_paise"] == 50_000, "input line not mutated"


async def test_longer_first_period_is_prorated(flag_on) -> None:
    start = _ist(2026, 11, 20)
    end = await cycle_end(
        _Db("subscriber", 1),
        _isp(),
        _sub(),
        _named(),
        start,
        start + timedelta(days=30),
    )
    assert end == _ist(2027, 1, 1)  # 20 Dec is nearer 1 Jan: 42 days
    got = prorate_line(_isp(), _named(), start, end, _line(59_900))
    assert got["amount_paise"] == 83_900  # 599 x 42 / 30 = 838.6 -> 839
    assert got["description"] == "Home 30 (pro-rated 42 days)"


async def test_later_period_on_the_anchor_is_full_price(flag_on) -> None:
    start = _ist(2026, 12, 1)  # already on anchor 1
    end = await cycle_end(
        _Db("subscriber", 1),
        _isp(),
        _sub(),
        _named(),
        start,
        start + timedelta(days=30),
    )
    assert end == _ist(2027, 1, 1)  # 31 days: snapped, but not a first period
    line = _line()
    assert prorate_line(_isp(), _named(), start, end, line) is line


def test_unsnapped_end_is_full_price(flag_on) -> None:
    start = _ist(2026, 11, 10)
    line = _line()
    end = start + timedelta(days=30)
    assert prorate_line(_isp(), _named(), start, end, line) is line


async def test_multi_cycle_prorates_only_the_first_period(flag_on) -> None:
    start = _ist(2026, 11, 10)
    end = await cycle_end(
        _Db("subscriber", 1),
        _isp(),
        _sub(),
        _named(),
        start,
        start + timedelta(days=90),
    )
    assert end == _ist(2027, 2, 1)  # 83 days for 3 x 30: first period 23 days
    got = prorate_line(_isp(), _named(), start, end, _line(50_000, 3), cycles=3)
    assert got["amount_paise"] == 2 * 50_000 + 38_300  # 500 x 23 / 30 = 383.3
    assert got["quantity"] == 1
    assert "first period pro-rated 23 days" in got["description"]


def test_recharge_prorates_right_after_the_line() -> None:
    import inspect

    from app.domains.isp_partner import plans_service

    src = inspect.getsource(plans_service.IspPlansService.recharge)
    assert src.count("_p1_prorate(") == 1
    i_line, i_call = src.index('"package_id": package.id,'), src.index("_p1_prorate(")
    assert i_line < i_call < src.index("apply_to_line")
    assert plans_service._p1_prorate is p1_cycle_hook.prorate_line
