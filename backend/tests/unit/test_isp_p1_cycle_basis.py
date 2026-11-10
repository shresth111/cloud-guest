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
from app.domains.isp_partner.p1_cycle_hook import cycle_end, snap_to_anchor

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
