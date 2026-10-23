"""NetLogs events per second (logs_rate_router)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from starlette.requests import Request

from app.domains.device_logs.repository import CustomerFilters
from app.domains.isp_partner import logs_rate_router as mod
from app.domains.isp_partner.exceptions import IspBadRequestError
from tests.unit.isp_partner_fixtures import CUST_A1, CUST_A2, context, estate

NOW = datetime(2026, 10, 23, 12, 0, 30, 400000, tzinfo=UTC)


def test_presets_end_on_the_next_whole_second() -> None:
    s, e = mod._window(5, None, None, NOW)
    assert e == datetime(2026, 10, 23, 12, 0, 31, tzinfo=UTC)
    assert e - s == timedelta(minutes=5)


@pytest.mark.parametrize("m", [1, 30, 120])
def test_only_the_three_presets(m) -> None:
    with pytest.raises(IspBadRequestError):
        mod._window(m, None, None, NOW)


def test_custom_range_keeps_second_precision_and_is_capped() -> None:
    s, e = mod._window(None, NOW - timedelta(seconds=90), NOW, NOW)
    assert s == datetime(2026, 10, 23, 11, 59, 0, tzinfo=UTC)
    assert e == datetime(2026, 10, 23, 12, 0, 31, tzinfo=UTC)
    with pytest.raises(IspBadRequestError):
        mod._window(None, NOW - timedelta(hours=3, seconds=1), NOW, NOW)
    with pytest.raises(IspBadRequestError):
        mod._window(None, NOW, None, NOW)
    whole = NOW.replace(microsecond=0)
    with pytest.raises(IspBadRequestError):
        mod._window(None, whole, whole, NOW)


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Db:
    def __init__(self, per_second, per_minute):
        self.statements = []
        self._answers = [per_second, per_minute]

    async def execute(self, stmt):
        self.statements.append(stmt)
        return _Result(self._answers.pop(0))


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "headers": [], "path": "/"})


async def test_dense_series_scoped_and_partition_pruned(monkeypatch) -> None:
    start = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    end = start + timedelta(seconds=10)
    filters = CustomerFilters(organization_id=CUST_A1, since=start, until=end)

    async def fake_filters(isp, db, **kw):
        assert kw["since"] == start and kw["until"] == end
        return SimpleNamespace(enabled=True), filters, [CUST_A1, CUST_A2]

    monkeypatch.setattr(mod, "_netlog_filters", fake_filters)
    rtr = "00000000-0000-0000-0000-0000a1010001"
    db = _Db(
        [(start + timedelta(seconds=2), 7), (start + timedelta(seconds=9), 1)],
        [(rtr, start, 2990)],
    )
    out = await mod.netlogs_per_second(
        _request(),
        isp_customer_id=None,
        isp_location_id=None,
        isp_router_id=None,
        minutes=None,
        since=start,
        until=end,
        severity=None,
        category=None,
        protocol=None,
        status=None,
        q=None,
        isp=context(estate()),
        db=db,
    )
    data = out["data"]
    assert data["counts"] == [0, 0, 7, 0, 0, 0, 0, 0, 0, 1]
    assert data["total"] == 8 and data["peak"] == 7 and data["step_seconds"] == 1
    assert data["throttled_minutes"][0]["count"] == 2990
    sql = str(
        db.statements[0].compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert "date_trunc('second', device_log_events.received_at)" in sql
    assert "device_log_events.organization_id IN" in sql
    assert str(CUST_A1) in sql and str(CUST_A2) in sql
    # the partition key bounds the scan (pruning)
    assert "device_log_events.received_at >=" in sql
    assert "device_log_events.received_at <" in sql
