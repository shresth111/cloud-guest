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


@pytest.mark.parametrize(
    ("env", "want"),
    [
        ({}, 3000),
        ({"NETLOGS_DISPLAY_CAP_PER_MIN": "6000"}, 6000),
        ({"NETLOGS_DISPLAY_CAP_PER_MIN": "0"}, 3000),
        ({"NETLOGS_DISPLAY_CAP_PER_MIN": "junk"}, 3000),
        ({"NETLOGS_DISPLAY_CAP_UNLIMITED": "true"}, None),
        (
            {"NETLOGS_DISPLAY_CAP_UNLIMITED": "true", "NETLOGS_DISPLAY_CAP_PER_MIN": "50"},
            None,
        ),
    ],
)
def test_the_cap_follows_the_collector_variables(monkeypatch, env, want) -> None:
    for k in ("NETLOGS_DISPLAY_CAP_PER_MIN", "NETLOGS_DISPLAY_CAP_UNLIMITED"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert mod.display_cap_per_minute() == want


def test_vector_default_is_unchanged_and_unlimited_is_opt_in() -> None:
    """Zero impact: with neither variable set, vector.yaml still caps at 3000."""
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parents[3]
    text = (root / "deploy/device-logs/vector.yaml").read_text()
    resolved = text.replace("${NETLOGS_DISPLAY_CAP_PER_MIN:-3000}", "3000").replace(
        "${NETLOGS_DISPLAY_CAP_UNLIMITED:-false}", "false"
    )
    conf = yaml.safe_load(resolved)
    throttle = conf["transforms"]["throttle_index"]
    assert throttle["threshold"] == 3000
    assert throttle["window_secs"] == 60
    assert throttle["exclude"]["source"] == '"false" == "true"'
    assert "${NETLOGS_DISPLAY_CAP_PER_MIN:-3000}" in text
    assert "${NETLOGS_DISPLAY_CAP_UNLIMITED:-false}" in text


async def test_unlimited_skips_the_ceiling_query(monkeypatch) -> None:
    monkeypatch.setenv("NETLOGS_DISPLAY_CAP_UNLIMITED", "true")
    start = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    end = start + timedelta(seconds=3)
    filters = CustomerFilters(organization_id=CUST_A1, since=start, until=end)

    async def fake_filters(isp, db, **kw):
        return SimpleNamespace(enabled=True), filters, [CUST_A1]

    monkeypatch.setattr(mod, "_netlog_filters", fake_filters)
    db = _Db([(start, 5000)], [])
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
    assert out["data"]["counts"][0] == 5000
    assert out["data"]["throttled_minutes"] == []
    assert out["data"]["throttle_per_router_per_minute"] is None
    assert len(db.statements) == 1
