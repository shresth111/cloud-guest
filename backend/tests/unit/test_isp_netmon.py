"""NETMON-2 pure rules + guards."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.domains.isp_partner import netmon as logic

NOW = datetime(2026, 11, 1, 6, 0, tzinfo=UTC)


def _pts(n: int, start: datetime, step: timedelta, v: float) -> list[dict]:
    return [
        {"at": (start + step * i).isoformat(), "in_mbps": v, "out_mbps": v / 2}
        for i in range(n)
    ]


def test_pick_wan_by_name_then_busiest() -> None:
    s = {
        "bridge": _pts(3, NOW, timedelta(minutes=5), 90),
        "ether1": _pts(3, NOW, timedelta(minutes=5), 10),
    }
    assert logic.pick_wan(s) == ("ether1", "name")
    assert logic.pick_wan({"pppoe-out1": [], "ether5": []}) == ("pppoe-out1", "name")
    s = {
        "bridge": _pts(2, NOW, timedelta(minutes=5), 90),
        "ether7": _pts(2, NOW, timedelta(minutes=5), 1),
    }
    assert logic.pick_wan(s) == ("bridge", "busiest")
    assert logic.pick_wan({}) == (None, "none")


def test_downsample_caps_and_averages() -> None:
    since = NOW - timedelta(days=1)
    pts = _pts(1000, since, timedelta(seconds=86), 4.0)
    out = logic.downsample(pts, since=since, until=NOW)
    assert 0 < len(out) <= logic.MAX_POINTS
    assert all(p["in_mbps"] == 4.0 and p["out_mbps"] == 2.0 for p in out)


def test_downsample_keeps_gaps_and_drops_out_of_range() -> None:
    since = NOW - timedelta(days=1)
    pts = _pts(5, since, timedelta(minutes=1), 1) + _pts(
        5, NOW - timedelta(hours=1), timedelta(minutes=1), 1
    )
    pts.append(
        {"at": (NOW + timedelta(hours=1)).isoformat(), "in_mbps": 99, "out_mbps": 99}
    )
    out = logic.downsample(pts, since=since, until=NOW)
    assert len(out) == 2 and all(p["in_mbps"] == 1 for p in out)


@pytest.mark.parametrize(
    ("kw", "want"),
    [
        (
            {"status": "pending_provisioning", "last_seen_at": None},
            (False, "not_set_up"),
        ),
        (
            {"status": "online", "last_seen_at": NOW - timedelta(hours=2)},
            (False, "offline"),
        ),
        ({"status": "offline", "last_seen_at": NOW}, (False, "offline")),
        ({"snmp_enabled": False}, (False, "monitoring_off")),
        ({"snmp_last_poll_status": "timeout"}, (False, "poll_failed")),
        ({"has_series": False}, (True, "no_data_yet")),
        ({}, (True, None)),
    ],
)
def test_readability(kw, want) -> None:  # noqa: ANN001
    base = {
        "status": "online",
        "last_seen_at": NOW - timedelta(minutes=1),
        "snmp_enabled": True,
        "snmp_last_poll_status": "ok",
        "has_series": True,
        "now": NOW,
    }
    readable, reason, hint = logic.readability(**{**base, **kw})
    assert (readable, reason) == want
    if reason:
        low = hint.lower()
        assert not any(w in low for w in logic.FORBIDDEN_HINT_WORDS), hint


def test_routes_guarded_and_flag_gated() -> None:
    from app.domains.isp_partner.netmon_router import (
        RequireNetmonEnabled,
        netmon_router,
    )

    paths = set()
    for r in netmon_router.routes:
        deps = {d.call for d in r.dependant.dependencies}
        names = {getattr(d, "__name__", type(d).__name__) for d in deps}
        assert RequireNetmonEnabled in deps
        assert {"RequireIspPartner", "RejectLocationRouterHeaders"} <= names
        paths.add(r.path)
    assert paths == {
        "/netmon/traffic",
        "/netmon/sessions/active",
        "/netmon/sessions/completed",
        "/netmon/sessions/completed/export.csv",
    }
