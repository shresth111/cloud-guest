"""JAZE-2 (ADDENDUM_05 J3/J8/J13/J20/J21): pure logic + route guards.

DB-free: periods, boost windows, carry-forward, the rate string, access
verdicts, interface-rate and optical maths, and the route table (every new
route under /isp, guarded, non-alias ids).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.isp_partner.enforcement import (
    MB,
    SessionFacts,
    access_verdicts,
    allowance_bytes,
    boost_active,
    carried_forward,
    counted_bytes,
    fup_period,
    fup_view,
    norm_mac,
    rate_from_group,
)
from app.domains.isp_partner.network_router import (
    _uptime_seconds,
    interface_rates,
    optical_reading,
    throughput_series,
)

IST = "Asia/Kolkata"


# -- boost window -----------------------------------------------------------


def _ist(h: int, m: int = 0) -> datetime:
    # 00:00 IST == 18:30 UTC the day before
    base = datetime(2026, 11, 1, 18, 30, tzinfo=UTC) - timedelta(days=1)
    return base + timedelta(hours=h, minutes=m)


@pytest.mark.parametrize(
    ("start", "end", "h", "expected"),
    [
        (120, 480, 1, False),
        (120, 480, 2, True),
        (120, 480, 7, True),
        (120, 480, 8, False),
        (1320, 360, 23, True),  # 22:00-06:00 wraps midnight
        (1320, 360, 3, True),
        (1320, 360, 12, False),
        (600, 600, 10, False),  # start == end never active
        (None, 480, 3, False),
    ],
)
def test_boost_window(start, end, h, expected):
    assert boost_active(start, end, _ist(h), IST) is expected


# -- FUP periods ------------------------------------------------------------


def test_period_day_is_local_midnight():
    s, e = fup_period("day", now=_ist(10), tz=IST, valid_until=None, validity_days=None)
    assert s == _ist(0) and e == _ist(24)


def test_period_month_is_calendar_month_local():
    now = datetime(2026, 11, 15, 6, tzinfo=UTC)
    s, e = fup_period("month", now=now, tz=IST, valid_until=None, validity_days=None)
    assert s == datetime(2026, 10, 31, 18, 30, tzinfo=UTC)
    assert e == datetime(2026, 11, 30, 18, 30, tzinfo=UTC)


def test_period_cycle_follows_validity_and_rolls_forward():
    vu = datetime(2026, 11, 20, tzinfo=UTC)
    now = datetime(2026, 11, 10, tzinfo=UTC)
    assert fup_period("cycle", now=now, tz=IST, valid_until=vu, validity_days=30) == (
        vu - timedelta(days=30),
        vu,
    )
    later = datetime(2026, 11, 25, tzinfo=UTC)
    s, e = fup_period("cycle", now=later, tz=IST, valid_until=vu, validity_days=30)
    assert s == vu and e == vu + timedelta(days=30) and s <= later < e


def test_period_cycle_without_validity_falls_back_to_month():
    now = datetime(2026, 11, 15, 6, tzinfo=UTC)
    assert fup_period(
        "cycle", now=now, tz=IST, valid_until=None, validity_days=30
    ) == fup_period("month", now=now, tz=IST, valid_until=None, validity_days=None)


# -- allowance / carry ------------------------------------------------------


def test_allowance_and_counting():
    assert allowance_bytes(None) is None and allowance_bytes(0) is None
    assert allowance_bytes(3) == 3 * MB
    assert counted_bytes(10, 5, exclude_upload=False) == 15
    assert counted_bytes(10, 5, exclude_upload=True) == 10


def test_carry_forward_capped_at_one_allowance():
    a = 1000 * MB
    assert carried_forward(allowance=a, used=400 * MB, carry_in=0, topup=0) == 600 * MB
    assert carried_forward(allowance=a, used=0, carry_in=a, topup=0) == a  # capped
    assert carried_forward(allowance=a, used=2 * a, carry_in=0, topup=0) == 0
    assert carried_forward(allowance=None, used=0, carry_in=0, topup=0) == 0


# -- rate string ------------------------------------------------------------


def _group(**kw):
    base = dict(
        download_kbps=102400,
        upload_kbps=51200,
        burst_download_kbps=None,
        burst_upload_kbps=None,
        burst_threshold_kbps=None,
        burst_time_seconds=None,
        priority=8,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_rate_plain_matches_queue_grammar():
    # rx = client upload first, tx = client download second
    assert rate_from_group(_group()) == "51200k/102400k"


def test_rate_unlimited_is_none():
    assert rate_from_group(_group(download_kbps=0, upload_kbps=0)) is None


def test_rate_priority_without_burst_uses_zero_bursts():
    assert rate_from_group(_group(), priority=2) == "51200k/102400k 0k/0k 0k/0k 0/0 2"


def test_rate_with_burst():
    g = _group(
        burst_download_kbps=204800,
        burst_upload_kbps=102400,
        burst_threshold_kbps=80000,
        burst_time_seconds=8,
        priority=5,
    )
    assert rate_from_group(g) == "51200k/102400k 102400k/204800k 80000k/80000k 8/8 5"


# -- access verdicts --------------------------------------------------------


def _policy(**kw):
    base = dict(
        mac_bind_count=0,
        mac_restriction=False,
        ip_restriction=False,
        max_simultaneous=None,
        idle_timeout_s=None,
        hard_timeout_s=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)


def _s(mins_ago: int, mac: str | None = None, ip: str | None = None, idle=None):
    started = NOW - timedelta(minutes=mins_ago)
    return SessionFacts(
        session_id=uuid.uuid4(),
        started_at=started,
        last_activity_at=(NOW - timedelta(minutes=idle))
        if idle is not None
        else started,
        mac=mac,
        ip=ip,
    )


def test_auto_bind_first_mac_then_reject_second():
    a, b = _s(10, "aa:bb:cc:00:00:01"), _s(5, "aa:bb:cc:00:00:02")
    verdicts, bind = access_verdicts(
        _policy(mac_bind_count=1), [a, b], set(), set(), now=NOW
    )
    assert bind == ["AA:BB:CC:00:00:01"]
    assert [(v.session_id, v.kind) for v in verdicts] == [(b.session_id, "mac_reject")]


def test_bound_mac_allowed_unknown_rejected_with_restriction():
    ok_s, bad = _s(3, "AA:BB:CC:00:00:01"), _s(2, "11:22:33:44:55:66")
    verdicts, bind = access_verdicts(
        _policy(mac_restriction=True),
        [ok_s, bad],
        {"AA:BB:CC:00:00:01"},
        set(),
        now=NOW,
    )
    assert bind == [] and [v.kind for v in verdicts] == ["mac_reject"]
    assert verdicts[0].session_id == bad.session_id


def test_restriction_without_any_binding_does_not_lock_everyone_out():
    v, _ = access_verdicts(
        _policy(mac_restriction=True),
        [_s(1, "AA:BB:CC:00:00:09")],
        set(),
        set(),
        now=NOW,
    )
    assert v == []


def test_ip_restriction():
    good, bad = _s(4, ip="10.0.0.5"), _s(3, ip="10.0.0.9")
    v, _ = access_verdicts(
        _policy(ip_restriction=True), [good, bad], set(), {"10.0.0.5"}, now=NOW
    )
    assert [x.session_id for x in v] == [bad.session_id]


def test_concurrency_keeps_oldest():
    s1, s2, s3 = _s(30), _s(20), _s(10)
    v, _ = access_verdicts(
        _policy(max_simultaneous=1), [s3, s1, s2], set(), set(), now=NOW
    )
    assert {x.session_id for x in v} == {s2.session_id, s3.session_id}
    assert all(x.kind == "concurrency" for x in v)


def test_timeouts():
    hard, idle, fine = _s(200), _s(30, idle=20), _s(30, idle=1)
    v, _ = access_verdicts(
        _policy(hard_timeout_s=3 * 3600, idle_timeout_s=900),
        [hard, idle, fine],
        set(),
        set(),
        now=NOW,
    )
    assert {(x.session_id, x.kind) for x in v} == {
        (hard.session_id, "hard_timeout"),
        (idle.session_id, "idle_timeout"),
    }


def test_one_verdict_per_session_and_timed_out_not_counted_for_concurrency():
    old, new = _s(300), _s(5)
    v, _ = access_verdicts(
        _policy(hard_timeout_s=3600, max_simultaneous=1),
        [old, new],
        set(),
        set(),
        now=NOW,
    )
    assert [(x.session_id, x.kind) for x in v] == [(old.session_id, "hard_timeout")]


def test_norm_mac():
    assert norm_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert norm_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"
    assert norm_mac(None) is None


# -- FUP view ---------------------------------------------------------------


def test_fup_view_remaining_and_throttle():
    gid = uuid.uuid4()
    policy = SimpleNamespace(
        fup_limit_mb=1000,
        fup_reset="cycle",
        fup_exclude_upload=True,
        fup_fallback_speed_group_id=gid,
    )
    row = SimpleNamespace(
        used_down_bytes=900 * MB,
        used_up_bytes=500 * MB,
        carry_bytes=100 * MB,
        topup_bytes=0,
        throttled=False,
        throttled_at=None,
        period_start=NOW,
        period_end=NOW + timedelta(days=30),
        last_computed_at=NOW,
    )
    v = fup_view(row, policy, {gid: "2 Mbps"})
    assert v["used_bytes"] == 900 * MB  # upload excluded
    assert v["remaining_bytes"] == 200 * MB
    assert v["fallback_speed_group"] == {"id": str(gid), "name": "2 Mbps"}


def test_fup_view_without_row():
    v = fup_view(None, None, {})
    assert v["fup_enabled"] is False and v["throttled"] is False


# -- network maths ----------------------------------------------------------


def test_interface_rates_and_reset_guard():
    first = [
        {
            "name": "ether1",
            "rx-byte": "1000",
            "tx-byte": "2000",
            "rx-packet": "10",
            "tx-packet": "20",
            "running": "true",
        },
        {"name": "ether2", "rx-byte": "5000", "tx-byte": "5000"},
        {"name": "lo", "rx-byte": "1", "tx-byte": "1"},
    ]
    second = [
        {
            "name": "ether1",
            "rx-byte": "2000",
            "tx-byte": "4000",
            "rx-packet": "20",
            "tx-packet": "40",
            "running": "true",
        },
        {"name": "ether2", "rx-byte": "10", "tx-byte": "10"},  # counter reset
        {"name": "lo", "rx-byte": "2", "tx-byte": "2"},
    ]
    out = {r["name"]: r for r in interface_rates(first, second, 1.0)}
    assert "lo" not in out
    assert out["ether1"]["rx_bps"] == 8000 and out["ether1"]["tx_pps"] == 20
    assert out["ether1"]["running"] is True
    assert out["ether2"]["rx_bps"] is None


@pytest.mark.parametrize(
    ("raw", "secs"),
    [
        ("3w2d04:05:06", 3 * 604800 + 2 * 86400 + 4 * 3600 + 5 * 60 + 6),
        ("1d2h3m4s", 86400 + 7200 + 180 + 4),
        ("00:00:09", 9),
        ("", None),
        ("garbage", None),
    ],
)
def test_uptime(raw, secs):
    assert _uptime_seconds(raw) == secs


def test_throughput_series():
    t0 = NOW
    snaps = [
        SimpleNamespace(
            recorded_at=t0,
            interface_traffic_counters=[
                {"if_name": "ether1", "in_octets": 0, "out_octets": 0}
            ],
        ),
        SimpleNamespace(
            recorded_at=t0 + timedelta(seconds=300),
            interface_traffic_counters=[
                {"if_name": "ether1", "in_octets": 37_500_000, "out_octets": 0}
            ],
        ),
        SimpleNamespace(
            recorded_at=t0 + timedelta(seconds=600), interface_traffic_counters=None
        ),
    ]
    s = throughput_series(snaps)
    assert s["ether1"] == [
        {
            "at": (t0 + timedelta(seconds=300)).isoformat(),
            "in_mbps": 1.0,
            "out_mbps": 0.0,
        }
    ]


_GPON = "InternetGatewayDevice.WANDevice.1.X_GponInterfaceConfig.RXPower"


@pytest.mark.parametrize(
    ("cache", "dbm", "band"),
    [
        (
            {
                "Device.Optical.Interface.1.OpticalSignalLevel": {
                    "value": ["-19.5", "xsd:string"]
                }
            },
            -19.5,
            "good",
        ),
        (
            {"InternetGatewayDevice.WANDevice.1.X_HW_OpticInfo.RxPower": "-2150"},
            -21.5,
            "good",
        ),
        (
            {"InternetGatewayDevice.WANDevice.1.X_GponInterfaceConfig.RXPower": "-26"},
            -26.0,
            "warn",
        ),
        (
            {_GPON: "-30.1"},
            -30.1,
            "bad",
        ),
    ],
)
def test_optical(cache, dbm, band):
    r = optical_reading(cache)
    assert r["available"] and r["dbm"] == dbm and r["band"] == band


def test_optical_missing():
    assert optical_reading({})["available"] is False
    assert optical_reading(None)["available"] is False


# -- route table ------------------------------------------------------------

_NEW_PATHS = {
    "/api/v1/isp/packages/{package_id}/policy",
    "/api/v1/isp/subscribers/{subscriber_id}/fup",
    "/api/v1/isp/subscribers/{subscriber_id}/fup/reset",
    "/api/v1/isp/subscribers/{subscriber_id}/fup/topup",
    "/api/v1/isp/subscribers/{subscriber_id}/mac-bindings",
    "/api/v1/isp/subscribers/{subscriber_id}/mac-bindings/{binding_id}",
    "/api/v1/isp/subscribers/{subscriber_id}/enforcement-events",
    "/api/v1/isp/locations/{isp_location_id}/ip-pools",
    "/api/v1/isp/locations/{isp_location_id}/ip-pools/{pool_id}/next-free",
    "/api/v1/isp/subscribers/{subscriber_id}/ip-bindings",
    "/api/v1/isp/subscribers/{subscriber_id}/ip-bindings/{binding_id}",
    "/api/v1/isp/routers/{isp_router_id}/health/live",
    "/api/v1/isp/routers/{isp_router_id}/health/history",
    "/api/v1/isp/routers/{isp_router_id}/sessions/active",
    "/api/v1/isp/tr069/summary",
    "/api/v1/isp/tr069/devices/{cpe_id}/optical",
}
_ALIASES = ("{organization_id}", "{customer_id}", "{location_id}", "{router_id}")


@pytest.fixture(scope="module")
def routes():
    from app.main import create_app

    return [r for r in create_app().routes if getattr(r, "path", "") in _NEW_PATHS]


def test_all_new_routes_mounted(routes):
    assert {r.path for r in routes} == _NEW_PATHS


def test_new_routes_use_no_scope_alias_ids(routes):
    for r in routes:
        assert not any(a in r.path for a in _ALIASES), r.path


def test_new_routes_are_isp_guarded_and_flag_gated(routes):
    from app.domains.isp_partner.config import RequireIspFeatureEnabled
    from app.domains.isp_partner.dependencies import RequireIspPartner

    def calls(dep):  # noqa: ANN001, ANN202
        out = {dep.call}
        for d in dep.dependencies:
            out |= calls(d)
        return out

    for r in routes:
        found = calls(r.dependant)
        assert RequireIspPartner in found, r.path
        assert RequireIspFeatureEnabled in found, r.path
