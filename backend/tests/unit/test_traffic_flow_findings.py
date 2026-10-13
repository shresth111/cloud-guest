"""Traffic Lens findings: five venue-level rules, computed on read.

Per rule: flagged, clear, too little data, missing input, and the boundary
at the threshold. Then the threat list and its delivery, the service's
scoping, the customer gates and withholding, and the privacy boundary: no
finding and no table carries both a device and a destination.

Every address below is from a documentation range (RFC 5737 / RFC 3849).
No real list content is in this file.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.database.base import Base
from app.domains.rbac.enums import ScopeType
from app.domains.traffic_flow import findings as f
from app.domains.traffic_flow import threat_list as threat_module
from app.domains.traffic_flow.destinations import DestinationScope, WindowStats
from app.domains.traffic_flow.findings import (
    AddressRow,
    HourRow,
    ServiceDay,
    build_findings,
    dominant_device,
    known_bad_destinations,
    quiet_hours_traffic,
    unusual_service,
    upload_heavy,
)
from app.domains.traffic_flow.findings_service import (
    CustomerFindingsService,
    TrafficFlowFindingsService,
    address_rows_statement,
    hour_rows_statement,
    service_history_statement,
)
from app.domains.traffic_flow.service import (
    TrafficFlowCrossLocationError,
    TrafficFlowCustomerService,
    TrafficFlowError,
    TrafficFlowLocationNotFoundError,
    TrafficFlowSummaryService,
)
from app.domains.traffic_flow.threat_list import ThreatList

MIB = 1024 * 1024
GIB = 1024 * MIB
#: The end of every period below: a whole UTC hour.
END = datetime(2026, 10, 12, 4, 0, tzinfo=UTC)
NOW = END + timedelta(minutes=5)
ORG_ID = uuid.UUID("22222222-0000-4000-8000-000000000002")
ORG_B = uuid.UUID("55555555-0000-4000-8000-000000000005")
LOCATION_ID = uuid.UUID("33333333-0000-4000-8000-000000000003")
SIBLING_LOCATION = uuid.UUID("66666666-0000-4000-8000-000000000006")
OTHER_LOCATION = uuid.UUID("44444444-0000-4000-8000-000000000004")
ROUTER_ID = uuid.UUID("11111111-0000-4000-8000-000000000001")


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    # A logger ``extra`` key that shadows a LogRecord attribute only raises
    # when INFO is actually emitted.
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------


def _quiet_night(hour_of_day: int) -> tuple[int, int]:
    """A venue that is shut from 00:00 to 06:00 UTC: (upload, download)."""
    if hour_of_day < 6:
        return (0, 1 * MIB)
    return (100 * MIB, 2 * GIB)


def _always_busy(_hour_of_day: int) -> tuple[int, int]:
    return (100 * MIB, 2 * GIB)


def _hours(
    profile: Any = _quiet_night,
    *,
    days: int = 7,
    until: datetime = END,
    overrides: dict[datetime, tuple[int, int]] | None = None,
    windows: int = 12,
) -> list[HourRow]:
    out = []
    start = until - timedelta(days=days)
    for index in range(days * 24):
        moment = start + timedelta(hours=index)
        up, down = (overrides or {}).get(moment, profile(moment.hour))
        out.append(HourRow(moment, up, down, windows, windows))
    return out


def _last_hour(**kw: Any) -> dict[str, datetime]:
    return {"since": END - timedelta(hours=1), "until": END, **kw}


LAST = END - timedelta(hours=1)  # 03:00 UTC, a quiet hour of the day


def _summary(
    *,
    up: int = 1 * GIB,
    down: int = 9 * GIB,
    devices_peak: int = 12,
    devices: list[dict[str, Any]] | None = None,
    services: list[dict[str, Any]] | None = None,
    windows: int = 12,
    windows_measured: int = 12,
    measured: bool = True,
) -> dict[str, Any]:
    if not measured:
        return {
            "feature_enabled": True,
            "measured": False,
            "since": LAST.isoformat(),
            "until": END.isoformat(),
            "windows": 0,
            "totals": None,
            "data_oldest": None,
            "data_newest": None,
            "services": {"items": [], "windows_measured": 0},
            "devices": {"items": []},
        }
    return {
        "feature_enabled": True,
        "measured": True,
        "since": LAST.isoformat(),
        "until": END.isoformat(),
        "windows": windows,
        "data_oldest": (END - timedelta(days=7)).isoformat(),
        "data_newest": (END - timedelta(minutes=5)).isoformat(),
        "totals": {"bytes_up": up, "bytes_down": down, "devices_peak": devices_peak},
        "services": {"items": services or [], "windows_measured": windows_measured},
        "devices": {"items": devices or []},
    }


def _device(share: float, nbytes: int = 7 * GIB) -> dict[str, Any]:
    return {
        "router_id": str(ROUTER_ID),
        "ip": "192.168.88.24",
        "bytes_up": 0,
        "bytes_down": nbytes,
        "bytes": nbytes,
        "flows": 10,
        "share_at_least": share,
        "match": "session",
        "guest_session_id": "77777777-0000-4000-8000-000000000007",
    }


def _svc(protocol: int, port: int, nbytes: int, share: float) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "protocol_name": {6: "tcp", 17: "udp"}.get(protocol, "other"),
        "port": port,
        "service_name": {443: "https"}.get(port),
        "bytes_up": nbytes // 2,
        "bytes_down": nbytes - nbytes // 2,
        "bytes": nbytes,
        "flows": 5,
        "share": share,
        "avg_bps": 0,
    }


def _write_list(
    directory: pathlib.Path,
    *,
    v4: list[str] | None = None,
    v6: list[str] | None = None,
    published: datetime = NOW - timedelta(hours=6),
    fetched_at: datetime | None = NOW - timedelta(hours=2),
    metadata: bool = True,
) -> pathlib.Path:
    """Synthetic files in the published shape: one object per line, then
    the dated metadata line."""
    directory.mkdir(parents=True, exist_ok=True)
    parts = {
        "drop_v4.json": ["203.0.113.0/24", "198.51.100.0/25"] if v4 is None else v4,
        "drop_v6.json": ["2001:db8:bad::/48"] if v6 is None else v6,
    }
    for name, cidrs in parts.items():
        lines = [
            json.dumps({"cidr": cidr, "sblid": f"SBL{index}", "rir": "test"})
            for index, cidr in enumerate(cidrs, start=1)
        ]
        if metadata:
            lines.append(
                json.dumps(
                    {
                        "type": "metadata",
                        "timestamp": int(published.timestamp()),
                        "records": len(cidrs),
                        "copyright": "(c) test",
                    }
                )
            )
        (directory / name).write_text("\n".join(lines) + "\n")
    if fetched_at is not None:
        (directory / threat_module.MANIFEST_FILENAME).write_text(
            json.dumps({"fetched_at": fetched_at.isoformat()})
        )
    return directory


@pytest.fixture
def threat(tmp_path: pathlib.Path) -> ThreatList:
    return ThreatList(_write_list(tmp_path / "threat"))


@pytest.fixture
def no_threat(tmp_path: pathlib.Path) -> ThreatList:
    return ThreatList(tmp_path / "nothing-here")


def _addr(address: str, nbytes: int, *, windows: int = 3) -> AddressRow:
    return AddressRow(address, nbytes // 2, nbytes - nbytes // 2, 4, windows)


def _known_bad(rows: list[AddressRow], threat: ThreatList, **kw: Any) -> dict[str, Any]:
    args: dict[str, Any] = {"now": NOW, "windows": 12, "windows_measured": 12}
    args.update(kw)
    return known_bad_destinations(rows, threat, **args)


# ---------------------------------------------------------------------------
# rule 1: upload-heavy hour
# ---------------------------------------------------------------------------


class TestUploadHeavy:
    # The typical busiest upload hour of the sample venue is 100 MiB, so the
    # bar is the absolute one: 1 GiB.

    def test_flagged(self) -> None:
        hours = _hours(overrides={LAST: (3 * GIB, 200 * MIB)})
        out = upload_heavy(hours, **_last_hour())
        assert out["state"] == "flagged" and out["severity"] == "look"
        assert out["parts"]["bytes_up"] == 3 * GIB
        assert out["parts"]["start"] == LAST.isoformat()
        assert out["parts"]["typical_bytes_up"] == 100 * MIB
        assert out["parts"]["times_typical"] == 30.7
        assert out["evidence"]["items"][0]["bytes_up"] == 3 * GIB
        assert out["evidence"]["derived"] is True
        assert out["names"] == "nothing"

    def test_clear(self) -> None:
        hours = _hours(overrides={LAST: (300 * MIB, 2 * GIB)})
        out = upload_heavy(hours, **_last_hour())
        assert out["state"] == "clear" and out["severity"] is None
        assert out["parts"] is None
        assert out["evidence"]["busiest_hour_bytes_up"] == 300 * MIB

    def test_boundary_on_the_absolute_size(self) -> None:
        at = _hours(overrides={LAST: (f.UPLOAD_HEAVY_MIN_BYTES, 0)})
        under = _hours(overrides={LAST: (f.UPLOAD_HEAVY_MIN_BYTES - 1, 0)})
        assert upload_heavy(at, **_last_hour())["state"] == "flagged"
        assert upload_heavy(under, **_last_hour())["state"] == "clear"

    def test_boundary_on_the_venues_own_baseline(self) -> None:
        """A venue whose busiest upload hour is usually 1 GiB: three times
        that is the bar, and 2.9 GiB is an ordinary day there."""

        def heavy(_hour: int) -> tuple[int, int]:
            return (1 * GIB, 2 * GIB)

        bar = int(f.UPLOAD_HEAVY_FACTOR * GIB)
        at = _hours(heavy, overrides={LAST: (bar, 0)})
        under = _hours(heavy, overrides={LAST: (bar - 1, 0)})
        assert upload_heavy(at, **_last_hour())["state"] == "flagged"
        assert upload_heavy(under, **_last_hour())["state"] == "clear"

    def test_a_daily_backup_is_this_venues_normal(self) -> None:
        """2 GiB up at 03:00 every night is the baseline, not a finding."""

        def nightly(hour: int) -> tuple[int, int]:
            return (2 * GIB, 0) if hour == 3 else (50 * MIB, 1 * GIB)

        assert upload_heavy(_hours(nightly), **_last_hour())["state"] == "clear"

    def test_too_little_traffic_to_judge(self) -> None:
        hours = _hours(overrides={LAST: (10 * MIB, 20 * MIB)})
        out = upload_heavy(hours, **_last_hour())
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "not_enough_traffic",
        )
        assert out["evidence"]["period_bytes"] == 30 * MIB

    def test_floor_boundary(self) -> None:
        floor = f.FINDINGS_MIN_TRAFFIC_BYTES
        at = upload_heavy(_hours(overrides={LAST: (0, floor)}), **_last_hour())
        under = upload_heavy(_hours(overrides={LAST: (0, floor - 1)}), **_last_hour())
        assert at["state"] == "clear"
        assert under["reason"] == "not_enough_traffic"

    def test_no_data_in_the_period_is_not_clear(self) -> None:
        hours = [h for h in _hours() if h.start != LAST]
        out = upload_heavy(hours, **_last_hour())
        assert (out["state"], out["reason"]) == ("could_not_check", "not_measured")

    def test_a_short_baseline_is_not_clear(self) -> None:
        hours = _hours(days=3, overrides={LAST: (3 * GIB, 0)})
        out = upload_heavy(hours, **_last_hour())
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "baseline_too_short",
        )
        assert out["evidence"]["baseline_days"] == 3

    def test_baseline_days_boundary(self) -> None:
        enough = _hours(days=f.BASELINE_MIN_DAYS, overrides={LAST: (3 * GIB, 0)})
        assert upload_heavy(enough, **_last_hour())["state"] == "flagged"


# ---------------------------------------------------------------------------
# rule 2: traffic while the venue is normally quiet
# ---------------------------------------------------------------------------


class TestQuietHours:
    def test_flagged(self) -> None:
        hours = _hours(overrides={LAST: (100 * MIB, 700 * MIB)})
        out = quiet_hours_traffic(hours, **_last_hour())
        assert out["state"] == "flagged" and out["severity"] == "look"
        assert out["parts"]["bytes"] == 800 * MIB
        assert out["parts"]["usual_at_most_bytes"] == 1 * MIB
        assert out["evidence"]["quiet_hours_utc"] == [0, 1, 2, 3, 4, 5]
        assert out["evidence"]["derived"] is True
        assert out["names"] == "nothing"

    def test_clear_when_the_quiet_hour_stayed_quiet(self) -> None:
        # The period is two hours so it clears the traffic floor on a busy
        # hour (before midnight UTC) while its quiet hour stays quiet.
        until = END - timedelta(hours=3)  # 01:00
        out = quiet_hours_traffic(
            _hours(), since=until - timedelta(hours=2), until=until
        )
        assert out["state"] == "clear"
        assert out["evidence"]["quiet_hours_in_period"] == 1

    def test_boundary_on_size(self) -> None:
        at = _hours(overrides={LAST: (0, f.QUIET_MIN_BYTES)})
        under = _hours(overrides={LAST: (0, f.QUIET_MIN_BYTES - 1)})
        assert quiet_hours_traffic(at, **_last_hour())["state"] == "flagged"
        assert quiet_hours_traffic(under, **_last_hour())["state"] == "clear"

    def test_boundary_on_what_makes_an_hour_quiet(self) -> None:
        """Quiet = at most 5% of the typical busiest hour on the other days."""
        peak = 100 * MIB + 2 * GIB
        edge = int(f.QUIET_SHARE_OF_PEAK * peak)

        def night(value: int) -> Any:
            return lambda hour: (0, value) if hour < 6 else (100 * MIB, 2 * GIB)

        spike = {LAST: (0, 2 * GIB)}
        quiet = quiet_hours_traffic(
            _hours(night(edge), overrides=spike), **_last_hour()
        )
        busy = quiet_hours_traffic(
            _hours(night(edge + 1), overrides=spike), **_last_hour()
        )
        assert quiet["state"] == "flagged"
        assert (busy["state"], busy["reason"]) == ("could_not_check", "no_quiet_hours")

    def test_a_venue_busy_round_the_clock_cannot_be_checked(self) -> None:
        out = quiet_hours_traffic(_hours(_always_busy), **_last_hour())
        assert (out["state"], out["reason"]) == ("could_not_check", "no_quiet_hours")
        assert out["evidence"]["quiet_hours_utc"] == []

    def test_two_odd_nights_are_not_normally_quiet(self) -> None:
        """Only one busiest day is left out. If the same hour was loud on
        another retained day too, it is not a quiet hour here."""
        earlier = LAST - timedelta(days=2)
        hours = _hours(
            overrides={LAST: (0, 2 * GIB), earlier: (0, 2 * GIB)},
        )
        out = quiet_hours_traffic(hours, **_last_hour())
        assert out["state"] == "clear"
        assert 3 not in out["evidence"]["quiet_hours_utc"]

    def test_too_little_traffic_to_judge(self) -> None:
        out = quiet_hours_traffic(_hours(), **_last_hour())
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "not_enough_traffic",
        )

    def test_no_data_in_the_period_is_not_clear(self) -> None:
        hours = [h for h in _hours() if h.start != LAST]
        out = quiet_hours_traffic(hours, **_last_hour())
        assert (out["state"], out["reason"]) == ("could_not_check", "not_measured")

    def test_a_short_baseline_is_not_clear(self) -> None:
        hours = _hours(days=3, overrides={LAST: (0, 2 * GIB)})
        out = quiet_hours_traffic(hours, **_last_hour())
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "baseline_too_short",
        )

    def test_enough_days_but_too_few_at_each_hour_of_day(self) -> None:
        """Four days make a baseline, but leaving the busiest one out leaves
        three per hour of day: fewer than QUIET_MIN_DAYS."""
        hours = _hours(days=4, overrides={LAST: (0, 2 * GIB)})
        out = quiet_hours_traffic(hours, **_last_hour())
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "baseline_too_short",
        )

    def test_a_half_measured_hour_is_not_a_quiet_hour(self) -> None:
        hours = _hours(windows=f.HOUR_MIN_WINDOWS - 1, overrides={LAST: (0, 2 * GIB)})
        out = quiet_hours_traffic(hours, **_last_hour())
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "baseline_too_short",
        )


# ---------------------------------------------------------------------------
# rule 3: one device dominating
# ---------------------------------------------------------------------------


class TestDominantDevice:
    def test_flagged_names_the_device_as_the_devices_list_does(self) -> None:
        out = dominant_device(_summary(devices=[_device(0.71)]))
        assert out["state"] == "flagged" and out["severity"] == "info"
        assert out["parts"]["share_at_least"] == 0.71
        assert out["parts"]["device"] == {
            "router_id": str(ROUTER_ID),
            "ip": "192.168.88.24",
            "match": "session",
            "guest_session_id": "77777777-0000-4000-8000-000000000007",
        }
        assert out["evidence"]["lower_bound"] is True
        assert out["names"] == "device"

    def test_clear(self) -> None:
        out = dominant_device(_summary(devices=[_device(0.31)]))
        assert out["state"] == "clear" and out["parts"] is None
        assert out["evidence"]["top_share_at_least"] == 0.31

    def test_boundary(self) -> None:
        at = dominant_device(_summary(devices=[_device(f.DOMINANT_DEVICE_SHARE)]))
        under = dominant_device(
            _summary(devices=[_device(f.DOMINANT_DEVICE_SHARE - 0.0001)])
        )
        assert at["state"] == "flagged" and under["state"] == "clear"

    def test_too_little_traffic_to_judge(self) -> None:
        out = dominant_device(
            _summary(up=10 * MIB, down=90 * MIB, devices=[_device(0.9)])
        )
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "not_enough_traffic",
        )

    def test_floor_boundary(self) -> None:
        floor = f.DOMINANT_DEVICE_MIN_BYTES
        at = dominant_device(_summary(up=0, down=floor, devices=[_device(0.9)]))
        under = dominant_device(_summary(up=0, down=floor - 1, devices=[_device(0.9)]))
        assert at["state"] == "flagged"
        assert under["reason"] == "not_enough_traffic"

    def test_a_cafe_with_three_guests_does_not_light_up(self) -> None:
        out = dominant_device(_summary(devices_peak=3, devices=[_device(0.9)]))
        assert (out["state"], out["reason"]) == ("could_not_check", "too_few_devices")

    def test_device_count_boundary(self) -> None:
        at = dominant_device(
            _summary(devices_peak=f.DOMINANT_DEVICE_MIN_DEVICES, devices=[_device(0.9)])
        )
        under = dominant_device(
            _summary(
                devices_peak=f.DOMINANT_DEVICE_MIN_DEVICES - 1, devices=[_device(0.9)]
            )
        )
        assert at["state"] == "flagged" and under["reason"] == "too_few_devices"

    def test_no_device_list_is_not_clear(self) -> None:
        out = dominant_device(_summary(devices=[]))
        assert (out["state"], out["reason"]) == ("could_not_check", "no_device_list")

    def test_not_measured(self) -> None:
        out = dominant_device(_summary(measured=False))
        assert (out["state"], out["reason"]) == ("could_not_check", "not_measured")


# ---------------------------------------------------------------------------
# rule 4: a service that is unusual for this venue
# ---------------------------------------------------------------------------

DAY = END.date()


def _days_ago(n: int) -> Any:
    return DAY - timedelta(days=n)


def _history(protocol: int, port: int, *days_ago: int) -> list[ServiceDay]:
    return [ServiceDay(_days_ago(n), protocol, port, 600 * MIB) for n in days_ago]


class TestUnusualService:
    def test_flagged_for_a_large_share(self) -> None:
        summary = _summary(
            services=[_svc(6, 443, 6 * GIB, 0.6), _svc(6, 6881, 3 * GIB, 0.3)]
        )
        # Seen today and on the first retained day: not usual (two days),
        # and not new (no measured day before its first sighting).
        out = unusual_service(summary, _history(6, 6881, 0, 7), _hours())
        assert out["state"] == "flagged" and out["severity"] == "look"
        assert out["parts"]["protocol"] == 6 and out["parts"]["port"] == 6881
        assert out["parts"]["why"] == "large_share"
        assert out["parts"]["service_name"] is None
        assert out["evidence"]["items"][0]["days_seen"] == 2
        assert out["names"] == "service"

    def test_flagged_when_new_for_this_venue(self) -> None:
        summary = _summary(services=[_svc(17, 6881, 1200 * MIB, 0.12)])
        out = unusual_service(summary, _history(17, 6881, 0), _hours())
        assert out["state"] == "flagged" and out["parts"]["why"] == "new"
        assert out["evidence"]["items"][0]["first_seen_day"] == DAY.isoformat()

    def test_clear_when_only_ordinary_services(self) -> None:
        summary = _summary(
            services=[_svc(6, 443, 6 * GIB, 0.6), _svc(17, 443, 4 * GIB, 0.4)]
        )
        assert unusual_service(summary, [], _hours())["state"] == "clear"

    def test_usual_for_this_venue_is_never_flagged(self) -> None:
        """A camera uploading on its own port every day is this venue's
        normal, whatever its share."""
        summary = _summary(services=[_svc(6, 8000, 5 * GIB, 0.5)])
        history = _history(6, 8000, 0, 1, 2)
        assert unusual_service(summary, history, _hours())["state"] == "clear"

    def test_usual_days_boundary(self) -> None:
        summary = _summary(services=[_svc(6, 8000, 5 * GIB, 0.5)])
        two = unusual_service(summary, _history(6, 8000, 0, 1), _hours())
        assert two["state"] == "flagged"

    def test_share_boundary_for_a_service_that_is_not_new(self) -> None:
        # First seen on the first retained day: no measured day before it.
        history = _history(6, 6881, 0, 7)
        at = _summary(services=[_svc(6, 6881, 3 * GIB, f.UNUSUAL_SERVICE_SHARE)])
        under = _summary(
            services=[_svc(6, 6881, 3 * GIB, f.UNUSUAL_SERVICE_SHARE - 0.0001)]
        )
        assert unusual_service(at, history, _hours())["state"] == "flagged"
        assert unusual_service(under, history, _hours())["state"] == "clear"

    def test_share_boundary_for_a_new_service(self) -> None:
        history = _history(6, 6881, 0)
        at = _summary(services=[_svc(6, 6881, GIB, f.UNUSUAL_NEW_SERVICE_SHARE)])
        under = _summary(
            services=[_svc(6, 6881, GIB, f.UNUSUAL_NEW_SERVICE_SHARE - 0.0001)]
        )
        assert unusual_service(at, history, _hours())["state"] == "flagged"
        assert unusual_service(under, history, _hours())["state"] == "clear"

    def test_size_boundary(self) -> None:
        history = _history(6, 6881, 0)
        at = _summary(services=[_svc(6, 6881, f.UNUSUAL_SERVICE_MIN_BYTES, 0.5)])
        under = _summary(services=[_svc(6, 6881, f.UNUSUAL_SERVICE_MIN_BYTES - 1, 0.5)])
        assert unusual_service(at, history, _hours())["state"] == "flagged"
        assert unusual_service(under, history, _hours())["state"] == "clear"

    def test_too_little_traffic_to_judge(self) -> None:
        summary = _summary(
            up=10 * MIB, down=50 * MIB, services=[_svc(6, 6881, 50 * MIB, 0.9)]
        )
        out = unusual_service(summary, [], _hours())
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "not_enough_traffic",
        )

    def test_services_not_measured_is_not_clear(self) -> None:
        out = unusual_service(_summary(windows_measured=0), [], _hours())
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "services_not_measured",
        )

    def test_a_short_baseline_is_not_clear(self) -> None:
        summary = _summary(services=[_svc(6, 6881, 3 * GIB, 0.9)])
        out = unusual_service(summary, _history(6, 6881, 0), _hours(days=3))
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "baseline_too_short",
        )

    def test_not_measured(self) -> None:
        out = unusual_service(_summary(measured=False), [], [])
        assert (out["state"], out["reason"]) == ("could_not_check", "not_measured")

    def test_the_ordinary_list_is_short_and_covers_what_was_asked(self) -> None:
        for protocol, port in [
            (6, 80),
            (6, 443),
            (17, 443),
            (17, 53),
            (17, 123),
            (6, 993),
            (6, 587),
            (17, 500),
            (17, 4500),
            (17, 1194),
            (17, 51820),
            (17, 3478),
            (50, 0),
            (1, 0),
        ]:
            assert f.is_ordinary_service(protocol, port), (protocol, port)
        for protocol, port in [(6, 6881), (6, 22), (6, 23), (6, 3389), (17, 6881)]:
            assert not f.is_ordinary_service(protocol, port), (protocol, port)
        assert len(f.ORDINARY_SERVICES) < 60

    def test_nothing_calls_a_service_malicious(self, threat: ThreatList) -> None:
        """Checked on what is sent: every key, code and value of a response
        in which all five rules flag."""
        data = build_findings(**_everything_flagged(threat))
        assert data["counts"]["flagged"] == 5
        text = json.dumps(data).lower()
        for word in ("malicious", "malware", "attack", "infected", "hacked", "threat"):
            assert word not in text.replace("threat_list", ""), word
        assert _by_id(data)["unusual_service"]["parts"]["why"] in {"new", "large_share"}


# ---------------------------------------------------------------------------
# rule 5: known-bad destinations
# ---------------------------------------------------------------------------


class TestKnownBad:
    def test_flagged_and_names_the_list_and_its_date(self, threat: ThreatList) -> None:
        rows = [_addr("203.0.113.9", 3 * GIB), _addr("192.0.2.1", 9 * GIB)]
        out = _known_bad(rows, threat)
        assert out["state"] == "flagged" and out["severity"] == "act"
        assert out["parts"]["address"] == "203.0.113.9"
        assert out["parts"]["addresses"] == 1
        assert out["parts"]["bytes_at_least"] == 3 * GIB
        assert out["parts"]["list_name"] == "Spamhaus DROP"
        assert (
            out["parts"]["list_date"] == (NOW - timedelta(hours=6)).date().isoformat()
        )
        (item,) = out["evidence"]["items"]
        assert item["list_entry"] == "203.0.113.0/24" and item["reference"] == "SBL1"
        assert out["evidence"]["addresses_checked"] == 2
        assert out["evidence"]["lower_bound"] is True
        assert out["names"] == "destination"

    def test_ipv6_matches(self, threat: ThreatList) -> None:
        out = _known_bad([_addr("2001:db8:bad::5", 5 * MIB)], threat)
        assert out["state"] == "flagged"

    def test_clear(self, threat: ThreatList) -> None:
        out = _known_bad([_addr("192.0.2.1", 9 * GIB)], threat)
        assert out["state"] == "clear" and out["severity"] is None
        assert out["evidence"]["addresses_matched"] == 0
        assert out["evidence"]["list"]["name"] == "Spamhaus DROP"

    def test_boundary_between_look_and_act(self, threat: ThreatList) -> None:
        at = _known_bad([_addr("203.0.113.9", f.KNOWN_BAD_ACT_BYTES)], threat)
        under = _known_bad([_addr("203.0.113.9", f.KNOWN_BAD_ACT_BYTES - 1)], threat)
        assert at["severity"] == "act" and under["severity"] == "look"

    def test_boundary_for_a_few_stray_packets(self, threat: ThreatList) -> None:
        at = _known_bad([_addr("203.0.113.9", f.KNOWN_BAD_MIN_BYTES)], threat)
        under = _known_bad([_addr("203.0.113.9", f.KNOWN_BAD_MIN_BYTES - 1)], threat)
        assert at["state"] == "flagged" and at["severity"] == "look"
        assert under["state"] == "clear" and under["evidence"]["ignored_small"] == 1

    def test_list_absent_is_not_clear(self, no_threat: ThreatList) -> None:
        out = _known_bad([_addr("203.0.113.9", GIB)], no_threat)
        assert (out["state"], out["reason"]) == ("could_not_check", "list_unavailable")
        assert out["evidence"]["list"] == {
            "name": "Spamhaus DROP",
            "date": None,
            "entries": 0,
        }

    def test_an_old_copy_is_not_matched_against(self, tmp_path: pathlib.Path) -> None:
        age = timedelta(days=threat_module.THREAT_LIST_MAX_AGE_DAYS)
        fresh = ThreatList(_write_list(tmp_path / "a", fetched_at=NOW - age))
        stale = ThreatList(
            _write_list(tmp_path / "b", fetched_at=NOW - age - timedelta(minutes=1))
        )
        rows = [_addr("203.0.113.9", GIB)]
        assert _known_bad(rows, fresh)["state"] == "flagged"
        out = _known_bad(rows, stale)
        assert (out["state"], out["reason"]) == ("could_not_check", "list_stale")

    def test_no_destination_records_is_not_clear(self, threat: ThreatList) -> None:
        out = _known_bad([], threat, windows_measured=0)
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "destinations_not_measured",
        )

    def test_no_windows_is_not_clear(self, threat: ThreatList) -> None:
        out = _known_bad([], threat, windows=0, windows_measured=0)
        assert (out["state"], out["reason"]) == ("could_not_check", "not_measured")

    def test_every_window_withheld_is_said_not_cleared(
        self, threat: ThreatList
    ) -> None:
        out = _known_bad([], threat, windows_withheld=12, min_devices=5)
        assert (out["state"], out["reason"]) == (
            "could_not_check",
            "withheld_small_venue",
        )
        assert out["evidence"]["windows_withheld"] == 12
        assert out["evidence"]["min_devices"] == 5

    def test_partly_withheld_is_checked_and_counted(self, threat: ThreatList) -> None:
        out = _known_bad(
            [_addr("192.0.2.1", GIB)], threat, windows_withheld=11, min_devices=5
        )
        assert out["state"] == "clear" and out["evidence"]["windows_withheld"] == 11

    def test_master_has_no_withholding_fields(self, threat: ThreatList) -> None:
        out = _known_bad([_addr("192.0.2.1", GIB)], threat)
        assert "windows_withheld" not in out["evidence"]
        assert "min_devices" not in out["evidence"]


# ---------------------------------------------------------------------------
# the threat list and how it reaches the image
# ---------------------------------------------------------------------------


class TestThreatList:
    def test_match_by_family_and_mapped_address(self, threat: ThreatList) -> None:
        assert threat.available and threat.entries == 3
        assert threat.match("203.0.113.255").cidr == "203.0.113.0/24"  # type: ignore[union-attr]
        assert threat.match("198.51.100.127") is not None
        assert threat.match("198.51.100.128") is None  # one past the /25
        assert threat.match("203.0.112.255") is None
        assert threat.match("2001:db8:bad:ffff::1") is not None
        assert threat.match("2001:db8:bae::1") is None
        assert threat.match("::ffff:203.0.113.1") is not None
        assert threat.match("not an address") is None

    def test_an_entry_inside_a_wider_one_keeps_the_wider(
        self, tmp_path: pathlib.Path
    ) -> None:
        listed = ThreatList(
            _write_list(tmp_path, v4=["203.0.113.0/24", "203.0.113.64/26"])
        )
        assert listed.match("203.0.113.70").cidr == "203.0.113.0/24"  # type: ignore[union-attr]
        assert listed.match("203.0.113.200") is not None

    def test_missing_directory_is_unavailable_not_an_error(
        self, no_threat: ThreatList
    ) -> None:
        assert no_threat.available is False and no_threat.entries == 0
        assert no_threat.match("203.0.113.9") is None
        assert no_threat.describe(NOW)["date"] is None
        assert "FileNotFoundError" in str(no_threat.unavailable_reason)

    def test_half_a_list_is_no_list(self, tmp_path: pathlib.Path) -> None:
        directory = _write_list(tmp_path)
        (directory / "drop_v6.json").unlink()
        assert ThreatList(directory).available is False
        assert ThreatList(directory).match("203.0.113.9") is None

    def test_a_file_without_its_date_is_refused(self, tmp_path: pathlib.Path) -> None:
        listed = ThreatList(_write_list(tmp_path, metadata=False))
        assert listed.available is False
        assert "no dated metadata" in str(listed.unavailable_reason)

    def test_a_corrupt_file_is_unavailable_not_an_error(
        self, tmp_path: pathlib.Path
    ) -> None:
        directory = _write_list(tmp_path)
        (directory / "drop_v4.json").write_text("{not json\n")
        assert ThreatList(directory).available is False

    def test_describe_gives_name_date_and_credit(self, threat: ThreatList) -> None:
        described = threat.describe(NOW)
        assert described["name"] == "Spamhaus DROP"
        assert described["date"] == (NOW - timedelta(hours=6)).date().isoformat()
        assert described["stale"] is False and described["entries"] == 3
        assert described["copyright"] == "(c) test"
        assert described["credit"]["url"].startswith("https://www.spamhaus.org/")

    def test_age_is_measured_from_the_fetch_not_the_files_own_date(
        self, tmp_path: pathlib.Path
    ) -> None:
        """The publisher re-dates a file only when it changes."""
        old_content = ThreatList(
            _write_list(
                tmp_path / "a",
                published=NOW - timedelta(days=60),
                fetched_at=NOW - timedelta(days=1),
            )
        )
        assert old_content.is_stale(NOW) is False
        no_manifest = ThreatList(
            _write_list(
                tmp_path / "b", published=NOW - timedelta(days=60), fetched_at=None
            )
        )
        assert no_manifest.is_stale(NOW) is True

    def test_one_list_per_directory_per_process(self, tmp_path: pathlib.Path) -> None:
        directory = _write_list(tmp_path)
        assert threat_module.get_threat_list(
            directory
        ) is threat_module.get_threat_list(str(directory))

    def test_default_directory_is_backend_data_threat(self) -> None:
        assert threat_module.default_threat_data_dir().parts[-2:] == ("data", "threat")


def _fetch_script() -> Any:
    spec = importlib.util.spec_from_file_location(
        "fetch_threat_data", pathlib.Path("scripts/fetch_threat_data.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _published(cidrs: list[str]) -> bytes:
    lines = [json.dumps({"cidr": cidr, "sblid": "SBL1"}) for cidr in cidrs]
    lines.append(
        json.dumps(
            {"type": "metadata", "timestamp": int(NOW.timestamp()), "copyright": "(c)"}
        )
    )
    return ("\n".join(lines) + "\n").encode()


class TestDelivery:
    def test_the_list_is_not_in_the_repository(self) -> None:
        assert "data/threat/" in pathlib.Path(".gitignore").read_text().splitlines()
        for root in ("app", "tests", "scripts"):
            assert not list(pathlib.Path(root).rglob("drop_v*.json"))

    def test_image_build_fetches_but_does_not_depend_on_it(self) -> None:
        text = pathlib.Path("Dockerfile").read_text()
        assert "scripts/fetch_threat_data.py --dest /app/data/threat" in text
        step = text[text.index("ARG FETCH_THREAT_DATA") :]
        assert "|| echo" in step  # a failed download must not fail the build
        assert text.index("COPY scripts") < text.index("fetch_threat_data.py")
        assert text.index("COPY app") < text.index("fetch_threat_data.py")

    def test_script_fetches_what_the_application_opens(self) -> None:
        script = _fetch_script()
        assert script.BASE_URL == "https://www.spamhaus.org/drop"
        assert script.THREAT_LIST_FILENAMES == threat_module.THREAT_LIST_FILENAMES

    def test_a_good_fetch_installs_the_files_untouched_and_a_manifest(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = _fetch_script()
        bodies = {
            "drop_v4.json": _published([f"203.0.{n}.0/24" for n in range(120)]),
            "drop_v6.json": _published(["2001:db8:bad::/48"]),
        }
        monkeypatch.setattr(script, "download", lambda url: bodies[url.split("/")[-1]])
        manifest = script.fetch(tmp_path)
        for name, body in bodies.items():
            # Byte for byte: the date and copyright line stay in the file.
            assert (tmp_path / name).read_bytes() == body
        assert manifest["entries"] == 121
        loaded = ThreatList(tmp_path)
        assert loaded.available and loaded.fetched_at is not None
        assert not [p for p in tmp_path.iterdir() if p.name.startswith(".staging")]

    def test_a_failed_fetch_leaves_the_existing_files_alone(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = _fetch_script()
        _write_list(tmp_path)
        before = (tmp_path / "drop_v4.json").read_bytes()

        def broken(url: str) -> bytes:
            if url.endswith("drop_v6.json"):
                raise OSError("network down")
            return _published([f"203.0.{n}.0/24" for n in range(120)])

        monkeypatch.setattr(script, "download", broken)
        with pytest.raises(OSError):
            script.fetch(tmp_path)
        assert (tmp_path / "drop_v4.json").read_bytes() == before

    def test_a_download_that_is_not_a_usable_list_is_refused(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = _fetch_script()
        monkeypatch.setattr(script, "download", lambda url: b"<html>blocked</html>")
        with pytest.raises(RuntimeError, match="not a usable list"):
            script.fetch(tmp_path)
        monkeypatch.setattr(
            script, "download", lambda url: _published(["203.0.113.0/24"])
        )
        with pytest.raises(RuntimeError, match="entries, refused"):
            script.fetch(tmp_path)
        assert not (tmp_path / "drop_v4.json").exists()


# ---------------------------------------------------------------------------
# the service: scoping, states, what is read
# ---------------------------------------------------------------------------


def _window(start: datetime, *, devices: int = 8, location: uuid.UUID) -> Any:
    return SimpleNamespace(
        router_id=ROUTER_ID,
        location_id=location,
        window_start=start,
        window_seconds=300,
        bytes_up=20 * MIB,
        bytes_down=180 * MIB,
        bytes_internal=0,
        bytes_unclassified=0,
        flows_total=50,
        services_measured=True,
        talker_count=devices,
        destination_count=20,
        top_talkers=[
            {
                "ip": "192.168.88.24",
                "bytes_up": 10 * MIB,
                "bytes_down": 150 * MIB,
                "flows": 9,
                "match": "none",
            }
        ],
        top_destinations=[
            {"ip": "192.0.2.1", "bytes": 100 * MIB, "bytes_up": 0, "bytes_down": 0}
        ],
    )


class SummaryRepo:
    """Stands in for ``TrafficFlowRepository`` under the REAL summary
    service. Windows are keyed by venue."""

    def __init__(self) -> None:
        self.windows: dict[uuid.UUID, list[Any]] = {}
        self.calls: list[Any] = []

    async def data_bounds(self, scope):  # noqa: ANN001
        self.calls.append(("bounds", scope))
        starts = [w.window_start for w in self.windows.get(scope.location_id, [])]
        return (min(starts), max(starts)) if starts else (None, None)

    async def windows_in_range(self, scope, *, since, until):  # noqa: ANN001
        self.calls.append(("windows", scope))
        return [
            w
            for w in self.windows.get(scope.location_id, [])
            if since <= w.window_start < until
        ]

    async def service_steps(self, scope, *, since, until, step_seconds):  # noqa: ANN001
        self.calls.append(("services", scope))
        return []


class FindingsRepo:
    """Rows keyed by venue, so a scope mix-up shows up as wrong findings."""

    def __init__(self) -> None:
        self.venues = {LOCATION_ID, SIBLING_LOCATION, OTHER_LOCATION}
        self.hours: dict[uuid.UUID, list[HourRow]] = {}
        self.addresses: dict[uuid.UUID, list[AddressRow]] = {}
        self.stats: dict[uuid.UUID, WindowStats] = {}
        self.calls: list[tuple[str, DestinationScope]] = []

    async def venue_exists(self, location_id):  # noqa: ANN001
        return location_id in self.venues

    async def hour_rows(self, scope, *, since, until):  # noqa: ANN001
        self.calls.append(("hours", scope))
        return [
            h for h in self.hours.get(scope.location_id, []) if since <= h.start < until
        ]

    async def service_history(self, scope, services, *, since, until):  # noqa: ANN001
        self.calls.append(("history", scope))
        return []

    async def address_rows(self, scope, *, since, until):  # noqa: ANN001
        self.calls.append(("addresses", scope))
        return self.addresses.get(scope.location_id, [])

    async def window_stats(self, scope, *, since, until):  # noqa: ANN001
        self.calls.append(("stats", scope))
        stats = self.stats.get(scope.location_id, WindowStats(12, 12, 0))
        return (
            stats if scope.min_devices else WindowStats(stats.windows, stats.measured)
        )


def _populated() -> tuple[FindingsRepo, SummaryRepo]:
    findings, summaries = FindingsRepo(), SummaryRepo()
    for venue, address in (
        (LOCATION_ID, "203.0.113.9"),
        (OTHER_LOCATION, "198.51.100.7"),
    ):
        summaries.windows[venue] = [
            _window(LAST + timedelta(minutes=5 * n), location=venue) for n in range(12)
        ]
        findings.hours[venue] = _hours(overrides={LAST: (3 * GIB, 0)})
        findings.addresses[venue] = [_addr(address, 3 * GIB)]
    return findings, summaries


def _service(
    findings: FindingsRepo,
    summaries: SummaryRepo,
    threat: ThreatList,
    *,
    enabled: bool = True,
) -> TrafficFlowFindingsService:
    settings = SimpleNamespace(traffic_flow_enabled=enabled)
    return TrafficFlowFindingsService(
        findings,
        TrafficFlowSummaryService(summaries, settings, now=lambda: END),  # type: ignore[arg-type]
        settings,  # type: ignore[arg-type]
        threat,
        now=lambda: NOW,
    )


def _by_id(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {finding["id"]: finding for finding in data["findings"]}


class Venues:
    """Stands in for ``LocationService.get_location``: the real one raises
    for a missing venue and for another organisation's."""

    owner = {LOCATION_ID: ORG_ID, SIBLING_LOCATION: ORG_ID, OTHER_LOCATION: ORG_B}

    async def get_location(self, location_id, *, requesting_organization_id=None):  # noqa: ANN001
        from app.domains.location.exceptions import (
            CrossOrganizationLocationAccessError,
            LocationNotFoundError,
        )

        if location_id not in self.owner:
            raise LocationNotFoundError(location_id)
        if self.owner[location_id] != requesting_organization_id:
            raise CrossOrganizationLocationAccessError()
        return SimpleNamespace(id=location_id, organization_id=self.owner[location_id])


def _customer(
    findings: FindingsRepo,
    summaries: SummaryRepo,
    threat: ThreatList,
    *,
    confined_to: frozenset[uuid.UUID] | None = None,
    enabled: bool = True,
) -> CustomerFindingsService:
    """The customer service as the route builds it: the REAL venue check of
    the customer venue routes in front of the findings read."""
    venues = TrafficFlowCustomerService(
        object(),  # type: ignore[arg-type]
        Venues(),
        SimpleNamespace(  # type: ignore[arg-type]
            traffic_flow_enabled=True,
            traffic_flow_agent_url="",
            traffic_flow_agent_secret="",
        ),
        caller_location_scope=confined_to,
        now=lambda: NOW,
    )
    return CustomerFindingsService(
        _service(findings, summaries, threat, enabled=enabled), venues
    )


async def _master(service: TrafficFlowFindingsService, **kw: Any) -> dict[str, Any]:
    args: dict[str, Any] = {"location_id": LOCATION_ID, "since": None, "until": None}
    args.update(kw)
    return await service.findings(**args)


async def _venue(service: CustomerFindingsService, venue: uuid.UUID) -> dict[str, Any]:
    return await service.findings(venue, organization_id=ORG_ID, since=None, until=None)


class TestService:
    async def test_all_five_rules_always_in_order(self, threat: ThreatList) -> None:
        data = await _master(_service(*_populated(), threat))
        assert [x["id"] for x in data["findings"]] == list(f.RULE_IDS)
        assert len(f.RULE_IDS) == 5
        for finding in data["findings"]:
            assert finding["state"] in {"flagged", "clear", "could_not_check"}
            assert (finding["reason"] is not None) == (
                finding["state"] == "could_not_check"
            )
            assert (finding["severity"] is not None) == (finding["state"] == "flagged")
            assert finding["period"] == {"since": data["since"], "until": data["until"]}
        assert sum(data["counts"].values()) == 5

    async def test_the_default_period_is_the_last_hour(
        self, threat: ThreatList
    ) -> None:
        data = await _master(_service(*_populated(), threat))
        assert data["since"] == LAST.isoformat() and data["until"] == END.isoformat()
        assert data["baseline"] == {
            "since": (END - timedelta(days=7)).isoformat(),
            "until": END.isoformat(),
            "days": 7,
            "derived": True,
            "timezone": "UTC",
        }
        assert data["notifications"] is False

    async def test_findings_from_the_venues_own_rows(self, threat: ThreatList) -> None:
        data = await _master(_service(*_populated(), threat))
        found = _by_id(data)
        assert found["upload_heavy"]["state"] == "flagged"
        assert found["known_bad_destinations"]["parts"]["address"] == "203.0.113.9"
        # 12 windows of 200 MiB with one device at 160 MiB of each.
        assert found["dominant_device"]["state"] == "flagged"
        assert found["dominant_device"]["parts"]["share_at_least"] == 0.8
        assert data["threat_list"]["name"] == "Spamhaus DROP"
        assert data["threat_list"]["date"] is not None
        assert data["feature_enabled"] is True and "min_devices" not in data

    async def test_one_venue_never_sees_another_venues_rows(
        self, threat: ThreatList
    ) -> None:
        service = _service(*_populated(), threat)
        mine = _by_id(await _master(service))["known_bad_destinations"]
        theirs = _by_id(await _master(service, location_id=OTHER_LOCATION))[
            "known_bad_destinations"
        ]
        assert mine["parts"]["address"] == "203.0.113.9"
        assert theirs["parts"]["address"] == "198.51.100.7"

    async def test_the_venue_reaches_every_read(self, threat: ThreatList) -> None:
        findings, summaries = _populated()
        await _master(_service(findings, summaries, threat))
        assert {name for name, _scope in findings.calls} == {
            "hours",
            "history",
            "stats",
            "addresses",
        }
        for _name, scope in findings.calls:
            assert scope.location_id == LOCATION_ID
            assert scope.organization_id is None and scope.min_devices == 0
        for _name, scope in summaries.calls:
            assert scope.location_id == LOCATION_ID

    async def test_a_venue_that_does_not_exist_is_a_404(
        self, threat: ThreatList
    ) -> None:
        findings, summaries = _populated()
        with pytest.raises(TrafficFlowError) as caught:
            await _master(
                _service(findings, summaries, threat), location_id=uuid.uuid4()
            )
        assert caught.value.status_code == 404
        assert caught.value.code == "TRAFFIC_FLOW_LOCATION_NOT_FOUND"
        assert findings.calls == [] and summaries.calls == []

    async def test_range_errors_are_the_summarys(self, threat: ThreatList) -> None:
        service = _service(*_populated(), threat)
        with pytest.raises(TrafficFlowError) as bad:
            await _master(service, since=END, until=LAST)
        assert bad.value.code == "TRAFFIC_FLOW_BAD_RANGE"
        with pytest.raises(TrafficFlowError) as large:
            await _master(service, since=END - timedelta(days=7, seconds=1), until=END)
        assert large.value.code == "TRAFFIC_FLOW_WINDOW_TOO_LARGE"
        seven = await _master(service, since=END - timedelta(days=7), until=END)
        assert seven["measured"] is True

    async def test_nothing_in_the_period_is_not_five_clears(
        self, threat: ThreatList
    ) -> None:
        findings, summaries = _populated()
        data = await _master(
            _service(findings, summaries, threat),
            since=END - timedelta(days=3),
            until=END - timedelta(days=2),
        )
        assert data["measured"] is False
        assert {x["state"] for x in data["findings"]} == {"could_not_check"}
        assert {x["reason"] for x in data["findings"]} == {"not_measured"}
        assert data["counts"] == {"flagged": 0, "clear": 0, "could_not_check": 5}
        assert findings.calls == []

    async def test_flag_off_says_so_and_reads_nothing(self, threat: ThreatList) -> None:
        findings, summaries = _populated()
        data = await _master(_service(findings, summaries, threat, enabled=False))
        assert data["feature_enabled"] is False and data["measured"] is False
        assert {x["reason"] for x in data["findings"]} == {"feature_off"}
        assert findings.calls == [] and summaries.calls == []

    async def test_without_the_list_no_address_is_even_read(
        self, no_threat: ThreatList
    ) -> None:
        findings, summaries = _populated()
        data = await _master(_service(findings, summaries, no_threat))
        found = _by_id(data)["known_bad_destinations"]
        assert (found["state"], found["reason"]) == (
            "could_not_check",
            "list_unavailable",
        )
        assert "addresses" not in {name for name, _scope in findings.calls}
        assert data["threat_list"]["available"] is False
        # The other four rules do not depend on the list.
        assert _by_id(data)["upload_heavy"]["state"] == "flagged"


# ---------------------------------------------------------------------------
# customer: whose venue, the add-on, withholding
# ---------------------------------------------------------------------------


def _dependency_calls(dependant: Any) -> set[Any]:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


def _closure(call: Any) -> list[Any]:
    return [c.cell_contents for c in (getattr(call, "__closure__", None) or ())]


class TestCustomer:
    async def test_own_venue_gets_the_findings_without_the_platform_switch(
        self, threat: ThreatList
    ) -> None:
        data = await _venue(_customer(*_populated(), threat), LOCATION_ID)
        assert "feature_enabled" not in data
        assert data["location_id"] == str(LOCATION_ID)
        assert data["min_devices"] == 5 and data["windows_withheld"] == 0
        assert _by_id(data)["known_bad_destinations"]["state"] == "flagged"

    async def test_every_read_carries_venue_organisation_and_the_rule(
        self, threat: ThreatList
    ) -> None:
        findings, summaries = _populated()
        await _venue(_customer(findings, summaries, threat), LOCATION_ID)
        assert len(findings.calls) == 4
        for _name, scope in findings.calls:
            assert scope.location_id == LOCATION_ID
            assert scope.organization_id == ORG_ID
            assert scope.min_devices == 5

    async def test_another_organisations_venue_is_a_404_and_nothing_is_read(
        self, threat: ThreatList
    ) -> None:
        findings, summaries = _populated()
        service = _customer(findings, summaries, threat)
        for venue in (OTHER_LOCATION, uuid.uuid4()):
            with pytest.raises(TrafficFlowLocationNotFoundError) as caught:
                await _venue(service, venue)
            assert caught.value.status_code == 404
        assert findings.calls == [] and summaries.calls == []

    async def test_a_caller_confined_to_one_venue_cannot_read_a_sibling(
        self, threat: ThreatList
    ) -> None:
        findings, summaries = _populated()
        service = _customer(
            findings, summaries, threat, confined_to=frozenset({LOCATION_ID})
        )
        assert (await _venue(service, LOCATION_ID))["measured"] is True
        findings.calls.clear()
        with pytest.raises(TrafficFlowCrossLocationError) as caught:
            await _venue(service, SIBLING_LOCATION)
        assert caught.value.status_code == 403 and findings.calls == []

    async def test_a_small_venue_is_told_it_was_not_checked(
        self, threat: ThreatList
    ) -> None:
        findings, summaries = _populated()
        findings.stats[LOCATION_ID] = WindowStats(12, 12, 12)
        findings.addresses[LOCATION_ID] = []  # what the withheld read returns
        data = await _venue(_customer(findings, summaries, threat), LOCATION_ID)
        found = _by_id(data)["known_bad_destinations"]
        assert (found["state"], found["reason"]) == (
            "could_not_check",
            "withheld_small_venue",
        )
        assert data["windows_withheld"] == 12
        # Master, same rows: nothing is withheld.
        master = await _master(_service(findings, summaries, threat))
        assert _by_id(master)["known_bad_destinations"]["state"] == "clear"
        assert "windows_withheld" not in master

    async def test_the_platform_switch_is_not_a_customers_to_know_about(
        self, threat: ThreatList
    ) -> None:
        data = await _venue(
            _customer(*_populated(), threat, enabled=False), LOCATION_ID
        )
        assert "feature_enabled" not in data
        assert {x["reason"] for x in data["findings"]} == {"not_measured"}

    def test_how_the_data_is_gathered_is_in_no_field(self, threat: ThreatList) -> None:
        data = build_findings(**_everything_flagged(threat), min_devices=5)
        text = json.dumps(data).lower()
        for word in (
            "tunnel",
            "wireguard",
            "exporter",
            "collector",
            "netflow",
            "ipfix",
        ):
            assert word not in text

    # -- the route --------------------------------------------------------

    def _route(self) -> Any:
        from app.domains.traffic_flow.findings_customer_router import (
            traffic_flow_findings_customer_router,
        )

        (route,) = traffic_flow_findings_customer_router.routes
        return route

    def test_read_only_and_only_this_one(self) -> None:
        route = self._route()
        assert route.path == "/traffic-flow/locations/{location_id}/findings"
        assert route.methods == {"GET"}

    def test_it_carries_the_customer_venue_routes_own_guards(self) -> None:
        """The very same three objects, so the add-on key and the permission
        cannot drift apart."""
        from app.domains.billing.constants import PlanFeatureKey
        from app.domains.rbac.dependencies import RequireOrganization
        from app.domains.traffic_flow import customer_router

        expected = [g.dependency for g in customer_router._GUARDS]  # noqa: SLF001
        assert len(expected) == 3 and expected[0] is RequireOrganization
        assert PlanFeatureKey.TRAFFIC_FLOW in _closure(expected[1])
        assert "venue_traffic.read" in _closure(expected[2])
        assert ScopeType.LOCATION in _closure(expected[2])
        guards = [d.dependency for d in self._route().dependencies]
        assert len(guards) == 3
        for mine, theirs in zip(guards, expected, strict=True):
            assert mine is theirs

    async def test_add_on_off_is_a_402_naming_the_feature(self) -> None:
        from decimal import Decimal

        from app.domains.billing.constants import PlanFeatureKey
        from app.domains.billing.exceptions import FeatureNotEntitledError

        (guard,) = [
            d.dependency
            for d in self._route().dependencies
            if PlanFeatureKey.TRAFFIC_FLOW in _closure(d.dependency)
        ]

        class Checker:
            def __init__(self, *features: str) -> None:
                self.features = features

            async def get_snapshot(self, organization_id: uuid.UUID) -> Any:
                return SimpleNamespace(
                    enabled_features=frozenset(self.features),
                    limits={"max_locations": Decimal(1)},
                    has_feature=lambda key: key.value in self.features,
                )

        with pytest.raises(FeatureNotEntitledError) as caught:
            await guard(organization_id=ORG_ID, checker=Checker("reports"))
        assert caught.value.status_code == 402
        assert caught.value.data == {
            "error_code": "feature_not_entitled",
            "feature_key": "traffic_flow",
        }
        assert await guard(organization_id=ORG_ID, checker=Checker("traffic_flow"))

    def test_it_resolves_organization_location_and_confinement(self) -> None:
        from app.domains.rbac.dependencies import (
            CurrentLocation,
            CurrentOrganization,
            RequireOrganization,
        )
        from app.domains.rbac.location_scope import CallerLocationScope

        calls = _dependency_calls(self._route().dependant)
        for needed in (
            RequireOrganization,
            CurrentOrganization,
            CurrentLocation,
            CallerLocationScope,
        ):
            assert needed in calls

    def test_it_takes_no_organisation_and_no_threshold(self) -> None:
        route = self._route()
        assert {p.name for p in route.dependant.path_params} == {"location_id"}
        assert {p.name for p in route.dependant.query_params} == {"since", "until"}
        assert route.dependant.body_params == []

    async def test_a_header_naming_another_venue_is_refused(self) -> None:
        from app.domains.traffic_flow.findings_customer_router import (
            get_venue_traffic_findings,
        )

        class Tripwire:
            async def findings(self, *args: Any, **kwargs: Any) -> Any:
                raise AssertionError("read after a mismatched header")

        with pytest.raises(TrafficFlowCrossLocationError):
            await get_venue_traffic_findings(
                LOCATION_ID,
                SimpleNamespace(state=SimpleNamespace(request_id="r")),  # type: ignore[arg-type]
                since=None,
                until=None,
                organization_id=ORG_ID,
                header_location_id=SIBLING_LOCATION,
                service=Tripwire(),  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Master route
# ---------------------------------------------------------------------------


def _pins(route: Any) -> dict[Any, Any]:
    closures = [
        {
            type(cell.cell_contents): cell.cell_contents
            for cell in (getattr(d.dependency, "__closure__", None) or ())
        }
        for d in route.dependencies
    ]
    pinned = [c for c in closures if ScopeType in c]
    assert pinned, closures
    return pinned[0]


class TestMasterRoute:
    def test_pinned_global_on_the_read_permission(self) -> None:
        from app.domains.traffic_flow.findings_router import (
            traffic_flow_findings_platform_router,
        )

        (route,) = traffic_flow_findings_platform_router.routes
        assert route.path == "/findings" and route.methods == {"GET"}
        pin = _pins(route)
        assert pin[ScopeType] == ScopeType.GLOBAL and pin[str] == "traffic_flows.read"

    def test_the_mounted_route_keeps_its_pin(self) -> None:
        from app.domains.traffic_flow.router import traffic_flow_platform_router

        (route,) = [
            r
            for r in traffic_flow_platform_router.routes
            if r.path.endswith("/findings")
        ]
        assert route.path == "/platform/traffic-flow/findings"
        assert _pins(route)[ScopeType] == ScopeType.GLOBAL

    def test_exactly_one_master_and_one_customer_route(self) -> None:
        from app.api.v1.router import api_v1_router

        assert sorted(r.path for r in api_v1_router.routes if "findings" in r.path) == [
            "/platform/traffic-flow/findings",
            "/traffic-flow/locations/{location_id}/findings",
        ]

    def test_the_venue_is_required(self) -> None:
        from app.domains.traffic_flow.findings_router import (
            traffic_flow_findings_platform_router,
        )

        (route,) = traffic_flow_findings_platform_router.routes
        params = {p.name: p for p in route.dependant.query_params}
        assert set(params) == {"location_id", "since", "until"}
        assert params["location_id"].required is True
        assert route.dependant.body_params == []


# ---------------------------------------------------------------------------
# statements
# ---------------------------------------------------------------------------


def _sql(statement: Any) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


_MASTER_SCOPE = DestinationScope(location_id=LOCATION_ID)
_CUSTOMER_SCOPE = DestinationScope(
    location_id=LOCATION_ID, organization_id=ORG_ID, min_devices=5
)


def _statements(scope: DestinationScope) -> dict[str, str]:
    span = {"since": LAST, "until": END}
    return {
        "hours": _sql(hour_rows_statement(scope, **span)),
        "history": _sql(service_history_statement(scope, [(6, 6881)], **span)),
        "addresses": _sql(address_rows_statement(scope, **span)),
    }


class TestStatements:
    @pytest.mark.parametrize("name", ["hours", "history", "addresses"])
    def test_every_read_is_scoped_to_the_venue(self, name: str) -> None:
        sql = _statements(_MASTER_SCOPE)[name]
        assert ".location_id = " in sql
        assert ".window_start >= " in sql and ".window_start < " in sql
        assert ".organization_id" not in sql

    @pytest.mark.parametrize("name", ["hours", "history", "addresses"])
    def test_a_customer_read_also_carries_the_organisation(self, name: str) -> None:
        sql = _statements(_CUSTOMER_SCOPE)[name]
        assert ".location_id = " in sql and ".organization_id = " in sql

    def test_addresses_use_the_destinations_small_venue_condition(self) -> None:
        """Not a copy of the rule: ``DestinationScope.visible`` itself, so a
        window with fewer than five devices contributes no address."""
        customer = _statements(_CUSTOMER_SCOPE)["addresses"]
        assert "EXISTS" in customer and "talker_count >= " in customer
        assert "EXISTS" not in _statements(_MASTER_SCOPE)["addresses"]
        source = pathlib.Path(
            "app/domains/traffic_flow/findings_service.py"
        ).read_text()
        assert "*scope.visible(bucket)," in source

    def test_addresses_never_include_the_folded_remainder(self) -> None:
        assert "remote_port != " in _statements(_MASTER_SCOPE)["addresses"]

    @pytest.mark.parametrize("scope", [_MASTER_SCOPE, _CUSTOMER_SCOPE])
    def test_no_statement_selects_a_device(self, scope: DestinationScope) -> None:
        for name, sql in _statements(scope).items():
            selected = sql.split("\nFROM ", 1)[0]
            for column in ("top_talkers", "top_destinations", "talker", "session"):
                assert column not in selected, (name, column)
            # The one use of the windows table by the address read is the
            # device COUNT of the small-venue rule.
            assert "top_talkers" not in sql and "guest" not in sql, name

    def test_the_hour_read_takes_sums_and_counts_only(self) -> None:
        selected = _statements(_MASTER_SCOPE)["hours"].split("\nFROM ", 1)[0]
        assert selected.count("sum(") == 2 and selected.count("count(") == 2
        assert "remote_address" not in _statements(_MASTER_SCOPE)["hours"]


# ---------------------------------------------------------------------------
# the privacy boundary
# ---------------------------------------------------------------------------


def _everything_flagged(threat: ThreatList) -> dict[str, Any]:
    """Inputs under which all five rules flag at once."""
    return {
        "feature_enabled": True,
        "location_id": str(LOCATION_ID),
        "summary": _summary(
            devices=[_device(0.71)],
            services=[_svc(6, 6881, 3 * GIB, 0.3)],
        ),
        "hours": _hours(overrides={LAST: (3 * GIB, 0)}),
        "service_history": _history(6, 6881, 0),
        "addresses": [_addr("203.0.113.9", 3 * GIB)],
        "threat": threat,
        "now": NOW,
        "since": LAST,
        "until": END,
        "baseline_since": END - timedelta(days=7),
        "windows_measured": 12,
    }


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        out = set(value)
        for inner in value.values():
            out |= _keys(inner)
        return out
    if isinstance(value, list):
        return set().union(*[_keys(inner) for inner in value]) if value else set()
    return set()


def _strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [s for inner in value.values() for s in _strings(inner)]
    if isinstance(value, list):
        return [s for inner in value for s in _strings(inner)]
    return [value] if isinstance(value, str) else []


#: Every traffic-flow table that exists. Findings add none.
_TABLES = {
    "traffic_flow_windows",
    "traffic_flow_ingest_state",
    "traffic_flow_service_buckets",
    "traffic_flow_dest_buckets",
    "traffic_flow_country_buckets",
    "router_traffic_flow_export",
}
#: The domain's migrations as they stand. Findings add none.
_MIGRATIONS = [
    "0156_create_traffic_flow_tables.py",
    "0157_traffic_flow_services_export.py",
    "0159_traffic_flow_dest_buckets.py",
    "0160_traffic_flow_country_buckets.py",
]
_DEVICE_COLUMNS = {
    "ip",
    "client_ip",
    "src_address",
    "source_address",
    "local_address",
    "device",
    "device_id",
    "mac",
    "mac_address",
    "guest_id",
    "guest_session_id",
    "session_id",
    "top_talkers",
}
_DESTINATION_COLUMNS = {"remote_address", "destination", "dst_address"}


class TestPrivacyBoundary:
    @pytest.mark.parametrize("min_devices", [0, 5])
    def test_no_finding_carries_a_device_and_a_destination(
        self, threat: ThreatList, min_devices: int
    ) -> None:
        data = build_findings(**_everything_flagged(threat), min_devices=min_devices)
        assert data["counts"]["flagged"] == 5  # every rule is saying something
        device_address = "192.168.88.24"
        destination_address = "203.0.113.9"
        named = {}
        for finding in data["findings"]:
            keys = _keys(finding)
            has_device = bool(keys & f.DEVICE_KEYS)
            has_destination = bool(keys & f.DESTINATION_KEYS)
            assert not (has_device and has_destination), finding["id"]
            # And by value, in case a key was renamed.
            strings = _strings(finding)
            assert not (
                device_address in strings and destination_address in strings
            ), finding["id"]
            named[finding["id"]] = (has_device, has_destination)
            assert finding["names"] == (
                "device"
                if has_device
                else "destination"
                if has_destination
                else finding["names"]
            )
        assert named == {
            "upload_heavy": (False, False),
            "quiet_hours_traffic": (False, False),
            "dominant_device": (True, False),
            "unusual_service": (False, False),
            "known_bad_destinations": (False, True),
        }

    def test_the_test_would_catch_a_pairing(self, threat: ThreatList) -> None:
        """The check above is not vacuous: a finding with both fails it."""
        data = build_findings(**_everything_flagged(threat))
        paired = dict(_by_id(data)["known_bad_destinations"])
        paired["parts"] = {**paired["parts"], "device": {"ip": "192.168.88.24"}}
        keys = _keys(paired)
        assert keys & f.DEVICE_KEYS and keys & f.DESTINATION_KEYS

    def test_findings_add_no_table(self) -> None:
        import app.domains.traffic_flow.models  # noqa: F401 -- registers them

        tables = {
            name
            for name in Base.metadata.tables
            if "traffic_flow" in name or "finding" in name or "threat" in name
        }
        assert tables == _TABLES

    def test_no_table_holds_a_device_beside_a_destination(self) -> None:
        import app.domains.traffic_flow.models  # noqa: F401

        for name in _TABLES:
            columns = set(Base.metadata.tables[name].columns.keys())
            device = columns & _DEVICE_COLUMNS
            destination = columns & _DESTINATION_COLUMNS
            if name == "traffic_flow_windows":
                # Two independent per-window lists, never joined (package
                # doc); neither is a column pairing one with the other.
                assert device == {"top_talkers"} and not destination
                continue
            if name == "router_traffic_flow_export":
                # The router's own export source address: a setting.
                assert device == {"src_address"} and not destination
                continue
            assert not (device and destination), name
            assert not device, name

    def test_findings_write_nothing_and_add_no_migration(self) -> None:
        for module in ("findings.py", "findings_service.py", "threat_list.py"):
            source = pathlib.Path("app/domains/traffic_flow", module).read_text()
            code = "\n".join(
                line
                for line in source.splitlines()
                if not line.lstrip().startswith("#")
            )
            for write in (
                "insert(",
                "pg_insert",
                ".add(self",
                "session.add",
                "update(",
            ):
                assert write not in code.split('"""', 2)[2], (module, write)
        names = [path.name for path in pathlib.Path("alembic/versions").glob("*.py")]
        assert not [n for n in names if "finding" in n or "threat" in n]
        assert sorted(n for n in names if "traffic_flow" in n) == _MIGRATIONS

    def test_no_alert_rule_is_created(self) -> None:
        """Findings are not raised through the alerting domain, so there is
        no rule row at all -- in particular none with a NULL organisation,
        which that domain reads as platform-wide."""
        for module in pathlib.Path("app/domains/traffic_flow").glob("findings*.py"):
            code = module.read_text().split('"""', 2)[2]
            assert "AlertRule" not in code and "monitoring" not in code, module.name
