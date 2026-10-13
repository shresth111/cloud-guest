"""Traffic flow: fleet status, the venue summary, the statements behind them,
the second migration and the hub artifacts.

* **Status** -- every state, and that "switched on, nothing received" is
  never shown as silence.
* **Summary** -- ``measured`` versus measured zero, the range limit, exact
  service sums versus lower-bound device/destination lists, gaps as gaps,
  and that no figure pairs a device with a destination or a service.
* **Statements** -- compiled for PostgreSQL (not executed: no database
  server is used here).
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

from app.domains.traffic_flow.constants import (
    OTHER_SERVICE_PORT,
    SILENT_AFTER_SECONDS,
    FlowState,
)
from app.domains.traffic_flow.ingest import reduce_window
from app.domains.traffic_flow.models import (
    RouterTrafficFlowExport,
    TrafficFlowServiceBucket,
    TrafficFlowWindow,
)
from app.domains.traffic_flow.service import (
    FleetRouter,
    RouterActivity,
    SummaryScope,
    TrafficFlowError,
    TrafficFlowStatusService,
    TrafficFlowSummaryService,
    flow_state,
    router_activity_statement,
    service_bucket_insert_statement,
    service_step_statement,
)
from app.domains.traffic_flow.summary import (
    ServiceStepRow,
    build_summary,
    service_name,
    step_start_of,
    timeline_step_seconds,
)

NOW = datetime(2026, 10, 12, 14, 10, tzinfo=UTC)
ROUTER_ID = uuid.UUID("8a199617-0000-4000-8000-000000000031")
OMADA_ID = uuid.UUID("22222222-0000-4000-8000-000000000002")
LOCATION_ID = uuid.UUID("33333333-0000-4000-8000-000000000003")
VERSIONS = pathlib.Path("alembic/versions")
OPS = pathlib.Path("ops")


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


def _settings(**over: Any) -> Any:
    base = {
        "traffic_flow_enabled": True,
        "traffic_flow_agent_url": "http://hub.invalid:9094",
        "traffic_flow_agent_secret": "s3cret",
    }
    return SimpleNamespace(**{**base, **over})


def _window(
    minutes_ago: int,
    *,
    up: int = 0,
    down: int = 0,
    talkers: list[dict[str, Any]] | None = None,
    destinations: list[dict[str, Any]] | None = None,
    measured: bool = True,
    router_id: uuid.UUID = ROUTER_ID,
    internal: int = 0,
    unclassified: int = 0,
    talker_count: int | None = None,
) -> Any:
    return SimpleNamespace(
        router_id=router_id,
        window_start=NOW - timedelta(minutes=minutes_ago),
        window_seconds=300,
        bytes_up=up,
        bytes_down=down,
        bytes_internal=internal,
        bytes_unclassified=unclassified,
        flows_total=1,
        services_measured=measured,
        talker_count=len(talkers or []) if talker_count is None else talker_count,
        destination_count=len(destinations or []),
        top_talkers=talkers or [],
        top_destinations=destinations or [],
    )


def _svc(
    minutes_ago: int, protocol: int, port: int, up: int, down: int
) -> ServiceStepRow:
    return ServiceStepRow(
        step_start=step_start_of(NOW - timedelta(minutes=minutes_ago), 300),
        protocol=protocol,
        remote_port=port,
        bytes_up=up,
        bytes_down=down,
        flows=1,
    )


def _build(windows: list[Any], rows: list[ServiceStepRow], **kw: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "windows": windows,
        "service_rows": rows,
        "since": NOW - timedelta(hours=1),
        "until": NOW,
        "window_seconds": 300,
        "step_seconds": 300,
        "limit": 10,
        "series": 8,
        "data_oldest": None,
        "data_newest": None,
    }
    args.update(kw)
    return build_summary(**args)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestFlowState:
    @pytest.mark.parametrize(
        ("enabled", "vendor", "configured", "age_seconds", "want"),
        [
            (False, "mikrotik", True, 60, FlowState.FEATURE_OFF),
            (True, "omada", False, None, FlowState.UNSUPPORTED_VENDOR),
            (True, "aruba_instant_on", True, 60, FlowState.UNSUPPORTED_VENDOR),
            (True, None, False, None, FlowState.UNSUPPORTED_VENDOR),
            (True, "mikrotik", False, None, FlowState.NOT_CONFIGURED),
            (True, "MikroTik", True, None, FlowState.AWAITING_FIRST_DATA),
            (True, "mikrotik", True, 60, FlowState.RECEIVING),
            (True, "mikrotik", True, SILENT_AFTER_SECONDS - 1, FlowState.RECEIVING),
            (True, "mikrotik", True, SILENT_AFTER_SECONDS, FlowState.SILENT),
            # Removed, but data is still held: the data decides.
            (True, "mikrotik", False, 60, FlowState.RECEIVING),
            (True, "mikrotik", False, 7200, FlowState.SILENT),
        ],
    )
    def test_states(self, enabled, vendor, configured, age_seconds, want) -> None:  # noqa: ANN001
        end = None if age_seconds is None else NOW - timedelta(seconds=age_seconds)
        assert (
            flow_state(
                feature_enabled=enabled,
                vendor=vendor,
                configured=configured,
                newest_window_end=end,
                now=NOW,
            )
            == want
        )


class StatusRepo:
    def __init__(self) -> None:
        self.routers: list[FleetRouter] = []
        self.activity: dict[uuid.UUID, RouterActivity] = {}
        self.recent_since: datetime | None = None
        self.state = SimpleNamespace(
            last_window_start=NOW - timedelta(minutes=10),
            last_pull_at=NOW - timedelta(minutes=4),
            last_pull_ok=True,
            last_error=None,
            unknown_exporters=["10.20.0.77"],
        )

    async def fleet_routers(self, router_id=None):  # noqa: ANN001
        return [r for r in self.routers if router_id in (None, r.router_id)]

    async def router_activity(self, recent_since):  # noqa: ANN001
        self.recent_since = recent_since
        return self.activity

    async def get_state(self):
        return self.state


def _fleet(router_id: uuid.UUID, vendor: str, export: Any = None) -> FleetRouter:
    return FleetRouter(
        router_id=router_id,
        router_name="Router",
        vendor=vendor,
        organization_id=None,
        organization_name="Example Org",
        location_id=LOCATION_ID,
        location_name="Main Hall",
        export=export,
    )


def _export(**over: Any) -> Any:
    base = {
        "enabled": True,
        "configured_at": NOW - timedelta(hours=4),
        "last_verified_at": NOW - timedelta(hours=4),
        "last_verdict_ok": True,
        "last_verdict_detail": "verified",
    }
    return SimpleNamespace(**{**base, **over})


class TestStatus:
    async def test_every_router_is_listed_with_an_honest_state(self) -> None:
        repo = StatusRepo()
        repo.routers = [
            _fleet(ROUTER_ID, "mikrotik", _export()),
            _fleet(OMADA_ID, "omada"),
        ]
        repo.activity = {
            ROUTER_ID: RouterActivity(
                newest_window_start=NOW - timedelta(minutes=10),
                newest_window_seconds=300,
                windows_recent=11,
                bytes_recent=4096,
            )
        }
        data = await TrafficFlowStatusService(
            repo, _settings(), now=lambda: NOW
        ).status()  # type: ignore[arg-type]
        assert data["feature_enabled"] is True
        assert repo.recent_since == NOW - timedelta(hours=1)
        mikrotik, omada = data["routers"]
        assert mikrotik["state"] == "receiving" and mikrotik["configured"] is True
        assert (
            mikrotik["last_window_start"] == (NOW - timedelta(minutes=10)).isoformat()
        )
        assert mikrotik["last_window_end"] == (NOW - timedelta(minutes=5)).isoformat()
        assert (mikrotik["windows_last_hour"], mikrotik["bytes_last_hour"]) == (
            11,
            4096,
        )
        assert (mikrotik["last_verdict_ok"], mikrotik["last_verdict_detail"]) == (
            True,
            "verified",
        )
        assert mikrotik["location_id"] == str(LOCATION_ID)
        assert omada["state"] == "unsupported_vendor" and omada["configured"] is False
        assert omada["last_window_start"] is None and omada["last_verdict_ok"] is None
        assert data["collector"]["unknown_exporters"] == ["10.20.0.77"]
        assert data["collector"]["agent_configured"] is True
        json.dumps(data)  # the whole response is plain JSON

    async def test_switched_on_with_nothing_received_is_awaiting_not_silent(
        self,
    ) -> None:
        repo = StatusRepo()
        repo.routers = [_fleet(ROUTER_ID, "mikrotik", _export())]
        data = await TrafficFlowStatusService(
            repo, _settings(), now=lambda: NOW
        ).status()  # type: ignore[arg-type]
        (row,) = data["routers"]
        assert row["state"] == "awaiting_first_data"
        assert row["windows_last_hour"] == 0 and row["last_window_end"] is None

    async def test_removed_router_is_not_configured(self) -> None:
        repo = StatusRepo()
        repo.routers = [_fleet(ROUTER_ID, "mikrotik", _export(enabled=False))]
        (row,) = (
            await TrafficFlowStatusService(repo, _settings(), now=lambda: NOW).status()  # type: ignore[arg-type]
        )["routers"]
        assert row["state"] == "not_configured" and row["configured"] is False
        assert row["last_verified_at"] is not None  # the removal's verdict is kept

    async def test_flag_off_marks_every_row_and_still_lists_them(self) -> None:
        repo = StatusRepo()
        repo.routers = [
            _fleet(ROUTER_ID, "mikrotik", _export()),
            _fleet(OMADA_ID, "omada"),
        ]
        data = await TrafficFlowStatusService(
            repo, _settings(traffic_flow_enabled=False), now=lambda: NOW
        ).status()  # type: ignore[arg-type]
        assert data["feature_enabled"] is False
        assert {r["state"] for r in data["routers"]} == {"feature_off"}

    async def test_unknown_router_has_no_status(self) -> None:
        service = TrafficFlowStatusService(StatusRepo(), _settings(), now=lambda: NOW)  # type: ignore[arg-type]
        assert await service.router_status(ROUTER_ID) is None


# ---------------------------------------------------------------------------
# summary: assembly
# ---------------------------------------------------------------------------


class TestSummaryAssembly:
    def test_no_windows_is_not_measured_and_has_no_totals(self) -> None:
        oldest = NOW - timedelta(days=2)
        data = _build([], [], data_oldest=oldest, data_newest=oldest)
        assert data["measured"] is False and data["totals"] is None
        assert data["timeline"]["steps"] == [] and data["protocols"] == []
        assert data["services"]["items"] == [] and data["devices"]["items"] == []
        # ...but it can still say where data starts.
        assert data["data_oldest"] == oldest.isoformat()

    def test_measured_zero_is_distinct_from_not_measured(self) -> None:
        data = _build([_window(10)], [])
        assert data["measured"] is True
        assert data["totals"]["bytes_up"] == 0 and data["totals"]["bytes_down"] == 0
        assert data["windows"] == 1 and len(data["timeline"]["steps"]) == 1
        assert data["timeline"]["steps"][0]["bytes_down"] == 0

    def test_totals_rates_and_exact_services(self) -> None:
        windows = [_window(10, up=100, down=900), _window(5, up=200, down=800)]
        rows = [
            _svc(10, 6, 443, 60, 840),
            _svc(10, 17, 53, 40, 60),
            _svc(5, 6, 443, 150, 750),
            _svc(5, 17, 443, 30, 20),
            _svc(5, 6, OTHER_SERVICE_PORT, 20, 30),
        ]
        data = _build(windows, rows)
        totals = data["totals"]
        assert (totals["bytes_up"], totals["bytes_down"]) == (300, 1700)
        assert totals["covered_seconds"] == 600
        assert totals["avg_bps_down"] == int(1700 * 8 / 600)
        services = data["services"]
        assert services["exact"] is True and data["services_measured"] is True
        assert [
            (i["protocol_name"], i["port"], i["bytes"]) for i in services["items"]
        ] == [
            ("tcp", 443, 1800),
            ("udp", 53, 100),
            ("udp", 443, 50),
        ]
        assert services["items"][0]["service_name"] == "https"
        assert services["items"][0]["share"] == 0.9
        assert services["items"][0]["avg_bps"] == int(1800 * 8 / 600)
        # The folded remainder is counted and reported, never listed.
        assert services["other_bytes"] == 50
        assert all(i["port"] != OTHER_SERVICE_PORT for i in services["items"])
        # Exact: listed services + other == all client traffic.
        assert (
            sum(i["bytes"] for i in services["items"]) + services["other_bytes"] == 2000
        )
        assert (
            abs(
                sum(i["share"] for i in services["items"]) + services["other_share"] - 1
            )
            < 1e-3
        )

    def test_protocol_breakdown_includes_the_folded_rows(self) -> None:
        rows = [
            _svc(10, 6, 443, 0, 600),
            _svc(10, 6, OTHER_SERVICE_PORT, 0, 100),
            _svc(10, 17, 53, 0, 200),
            _svc(10, 1, 0, 0, 60),
            _svc(10, 58, 0, 0, 20),
            _svc(10, 47, 0, 0, 20),
        ]
        data = _build([_window(10, down=1000)], rows)
        assert [(p["protocol_name"], p["bytes"]) for p in data["protocols"]] == [
            ("tcp", 700),
            ("udp", 200),
            ("icmp", 80),
            ("other", 20),
        ]
        assert [p["protocol"] for p in data["protocols"]] == [6, 17, 1, None]
        assert sum(p["bytes"] for p in data["protocols"]) == 1000
        assert data["timeline"]["steps"][0]["protocols"] == {
            "tcp": 700,
            "udp": 200,
            "icmp": 80,
            "other": 20,
        }

    def test_timeline_bands_add_up_and_a_missing_step_is_a_gap(self) -> None:
        windows = [_window(30, up=0, down=1000), _window(10, up=0, down=500)]
        rows = [
            _svc(30, 6, 443, 0, 700),
            _svc(30, 17, 443, 0, 200),
            _svc(30, 6, 80, 0, 100),
            _svc(10, 6, 443, 0, 500),
        ]
        data = _build(windows, rows, series=2)
        timeline = data["timeline"]
        assert [s["key"] for s in timeline["series"]] == ["6/443", "17/443"]
        first, second = timeline["steps"]
        # Two steps for two windows 20 minutes apart: the steps between them
        # are absent, not zero.
        assert len(timeline["steps"]) == 2
        assert first["services"] == {"6/443": 700, "17/443": 200}
        assert first["other_bytes"] == 100
        assert second["services"] == {"6/443": 500, "17/443": 0}
        for step in timeline["steps"]:
            assert (
                sum(step["services"].values()) + step["other_bytes"]
                == step["bytes_up"] + step["bytes_down"]
            )
        assert first["covered_seconds"] == 300
        assert first["bps_down"] == int(1000 * 8 / 300)

    def test_a_wider_step_reports_how_much_of_it_has_data(self) -> None:
        # 13:45 and 13:55 fall in the same 15-minute step; 13:50 is missing.
        windows = [_window(25, down=300), _window(15, down=300)]
        data = _build(windows, [], step_seconds=900)
        (step,) = data["timeline"]["steps"]
        assert step["covered_seconds"] == 600
        assert step["bps_down"] == int(600 * 8 / 600)

    def test_window_without_service_data_is_not_measured_not_empty(self) -> None:
        windows = [
            _window(10, down=1000, measured=True),
            _window(5, down=400, measured=False),
        ]
        data = _build(windows, [_svc(10, 6, 443, 0, 1000)])
        assert data["services_measured"] is False
        assert data["services"]["exact"] is False
        assert data["services"]["windows_measured"] == 1
        measured, unmeasured = data["timeline"]["steps"]
        assert measured["services_measured"] is True
        assert unmeasured["services_measured"] is False
        assert unmeasured["services"] == {} and unmeasured["protocols"] is None
        assert unmeasured["other_bytes"] == 400

    def test_devices_and_destinations_are_flagged_lower_bounds(self) -> None:
        sid = str(uuid.uuid4())
        talker = {
            "ip": "192.168.88.24",
            "bytes_up": 10,
            "bytes_down": 290,
            "flows": 3,
            "match": "session",
            "guest_session_id": sid,
        }
        dest = {
            "ip": "142.250.1.1",
            "bytes": 250,
            "bytes_up": 5,
            "bytes_down": 245,
            "flows": 2,
        }
        windows = [
            _window(10, up=20, down=480, talkers=[talker], destinations=[dest]),
            _window(5, up=20, down=480, talkers=[talker], destinations=[dest]),
        ]
        data = _build(windows, [])
        accuracy = data["list_accuracy"]
        assert accuracy == {
            "method": "sum_of_per_window_top_n",
            "per_window_top_n": 10,
            "lower_bound": True,
            "applies_to": ["devices", "destinations"],
        }
        (device,) = data["devices"]["items"]
        assert (device["bytes_up"], device["bytes_down"], device["bytes"]) == (
            20,
            580,
            600,
        )
        assert device["share_at_least"] == 0.6
        assert device["match"] == "session" and device["guest_session_id"] == sid
        assert device["router_id"] == str(ROUTER_ID)
        assert data["devices"]["other_bytes_at_most"] == 400
        (destination,) = data["destinations"]["items"]
        assert destination["bytes"] == 500 and destination["bytes_down"] == 490
        assert destination["share_at_least"] == 0.5
        assert data["destinations"]["other_bytes_at_most"] == 500

    def test_a_device_held_by_two_sessions_is_ambiguous(self) -> None:
        def talker(session: str | None, match: str) -> dict[str, Any]:
            return {
                "ip": "192.168.88.24",
                "bytes_up": 1,
                "bytes_down": 1,
                "flows": 1,
                "match": match,
                "guest_session_id": session,
            }

        windows = [
            _window(10, up=1, down=1, talkers=[talker(str(uuid.uuid4()), "session")]),
            _window(5, up=1, down=1, talkers=[talker(str(uuid.uuid4()), "session")]),
        ]
        (device,) = _build(windows, [])["devices"]["items"]
        assert device["match"] == "ambiguous" and device["guest_session_id"] is None

    def test_same_address_at_two_routers_is_two_devices(self) -> None:
        talker = {
            "ip": "192.168.88.24",
            "bytes_up": 1,
            "bytes_down": 1,
            "flows": 1,
            "match": "none",
            "guest_session_id": None,
        }
        windows = [
            _window(10, up=1, down=1, talkers=[talker]),
            _window(10, up=1, down=1, talkers=[talker], router_id=OMADA_ID),
        ]
        data = _build(windows, [])
        assert len(data["devices"]["items"]) == 2
        # Two routers, one window start: covered once, devices summed.
        assert data["totals"]["covered_seconds"] == 300
        assert data["totals"]["devices_peak"] == 2

    def test_internal_and_unclassified_are_reported_apart(self) -> None:
        data = _build([_window(10, up=10, down=10, internal=70, unclassified=30)], [])
        assert data["totals"]["bytes_internal"] == 70
        assert data["totals"]["bytes_unclassified"] == 30
        assert data["devices"]["other_bytes_at_most"] == 20  # client traffic only

    def test_limit_cuts_the_lists_and_the_rest_is_other(self) -> None:
        rows = [_svc(10, 6, port, 0, 100 - port) for port in range(1, 6)]
        data = _build(
            [_window(10, down=sum(100 - p for p in range(1, 6)))], rows, limit=2
        )
        assert [i["port"] for i in data["services"]["items"]] == [1, 2]
        assert data["services"]["other_bytes"] == 97 + 96 + 95

    def test_no_item_pairs_a_device_with_a_destination_or_a_service(self) -> None:
        """The privacy rule, as a property of the response: each list's items
        carry only their own kind of key."""
        w = reduce_window(
            [
                {
                    "peer_ip_src": "10.20.0.31",
                    "ip_src": "192.168.88.24",
                    "ip_dst": "142.250.1.1",
                    "bytes": 10,
                    "packets": 1,
                    "flows": 1,
                    "ip_proto": "tcp",
                    "port_src": 50000,
                    "port_dst": 443,
                }
            ]
        )["10.20.0.31"]
        talkers = [
            {
                "ip": ip,
                "bytes_up": t.bytes_up,
                "bytes_down": t.bytes_down,
                "flows": t.flows,
                "match": "none",
                "guest_session_id": None,
            }
            for ip, t in w.talkers.items()
        ]
        dests = [
            {
                "ip": ip,
                "bytes": v[0],
                "flows": v[1],
                "bytes_up": v[2],
                "bytes_down": v[3],
            }
            for ip, v in w.destinations.items()
        ]
        data = _build(
            [_window(10, up=10, talkers=talkers, destinations=dests)],
            [_svc(10, 6, 443, 10, 0)],
        )
        device_text = json.dumps(data["devices"])
        destination_text = json.dumps(data["destinations"])
        service_text = json.dumps(
            [data["services"], data["timeline"], data["protocols"]]
        )
        assert "142.250.1.1" not in device_text and "443" not in device_text
        assert "192.168.88.24" not in destination_text and "443" not in destination_text
        assert "192.168.88.24" not in service_text and "142.250.1.1" not in service_text
        assert set(data["services"]["items"][0]) == {
            "protocol",
            "protocol_name",
            "port",
            "service_name",
            "bytes_up",
            "bytes_down",
            "bytes",
            "flows",
            "share",
            "avg_bps",
        }

    def test_port_label_is_a_port_label(self) -> None:
        assert service_name(443) == "https" and service_name(53) == "domain"
        assert service_name(19305) is None

    @pytest.mark.parametrize(
        ("hours", "step"),
        [(1, 300), (6, 300), (6.5, 900), (24, 900), (25, 3600), (168, 3600)],
    )
    def test_step_widens_with_the_range(self, hours: float, step: int) -> None:
        assert timeline_step_seconds(hours * 3600) == step


# ---------------------------------------------------------------------------
# summary: service (range rules, flag, scope)
# ---------------------------------------------------------------------------


class SummaryRepo:
    def __init__(self, windows: list[Any] | None = None) -> None:
        self.windows = windows or []
        self.calls: list[tuple[str, Any]] = []

    async def data_bounds(self, scope):  # noqa: ANN001
        self.calls.append(("bounds", scope))
        starts = [w.window_start for w in self.windows]
        return (min(starts), max(starts)) if starts else (None, None)

    async def windows_in_range(self, scope, *, since, until):  # noqa: ANN001
        self.calls.append(("windows", (scope, since, until)))
        return [w for w in self.windows if since <= w.window_start < until]

    async def service_steps(self, scope, *, since, until, step_seconds):  # noqa: ANN001
        self.calls.append(("services", step_seconds))
        return []


def _summary(repo: SummaryRepo, **settings: Any) -> TrafficFlowSummaryService:
    return TrafficFlowSummaryService(repo, _settings(**settings), now=lambda: NOW)  # type: ignore[arg-type]


async def _ask(service: TrafficFlowSummaryService, **kw: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "router_id": ROUTER_ID,
        "location_id": None,
        "since": None,
        "until": None,
    }
    args.update(kw)
    return await service.summary(**args)


class TestSummaryService:
    async def test_default_range_is_the_last_hour(self) -> None:
        repo = SummaryRepo([_window(10, down=5)])
        data = await _ask(_summary(repo))
        assert data["since"] == (NOW - timedelta(hours=1)).isoformat()
        assert data["until"] == NOW.isoformat()
        assert data["measured"] is True and data["step_seconds"] == 300

    async def test_seven_days_is_allowed_and_more_is_refused_not_clamped(self) -> None:
        repo = SummaryRepo()
        data = await _ask(_summary(repo), since=NOW - timedelta(days=7), until=NOW)
        assert data["step_seconds"] == 3600
        repo = SummaryRepo()
        with pytest.raises(TrafficFlowError) as exc:
            await _ask(
                _summary(repo), since=NOW - timedelta(days=7, seconds=1), until=NOW
            )
        assert exc.value.code == "TRAFFIC_FLOW_WINDOW_TOO_LARGE"
        assert exc.value.status_code == 422
        assert repo.calls == []  # refused before any read

    async def test_inverted_range_is_refused(self) -> None:
        with pytest.raises(TrafficFlowError) as exc:
            await _ask(
                _summary(SummaryRepo()), since=NOW, until=NOW - timedelta(hours=1)
            )
        assert exc.value.code == "TRAFFIC_FLOW_BAD_RANGE"

    async def test_a_scope_is_required(self) -> None:
        with pytest.raises(TrafficFlowError) as exc:
            await _ask(_summary(SummaryRepo()), router_id=None, location_id=None)
        assert exc.value.code == "TRAFFIC_FLOW_SCOPE_REQUIRED"

    async def test_scope_reaches_the_repository(self) -> None:
        repo = SummaryRepo()
        await _ask(_summary(repo), router_id=None, location_id=LOCATION_ID)
        assert repo.calls[0] == ("bounds", SummaryScope(location_id=LOCATION_ID))

    async def test_empty_range_is_not_measured_but_knows_where_data_starts(
        self,
    ) -> None:
        repo = SummaryRepo([_window(60 * 30, down=5)])  # 30 hours ago
        data = await _ask(_summary(repo))
        assert data["measured"] is False and data["totals"] is None
        assert data["data_oldest"] == (NOW - timedelta(hours=30)).isoformat()
        assert ("services", 300) not in repo.calls  # nothing to sum

    async def test_flag_off_says_so_and_reads_nothing(self) -> None:
        repo = SummaryRepo([_window(10, down=5)])
        data = await _ask(_summary(repo, traffic_flow_enabled=False))
        assert data["feature_enabled"] is False and data["measured"] is False
        assert repo.calls == []

    async def test_naive_times_are_read_as_utc(self) -> None:
        data = await _ask(
            _summary(SummaryRepo()),
            since=datetime(2026, 10, 12, 13, 0),
            until=datetime(2026, 10, 12, 14, 0),
        )
        assert data["since"] == "2026-10-12T13:00:00+00:00"


# ---------------------------------------------------------------------------
# statements (compiled for PostgreSQL; NOT executed)
# ---------------------------------------------------------------------------


def _sql(statement: Any) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


class TestStatements:
    def test_service_steps_group_on_the_epoch_grid_within_the_scope(self) -> None:
        sql = _sql(
            service_step_statement(
                SummaryScope(router_id=ROUTER_ID, location_id=LOCATION_ID),
                since=NOW - timedelta(hours=1),
                until=NOW,
                step_seconds=900,
            )
        )
        assert "to_timestamp(floor(EXTRACT(epoch FROM" in sql
        assert "GROUP BY" in sql and "traffic_flow_service_buckets.remote_port" in sql
        assert "traffic_flow_service_buckets.router_id =" in sql
        assert "traffic_flow_service_buckets.location_id =" in sql
        assert "window_start >=" in sql and "window_start <" in sql

    def test_python_and_sql_use_the_same_step_grid(self) -> None:
        moment = datetime(2026, 10, 12, 13, 52, 30, tzinfo=UTC)
        assert step_start_of(moment, 900) == datetime(2026, 10, 12, 13, 45, tzinfo=UTC)
        assert step_start_of(moment, 3600) == datetime(2026, 10, 12, 13, 0, tzinfo=UTC)
        assert step_start_of(moment, 300) == datetime(2026, 10, 12, 13, 50, tzinfo=UTC)

    def test_service_bucket_insert_is_idempotent_on_the_unique_key(self) -> None:
        row = {
            "router_id": ROUTER_ID,
            "organization_id": None,
            "location_id": None,
            "source": "mikrotik_ipfix",
            "window_start": NOW,
            "window_seconds": 300,
            "protocol": 6,
            "remote_port": 443,
            "bytes_up": 1,
            "bytes_down": 2,
            "flows": 1,
        }
        sql = _sql(service_bucket_insert_statement([row, {**row, "remote_port": 80}]))
        assert "ON CONFLICT ON CONSTRAINT uq_traffic_flow_service_buckets_key" in sql
        assert "DO NOTHING" in sql

    def test_router_activity_counts_only_the_recent_windows(self) -> None:
        sql = _sql(router_activity_statement(NOW - timedelta(hours=1)))
        assert sql.count("FILTER (WHERE") == 2 and "GROUP BY" in sql

    def test_unique_keys_are_what_idempotency_relies_on(self) -> None:
        def unique(model: Any) -> set[tuple[str, ...]]:
            return {
                tuple(c.name for c in constraint.columns)
                for constraint in model.__table__.constraints
                if constraint.__class__.__name__ == "UniqueConstraint"
            }

        assert unique(TrafficFlowServiceBucket) == {
            ("router_id", "source", "window_start", "protocol", "remote_port")
        }
        assert unique(RouterTrafficFlowExport) == {("router_id",)}


# ---------------------------------------------------------------------------
# migration 0157 (static: no database server)
# ---------------------------------------------------------------------------


def _migration(filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(
        filename.removesuffix(".py"), VERSIONS / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(module: Any, monkeypatch: pytest.MonkeyPatch, fn: str) -> list[str]:
    statements: list[str] = []

    class _Op:
        def execute(self, sql: Any) -> None:
            statements.append(" ".join(str(sql).split()))

        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"op.{name} is not guarded; use op.execute")

    monkeypatch.setattr(module, "op", _Op())
    getattr(module, fn)()
    return statements


class TestSecondMigration:
    FILE = "0157_traffic_flow_services_export.py"

    def test_chain(self) -> None:
        module = _migration(self.FILE)
        assert module.down_revision == "0156_create_traffic_flow_tables"
        assert len(module.revision) <= 40

    def test_every_statement_is_a_no_op_when_already_applied(self, monkeypatch) -> None:
        statements = _run(_migration(self.FILE), monkeypatch, "upgrade")
        assert statements
        for statement in statements:
            assert "IF NOT EXISTS" in statement, statement
        for statement in _run(_migration(self.FILE), monkeypatch, "downgrade"):
            assert "IF EXISTS" in statement, statement

    def test_added_columns_and_tables_match_the_models(self, monkeypatch) -> None:
        text = "\n".join(_run(_migration(self.FILE), monkeypatch, "upgrade"))
        for column in ("bytes_up", "bytes_down", "services_measured"):
            assert f"ADD COLUMN IF NOT EXISTS {column} " in text
        for model in (TrafficFlowServiceBucket, RouterTrafficFlowExport):
            assert f"CREATE TABLE IF NOT EXISTS {model.__tablename__} " in text
            start = text.index(f"CREATE TABLE IF NOT EXISTS {model.__tablename__} ")
            body = text[start : text.index("CREATE", start + 10)]
            for column in model.__table__.columns:
                if column.name in {"packets_up", "packets_down"}:
                    continue  # added by 0161, see test_traffic_flow_destinations
                assert f" {column.name} " in body, (model.__tablename__, column.name)
        assert (
            "uq_traffic_flow_service_buckets_key UNIQUE "
            "(router_id, source, window_start, protocol, remote_port)" in text
        )
        # NOT NULL additions carry a default, or they fail on a table with rows.
        for line in text.splitlines():
            if "ADD COLUMN" in line and "NOT NULL" in line:
                assert "DEFAULT" in line, line

    def test_window_model_has_no_column_the_two_revisions_do_not_create(
        self, monkeypatch
    ) -> None:
        created = "\n".join(
            _run(
                _migration("0156_create_traffic_flow_tables.py"), monkeypatch, "upgrade"
            )
            + _run(_migration(self.FILE), monkeypatch, "upgrade")
        )
        for column in TrafficFlowWindow.__table__.columns:
            assert f" {column.name} " in created, column.name


# ---------------------------------------------------------------------------
# hub artifacts
# ---------------------------------------------------------------------------


class TestHubArtifacts:
    def _conf(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in (OPS / "netflow" / "nfacctd.conf").read_text().splitlines():
            if line.startswith("!") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            out[key.strip()] = value.strip()
        return out

    def test_collector_aggregates_on_protocol_and_both_ports(self) -> None:
        fields = [f.strip() for f in self._conf()["aggregate[wyfy]"].split(",")]
        # The rollup's KEYS are unchanged; "flows" is a counter, not a key.
        assert fields == [
            "peer_src_ip",
            "src_host",
            "dst_host",
            "proto",
            "src_port",
            "dst_port",
            "flows",
        ]

    def test_templates_survive_a_restart(self) -> None:
        conf = self._conf()
        path = conf["nfacctd_templates_file"]
        assert path.startswith("/var/lib/wyfy-nfacctd/")
        unit = (OPS / "hub-agents" / "systemd" / "wyfy-nfacctd.service").read_text()
        assert "StateDirectory=wyfy-nfacctd" in unit

    def test_agent_passes_protocol_and_ports_through_and_only_when_present(
        self, tmp_path: pathlib.Path
    ) -> None:
        spec = importlib.util.spec_from_file_location(
            "flow_agent_under_test", OPS / "hub-agents" / "flow_agent.py"
        )
        assert spec is not None and spec.loader is not None
        agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(agent)
        new = {
            "peer_ip_src": "10.20.0.31",
            "ip_src": "192.168.88.24",
            "ip_dst": "142.250.1.1",
            "ip_proto": "tcp",
            "port_src": 50000,
            "port_dst": 443,
            "bytes": 10,
            "packets": 1,
            "flows": 1,
            "stamp_inserted": "ignored",
        }
        old = {
            k: v
            for k, v in new.items()
            if k not in ("ip_proto", "port_src", "port_dst")
        }
        path = tmp_path / "20261012-1400.json"
        path.write_text(json.dumps(new) + "\n" + json.dumps(old) + "\n")
        first, second = agent.read_rows(str(path))
        assert (first["ip_proto"], first["port_src"], first["port_dst"]) == (
            "tcp",
            50000,
            443,
        )
        assert "stamp_inserted" not in first
        assert not {"ip_proto", "port_src", "port_dst"} & set(second)
        # ...and the app reads exactly these keys.
        window = reduce_window([first])["10.20.0.31"]
        assert window.services == {(6, 443): [10, 0, 1]}
