"""NetFlow/IPFIX MVP (``app.domains.traffic_flow``).

Pins, in order:

* **Ingest** -- local/remote split by which side is private (not by flow
  direction), internal and unclassified bytes counted not dropped, top-N
  with the remainder kept, attribution never guesses.
* **Privacy shape** -- a stored window holds no talker x destination pair.
* **Parity** -- the generator's lines parse back to exactly the writer's
  desired rows; the block is structurally balanced; the target add is
  guarded; v6 gets a comment, not a guess.
* **Gates** -- flag, allowlist, vendor, tunnel, on both config paths.
* **Overview states** -- disabled / not_allowlisted / collector_unreachable
  / no_windows / stale / ok, never an unexplained empty table.
* **Device service** -- dry run writes nothing, refusals surface their code,
  a real apply audits and reports read-back.
* **Pull sweep** -- failure is recorded, cursor advances, re-pull is a no-op.
* **Authorization** -- every route pinned GLOBAL on ``traffic_flows.*``; the
  module is GLOBAL-only and held by Super Admin / Platform Admin only.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import Settings
from app.domains.network_config.renderers import render_network_config
from app.domains.rbac.enums import PermissionModule, ScopeType
from app.domains.rbac.seed import MODULE_NARROWEST_SCOPE, SYSTEM_ROLES
from app.domains.traffic_flow.constants import (
    OTHER_SERVICE_PORT,
    ROUTEROS_CACHE_ENTRIES,
    TRAFFIC_FLOW_SECTION_HEADER,
    TRAFFIC_FLOW_TARGET_MARKER,
    FlowState,
    RouterFlowState,
    TalkerMatch,
)
from app.domains.traffic_flow.ingest import (
    attribute_talkers,
    is_local_address,
    parse_protocol,
    reduce_window,
    service_rows,
    top_destinations,
    top_talkers,
)
from app.domains.traffic_flow.routeros import (
    TrafficFlowTarget,
    desired_config,
    render_removal_lines,
    render_traffic_flow_lines,
    traffic_flow_lines_for_router,
)
from app.domains.traffic_flow.service import (
    ExporterRouter,
    FleetRouter,
    RouterActivity,
    TrafficFlowDeviceService,
    TrafficFlowError,
    TrafficFlowIngestService,
    TrafficFlowOverviewService,
)
from app.domains.traffic_flow.tasks import pull_once

ROUTER_ID = uuid.UUID("8a199617-0000-4000-8000-000000000031")
OTHER_ROUTER = uuid.UUID("11111111-0000-4000-8000-000000000001")
NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
TARGET = TrafficFlowTarget(
    collector_address="10.20.0.1", collector_port=2055, source_address="10.20.0.31"
)


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "traffic_flow_enabled": True,
        "traffic_flow_agent_url": "http://hub.invalid:9094",
        "traffic_flow_agent_secret": "s3cret",
    }
    base.update(overrides)
    return Settings(**base)


def _row(
    src: str,
    dst: str,
    nbytes: int,
    *,
    exporter: str = "10.20.0.31",
    flows: int = 1,
    proto: Any = None,
    sport: int | None = None,
    dport: int | None = None,
):
    row = {
        "peer_ip_src": exporter,
        "ip_src": src,
        "ip_dst": dst,
        "bytes": nbytes,
        "packets": 1,
        "flows": flows,
    }
    # Absent unless given: the pre-service collector sends no such keys.
    if proto is not None:
        row["ip_proto"] = proto
    if sport is not None:
        row["port_src"] = sport
    if dport is not None:
        row["port_dst"] = dport
    return row


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    """INFO on, as in CI: a logger ``extra`` key that collides with a
    LogRecord attribute only raises when the record is actually built."""
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


class TestIngest:
    def test_local_side_decides_talker_regardless_of_direction(self) -> None:
        windows = reduce_window(
            [
                _row("192.168.95.10", "142.250.1.1", 100),  # upload
                _row("142.250.1.1", "192.168.95.10", 900),  # download
            ]
        )
        w = windows["10.20.0.31"]
        assert w.talkers["192.168.95.10"].bytes_up == 100
        assert w.talkers["192.168.95.10"].bytes_down == 900
        assert w.destinations["142.250.1.1"] == [1000, 2, 100, 900]
        assert (w.bytes_up, w.bytes_down) == (100, 900)

    def test_internal_and_unclassified_are_counted_not_ranked(self) -> None:
        w = reduce_window(
            [
                _row("192.168.95.10", "192.168.95.1", 50),  # guest -> router DNS
                _row("10.20.0.31", "10.20.0.1", 70),  # export over the tunnel
                _row("8.8.8.8", "1.1.1.1", 5),  # should not happen behind NAT
            ]
        )["10.20.0.31"]
        assert w.bytes_internal == 120
        assert w.bytes_unclassified == 5
        assert w.bytes_total == 125
        assert w.destinations == {}

    def test_cgnat_counts_as_local(self) -> None:
        assert is_local_address("100.64.3.2") is True
        assert is_local_address("142.250.1.1") is False
        assert is_local_address("not-an-ip") is None

    def test_unparseable_row_is_rejected_and_counted(self) -> None:
        w = reduce_window([_row("garbage", "1.1.1.1", 10)])["10.20.0.31"]
        assert w.rows_rejected == 1 and w.bytes_total == 0

    def test_top_n_keeps_the_remainder(self) -> None:
        rows = [_row(f"192.168.95.{i}", "1.1.1.1", i * 10) for i in range(1, 15)]
        w = reduce_window(rows)["10.20.0.31"]
        entries, rest = top_talkers(w, {}, limit=10)
        assert len(entries) == 10
        assert entries[0]["ip"] == "192.168.95.14"
        assert rest == sum(i * 10 for i in range(1, 5))
        dests, dest_rest = top_destinations(w, limit=10)
        assert dests[0]["bytes"] == sum(i * 10 for i in range(1, 15)) and dest_rest == 0

    def test_attribution_never_guesses(self) -> None:
        a, b = uuid.uuid4(), uuid.uuid4()
        got = attribute_talkers(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            {"10.0.0.1": [a], "10.0.0.2": [a, b]},
        )
        assert got["10.0.0.1"] == (TalkerMatch.SESSION, a)
        assert got["10.0.0.2"] == (TalkerMatch.AMBIGUOUS, None)
        assert got["10.0.0.3"] == (TalkerMatch.NONE, None)

    def test_service_is_the_remote_port_whatever_the_direction(self) -> None:
        w = reduce_window(
            [
                # upload: the remote end is the destination, port 443
                _row(
                    "192.168.95.10",
                    "142.250.1.1",
                    100,
                    proto="tcp",
                    sport=51544,
                    dport=443,
                ),
                # download of the same conversation: the remote end is the source
                _row(
                    "142.250.1.1", "192.168.95.10", 900, proto=6, sport=443, dport=51544
                ),
                _row(
                    "192.168.95.11", "8.8.8.8", 50, proto="udp", sport=40000, dport=53
                ),
            ]
        )["10.20.0.31"]
        assert w.services == {(6, 443): [100, 900, 2], (17, 53): [50, 0, 1]}
        assert w.services_measured is True
        assert service_rows(w) == [
            {
                "protocol": 6,
                "remote_port": 443,
                "bytes_up": 100,
                "bytes_down": 900,
                "flows": 2,
            },
            {
                "protocol": 17,
                "remote_port": 53,
                "bytes_up": 50,
                "bytes_down": 0,
                "flows": 1,
            },
        ]

    @pytest.mark.parametrize(
        ("value", "want"),
        [
            ("tcp", 6),
            ("UDP", 17),
            ("icmp", 1),
            ("ipv6-icmp", 58),
            (47, 47),
            ("6", 6),
            ("made-up", None),
            (None, None),
            (True, None),
            (300, None),
            ("", None),
        ],
    )
    def test_protocol_is_parsed_or_refused_never_guessed(self, value, want) -> None:  # noqa: ANN001
        assert parse_protocol(value) == want

    def test_rest_is_folded_into_one_other_row_per_protocol(self) -> None:
        rows = [
            _row(
                "192.168.95.10",
                "142.250.1.1",
                1000 - port,
                proto="tcp",
                sport=50000,
                dport=port,
            )
            for port in range(1, 8)
        ] + [
            _row(
                "192.168.95.10", "1.1.1.1", 5, proto="udp", sport=50000, dport=9000 + i
            )
            for i in range(3)
        ]
        w = reduce_window(rows)["10.20.0.31"]
        out = service_rows(w, limit=4)
        listed = [r for r in out if r["remote_port"] != OTHER_SERVICE_PORT]
        other = {
            r["protocol"]: r for r in out if r["remote_port"] == OTHER_SERVICE_PORT
        }
        assert [r["remote_port"] for r in listed] == [1, 2, 3, 4]
        assert set(other) == {6, 17}
        assert other[6]["bytes_up"] == sum(1000 - p for p in (5, 6, 7))
        assert other[17]["bytes_up"] == 15 and other[17]["flows"] == 3
        # Nothing is dropped: the rows sum to the window's client traffic,
        # which is what makes sums over the table exact.
        assert (
            sum(r["bytes_up"] + r["bytes_down"] for r in out)
            == w.bytes_up + w.bytes_down
        )

    def test_rows_without_ports_are_not_measured_not_zero(self) -> None:
        old = reduce_window([_row("192.168.95.10", "142.250.1.1", 100)])["10.20.0.31"]
        assert old.services_measured is False and service_rows(old) == []
        # One row without them is enough: a partial list would read as whole.
        mixed = reduce_window(
            [
                _row(
                    "192.168.95.10", "142.250.1.1", 100, proto="tcp", sport=5, dport=443
                ),
                _row("192.168.95.10", "142.250.1.2", 100),
            ]
        )["10.20.0.31"]
        assert mixed.services_measured is False and service_rows(mixed) == []
        assert (mixed.bytes_up, mixed.bytes_down) == (200, 0)  # totals still counted

    def test_internal_and_unclassified_rows_are_in_no_service(self) -> None:
        w = reduce_window(
            [
                _row(
                    "192.168.95.10", "192.168.95.1", 70, proto="udp", sport=5, dport=53
                ),
                _row("1.1.1.1", "8.8.8.8", 30, proto="tcp", sport=5, dport=443),
            ]
        )["10.20.0.31"]
        assert w.services == {} and w.services_measured is True
        assert (w.bytes_internal, w.bytes_unclassified) == (70, 30)
        assert (w.bytes_up, w.bytes_down) == (0, 0)

    def test_a_service_row_carries_no_address(self) -> None:
        w = reduce_window(
            [_row("192.168.95.10", "142.250.1.1", 100, proto="tcp", sport=5, dport=443)]
        )["10.20.0.31"]
        (row,) = service_rows(w)
        assert set(row) == {
            "protocol",
            "remote_port",
            "bytes_up",
            "bytes_down",
            "flows",
        }
        from app.domains.traffic_flow.models import TrafficFlowServiceBucket

        columns = {c.name for c in TrafficFlowServiceBucket.__table__.columns}
        assert not any("ip" in name.split("_") or "address" in name for name in columns)

    def test_stored_window_never_pairs_a_talker_with_a_destination(self) -> None:
        w = reduce_window([_row("192.168.95.10", "142.250.1.1", 100)])["10.20.0.31"]
        talkers, _ = top_talkers(w, {})
        dests, _ = top_destinations(w)
        assert set(talkers[0]) == {
            "ip",
            "bytes_up",
            "bytes_down",
            "flows",
            "match",
            "guest_session_id",
        }
        assert set(dests[0]) == {"ip", "bytes", "bytes_up", "bytes_down", "flows"}


# ---------------------------------------------------------------------------
# parity between the generator and the device writer
# ---------------------------------------------------------------------------


def _kv(text: str) -> dict[str, str]:
    return dict(re.findall(r'([a-z0-9-]+)=("[^"]*"|\S+)', text))


class TestParity:
    def test_rendered_lines_equal_the_writer_desired_rows(self) -> None:
        config = desired_config(TARGET)
        lines = render_traffic_flow_lines(config, routeros_version="7.16.2 (stable)")
        assert lines[0] == TRAFFIC_FLOW_SECTION_HEADER
        settings_line = next(x for x in lines if x.startswith("/ip traffic-flow set "))
        ipfix_line = next(
            x for x in lines if x.startswith("/ip traffic-flow ipfix set ")
        )
        target_set = next(
            x for x in lines if x.startswith("/ip traffic-flow target set ")
        )
        assert _kv(settings_line.removeprefix("/ip traffic-flow set ")) == dict(
            config.settings
        )
        assert _kv(ipfix_line.removeprefix("/ip traffic-flow ipfix set ")) == dict(
            config.ipfix
        )
        target_fields = _kv(target_set.split("]", 1)[1])
        assert target_fields == dict(config.target or {})

    def test_cache_entries_is_the_one_constant(self) -> None:
        config = desired_config(TARGET)
        assert config.settings["cache-entries"] == ROUTEROS_CACHE_ENTRIES == "16k"
        lines = render_traffic_flow_lines(config, routeros_version="7.16.2")
        assert any("cache-entries=16k" in line for line in lines)

    def test_removal_script_is_the_writers_removal(self) -> None:
        """The paste removal and the 8728 removal come from one description:
        plan the writer's removal against a router that holds our export and
        compare, write for write, in order."""
        from wyfy_device_gateway.mikrotik_traffic_flow import (
            TrafficFlowState,
            plan_traffic_flow,
        )

        from app.domains.traffic_flow.routeros import disabled_config

        state = TrafficFlowState(
            routeros_version="7.16.2",
            settings={"enabled": "yes"},
            ipfix={},
            targets=({".id": "*1", "comment": TRAFFIC_FLOW_TARGET_MARKER},),
            foreign_targets=0,
        )
        plan = plan_traffic_flow(state, disabled_config())
        assert [(op, path) for op, path, _fields in plan] == [
            ("set", ("ip", "traffic-flow")),
            ("remove", ("ip", "traffic-flow", "target")),
        ]
        script = render_removal_lines()
        assert script == [
            "/ip traffic-flow set enabled=no",
            "/ip traffic-flow target remove "
            f'[find where comment="{TRAFFIC_FLOW_TARGET_MARKER}"]',
        ]
        assert plan[0][2] == {"enabled": "no"}
        text = "\n".join(script)
        assert text.count("[") == text.count("]") and text.count('"') % 2 == 0

    def test_target_add_is_guarded_and_duplicates_are_collapsed(self) -> None:
        lines = render_traffic_flow_lines(
            desired_config(TARGET), routeros_version="7.15"
        )
        add = next(x for x in lines if "target add" in x)
        assert add.startswith(":if ([:len [/ip traffic-flow target find where comment=")
        assert f'comment="{TRAFFIC_FLOW_TARGET_MARKER}"' in add
        assert any("target remove [:pick" in x for x in lines)
        # target in place before export is switched on (same order as the writer)
        assert lines.index(add) < next(
            i for i, x in enumerate(lines) if x.startswith("/ip traffic-flow set ")
        )

    def test_block_is_structurally_balanced(self) -> None:
        for line in render_traffic_flow_lines(
            desired_config(TARGET), routeros_version="7.15"
        ):
            assert line.count("{") == line.count("}"), line
            assert line.count("[") == line.count("]"), line
            assert line.count('"') % 2 == 0, line

    @pytest.mark.parametrize("version", ["6.49.10", None, "garbage"])
    def test_non_v7_gets_a_comment_not_a_guess(self, version: str | None) -> None:
        lines = render_traffic_flow_lines(
            desired_config(TARGET), routeros_version=version
        )
        assert all(x.startswith("#") for x in lines)
        assert "RouterOS 7 required" in lines[1]

    def test_render_network_config_carries_its_own_wrapped_block(self) -> None:
        lines = render_traffic_flow_lines(
            desired_config(TARGET), routeros_version="7.15"
        )
        script = render_network_config(
            dhcp_pools=[], vlans=[], port_forwarding_rules=[], traffic_flow_lines=lines
        )
        assert TRAFFIC_FLOW_SECTION_HEADER in script
        assert ":do { /ip traffic-flow set enabled=yes" in script
        assert (
            render_network_config(
                dhcp_pools=[],
                vlans=[],
                port_forwarding_rules=[],
                traffic_flow_lines=None,
            )
            == ""
        )


class TestGeneratorGate:
    peer = SimpleNamespace(tunnel_ip_address="10.20.0.31")
    server = SimpleNamespace(tunnel_network_cidr="10.20.0.0/24")

    def _lines(self, settings: Settings, **kw: Any) -> list[str] | None:
        args: dict[str, Any] = {
            "export_enabled": True,
            "vendor": "mikrotik",
            "routeros_version": "7.15",
            "peer": self.peer,
            "server": self.server,
        }
        args["settings"] = kw.pop("settings_override", settings)
        args.update(kw)
        return traffic_flow_lines_for_router(**args)

    def test_on_when_every_gate_passes(self) -> None:
        lines = self._lines(_settings())
        assert lines and "dst-address=10.20.0.1" in "\n".join(lines)
        assert "src-address=10.20.0.31" in "\n".join(lines)

    @pytest.mark.parametrize(
        "kw",
        [
            {"settings": "flag_off"},
            {"export_enabled": False},
            {"vendor": "omada"},
            {"peer": None},
        ],
    )
    def test_off_when_any_gate_fails(self, kw: dict[str, Any]) -> None:
        kw = dict(kw)
        if kw.pop("settings", None) == "flag_off":
            kw["settings_override"] = _settings(traffic_flow_enabled=False)
        assert self._lines(_settings(), **kw) is None

    @pytest.mark.parametrize(
        ("lookup_answer", "expect_lines"),
        [(True, True), (False, False), (None, False)],
    )
    async def test_generator_asks_the_per_router_switch(
        self,
        monkeypatch: pytest.MonkeyPatch,
        lookup_answer: bool | None,
        expect_lines: bool,
    ) -> None:
        """``render_network_config`` gets a traffic-flow section only for a
        router whose switch is on. No lookup wired means "not switched on"."""
        from app.core import config as core_config
        from app.domains.network_config.service import NetworkConfigService

        monkeypatch.setattr(core_config, "get_settings", lambda: _settings())
        asked: list[uuid.UUID] = []

        class Lookup:
            async def export_enabled(self, router_id: uuid.UUID) -> bool:
                asked.append(router_id)
                return bool(lookup_answer)

        class Routers:
            async def get_router(self, router_id, **kw):  # noqa: ANN001, ANN003
                return SimpleNamespace(vendor="mikrotik", routeros_version="7.16.2")

        service = NetworkConfigService(
            *([None] * 6),  # type: ignore[arg-type]
            dns_lookup=None,  # type: ignore[arg-type]
            firewall_lookup=None,  # type: ignore[arg-type]
            router_lookup=Routers(),  # type: ignore[arg-type]
            traffic_flow_export_lookup=None if lookup_answer is None else Lookup(),
        )
        lines = await service._gather_traffic_flow_lines(  # noqa: SLF001
            ROUTER_ID, self.peer, self.server, requesting_organization_id=None
        )
        assert bool(lines) is expect_lines
        assert asked == ([] if lookup_answer is None else [ROUTER_ID])

    def test_defaults_are_off(self) -> None:
        defaults = Settings()
        assert defaults.traffic_flow_enabled is False
        # The environment allowlist is gone: the per-router switch is a
        # database row, and it defaults to "no row".
        assert not hasattr(defaults, "traffic_flow_router_ids")


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class FakeRepo:
    def __init__(self) -> None:
        self.windows: list[Any] = []
        self.inserted: list[dict[str, Any]] = []
        self.keys: set[tuple[Any, ...]] = set()
        self.state = SimpleNamespace(
            last_window_start=None,
            last_pull_at=None,
            last_pull_ok=None,
            last_error=None,
            unknown_exporters=[],
        )
        self.exporters = {
            "10.20.0.31": ExporterRouter(
                router_id=ROUTER_ID, organization_id=None, location_id=None
            )
        }
        self.sessions: dict[str, list[uuid.UUID]] = {}
        self.peer: Any = SimpleNamespace(tunnel_ip_address="10.20.0.31", server_id=1)
        self.server: Any = SimpleNamespace(tunnel_network_cidr="10.20.0.0/24")
        self.pruned_before: datetime | None = None
        self.service_rows: list[dict[str, Any]] = []
        self.service_pruned_before: datetime | None = None
        self.destination_rows: list[dict[str, Any]] = []
        self.destination_pruned_before: datetime | None = None
        self.export: Any = None
        self.saved_exports: list[Any] = []
        self.fleet_vendor = "mikrotik"

    async def insert_service_buckets(self, rows):  # noqa: ANN001
        self.service_rows.extend(dict(r) for r in rows)

    async def insert_destination_buckets(self, rows):  # noqa: ANN001
        self.destination_rows.extend(dict(r) for r in rows)

    async def delete_destination_buckets_before(self, cutoff, *, limit):  # noqa: ANN001
        self.destination_pruned_before = cutoff
        return 0

    async def delete_service_buckets_before(self, cutoff, *, limit):  # noqa: ANN001
        self.service_pruned_before = cutoff
        return 0

    async def get_export(self, router_id):  # noqa: ANN001
        return self.export

    async def save_export(self, row):  # noqa: ANN001
        self.export = row
        self.saved_exports.append(row)
        return row

    async def export_enabled(self, router_id):  # noqa: ANN001
        return bool(self.export is not None and self.export.enabled)

    async def enabled_export_router_ids(self):
        if self.export is not None and self.export.enabled:
            return {ROUTER_ID}
        return set()

    async def fleet_routers(self, router_id=None):  # noqa: ANN001
        return [
            FleetRouter(
                router_id=ROUTER_ID,
                router_name="Lab hEX",
                vendor=self.fleet_vendor,
                organization_id=None,
                organization_name="Example Org",
                location_id=None,
                location_name="Lab",
                export=self.export,
            )
        ]

    async def router_activity(self, recent_since):  # noqa: ANN001
        mine = [w for w in self.windows if w.router_id == ROUTER_ID]
        if not mine:
            return {}
        newest = max(w.window_start for w in mine)
        recent = [w for w in mine if w.window_start >= recent_since]
        return {
            ROUTER_ID: RouterActivity(
                newest_window_start=newest,
                newest_window_seconds=300,
                windows_recent=len(recent),
                bytes_recent=sum(w.bytes_up + w.bytes_down for w in recent),
            )
        }

    async def exporter_router_map(self):
        return self.exporters

    async def sessions_by_ip(self, router_id, ips, *, start, end):  # noqa: ANN001
        return {ip: self.sessions[ip] for ip in ips if ip in self.sessions}

    async def insert_window(self, values):  # noqa: ANN001
        key = (values["router_id"], values["source"], values["window_start"])
        if key in self.keys:
            return False
        self.keys.add(key)
        self.inserted.append(dict(values))
        self.windows.append(SimpleNamespace(**values))
        return True

    async def get_state(self):
        return self.state

    async def windows_since(self, since):  # noqa: ANN001
        return [w for w in self.windows if w.window_start >= since]

    async def router_labels(self, ids):  # noqa: ANN001
        return {
            i: {
                "router_name": "Lab hEX",
                "vendor": "mikrotik",
                "location_name": "Lab",
                "organization_name": "Wyfy",
            }
            for i in ids
        }

    async def peer_and_server(self, router_id):  # noqa: ANN001
        return self.peer, self.server

    async def delete_windows_before(self, cutoff, *, limit):  # noqa: ANN001
        self.pruned_before = cutoff
        return 0


# ---------------------------------------------------------------------------
# ingest service + overview
# ---------------------------------------------------------------------------


class TestIngestAndOverview:
    async def _ingest(self, repo: FakeRepo, start: datetime, rows: list[dict]) -> Any:
        return await TrafficFlowIngestService(repo).ingest_window(  # type: ignore[arg-type]
            window_start=start, window_seconds=300, rows=rows
        )

    async def test_ingest_attributes_and_is_idempotent(self) -> None:
        repo = FakeRepo()
        sid = uuid.uuid4()
        repo.sessions = {"192.168.95.10": [sid]}
        start = NOW - timedelta(minutes=10)
        rows = [
            _row("192.168.95.10", "142.250.1.1", 500),
            _row("10.9.9.9", "1.1.1.1", 1, exporter="10.20.0.99"),
        ]
        first = await self._ingest(repo, start, rows)
        assert first.written == 1 and first.unknown_exporters == ("10.20.0.99",)
        talker = repo.inserted[0]["top_talkers"][0]
        assert talker["match"] == "session" and talker["guest_session_id"] == str(sid)
        again = await self._ingest(repo, start, rows)
        assert again.written == 0 and again.duplicates == 1

    async def test_service_buckets_are_written_once_with_the_window(self) -> None:
        repo = FakeRepo()
        start = NOW - timedelta(minutes=10)
        rows = [
            _row("192.168.95.10", "142.250.1.1", 100, proto="tcp", sport=5, dport=443),
            _row("142.250.1.1", "192.168.95.10", 900, proto="tcp", sport=443, dport=5),
        ]
        await self._ingest(repo, start, rows)
        window = repo.inserted[0]
        assert (window["bytes_up"], window["bytes_down"]) == (100, 900)
        assert window["services_measured"] is True
        assert repo.service_rows == [
            {
                "router_id": ROUTER_ID,
                "organization_id": None,
                "location_id": None,
                "source": "mikrotik_ipfix",
                "window_start": start,
                "window_seconds": 300,
                "protocol": 6,
                "remote_port": 443,
                "bytes_up": 100,
                "bytes_down": 900,
                "flows": 2,
            }
        ]
        # A re-pulled window adds nothing: not a second window, not a second
        # set of service rows.
        await self._ingest(repo, start, rows)
        assert len(repo.inserted) == 1 and len(repo.service_rows) == 1

    async def test_window_without_ports_stores_no_service_rows(self) -> None:
        repo = FakeRepo()
        await self._ingest(
            repo, NOW - timedelta(minutes=10), [_row("192.168.95.10", "1.1.1.1", 9)]
        )
        assert repo.inserted[0]["services_measured"] is False
        assert repo.service_rows == []

    async def test_overview_ok_and_merged(self) -> None:
        repo = FakeRepo()
        for minutes in (10, 15):
            await self._ingest(
                repo,
                NOW - timedelta(minutes=minutes),
                [_row("192.168.95.10", "142.250.1.1", 100)],
            )
        repo.state.last_pull_ok = True
        repo.export = SimpleNamespace(enabled=True)
        data = await TrafficFlowOverviewService(
            repo, _settings(), now=lambda: NOW
        ).overview(minutes=60)  # type: ignore[arg-type]
        (router,) = data["routers"]
        assert router["state"] == RouterFlowState.OK.value
        assert router["windows"] == 2 and router["approximate"] is True
        assert router["talkers"][0]["bytes_up"] == 200
        assert router["destinations"][0] == {
            "ip": "142.250.1.1",
            "bytes": 200,
            "flows": 2,
        }
        assert router["allowlisted"] is True  # the per-router switch

    @pytest.mark.parametrize(
        ("settings_kw", "switched_on", "pull_ok", "age_min", "want"),
        [
            ({"traffic_flow_enabled": False}, True, True, 5, RouterFlowState.DISABLED),
            ({}, False, True, 5, RouterFlowState.NOT_ALLOWLISTED),
            ({}, True, False, 5, RouterFlowState.COLLECTOR_UNREACHABLE),
            ({}, True, True, None, RouterFlowState.NO_WINDOWS),
            ({}, True, True, 40, RouterFlowState.STALE),
        ],
    )
    async def test_overview_states(
        self,
        settings_kw,
        switched_on,
        pull_ok,
        age_min,
        want,  # noqa: ANN001
    ) -> None:
        repo = FakeRepo()
        repo.export = SimpleNamespace(enabled=switched_on)
        if age_min is not None:
            await self._ingest(
                repo,
                NOW - timedelta(minutes=age_min),
                [_row("192.168.95.10", "1.1.1.1", 1)],
            )
        repo.state.last_pull_ok = pull_ok
        data = await TrafficFlowOverviewService(
            repo,
            _settings(**settings_kw),
            now=lambda: NOW,  # type: ignore[arg-type]
        ).overview(minutes=60)
        states = {r["router_id"]: r["state"] for r in data["routers"]}
        assert states[str(ROUTER_ID)] == want.value


# ---------------------------------------------------------------------------
# pull sweep
# ---------------------------------------------------------------------------


class TestPull:
    async def _commit(self) -> None:
        return None

    async def test_failure_is_recorded_not_swallowed(self) -> None:
        repo = FakeRepo()

        async def boom(after: int):
            raise ConnectionError("agent down")

        result = await pull_once(
            repository=repo,
            settings=_settings(),  # type: ignore[arg-type]
            fetch_windows=boom,
            commit=self._commit,
            now=lambda: NOW,
        )
        assert result["ok"] is False
        assert (
            repo.state.last_pull_ok is False and "agent down" in repo.state.last_error
        )

    async def test_cursor_advances_and_repull_is_noop(self) -> None:
        repo = FakeRepo()
        start = int((NOW - timedelta(minutes=10)).timestamp())
        asked: list[int] = []

        async def fetch(after: int):
            asked.append(after)
            return {
                "windows": [
                    {
                        "window_start": start,
                        "window_seconds": 300,
                        "rows": [_row("192.168.95.10", "1.1.1.1", 9)],
                    }
                ]
            }

        first = await pull_once(
            repository=repo,
            settings=_settings(),  # type: ignore[arg-type]
            fetch_windows=fetch,
            commit=self._commit,
            now=lambda: NOW,
        )
        assert first["written"] == 1
        assert repo.state.last_window_start == datetime.fromtimestamp(start, tz=UTC)
        assert repo.pruned_before == NOW - timedelta(days=7)
        # Service buckets age out on the same cutoff as their windows.
        assert repo.service_pruned_before == NOW - timedelta(days=7)
        second = await pull_once(
            repository=repo,
            settings=_settings(),  # type: ignore[arg-type]
            fetch_windows=fetch,
            commit=self._commit,
            now=lambda: NOW,
        )
        assert asked[1] == start and second["windows"] == 0

    @pytest.mark.parametrize(
        ("kw", "skip"),
        [
            ({"traffic_flow_enabled": False}, "disabled"),
            ({"traffic_flow_agent_url": ""}, "agent_not_configured"),
        ],
    )
    async def test_gated_off_makes_no_call(self, kw, skip) -> None:  # noqa: ANN001
        async def never(after: int):
            raise AssertionError("must not be called")

        result = await pull_once(
            repository=FakeRepo(),
            settings=_settings(**kw),  # type: ignore[arg-type]
            fetch_windows=never,
            commit=self._commit,
        )
        assert result == {"skipped": skip}


# ---------------------------------------------------------------------------
# device service
# ---------------------------------------------------------------------------


class FakeAdapter:
    def __init__(
        self,
        *,
        refuse: bool = False,
        mismatches: tuple[str, ...] = (),
        unreachable: bool = False,
    ) -> None:
        self.applied: list[Any] = []
        self.refuse = refuse
        self.mismatches = mismatches
        self.unreachable = unreachable
        self.state = SimpleNamespace(
            routeros_version="7.16.2",
            settings={"enabled": "no"},
            ipfix={},
            targets=(),
            foreign_targets=0,
        )

    async def read_traffic_flow(self, creds, *, marker):  # noqa: ANN001
        return self.state

    async def apply_traffic_flow(self, creds, config):  # noqa: ANN001
        from wyfy_device_gateway.mikrotik_traffic_flow import (
            TRAFFIC_FLOW_V7_REQUIRED,
            TrafficFlowRefusal,
        )

        if self.refuse:
            raise TrafficFlowRefusal(TRAFFIC_FLOW_V7_REQUIRED, "RouterOS 7 required")
        if self.unreachable:
            from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError

            raise MikroTikDeviceError("10.20.0.31", "timed out")
        self.applied.append(config)
        return SimpleNamespace(
            writes=("add /ip/traffic-flow/target ...",),
            matches=not self.mismatches,
            mismatches=self.mismatches,
            before=self.state,
            after=self.state,
        )


class FakeRouters:
    def __init__(self, **kw: Any) -> None:
        self.router = SimpleNamespace(
            id=ROUTER_ID,
            vendor="mikrotik",
            routeros_version="7.16.2",
            management_ip_address="10.20.0.31",
            public_ip_address=None,
            api_username="wyfy",
            organization_id=None,
        )
        for k, v in kw.items():
            setattr(self.router, k, v)

    async def get_router(self, router_id):  # noqa: ANN001
        return self.router

    def get_decrypted_api_secret(self, router):  # noqa: ANN001
        return "pw"


class FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def create_audit_log_entry(self, **kw: Any) -> None:
        self.entries.append(kw)


def _device(
    settings: Settings | None = None,
    adapter: FakeAdapter | None = None,
    routers: FakeRouters | None = None,
    audit: FakeAudit | None = None,
):
    adapter = adapter or FakeAdapter()
    return TrafficFlowDeviceService(
        FakeRepo(),  # type: ignore[arg-type]
        routers or FakeRouters(),
        settings or _settings(),
        adapter_factory=lambda: adapter,
        credentials_factory=lambda router, secret: ("creds", secret),
        audit_writer=audit,
        now=lambda: NOW,
    ), adapter


class TestDeviceService:
    async def test_preview_renders_from_the_shared_source(self) -> None:
        service, _ = _device()
        data = await service.preview(ROUTER_ID)
        assert data["eligible"] is True and data["blockers"] == []
        assert data["blocker_codes"] == []
        assert data["lines"] == render_traffic_flow_lines(
            desired_config(TARGET), routeros_version="7.16.2"
        )
        assert data["paste_script"] == data["lines"]
        assert data["removal_script"] == render_removal_lines()
        assert data["desired"] == {
            "target_host": "10.20.0.1",
            "target_port": 2055,
            "src_address": "10.20.0.31",
            "version": "ipfix",
        }
        assert data["status"]["state"] == FlowState.NOT_CONFIGURED.value

    async def test_dry_run_is_the_default_shape_and_writes_nothing(self) -> None:
        service, adapter = _device()
        data = await service.apply(
            ROUTER_ID, enabled=True, dry_run=True, actor_user_id=None
        )
        assert data["dry_run"] is True and adapter.applied == []
        assert any("add /ip/traffic-flow/target" in w for w in data["planned_writes"])

    @pytest.mark.parametrize(
        ("settings", "router_kw", "needle"),
        [
            ({"traffic_flow_enabled": False}, {}, "ENABLED is off"),
            ({}, {"vendor": "omada"}, "MikroTik only"),
            ({}, {"routeros_version": "6.49.10"}, "RouterOS 7 required"),
        ],
    )
    async def test_blocked_routers_are_refused_before_any_device_call(
        self,
        settings,
        router_kw,
        needle,  # noqa: ANN001
    ) -> None:
        service, adapter = _device(
            _settings(**settings), routers=FakeRouters(**router_kw)
        )
        with pytest.raises(TrafficFlowError) as exc:
            await service.apply(
                ROUTER_ID, enabled=True, dry_run=False, actor_user_id=None
            )
        assert needle in exc.value.message and adapter.applied == []

    async def test_remove_needs_no_tunnel_and_clears_the_switch(self) -> None:
        service, adapter = _device()
        repo = service.repository
        await service.apply(ROUTER_ID, enabled=True, dry_run=False, actor_user_id=None)
        assert repo.export.enabled is True
        repo.peer = repo.server = None  # the tunnel has since gone
        data = await service.remove(ROUTER_ID, actor_user_id=None)
        assert data["ok"] is True and data["enabled"] is False
        assert adapter.applied[-1].target is None
        assert repo.export.enabled is False
        assert data["state"] == FlowState.NOT_CONFIGURED.value

    async def test_real_apply_records_the_switch_and_the_verdict(self) -> None:
        service, _ = _device()
        actor = uuid.uuid4()
        data = await service.apply(
            ROUTER_ID, enabled=True, dry_run=False, actor_user_id=actor
        )
        row = service.repository.export
        assert row.enabled is True and row.last_verdict_ok is True
        assert row.last_verdict_detail == "verified"
        assert (row.target_host, row.target_port, row.src_address) == (
            "10.20.0.1",
            2055,
            "10.20.0.31",
        )
        assert row.export_version == "ipfix"
        assert row.configured_at == NOW and row.last_verified_at == NOW
        assert row.created_by == actor
        assert (data["ok"], data["detail"]) == (True, "verified")
        # Applied is not "receiving": nothing has arrived yet.
        assert data["state"] == FlowState.AWAITING_FIRST_DATA.value

    async def test_read_back_mismatch_is_recorded_as_not_ok(self) -> None:
        adapter = FakeAdapter(mismatches=("settings.cache-entries: want 16k, got 4k",))
        service, _ = _device(adapter=adapter)
        data = await service.apply(
            ROUTER_ID, enabled=True, dry_run=False, actor_user_id=None
        )
        row = service.repository.export
        assert data["ok"] is False and data["matches"] is False
        assert "cache-entries" in data["detail"]
        assert row.last_verdict_ok is False
        assert row.last_verdict_detail == data["detail"]
        # The switch is on -- the router WAS written -- but it is not verified.
        assert row.enabled is True

    async def test_dry_run_and_device_failure_record_nothing(self) -> None:
        service, _ = _device()
        await service.apply(ROUTER_ID, enabled=True, dry_run=True, actor_user_id=None)
        assert service.repository.saved_exports == []
        service, _ = _device(adapter=FakeAdapter(unreachable=True))
        with pytest.raises(TrafficFlowError) as exc:
            await service.apply(
                ROUTER_ID, enabled=True, dry_run=False, actor_user_id=None
            )
        assert exc.value.code == "TRAFFIC_FLOW_DEVICE_ERROR"
        assert service.repository.saved_exports == []

    async def test_preview_names_blockers_by_code(self) -> None:
        routers = FakeRouters(vendor="omada")
        service, _ = _device(_settings(traffic_flow_enabled=False), routers=routers)
        service.repository.fleet_vendor = "omada"
        data = await service.preview(ROUTER_ID)
        assert data["eligible"] is False
        assert data["blocker_codes"] == ["FEATURE_OFF", "UNSUPPORTED_VENDOR"]
        assert data["paste_script"] == [] and data["removal_script"] == []
        assert data["desired"] is None

    async def test_preview_without_credentials_still_offers_the_script(self) -> None:
        service, _ = _device(routers=FakeRouters(api_username=None))
        data = await service.preview(ROUTER_ID)
        assert data["blocker_codes"] == ["NO_API_CREDENTIALS"]
        assert data["paste_script"] and data["removal_script"]

    async def test_device_refusal_surfaces_its_code(self) -> None:
        service, _ = _device(adapter=FakeAdapter(refuse=True))
        with pytest.raises(TrafficFlowError) as exc:
            await service.apply(
                ROUTER_ID, enabled=True, dry_run=False, actor_user_id=None
            )
        assert exc.value.code == "TRAFFIC_FLOW_V7_REQUIRED"

    async def test_real_apply_audits_and_reports_read_back(self) -> None:
        audit = FakeAudit()
        service, _ = _device(audit=audit)
        actor = uuid.uuid4()
        data = await service.apply(
            ROUTER_ID, enabled=True, dry_run=False, actor_user_id=actor
        )
        assert data["matches"] is True
        assert audit.entries[0]["action"] == "traffic_flow_applied"
        assert audit.entries[0]["actor_user_id"] == actor


# ---------------------------------------------------------------------------
# authorization
# ---------------------------------------------------------------------------


def _pins(router, path_suffix: str, method: str) -> dict:  # noqa: ANN001
    route = next(
        r for r in router.routes if r.path.endswith(path_suffix) and method in r.methods
    )
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


class TestAuthorization:
    @pytest.mark.parametrize(
        ("suffix", "method", "perm"),
        [
            ("/overview", "GET", "traffic_flows.read"),
            ("/status", "GET", "traffic_flows.read"),
            ("/summary", "GET", "traffic_flows.read"),
            ("/routers/{router_id}/config", "GET", "traffic_flows.read"),
            ("/routers/{router_id}/apply", "POST", "traffic_flows.update"),
            ("/routers/{router_id}/remove", "POST", "traffic_flows.update"),
        ],
    )
    def test_every_route_pinned_global(
        self, suffix: str, method: str, perm: str
    ) -> None:
        from app.domains.traffic_flow.router import traffic_flow_platform_router

        pin = _pins(traffic_flow_platform_router, suffix, method)
        assert pin[ScopeType] == ScopeType.GLOBAL and pin[str] == perm

    def test_no_route_exists_outside_the_pinned_set(self) -> None:
        from app.domains.traffic_flow.router import traffic_flow_platform_router

        assert len(traffic_flow_platform_router.routes) == 6
        for route in traffic_flow_platform_router.routes:
            (method,) = route.methods
            assert (
                _pins(traffic_flow_platform_router, route.path, method)[ScopeType]
                == ScopeType.GLOBAL
            )

    def test_routes_are_mounted_under_platform(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        assert "/platform/traffic-flow/overview" in paths
        # Outside /platform there are exactly the read-only customer routes
        # (the venue view's two and the Destinations three, all behind the
        # add-on and venue_traffic.read) and nothing else: no Master route is
        # reachable without the GLOBAL pin.
        assert {
            p for p in paths if "traffic-flow" in p and not p.startswith("/platform/")
        } == {
            "/traffic-flow/locations/{location_id}/status",
            "/traffic-flow/locations/{location_id}/summary",
            "/traffic-flow/locations/{location_id}/destinations",
            "/traffic-flow/locations/{location_id}/destinations/export",
            "/traffic-flow/locations/{location_id}/services/destinations",
        }

    def test_module_is_global_only(self) -> None:
        assert (
            MODULE_NARROWEST_SCOPE[PermissionModule.TRAFFIC_FLOWS] == ScopeType.GLOBAL
        )

    def test_only_super_admin_and_platform_admin_hold_it(self) -> None:
        holders = {
            role.slug
            for role in SYSTEM_ROLES
            if role.grants().get(PermissionModule.TRAFFIC_FLOWS)
        }
        assert holders == {"super-admin", "platform-admin"}
