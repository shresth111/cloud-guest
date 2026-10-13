"""Hub side of the flow table: the collector's second print plugin, the
agent that forwards its rows as ``flow_rows``, and the check script that
keeps the two in step.

The app is live while this is deployed, and the hub may get the new agent
before or after the app learns ``flow_rows``. So the tests that matter most
here are the ones about what does NOT change: the rollup rows, the three
keys an older app reads, and a spool written by the older collector config.

Static and file-based only: no daemon is started, no socket opened.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
from typing import Any

import pytest

OPS = pathlib.Path("ops")
CONF = OPS / "netflow" / "nfacctd.conf"
UNIT = OPS / "hub-agents" / "systemd" / "wyfy-nfacctd.service"
AGENT = OPS / "hub-agents" / "flow_agent.py"

#: 2026-10-12 14:00 UTC, the window every test spools.
W = 1_791_813_600
STAMP = "20261012-1400"
#: Late enough that window W and the one after it are complete.
NOW = W + 2 * 300 + 400

EXPORTER = "10.20.0.31"  # a tunnel address, as in the other fixtures
GUEST = "192.168.88.24"
WAN = "198.51.100.7"  # documentation range
# Outside ends must be addresses the app's reducer treats as public, which
# rules out the documentation ranges; these are well-known public resolvers.
REMOTE = "8.8.8.8"
GUEST6 = "2001:db8:1::24"
REMOTE6 = "2001:4860:4860::8888"


def _load(path: pathlib.Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def agent(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    module = _load(AGENT, "flow_agent_flow_rows_test")
    monkeypatch.setattr(module, "SPOOL_DIR", str(tmp_path))
    return module


@pytest.fixture(scope="module")
def check() -> Any:
    return _load(OPS / "netflow" / "check_nfacctd_memory.py", "check_flow_rows_test")


@pytest.fixture(scope="module")
def conf(check: Any) -> dict[str, str]:
    return check.parse_config(CONF.read_text())


# -- realistic collector lines ----------------------------------------------
# Shapes follow pmacct 1.7.7's print plugin JSON for the two aggregates in
# nfacctd.conf, with timestamps_since_epoch on. They are written from the
# documentation and the source, NOT copied from a live spool.

ROLLUP_UP = {
    "event_type": "purge",
    "peer_ip_src": EXPORTER,
    "ip_src": GUEST,
    "ip_dst": REMOTE,
    "port_src": 51544,
    "port_dst": 443,
    "ip_proto": "tcp",
    "stamp_inserted": "1791813600",
    "stamp_updated": "1791813901",
    "packets": 61,
    "flows": 2,
    "bytes": 48213,
}
FLOW_V4_UP = {
    "event_type": "purge",
    "peer_ip_src": EXPORTER,
    "ip_src": GUEST,
    "ip_dst": REMOTE,
    "port_src": 51544,
    "port_dst": 443,
    "ip_proto": "tcp",
    "post_nat_ip_src": WAN,
    "post_nat_ip_dst": REMOTE,
    "post_nat_port_src": 40112,
    "post_nat_port_dst": 443,
    "timestamp_start": "1791813611.120000",
    "timestamp_end": "1791813669.480000",
    "timestamp_arrival": "1791813671.002113",
    "stamp_inserted": "1791813600",
    "stamp_updated": "1791813901",
    "packets": 40,
    "flows": 1,
    "bytes": 30100,
}
FLOW_V4_DOWN = {
    **FLOW_V4_UP,
    "ip_src": REMOTE,
    "ip_dst": GUEST,
    "port_src": 443,
    "port_dst": 51544,
    "post_nat_ip_src": REMOTE,
    "post_nat_ip_dst": GUEST,
    "post_nat_port_src": 443,
    "post_nat_port_dst": 51544,
    "packets": 310,
    "bytes": 402_000,
}
#: IPv6: the routers' IPv6 template has no NAT elements, so pmacct prints
#: zero addresses and ports for them.
FLOW_V6 = {
    "event_type": "purge",
    "peer_ip_src": EXPORTER,
    "ip_src": GUEST6,
    "ip_dst": REMOTE6,
    "port_src": 55001,
    "port_dst": 443,
    "ip_proto": "udp",
    "post_nat_ip_src": "::",
    "post_nat_ip_dst": "::",
    "post_nat_port_src": 0,
    "post_nat_port_dst": 0,
    "timestamp_start": "1791813700.000000",
    "timestamp_end": "1791813712.250000",
    "timestamp_arrival": "1791813731.500000",
    "stamp_inserted": "1791813600",
    "stamp_updated": "1791813901",
    "packets": 12,
    "flows": 1,
    "bytes": 9000,
}
#: A row with no timestamps at all (a collector build or config without
#: them): the keys are simply not there.
FLOW_NO_TIMES = {
    key: value for key, value in FLOW_V4_UP.items() if not key.startswith("timestamp_")
} | {"ip_dst": "1.1.1.1", "bytes": 700, "packets": 3}


def _spool(
    directory: pathlib.Path, name: str, rows: list[dict], *, age: int = 600
) -> None:
    path = directory / name
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    mtime = NOW - age
    os.utime(path, (mtime, mtime))


def _old(directory: pathlib.Path) -> None:
    """Age every spooled file, so a test can ask "what is served at an
    earlier moment" without the files looking freshly written."""
    for path in directory.iterdir():
        os.utime(path, (W - 3600, W - 3600))


def _both(
    directory: pathlib.Path, stamp: str = STAMP, flows: list[dict] | None = None
) -> None:
    _spool(directory, f"{stamp}.json", [ROLLUP_UP])
    _spool(
        directory,
        f"records-{stamp}.json",
        [FLOW_V4_UP, FLOW_V4_DOWN, FLOW_V6, FLOW_NO_TIMES] if flows is None else flows,
    )


# ---------------------------------------------------------------------------
# the agent: parsing and forwarding
# ---------------------------------------------------------------------------


class TestFlowRows:
    def test_ipv4_row_with_nat_is_forwarded_as_printed(self, agent, tmp_path) -> None:
        _both(tmp_path)
        (window,) = agent.complete_windows(0, 12, NOW)
        assert window["flow_rows_total"] == 4
        assert window["flow_rows_truncated"] is False
        up = next(r for r in window["flow_rows"] if r["bytes"] == 30100)
        assert up == {
            "peer_ip_src": EXPORTER,
            "ip_src": GUEST,
            "ip_dst": REMOTE,
            "ip_proto": "tcp",
            "port_src": 51544,
            "port_dst": 443,
            "post_nat_ip_src": WAN,
            "post_nat_ip_dst": REMOTE,
            "post_nat_port_src": 40112,
            "post_nat_port_dst": 443,
            "timestamp_start": "1791813611.120000",
            "timestamp_end": "1791813669.480000",
            "timestamp_arrival": "1791813671.002113",
            "bytes": 30100,
            "packets": 40,
            "flows": 1,
        }
        # Exactly the documented keys: no bookkeeping key rides along.
        assert tuple(up) == agent.FLOW_ROW_KEYS
        assert "stamp_inserted" not in up and "event_type" not in up

    def test_each_direction_is_its_own_row(self, agent, tmp_path) -> None:
        _both(tmp_path)
        (window,) = agent.complete_windows(0, 12, NOW)
        pair = [
            r
            for r in window["flow_rows"]
            if {r["ip_src"], r["ip_dst"]} == {GUEST, REMOTE}
        ]
        assert sorted((r["ip_src"], r["bytes"]) for r in pair) == [
            (GUEST, 30100),
            (REMOTE, 402_000),
        ]

    def test_ipv6_row_keeps_the_zero_nat_fields_the_collector_printed(
        self, agent, tmp_path
    ) -> None:
        """The agent does not interpret: pmacct prints a zero address for a
        NAT field the router did not send, and the app's ingest is what
        stores that as "not recorded"."""
        _both(tmp_path)
        (window,) = agent.complete_windows(0, 12, NOW)
        v6 = next(r for r in window["flow_rows"] if r["ip_src"] == GUEST6)
        assert v6["ip_dst"] == REMOTE6 and v6["ip_proto"] == "udp"
        assert (v6["post_nat_ip_src"], v6["post_nat_port_src"]) == ("::", 0)
        assert v6["timestamp_start"] == "1791813700.000000"

    def test_row_missing_timestamps_has_no_timestamp_keys(
        self, agent, tmp_path
    ) -> None:
        _both(tmp_path)
        (window,) = agent.complete_windows(0, 12, NOW)
        bare = next(r for r in window["flow_rows"] if r["bytes"] == 700)
        assert not [key for key in bare if key.startswith("timestamp_")]
        # Absent, not null and not zero: the app reads absence as "not
        # recorded" and must never see a fabricated time.
        assert "timestamp_start" not in bare
        assert bare["post_nat_ip_src"] == WAN and bare["packets"] == 3

    def test_malformed_and_non_object_lines_are_skipped(self, agent, tmp_path) -> None:
        _spool(tmp_path, f"{STAMP}.json", [ROLLUP_UP])
        path = tmp_path / f"records-{STAMP}.json"
        path.write_text(
            json.dumps(FLOW_V4_UP)
            + "\n{not json\n\n[1, 2]\n"
            + json.dumps(FLOW_V6)
            + "\n"
        )
        os.utime(path, (NOW - 600, NOW - 600))
        (window,) = agent.complete_windows(0, 12, NOW)
        assert window["flow_rows_total"] == 2

    def test_a_window_written_in_parts_is_all_served(self, agent, tmp_path) -> None:
        """A full cache purges early and appends: one window, several
        writes, one file. Every line is a row."""
        _both(tmp_path, flows=[FLOW_V4_UP] * 3 + [FLOW_V4_DOWN] * 2)
        (window,) = agent.complete_windows(0, 12, NOW)
        assert window["flow_rows_total"] == 5 and len(window["flow_rows"]) == 5

    def test_what_the_agent_sends_is_what_the_ingest_reads(
        self, agent, tmp_path
    ) -> None:
        """The app-side reducer on ``origin/main`` reads the rollup keys;
        the flow-record ingest (a separate change) reads these spellings.
        Pinned here so a rename on either side fails a test."""
        from app.domains.traffic_flow.ingest import reduce_window

        _both(tmp_path)
        (window,) = agent.complete_windows(0, 12, NOW)
        reduced = reduce_window(window["rows"])[EXPORTER]
        assert reduced.services == {(6, 443): [48213, 0, 2]}
        assert reduced.packets_measured is True
        expected_by_ingest = {
            "peer_ip_src",
            "ip_src",
            "ip_dst",
            "port_src",
            "port_dst",
            "ip_proto",
            "post_nat_ip_src",
            "post_nat_ip_dst",
            "post_nat_port_src",
            "post_nat_port_dst",
            "timestamp_start",
            "timestamp_end",
            "timestamp_arrival",
            "bytes",
            "packets",
            "flows",
        }
        assert set(agent.FLOW_ROW_KEYS) == expected_by_ingest
        # Per-flow rows are reducible too: an app may use them for nothing
        # else, but they are the same traffic.
        again = reduce_window(window["flow_rows"])[EXPORTER]
        assert again.rows_rejected == 0


class TestLimits:
    def test_per_window_cap_keeps_the_largest_and_says_so(
        self, agent, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setattr(agent, "FLOW_ROWS_PER_WINDOW", 2)
        rows = [{**FLOW_V4_UP, "bytes": size} for size in (10, 5000, 300, 9000, 40)]
        _both(tmp_path, flows=rows)
        (window,) = agent.complete_windows(0, 12, NOW)
        assert [r["bytes"] for r in window["flow_rows"]] == [9000, 5000]
        assert window["flow_rows_total"] == 5
        assert window["flow_rows_truncated"] is True
        # The rollup of the same window is untouched by the cap.
        assert len(window["rows"]) == 1

    def test_a_response_stops_adding_windows_at_its_row_budget(
        self, agent, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setattr(agent, "FLOW_ROWS_PER_RESPONSE", 4)
        for stamp in ("20261012-1400", "20261012-1405"):
            _both(tmp_path, stamp=stamp)
        windows = agent.complete_windows(0, 12, NOW)
        assert [w["window_start"] for w in windows] == [W]
        # The next pull, from the cursor, gets the next window: none skipped.
        windows = agent.complete_windows(W, 12, NOW)
        assert [w["window_start"] for w in windows] == [W + 300]

    def test_defaults_bound_one_response(self, agent) -> None:
        assert agent.FLOW_ROWS_PER_WINDOW == 20_000
        assert agent.FLOW_ROWS_PER_RESPONSE == 60_000
        # At about 300 bytes a row, a worst response is tens of MB, not GB.
        worst = agent.FLOW_ROWS_PER_RESPONSE + agent.FLOW_ROWS_PER_WINDOW
        assert worst * 300 < 30_000_000


# ---------------------------------------------------------------------------
# compatibility, both directions
# ---------------------------------------------------------------------------


class TestCompatibility:
    def test_rollup_rows_are_what_they_were(self, agent, tmp_path) -> None:
        _both(tmp_path)
        (window,) = agent.complete_windows(0, 12, NOW)
        assert window["window_start"] == W and window["window_seconds"] == 300
        assert window["rows"] == [
            {
                "peer_ip_src": EXPORTER,
                "ip_src": GUEST,
                "ip_dst": REMOTE,
                "ip_proto": "tcp",
                "port_src": 51544,
                "port_dst": 443,
                "bytes": 48213,
                "packets": 61,
                "flows": 2,
            }
        ]
        assert tuple(window["rows"][0]) == agent.ROLLUP_KEYS

    def test_an_app_that_reads_three_keys_sees_no_difference(
        self, agent, tmp_path
    ) -> None:
        """New agent, old app: the app takes window_start, window_seconds
        and rows, and ignores whatever else is there."""
        _spool(tmp_path, f"{STAMP}.json", [ROLLUP_UP])
        (before,) = agent.complete_windows(0, 12, NOW)
        _spool(tmp_path, f"records-{STAMP}.json", [FLOW_V4_UP])
        (after,) = agent.complete_windows(0, 12, NOW)
        old_app_reads = ("window_start", "window_seconds", "rows")
        assert {k: before[k] for k in old_app_reads} == {
            k: after[k] for k in old_app_reads
        }
        assert set(before) == set(old_app_reads)

    def test_old_collector_config_gives_no_flow_rows_key(self, agent, tmp_path) -> None:
        """New agent, old collector: no records-*.json exists. The key is
        absent, so the app falls back to the rollup rows as it does today;
        an empty list would claim there were no flows."""
        _spool(tmp_path, f"{STAMP}.json", [ROLLUP_UP])
        (window,) = agent.complete_windows(0, 12, NOW)
        assert "flow_rows" not in window and "flow_rows_total" not in window

    def test_old_collector_rows_without_ports_or_flows_still_serve(
        self, agent, tmp_path
    ) -> None:
        old = {
            k: v
            for k, v in ROLLUP_UP.items()
            if k not in {"port_src", "port_dst", "ip_proto", "flows"}
        }
        _spool(tmp_path, f"{STAMP}.json", [old])
        (window,) = agent.complete_windows(0, 12, NOW)
        assert window["rows"] == [
            {
                "peer_ip_src": EXPORTER,
                "ip_src": GUEST,
                "ip_dst": REMOTE,
                "bytes": 48213,
                "packets": 61,
                "flows": 0,
            }
        ]

    def test_an_empty_flow_file_is_an_empty_list_not_a_missing_key(
        self, agent, tmp_path
    ) -> None:
        _both(tmp_path, flows=[])
        (window,) = agent.complete_windows(0, 12, NOW)
        assert window["flow_rows"] == [] and window["flow_rows_total"] == 0

    def test_a_flow_file_is_never_mistaken_for_a_rollup_file(self, agent) -> None:
        assert agent.window_start_of(f"{STAMP}.json") == W
        assert agent.window_start_of(f"records-{STAMP}.json") is None
        assert agent.flow_window_start_of(f"records-{STAMP}.json") == W
        assert agent.flow_window_start_of(f"{STAMP}.json") is None
        for junk in (
            "records-.json",
            "records-20261012.json",
            "x-records-20261012-1400.json",
        ):
            assert agent.window_start_of(junk) is None
            assert agent.flow_window_start_of(junk) is None


class TestCompleteness:
    def test_a_flow_file_still_being_written_holds_the_window_back(
        self, agent, tmp_path
    ) -> None:
        _spool(tmp_path, f"{STAMP}.json", [ROLLUP_UP])
        _spool(tmp_path, f"records-{STAMP}.json", [FLOW_V4_UP], age=1)
        assert agent.complete_windows(0, 12, NOW) == []
        # ...and a later window is not served past it: the app's cursor
        # would then skip this one for good.
        _both(tmp_path, stamp="20261012-1405")
        assert agent.complete_windows(0, 12, NOW) == []

    def test_a_late_flow_file_is_waited_for_then_given_up_on(
        self, agent, tmp_path
    ) -> None:
        # The collector writes per-flow files (an earlier window has one)...
        _both(tmp_path, stamp="20261012-1355")
        # ...but this window's has not appeared yet.
        _spool(tmp_path, f"{STAMP}.json", [ROLLUP_UP])
        _old(tmp_path)
        just_complete = W + 300 + agent.GRACE_SECONDS + 5
        starts = [
            w["window_start"] for w in agent.complete_windows(0, 12, just_complete)
        ]
        assert starts == [W - 300]
        later = just_complete + agent.FLOW_FILE_EXTRA_GRACE_SECONDS
        windows = agent.complete_windows(0, 12, later)
        assert [w["window_start"] for w in windows] == [W - 300, W]
        assert "flow_rows" not in windows[1]

    def test_the_current_window_is_never_served(self, agent, tmp_path) -> None:
        _both(tmp_path)
        _old(tmp_path)
        assert agent.complete_windows(0, 12, W + 200) == []
        assert len(agent.complete_windows(0, 12, W + 300 + agent.GRACE_SECONDS)) == 1


class TestSpool:
    def test_both_kinds_of_file_are_pruned_after_two_hours(
        self, agent, tmp_path
    ) -> None:
        assert agent.SPOOL_HOURS == 2 and agent.WINDOW_SECONDS == 300
        _both(tmp_path, stamp="20261012-1400")
        _both(tmp_path, stamp="20261012-1600")
        (tmp_path / "notes.txt").write_text("not ours")
        agent.prune(W + 2 * 3600 + 301)
        assert sorted(p.name for p in tmp_path.iterdir()) == [
            "20261012-1600.json",
            "notes.txt",
            "records-20261012-1600.json",
        ]

    def test_health_counts_both(self, agent, tmp_path) -> None:
        _both(tmp_path)
        _spool(tmp_path, "20261012-1405.json", [ROLLUP_UP])
        assert len(agent.spooled()) == 2 and len(agent.spooled_flows()) == 1


# ---------------------------------------------------------------------------
# the collector config and the check script
# ---------------------------------------------------------------------------


class TestCollectorConfig:
    def test_two_plugins_and_the_rollup_keys_are_unchanged(self, check, conf) -> None:
        assert check.plugin_names(conf) == ["wyfy", "wyfyflows"]
        assert check.aggregate_of(conf, "wyfy")[:6] == [
            "peer_src_ip",
            "src_host",
            "dst_host",
            "proto",
            "src_port",
            "dst_port",
        ]
        # No timestamp or NAT primitive on the rollup: its rows keep merging.
        assert not check.NAT_OR_TIMESTAMP_PRIMITIVES & set(
            check.aggregate_of(conf, "wyfy")
        )
        assert (
            conf["print_output_file[wyfy]"] == "/var/spool/wyfy-flows/%Y%m%d-%H%M.json"
        )
        assert conf["print_cache_entries[wyfy]"] == "16411"

    def test_flows_is_in_both_aggregates(self, check, conf) -> None:
        """pmacct writes the "flows" key only when the word is in the
        aggregate; without it every row's flow count was 0."""
        for plugin in ("wyfy", "wyfyflows"):
            assert "flows" in check.aggregate_of(conf, plugin), plugin

    def test_flow_plugin_carries_nat_and_all_three_timestamps(
        self, check, conf
    ) -> None:
        aggregate = set(check.aggregate_of(conf, "wyfyflows"))
        assert aggregate >= check.NAT_OR_TIMESTAMP_PRIMITIVES
        assert conf["print_output_file_append[wyfyflows]"] == "true"
        assert conf["print_refresh_time[wyfyflows]"] == "300"
        assert conf["print_history[wyfyflows]"] == "5m"
        assert conf["timestamps_since_epoch"] == "true"

    def test_memory_arithmetic_matches_the_comment(self, check, conf) -> None:
        report = check.startup_bytes(conf)
        flows = report["wyfyflows"]
        assert flows["entries"] == 8209
        assert all(8209 % d for d in range(2, 91))  # prime
        assert flows["cache_bytes"] == 33_230_032 == 8209 * 4048
        assert flows["capacity_rows"] == 90_299
        assert flows["full_cache_extra_bytes"] == 11_558_272 == 90_299 * 128
        text = CONF.read_text()
        for figure in (
            "33,230,032",
            "90,299",
            "11,558,272",
            "120,141,760",
            "131,700,032",
        ):
            assert figure in text, figure

    def test_worst_case_leaves_room_under_memory_max(self, check, conf) -> None:
        limit = check.memory_max_bytes(UNIT.read_text())
        assert limit == 256 * 2**20
        worst = check.worst_case_bytes(check.startup_bytes(conf))
        assert worst <= check.WORST_CASE_SHARE * limit
        assert worst < limit / 2  # "room to spare": under half

    def test_one_busy_venue_fits_without_an_early_purge(self, check, conf) -> None:
        busy_venue_rows = 75_000  # 50 guests, the high assumption
        assert (
            check.startup_bytes(conf)["wyfyflows"]["capacity_rows"] >= busy_venue_rows
        )

    def test_no_public_or_private_production_address(self) -> None:
        import re

        for path in (CONF, AGENT, OPS / "netflow" / "README.md"):
            text = path.read_text()
            assert not re.search(r"\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", text), path


class TestCheckScript:
    ARGS = [str(CONF), "--unit", str(UNIT), "--agent", str(AGENT)]

    def test_the_shipped_files_pass(self, check, capsys) -> None:
        assert check.main(self.ARGS) == 0
        out = capsys.readouterr().out
        assert "collector and agent agree on keys and file names: OK" in out
        assert "worst case (every cache full): 132 MB" in out

    def test_keys_the_config_produces_are_the_keys_the_agent_forwards(
        self, check, conf
    ) -> None:
        agent = check.load_agent(str(AGENT))
        assert check.key_problems(conf, agent) == []
        assert set(check.json_keys_of(conf, "wyfyflows")) == set(agent.FLOW_ROW_KEYS)
        assert set(check.json_keys_of(conf, "wyfy")) == set(agent.ROLLUP_KEYS)

    def _edited(self, tmp_path: pathlib.Path, old: str, new: str) -> str:
        text = CONF.read_text()
        assert old in text
        path = tmp_path / "nfacctd.conf"
        path.write_text(text.replace(old, new))
        return str(path)

    def test_a_primitive_the_agent_does_not_forward_fails(
        self, check, tmp_path, capsys
    ) -> None:
        conf_path = self._edited(
            tmp_path, "timestamp_arrival, flows", "timestamp_arrival, src_mac, flows"
        )
        assert check.main([conf_path, "--agent", str(AGENT)]) == 1
        assert "KEY MISMATCH" in capsys.readouterr().out

    def test_a_key_the_agent_expects_and_the_config_lacks_fails(
        self, check, tmp_path, capsys
    ) -> None:
        conf_path = self._edited(tmp_path, "timestamp_start, timestamp_end, ", "")
        assert check.main([conf_path, "--agent", str(AGENT)]) == 1
        out = capsys.readouterr().out
        assert "agent forwards 'timestamp_start' in flow_rows" in out

    def test_a_file_name_the_agent_cannot_read_fails(
        self, check, tmp_path, capsys
    ) -> None:
        conf_path = self._edited(
            tmp_path, "wyfy-flows/records-%Y", "wyfy-flows/flowlog-%Y"
        )
        assert check.main([conf_path, "--agent", str(AGENT)]) == 1
        assert "is not a name the agent reads as flow_rows" in capsys.readouterr().out

    def test_append_off_on_the_flow_plugin_fails(self, check, tmp_path, capsys) -> None:
        conf_path = self._edited(
            tmp_path,
            "print_output_file_append[wyfyflows]: true",
            "print_output_file_append[wyfyflows]: false",
        )
        assert check.main([conf_path, "--agent", str(AGENT)]) == 1
        assert "print_output_file_append must be true" in capsys.readouterr().out

    def test_a_cache_sized_too_close_to_memory_max_fails(
        self, check, tmp_path, capsys
    ) -> None:
        conf_path = self._edited(
            tmp_path,
            "print_cache_entries[wyfyflows]: 8209",
            "print_cache_entries[wyfyflows]: 32771",
        )
        assert check.main([conf_path, "--unit", str(UNIT), "--budget-mb", "400"]) == 1
        assert "TOO CLOSE TO MemoryMax" in capsys.readouterr().out

    def test_the_old_one_plugin_config_still_checks_clean(
        self, check, tmp_path
    ) -> None:
        """The config on the hub today (rollups only) must not be reported
        as broken by the new script: it may be run before the config is
        replaced."""
        text = CONF.read_text().replace(
            "plugins: print[wyfy], print[wyfyflows]", "plugins: print[wyfy]"
        )
        path = tmp_path / "nfacctd.conf"
        path.write_text(text)
        assert check.main([str(path), "--unit", str(UNIT), "--agent", str(AGENT)]) == 0
