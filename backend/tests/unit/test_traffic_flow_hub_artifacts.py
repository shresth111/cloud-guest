"""Hub collector artifacts (``ops/netflow``, ``ops/hub-agents``): the checks
that would have caught what the first prod install hit.

* nfacctd allocated 1.06 GB at start on a 2 GB hub, because
  ``print_cache_entries`` was sized for capacity and nobody did the sum.
* The units could not start as shipped: no ``pmacct`` user, a spool
  directory the service user cannot create, and a firewall unit that was
  referenced but did not exist.

Static checks only: nothing here starts a daemon.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
from typing import Any

import pytest

OPS = pathlib.Path("ops")
CONF = OPS / "netflow" / "nfacctd.conf"
UNITS = OPS / "hub-agents" / "systemd"

#: Start-up memory budget for the collector on the hub.
BUDGET_BYTES = 100_000_000
#: The fleet today, and DESIGN.md §5's average flow rate per venue.
ROUTERS = 15
AVERAGE_FLOWS_PER_SECOND = 10
WINDOW_SECONDS = 300


@pytest.fixture(scope="module")
def check() -> Any:
    spec = importlib.util.spec_from_file_location(
        "check_nfacctd_memory", OPS / "netflow" / "check_nfacctd_memory.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def conf(check: Any) -> dict[str, str]:
    return check.parse_config(CONF.read_text())


def _unit(name: str) -> dict[str, list[str]]:
    """``Key=value`` lines of a unit file, all sections flattened."""
    out: dict[str, list[str]] = {}
    for line in (UNITS / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out.setdefault(key, []).append(value)
    return out


class TestCollectorMemory:
    def test_formula_reproduces_what_the_hub_logged(self, check: Any) -> None:
        """262139 entries -> "base cache memory=1061138672 bytes", read off
        the prod hub's log. If this fails the formula is wrong, and so is
        every number derived from it."""
        assert check.base_cache_bytes(262139) == 1_061_138_672
        assert check.base_cache_bytes(1) == 4048

    def test_startup_memory_is_under_budget(self, check: Any, conf: dict) -> None:
        report = check.startup_bytes(conf)
        assert list(report) == ["wyfy", "wyfyflows"]
        # The rollup plugin is exactly what it was before the second one.
        rollup = report["wyfy"]
        assert rollup["cache_bytes"] + rollup["pipe_bytes"] == 76_671_728
        assert rollup["cache_bytes"] + rollup["pipe_bytes"] <= BUDGET_BYTES
        assert rollup["full_cache_extra_bytes"] == 0
        # Both together, at start and with every cache full.
        assert check.total_bytes(report) == 120_141_760
        assert check.worst_case_bytes(report) == 131_700_032
        assert check.total_bytes(report) <= check.DEFAULT_BUDGET_MB * 1_000_000

    def test_cache_holds_five_minutes_of_the_fleet(
        self, check: Any, conf: dict
    ) -> None:
        plugin = check.startup_bytes(conf)["wyfy"]
        expected_rows = ROUTERS * AVERAGE_FLOWS_PER_SECOND * WINDOW_SECONDS
        assert expected_rows == 45_000
        # At least twice the assumed average, since the rate is unmeasured.
        assert plugin["capacity_rows"] >= 2 * expected_rows

    def test_cache_entries_is_set_explicitly_and_is_prime(self, conf: dict) -> None:
        entries = int(conf["print_cache_entries[wyfy]"])
        assert all(entries % d for d in range(2, int(entries**0.5) + 1))

    def test_a_full_cache_appends_instead_of_overwriting(self, conf: dict) -> None:
        """A full cache purges early into the window's file. With append off
        the regular purge then replaces that file and the early part of the
        window is lost without a trace."""
        assert conf["print_output_file_append[wyfy]"] == "true"
        assert conf["print_refresh_time[wyfy]"] == "300"
        assert conf["print_history[wyfy]"] == "5m"

    def test_no_plugin_is_left_to_an_unsized_default(
        self, check: Any, conf: dict
    ) -> None:
        for name in check.plugin_names(conf):
            assert f"print_cache_entries[{name}]" in conf, name

    def test_the_check_script_fails_over_budget(
        self, check: Any, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert check.main([str(CONF)]) == 0
        assert "OK" in capsys.readouterr().out
        big = tmp_path / "nfacctd.conf"
        big.write_text(
            re.sub(
                r"^print_cache_entries\[wyfy\]:.*$",
                "print_cache_entries[wyfy]: 262139",
                CONF.read_text(),
                flags=re.M,
            )
        )
        assert check.main([str(big)]) == 1
        assert "OVER BUDGET" in capsys.readouterr().out

    def test_the_config_comment_states_the_same_numbers(self, check: Any) -> None:
        text = CONF.read_text()
        assert "1,061,138,672" in text
        assert f"{check.base_cache_bytes(16411):,}" in text


class TestHubUnits:
    def test_the_service_user_is_created_by_the_repo(self) -> None:
        users = {
            line.split()[1]
            for line in (UNITS / "wyfy-pmacct.sysusers.conf").read_text().splitlines()
            if line.startswith("u ")
        }
        for name in ("wyfy-nfacctd.service", "flow-agent.service"):
            (user,) = _unit(name)["User"]
            assert user in users, name

    def test_spool_directory_is_created_as_root(self) -> None:
        unit = _unit("wyfy-nfacctd.service")
        (pre,) = unit["ExecStartPre"]
        # "+" = run with full privileges; the service user cannot mkdir
        # under /var/spool.
        assert pre.startswith("+") and "install -d" in pre
        assert "-o pmacct -g pmacct" in pre and pre.endswith("/var/spool/wyfy-flows")

    def test_spool_and_template_paths_match_the_config(self, conf: dict) -> None:
        unit = _unit("wyfy-nfacctd.service")
        spool = str(pathlib.PurePosixPath(conf["print_output_file[wyfy]"]).parent)
        assert unit["ExecStartPre"][0].endswith(spool)
        templates = pathlib.PurePosixPath(conf["nfacctd_templates_file"]).parent
        assert str(templates) == f"/var/lib/{unit['StateDirectory'][0]}"

    def test_every_unit_named_in_an_ordering_exists(self) -> None:
        """``After=flow-agent-firewall.service`` pointed at a unit that was
        not in the repo: systemd ignores a missing unit in After=, so the
        rules were simply never re-applied at boot."""
        external = {"network.target", "network-online.target", "wg-quick@wg0.service"}
        shipped = {p.name for p in UNITS.iterdir()}
        for name in (
            "wyfy-nfacctd.service",
            "flow-agent.service",
            "flow-agent-firewall.service",
        ):
            unit = _unit(name)
            for key in ("After", "Before", "Wants", "Requires"):
                for value in unit.get(key, []):
                    for ref in value.split():
                        assert ref in shipped | external, (name, key, ref)

    def test_firewall_unit_runs_at_boot_before_what_it_protects(self) -> None:
        unit = _unit("flow-agent-firewall.service")
        assert unit["Type"] == ["oneshot"] and unit["RemainAfterExit"] == ["yes"]
        assert unit["WantedBy"] == ["multi-user.target"]
        assert set(unit["Before"][0].split()) == {
            "wyfy-nfacctd.service",
            "flow-agent.service",
        }
        script = pathlib.PurePosixPath(unit["ExecStart"][0]).name
        assert (OPS / "hub-agents" / script).exists()
        # The script refuses to run without APP_SOURCES; the unit supplies it.
        assert "APP_SOURCES:?" in (OPS / "hub-agents" / script).read_text()
        assert unit["EnvironmentFile"] == ["/etc/wyfy/flow-agent-firewall.env"]

    def test_collector_has_a_memory_backstop_and_utc(
        self, check: Any, conf: dict
    ) -> None:
        unit = _unit("wyfy-nfacctd.service")
        (limit,) = unit["MemoryMax"]
        assert limit.endswith("M")
        limit_bytes = int(limit[:-1]) * 1024 * 1024
        # Above what it needs at start, far below what the hub has.
        assert check.total_bytes(check.startup_bytes(conf)) * 2 <= limit_bytes
        assert limit_bytes <= 512 * 1024 * 1024
        assert "TZ=UTC" in unit["Environment"]

    def test_no_private_address_in_the_shipped_files(self) -> None:
        for path in [*UNITS.iterdir(), *(OPS / "netflow").iterdir()]:
            if path.is_file():
                assert not re.search(
                    r"\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", path.read_text()
                ), path
