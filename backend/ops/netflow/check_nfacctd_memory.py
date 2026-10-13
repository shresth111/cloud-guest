#!/usr/bin/env python3
"""Will this nfacctd config fit in memory, and do the collector and the hub
agent agree on what a row looks like?

    python3 check_nfacctd_memory.py [nfacctd.conf]
        [--unit ../hub-agents/systemd/wyfy-nfacctd.service]
        [--agent ../hub-agents/flow_agent.py]
        [--budget-mb 160]

Stdlib only; run it on the hub before (re)starting the collector, or
anywhere. Exits 1 on any failure and says which.

## Memory

``print_cache_entries`` is a number of hash buckets, and nfacctd allocates
the whole cache at start, per plugin. A value sized for "2M entries"
(262139) once took 1.06 GB of a 2 GB hub that also carries RADIUS and
WireGuard for every venue.

The formula is pmacct 1.7.7 ``src/plugin_common.c``
(``P_init_default_values``)::

    base = E*S + (10*E)*S + 2*((10*E + E) * P)

with ``AVERAGE_CHAIN_LEN = 10``, ``S = sizeof(struct chained_cache)`` and
``P`` a pointer. ``S`` is 352 bytes on the hub's build: that is the value
which makes the formula give exactly the 1,061,138,672 bytes nfacctd logged
there for 262139 entries. On another build, read "base cache memory=" from
the log and compare.

The aggregate does not change the base. A plugin whose aggregate carries a
NAT or timestamp primitive additionally mallocs one ``struct
pkt_nat_primitives`` per USED entry (about 128 bytes with allocator
overhead; computed from the struct, not measured), so its worst case is
``base + capacity * 128``. ``plugin_pipe_size`` is separate, once per
plugin.

Two limits: the start-up total against ``--budget-mb``, and, when ``--unit``
is given, the worst case against ``WORST_CASE_SHARE`` of the unit's
``MemoryMax``.

## Keys

Each aggregate primitive becomes a known JSON key in the print plugin's
output (pmacct 1.7.7 ``src/plugin_cmn_json.c``). With ``--agent``, the keys
the config will produce are compared with the keys ``flow_agent.py``
forwards, and each plugin's output file name with the pattern the agent
looks for. A primitive added here and not there would be collected, spooled
and silently dropped.
"""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import re
import sys
from typing import Any

AVERAGE_CHAIN_LEN = 10
CHAINED_CACHE_BYTES = 352
POINTER_BYTES = 8
#: Per used entry, for a plugin with a NAT or timestamp primitive.
NAT_PRIMITIVES_BYTES = 128
#: pmacct's defaults when a key is absent.
DEFAULT_CACHE_ENTRIES = 16411
DEFAULT_PIPE_BYTES = 4 * 1024 * 1024
#: Start-up memory of the whole collector (both plugins).
DEFAULT_BUDGET_MB = 160
#: The worst case may use at most this share of the unit's MemoryMax; the
#: rest is for the core process and the writer processes a purge forks.
WORST_CASE_SHARE = 0.6

#: Aggregate primitive -> JSON key in the print plugin's output.
PRIMITIVE_JSON_KEYS: dict[str, str] = {
    "peer_src_ip": "peer_ip_src",
    "src_host": "ip_src",
    "dst_host": "ip_dst",
    "proto": "ip_proto",
    "src_port": "port_src",
    "dst_port": "port_dst",
    "post_nat_src_host": "post_nat_ip_src",
    "post_nat_dst_host": "post_nat_ip_dst",
    "post_nat_src_port": "post_nat_port_src",
    "post_nat_dst_port": "post_nat_port_dst",
    "timestamp_start": "timestamp_start",
    "timestamp_end": "timestamp_end",
    "timestamp_arrival": "timestamp_arrival",
    "flows": "flows",
}
#: Written on every row whatever the aggregate.
ALWAYS_PRINTED_KEYS = ("bytes", "packets")
#: Primitives stored in ``struct pkt_nat_primitives``.
NAT_OR_TIMESTAMP_PRIMITIVES = frozenset(
    {
        "post_nat_src_host",
        "post_nat_dst_host",
        "post_nat_src_port",
        "post_nat_dst_port",
        "timestamp_start",
        "timestamp_end",
        "timestamp_arrival",
    }
)
#: Which plugin feeds which part of the agent's response.
ROLLUP_PLUGIN = "wyfy"
FLOW_PLUGIN = "wyfyflows"


def base_cache_bytes(entries: int) -> int:
    """nfacctd's own "base cache memory" figure for one print plugin."""
    chained = entries * AVERAGE_CHAIN_LEN
    return (
        entries * CHAINED_CACHE_BYTES
        + chained * CHAINED_CACHE_BYTES
        + 2 * (chained + entries) * POINTER_BYTES
    )


def capacity_rows(entries: int) -> int:
    """Most distinct rows one purge interval can hold before an early purge."""
    return entries * (1 + AVERAGE_CHAIN_LEN)


def parse_config(text: str) -> dict[str, str]:
    """``key: value`` lines; ``!`` starts a comment line."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def plugin_names(config: dict[str, str]) -> list[str]:
    names = []
    for item in config.get("plugins", "").split(","):
        item = item.strip()
        if "[" in item and item.endswith("]"):
            names.append(item[item.index("[") + 1 : -1])
    return names


def aggregate_of(config: dict[str, str], plugin: str) -> list[str]:
    return [
        part.strip()
        for part in config.get(f"aggregate[{plugin}]", "").split(",")
        if part.strip()
    ]


def json_keys_of(config: dict[str, str], plugin: str) -> list[str]:
    """The JSON keys this plugin's rows will carry, in aggregate order.
    Raises ``KeyError`` for a primitive this script does not know."""
    keys = [PRIMITIVE_JSON_KEYS[name] for name in aggregate_of(config, plugin)]
    return [*keys, *ALWAYS_PRINTED_KEYS]


def startup_bytes(config: dict[str, str]) -> dict[str, dict[str, int]]:
    """Per plugin: cache entries, base cache bytes, pipe bytes, row capacity
    and the extra a full cache costs (0 unless the aggregate carries a NAT
    or timestamp primitive)."""
    report: dict[str, dict[str, int]] = {}
    for name in plugin_names(config):
        entries = int(config.get(f"print_cache_entries[{name}]", DEFAULT_CACHE_ENTRIES))
        pipe = int(config.get(f"plugin_pipe_size[{name}]", DEFAULT_PIPE_BYTES))
        capacity = capacity_rows(entries)
        per_entry = (
            NAT_PRIMITIVES_BYTES
            if NAT_OR_TIMESTAMP_PRIMITIVES & set(aggregate_of(config, name))
            else 0
        )
        report[name] = {
            "entries": entries,
            "cache_bytes": base_cache_bytes(entries),
            "pipe_bytes": pipe,
            "capacity_rows": capacity,
            "full_cache_extra_bytes": capacity * per_entry,
        }
    return report


def total_bytes(report: dict[str, dict[str, int]]) -> int:
    """Start-up memory: every plugin's base cache and pipe."""
    return sum(p["cache_bytes"] + p["pipe_bytes"] for p in report.values())


def worst_case_bytes(report: dict[str, dict[str, int]]) -> int:
    """Start-up memory plus every cache completely full."""
    return total_bytes(report) + sum(
        p["full_cache_extra_bytes"] for p in report.values()
    )


def memory_max_bytes(unit_text: str) -> int | None:
    """``MemoryMax=`` of a systemd unit, in bytes; None when it has none."""
    match = re.search(r"^MemoryMax=(\d+)([KMGT]?)\s*$", unit_text, re.M)
    if not match:
        return None
    scale = {"": 1, "K": 2**10, "M": 2**20, "G": 2**30, "T": 2**40}[match.group(2)]
    return int(match.group(1)) * scale


def load_agent(path: str) -> Any:
    spec = importlib.util.spec_from_file_location("flow_agent_checked", path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def key_problems(config: dict[str, str], agent: Any) -> list[str]:
    """Every way the collector's output and the agent's reading disagree."""
    problems: list[str] = []
    expected = {
        ROLLUP_PLUGIN: (tuple(agent.ROLLUP_KEYS), agent.window_start_of, "rows"),
        FLOW_PLUGIN: (
            tuple(agent.FLOW_ROW_KEYS),
            agent.flow_window_start_of,
            "flow_rows",
        ),
    }
    names = plugin_names(config)
    for plugin in names:
        if plugin not in expected:
            problems.append(f"plugin {plugin}: the agent serves nothing from it")
    for plugin, (agent_keys, start_of, served_as) in expected.items():
        if plugin not in names:
            if plugin == ROLLUP_PLUGIN:
                problems.append(f"plugin {plugin} (the rollups) is not configured")
            continue
        try:
            produced = json_keys_of(config, plugin)
        except KeyError as exc:
            problems.append(
                f"plugin {plugin}: aggregate primitive {exc.args[0]!r} has no "
                "known JSON key in this script"
            )
            continue
        for key in produced:
            if key not in agent_keys:
                problems.append(
                    f"plugin {plugin}: collector writes {key!r} but the agent "
                    f"does not forward it in {served_as}"
                )
        for key in agent_keys:
            if key not in produced:
                problems.append(
                    f"plugin {plugin}: agent forwards {key!r} in {served_as} but "
                    "the aggregate does not produce it"
                )
        filename = pathlib.PurePosixPath(
            config.get(f"print_output_file[{plugin}]", "")
        ).name
        sample = filename.replace("%Y%m%d", "20260101").replace("%H%M", "0000")
        if start_of(sample) is None:
            problems.append(
                f"plugin {plugin}: output file {filename!r} is not a name the "
                f"agent reads as {served_as}"
            )
        if config.get(f"print_output_file_append[{plugin}]") != "true":
            problems.append(
                f"plugin {plugin}: print_output_file_append must be true, or an "
                "early purge is overwritten by the next write"
            )
    directories = {
        str(pathlib.PurePosixPath(config.get(f"print_output_file[{p}]", "")).parent)
        for p in names
    }
    if len(directories) > 1:
        problems.append(
            f"plugins write to different directories {sorted(directories)}; the "
            "agent reads and prunes one spool directory"
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "config",
        nargs="?",
        default=str(pathlib.Path(__file__).with_name("nfacctd.conf")),
    )
    parser.add_argument("--budget-mb", type=int, default=DEFAULT_BUDGET_MB)
    parser.add_argument("--unit", help="wyfy-nfacctd.service, for its MemoryMax")
    parser.add_argument("--agent", help="flow_agent.py, for the key agreement check")
    args = parser.parse_args(argv)
    config = parse_config(pathlib.Path(args.config).read_text(encoding="utf-8"))
    report = startup_bytes(config)
    if not report:
        print("no print plugin found in the config", file=sys.stderr)
        return 1
    failed = False
    for name, plugin in report.items():
        extra = plugin["full_cache_extra_bytes"]
        print(
            f"plugin {name}: print_cache_entries={plugin['entries']} "
            f"base cache memory={plugin['cache_bytes']} bytes "
            f"({plugin['cache_bytes'] / 1e6:.0f} MB), "
            f"pipe={plugin['pipe_bytes'] / 1e6:.0f} MB, "
            f"holds up to {plugin['capacity_rows']} rows per purge"
            + (f", up to {extra / 1e6:.0f} MB more when full" if extra else "")
        )
    total = total_bytes(report)
    budget = args.budget_mb * 1_000_000
    verdict = "OK" if total <= budget else "OVER BUDGET"
    failed |= total > budget
    print(
        f"start-up total: {total / 1e6:.0f} MB, budget {args.budget_mb} MB: {verdict}"
    )
    worst = worst_case_bytes(report)
    print(f"worst case (every cache full): {worst / 1e6:.0f} MB")
    if args.unit:
        limit = memory_max_bytes(pathlib.Path(args.unit).read_text(encoding="utf-8"))
        if limit is None:
            print("unit has no MemoryMax: NO BACKSTOP")
            failed = True
        else:
            allowed = int(limit * WORST_CASE_SHARE)
            verdict = "OK" if worst <= allowed else "TOO CLOSE TO MemoryMax"
            failed |= worst > allowed
            print(
                f"MemoryMax {limit / 1e6:.0f} MB, worst case may use "
                f"{WORST_CASE_SHARE:.0%} = {allowed / 1e6:.0f} MB: {verdict}"
            )
    if args.agent:
        problems = key_problems(config, load_agent(args.agent))
        for problem in problems:
            print(f"KEY MISMATCH: {problem}")
        if not problems:
            print("collector and agent agree on keys and file names: OK")
        failed |= bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
