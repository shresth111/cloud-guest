#!/usr/bin/env python3
"""How much memory will nfacctd take at start with this config?

    python3 check_nfacctd_memory.py [nfacctd.conf] [--budget-mb 100]

Stdlib only; run it on the hub before (re)starting the collector, or
anywhere. Exits 1 when the start-up memory is over budget.

Why it exists: ``print_cache_entries`` is a number of hash buckets, and
nfacctd allocates the whole cache at start. A value sized for "2M entries"
(262139) took 1.06 GB of a 2 GB hub that also carries RADIUS and WireGuard
for every venue.

The formula is pmacct 1.7.7 ``src/plugin_common.c``
(``P_init_default_values``)::

    base = E*S + (10*E)*S + 2*((10*E + E) * P)

with ``AVERAGE_CHAIN_LEN = 10``, ``S = sizeof(struct chained_cache)`` and
``P`` a pointer. ``S`` is 352 bytes on the hub's build: that is the value
which makes the formula give exactly the 1,061,138,672 bytes nfacctd logged
there for 262139 entries. On another build, read "base cache memory=" from
the log and compare.

The aggregate does not change it; ``plugin_pipe_size`` is separate and is
added below, once per plugin.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

AVERAGE_CHAIN_LEN = 10
CHAINED_CACHE_BYTES = 352
POINTER_BYTES = 8
#: pmacct's defaults when a key is absent.
DEFAULT_CACHE_ENTRIES = 16411
DEFAULT_PIPE_BYTES = 4 * 1024 * 1024
DEFAULT_BUDGET_MB = 100


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


def startup_bytes(config: dict[str, str]) -> dict[str, dict[str, int]]:
    """Per plugin: cache entries, base cache bytes, pipe bytes, row capacity."""
    report: dict[str, dict[str, int]] = {}
    for name in plugin_names(config):
        entries = int(config.get(f"print_cache_entries[{name}]", DEFAULT_CACHE_ENTRIES))
        pipe = int(config.get(f"plugin_pipe_size[{name}]", DEFAULT_PIPE_BYTES))
        report[name] = {
            "entries": entries,
            "cache_bytes": base_cache_bytes(entries),
            "pipe_bytes": pipe,
            "capacity_rows": capacity_rows(entries),
        }
    return report


def total_bytes(report: dict[str, dict[str, int]]) -> int:
    return sum(p["cache_bytes"] + p["pipe_bytes"] for p in report.values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "config",
        nargs="?",
        default=str(pathlib.Path(__file__).with_name("nfacctd.conf")),
    )
    parser.add_argument("--budget-mb", type=int, default=DEFAULT_BUDGET_MB)
    args = parser.parse_args(argv)
    config = parse_config(pathlib.Path(args.config).read_text(encoding="utf-8"))
    report = startup_bytes(config)
    if not report:
        print("no print plugin found in the config", file=sys.stderr)
        return 1
    for name, plugin in report.items():
        print(
            f"plugin {name}: print_cache_entries={plugin['entries']} "
            f"base cache memory={plugin['cache_bytes']} bytes "
            f"({plugin['cache_bytes'] / 1e6:.0f} MB), "
            f"pipe={plugin['pipe_bytes'] / 1e6:.0f} MB, "
            f"holds up to {plugin['capacity_rows']} rows per purge"
        )
    total = total_bytes(report)
    budget = args.budget_mb * 1_000_000
    verdict = "OK" if total <= budget else "OVER BUDGET"
    print(
        f"start-up total: {total / 1e6:.0f} MB, budget {args.budget_mb} MB: {verdict}"
    )
    return 0 if total <= budget else 1


if __name__ == "__main__":
    sys.exit(main())
