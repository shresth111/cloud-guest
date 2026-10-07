"""RouterOS ``/ip traffic-flow`` (NetFlow v9 / IPFIX export), over the API (8728).

Read, plan, write, read back. The caller (the platform's ``traffic_flow``
domain) builds the desired rows ONCE and hands the same three mappings to
both this writer and the script renderer, so the two config paths cannot
drift (see ``~/wyfy-ops/netflow/DESIGN.md`` §2).

## Three RouterOS objects, two shapes

* ``/ip traffic-flow`` and ``/ip traffic-flow ipfix`` are **singletons**:
  a ``set`` is naturally idempotent. They are written only for the fields
  that differ, so an unchanged re-apply issues no write at all.
* ``/ip traffic-flow target`` is a **list with no natural unique key**.
  ``add`` duplicates on every push, and two targets mean every flow is
  exported, and counted, twice. Our row is found by its ``comment`` marker,
  updated in place, and any *extra* marked rows are removed. Targets without
  our marker belong to someone else and are never touched; they are counted
  and reported so an operator can see a pre-existing export.

## RouterOS v6 is refused, not guessed at

v6 spells the target ``address=IP:port`` and has no ``src-address`` or
``packet-sampling``. Rather than translate (and be wrong in a way nothing
reads back), :func:`apply_traffic_flow` refuses a non-v7 router with
:class:`TrafficFlowRefusal` before writing anything.

## Read-back, because RouterOS writes can return cleanly and change nothing

After the writes the three objects are read again and compared field by
field with the desired rows; ``matches`` is False with a per-field reason
when anything differs. "No exception" is never treated as success -- see the
2026-08-18 hotspot-profile rebind failure modelled in the write fake.

Nothing in this module has run against hardware yet; the device plan is H1
and H7 in DESIGN.md §9.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "TRAFFIC_FLOW_V7_REQUIRED",
    "TrafficFlowApplyResult",
    "TrafficFlowConfig",
    "TrafficFlowRefusal",
    "TrafficFlowState",
    "apply_traffic_flow",
    "diff_traffic_flow",
    "normalize_value",
    "plan_traffic_flow",
    "read_traffic_flow",
]

#: Refusal code: the router does not run RouterOS 7.
TRAFFIC_FLOW_V7_REQUIRED = "TRAFFIC_FLOW_V7_REQUIRED"

_SETTINGS_PATH = ("ip", "traffic-flow")
_IPFIX_PATH = ("ip", "traffic-flow", "ipfix")
_TARGET_PATH = ("ip", "traffic-flow", "target")

#: Fields whose value is a RouterOS duration ("1m", "00:01:00", "60s").
_DURATION_FIELDS = frozenset({"active-flow-timeout", "inactive-flow-timeout"})


class TrafficFlowRefusal(Exception):  # noqa: N818 -- mirrors FirewallRefusal
    """Nothing was written; ``code`` says why."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class TrafficFlowConfig:
    """The desired state, as RouterOS field -> value strings.

    ``target`` is ``None`` to mean "no export target of ours should exist"
    (the disable path). ``marker`` is the ``comment`` that identifies our
    target row."""

    settings: Mapping[str, str]
    ipfix: Mapping[str, str]
    target: Mapping[str, str] | None
    marker: str


@dataclass(frozen=True, slots=True)
class TrafficFlowState:
    """What one read of the three objects found. Values are normalized (see
    :func:`normalize_value`) so they compare equal to desired rows."""

    routeros_version: str | None
    settings: dict[str, str]
    ipfix: dict[str, str]
    targets: tuple[dict[str, str], ...]
    foreign_targets: int

    @property
    def major_version(self) -> int | None:
        if not self.routeros_version:
            return None
        match = re.match(r"\s*(\d+)", self.routeros_version)
        return int(match.group(1)) if match else None


@dataclass(frozen=True, slots=True)
class TrafficFlowApplyResult:
    """``writes`` lists every write issued, in order, as ``"<op> <path>
    <fields>"``. ``matches`` is the read-back verdict; ``mismatches`` names
    each field that still differs."""

    writes: tuple[str, ...]
    before: TrafficFlowState
    after: TrafficFlowState
    matches: bool
    mismatches: tuple[str, ...] = field(default_factory=tuple)


# -- normalization ----------------------------------------------------------


def _duration_seconds(value: str) -> int | None:
    text = value.strip().lower()
    if not text:
        return None
    if re.fullmatch(r"\d+:\d{2}:\d{2}", text):
        hours, minutes, seconds = (int(p) for p in text.split(":"))
        return hours * 3600 + minutes * 60 + seconds
    total = 0
    matched = False
    for amount, unit in re.findall(r"(\d+)(w|d|h|ms|m|s)", text):
        matched = True
        n = int(amount)
        total += {
            "w": n * 604800,
            "d": n * 86400,
            "h": n * 3600,
            "m": n * 60,
            "s": n,
            "ms": 0,
        }[unit]
    if matched:
        return total
    if text.isdigit():
        return int(text)
    return None


def normalize_value(key: str, value: Any) -> str:
    """One spelling per value: booleans as ``yes``/``no`` (the API reads a
    real ``bool`` and accepts strings on write), durations as whole seconds,
    everything else as a stripped lower-case string."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = "" if value is None else str(value).strip()
    lowered = text.lower()
    if lowered in {"true", "yes"}:
        return "yes"
    if lowered in {"false", "no"}:
        return "no"
    if key in _DURATION_FIELDS:
        seconds = _duration_seconds(lowered)
        if seconds is not None:
            return f"{seconds}s"
    return lowered


def _normalized_row(
    row: Mapping[str, Any], keys: set[str] | None = None
) -> dict[str, str]:
    return {
        str(k): normalize_value(str(k), v)
        for k, v in row.items()
        if not str(k).startswith(".") and (keys is None or k in keys)
    }


# -- read -------------------------------------------------------------------


def _first_row(api: Any, path: tuple[str, ...]) -> dict[str, Any]:
    for row in api.path(*path):
        return dict(row)
    return {}


def read_traffic_flow(api: Any, *, marker: str) -> TrafficFlowState:
    """Read-only. Never writes."""
    resource = _first_row(api, ("system", "resource"))
    version = resource.get("version")
    settings = _normalized_row(_first_row(api, _SETTINGS_PATH))
    ipfix = _normalized_row(_first_row(api, _IPFIX_PATH))
    ours: list[dict[str, str]] = []
    foreign = 0
    for row in api.path(*_TARGET_PATH):
        if str(row.get("comment", "")) == marker:
            normalized = _normalized_row(row)
            normalized[".id"] = str(row.get(".id", ""))
            ours.append(normalized)
        else:
            foreign += 1
    return TrafficFlowState(
        routeros_version=str(version) if version else None,
        settings=settings,
        ipfix=ipfix,
        targets=tuple(ours),
        foreign_targets=foreign,
    )


# -- diff / plan --------------------------------------------------------------


def _changed(current: Mapping[str, str], desired: Mapping[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in desired.items()
        if current.get(key) != normalize_value(key, value)
    }


def diff_traffic_flow(
    state: TrafficFlowState, config: TrafficFlowConfig
) -> tuple[str, ...]:
    """Every field on the device that differs from ``config``, as readable
    reasons. Empty means the device already holds exactly the desired
    state."""
    reasons: list[str] = []
    for key, value in _changed(state.settings, config.settings).items():
        reasons.append(
            f"traffic-flow {key}: have {state.settings.get(key)!r}, want {value!r}"
        )
    for key, value in _changed(state.ipfix, config.ipfix).items():
        reasons.append(
            f"traffic-flow ipfix {key}: have {state.ipfix.get(key)!r}, want {value!r}"
        )
    if config.target is None:
        if state.targets:
            reasons.append(
                f"{len(state.targets)} export target(s) of ours still present"
            )
    else:
        if not state.targets:
            reasons.append("export target of ours is missing")
        else:
            for key, value in _changed(state.targets[0], config.target).items():
                reasons.append(
                    f"traffic-flow target {key}: have {state.targets[0].get(key)!r}, want {value!r}"
                )
            if len(state.targets) > 1:
                reasons.append(
                    f"{len(state.targets)} export targets of ours (duplicates double-count every flow)"
                )
    return tuple(reasons)


def plan_traffic_flow(
    state: TrafficFlowState, config: TrafficFlowConfig
) -> list[tuple[str, tuple[str, ...], dict[str, str]]]:
    """The writes :func:`apply_traffic_flow` would issue, in order, as
    ``(op, path, fields)``. Pure: used for ``dry_run``.

    Order matters for a clean turn-on and turn-off: the target is put in
    place before export is enabled (no records sent to a stale target), and
    on disable export is switched off before the target is removed."""
    ops: list[tuple[str, tuple[str, ...], dict[str, str]]] = []
    settings_change = _changed(state.settings, config.settings)
    ipfix_change = _changed(state.ipfix, config.ipfix)
    disabling = (
        normalize_value("enabled", config.settings.get("enabled", "yes")) == "no"
    )

    if disabling and settings_change:
        ops.append(("set", _SETTINGS_PATH, settings_change))
    if ipfix_change:
        ops.append(("set", _IPFIX_PATH, ipfix_change))

    if config.target is None:
        for row in state.targets:
            ops.append(("remove", _TARGET_PATH, {".id": row[".id"]}))
    else:
        if not state.targets:
            ops.append(
                ("add", _TARGET_PATH, {**config.target, "comment": config.marker})
            )
        else:
            keep, *extra = state.targets
            change = _changed(keep, config.target)
            if change:
                ops.append(("update", _TARGET_PATH, {".id": keep[".id"], **change}))
            for row in extra:
                ops.append(("remove", _TARGET_PATH, {".id": row[".id"]}))

    if not disabling and settings_change:
        ops.append(("set", _SETTINGS_PATH, settings_change))
    return ops


# -- write ------------------------------------------------------------------


def _describe(op: str, path: tuple[str, ...], fields: Mapping[str, str]) -> str:
    rendered = " ".join(f"{k}={v}" for k, v in fields.items())
    return f"{op} /{'/'.join(path)} {rendered}".rstrip()


def apply_traffic_flow(api: Any, config: TrafficFlowConfig) -> TrafficFlowApplyResult:
    """Make the device hold ``config``, then read it back.

    Raises :class:`TrafficFlowRefusal` (nothing written) on a router that is
    not RouterOS 7. An unchanged device gets zero writes."""
    before = read_traffic_flow(api, marker=config.marker)
    if before.major_version != 7:
        raise TrafficFlowRefusal(
            TRAFFIC_FLOW_V7_REQUIRED,
            f"RouterOS 7 required for /ip traffic-flow export; router reports "
            f"{before.routeros_version or 'no version'}",
        )
    writes: list[str] = []
    for op, path, fields in plan_traffic_flow(before, config):
        menu = api.path(*path)
        if op == "set":
            menu.update(**fields)
        elif op == "add":
            menu.add(**fields)
        elif op == "update":
            menu.update(**fields)
        elif op == "remove":
            menu.remove(fields[".id"])
        writes.append(_describe(op, path, fields))
    after = read_traffic_flow(api, marker=config.marker)
    mismatches = diff_traffic_flow(after, config)
    return TrafficFlowApplyResult(
        writes=tuple(writes),
        before=before,
        after=after,
        matches=not mismatches,
        mismatches=mismatches,
    )
