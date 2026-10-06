"""Remote logging (syslog) on a MikroTik router, over the RouterOS API (8728).

Its own module on purpose: ``mikrotik_adapter.py`` is shared by several
concurrent workstreams (SNMP, NetFlow), and this writer needs nothing from
it except a connection.

## What is written

Exactly two kinds of object, both described by the caller (cloud-guest's
``app.domains.device_logs.routeros``, which also renders the paste script
from the same rows -- one description, two paths, no drift):

* one ``/system logging action`` row, identified by its ``name`` (unique on
  RouterOS);
* one ``/system logging`` rule per topic, identified by ``action=<name>``.
  Rules have no unique key, so this module converges them by content:
  matching rows are kept, everything else pointing at our action is
  removed, missing ones are added. A second apply of the same desired state
  writes nothing.

Nothing else is touched -- not the default memory/disk/echo actions, not
rules pointing at any other action.

## Read-back after write

``apply``/``remove`` always finish by re-reading both menus *from the
device* and comparing against what was asked for. The caller stores that
verdict; a write that RouterOS accepted but did not hold (a field silently
ignored on an older version, a rule that came back disabled) reads as
``ok=False`` with the difference named, never as success.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from librouteros.exceptions import LibRouterosError

from .contract import DeviceCredentials, DeviceVendor
from .mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError

_ACTION_MENU = ("system", "logging", "action")
_RULE_MENU = ("system", "logging")
_BOOLEAN_FIELDS = frozenset({"bsd-syslog", "disabled"})


@dataclass(frozen=True)
class RemoteLoggingReadback:
    """What the device holds after the write, compared to what was asked."""

    action_present: bool
    #: field -> (wanted, found) for every action field that differs.
    action_mismatches: dict[str, tuple[str, str | None]] = field(
        default_factory=dict
    )
    #: Topics of the enabled rules pointing at our action, as read back.
    rule_topics: tuple[str, ...] = ()
    missing_rules: tuple[str, ...] = ()
    unexpected_rules: int = 0
    ok: bool = False
    detail: str = ""


def _norm(key: str, value: object) -> str | None:
    if value is None:
        return None
    if key in _BOOLEAN_FIELDS or isinstance(value, bool):
        if isinstance(value, bool):
            return "yes" if value else "no"
        return "yes" if str(value).strip().lower() in {"yes", "true"} else "no"
    return str(value).strip()


def _rule_key(row: Mapping[str, Any]) -> tuple[str | None, str | None]:
    return (_norm("topics", row.get("topics")), _norm("prefix", row.get("prefix")))


def _ours(rows: Sequence[Mapping[str, Any]], action_name: str) -> list[Mapping[str, Any]]:
    return [r for r in rows if _norm("action", r.get("action")) == action_name]


def read_remote_logging(
    api: Any,
    *,
    desired_action: Mapping[str, str] | None,
    desired_rules: Sequence[Mapping[str, str]],
    action_name: str,
) -> RemoteLoggingReadback:
    """Compare the device with the desired state. ``desired_action=None``
    means "expect it gone" (the read-back after a removal)."""
    actions = [
        r
        for r in api.path(*_ACTION_MENU)
        if _norm("name", r.get("name")) == action_name
    ]
    rules = _ours(list(api.path(*_RULE_MENU)), action_name)
    enabled = [r for r in rules if _norm("disabled", r.get("disabled")) != "yes"]
    topics = tuple(sorted(_norm("topics", r.get("topics")) or "" for r in enabled))

    if desired_action is None:
        ok = not actions and not rules
        return RemoteLoggingReadback(
            action_present=bool(actions),
            rule_topics=topics,
            unexpected_rules=len(rules),
            ok=ok,
            detail="removed" if ok else (
                f"still present: {len(actions)} action(s), {len(rules)} rule(s)"
            ),
        )

    mismatches: dict[str, tuple[str, str | None]] = {}
    if actions:
        row = actions[0]
        for key, wanted in desired_action.items():
            found = _norm(key, row.get(key))
            if found != _norm(key, wanted):
                mismatches[key] = (wanted, found)
        if _norm("disabled", row.get("disabled")) == "yes":
            mismatches["disabled"] = ("no", "yes")
    wanted_keys = [_rule_key(r) for r in desired_rules]
    have_keys = [_rule_key(r) for r in enabled]
    missing = tuple(
        topic or "" for (topic, _prefix) in wanted_keys if (topic, _prefix) not in have_keys
    )
    unexpected = len(rules) - sum(1 for k in have_keys if k in wanted_keys)

    problems: list[str] = []
    if not actions:
        problems.append("action missing")
    if len(actions) > 1:
        problems.append(f"{len(actions)} actions named {action_name}")
    if mismatches:
        problems.append(
            "action fields differ: "
            + ", ".join(f"{k} wanted {w!r} found {f!r}" for k, (w, f) in mismatches.items())
        )
    if missing:
        problems.append("missing rules: " + ", ".join(missing))
    if unexpected:
        problems.append(f"{unexpected} unexpected or disabled rule(s)")
    return RemoteLoggingReadback(
        action_present=bool(actions),
        action_mismatches=mismatches,
        rule_topics=topics,
        missing_rules=missing,
        unexpected_rules=unexpected,
        ok=not problems,
        detail="; ".join(problems) or "verified",
    )


def apply_remote_logging(
    api: Any,
    *,
    desired_action: Mapping[str, str],
    desired_rules: Sequence[Mapping[str, str]],
) -> RemoteLoggingReadback:
    action_name = desired_action["name"]
    action_menu = api.path(*_ACTION_MENU)
    existing = [
        r for r in action_menu if _norm("name", r.get("name")) == action_name
    ]
    if not existing:
        action_menu.add(**dict(desired_action))
    else:
        row = existing[0]
        changed = {
            key: value
            for key, value in desired_action.items()
            if key != "name" and _norm(key, row.get(key)) != _norm(key, value)
        }
        if _norm("disabled", row.get("disabled")) == "yes":
            changed["disabled"] = "no"
        if changed:
            action_menu.update(**{".id": row[".id"], **changed})

    rule_menu = api.path(*_RULE_MENU)
    wanted = [_rule_key(r) for r in desired_rules]
    satisfied: set[tuple[str | None, str | None]] = set()
    stale: list[str] = []
    for row in _ours(list(rule_menu), action_name):
        key = _rule_key(row)
        if (
            key in wanted
            and key not in satisfied
            and _norm("disabled", row.get("disabled")) != "yes"
        ):
            satisfied.add(key)
        else:
            stale.append(row[".id"])
    if stale:
        rule_menu.remove(*stale)
    for row in desired_rules:
        if _rule_key(row) not in satisfied:
            rule_menu.add(**dict(row))

    return read_remote_logging(
        api,
        desired_action=desired_action,
        desired_rules=desired_rules,
        action_name=action_name,
    )


def remove_remote_logging(api: Any, *, action_name: str) -> RemoteLoggingReadback:
    """Rules first: RouterOS refuses to remove an action a rule still uses."""
    rule_menu = api.path(*_RULE_MENU)
    ours = [r[".id"] for r in _ours(list(rule_menu), action_name)]
    if ours:
        rule_menu.remove(*ours)
    action_menu = api.path(*_ACTION_MENU)
    ids = [
        r[".id"] for r in action_menu if _norm("name", r.get("name")) == action_name
    ]
    if ids:
        action_menu.remove(*ids)
    return read_remote_logging(
        api, desired_action=None, desired_rules=(), action_name=action_name
    )


class MikroTikRemoteLogging:
    """Async entry points. ``connect`` is injectable for tests; by default it
    is the MikroTik adapter's own connection (same port, timeout and error
    mapping as every other 8728 writer)."""

    def __init__(self, connect: Callable[[DeviceCredentials], Any] | None = None) -> None:
        self._connect = connect or MikroTikAdapter()._connect_api  # noqa: SLF001

    async def apply(
        self,
        creds: DeviceCredentials,
        *,
        desired_action: Mapping[str, str],
        desired_rules: Sequence[Mapping[str, str]],
    ) -> RemoteLoggingReadback:
        return await asyncio.to_thread(
            self._run,
            creds,
            lambda api: apply_remote_logging(
                api, desired_action=desired_action, desired_rules=desired_rules
            ),
        )

    async def read(
        self,
        creds: DeviceCredentials,
        *,
        desired_action: Mapping[str, str],
        desired_rules: Sequence[Mapping[str, str]],
    ) -> RemoteLoggingReadback:
        return await asyncio.to_thread(
            self._run,
            creds,
            lambda api: read_remote_logging(
                api,
                desired_action=desired_action,
                desired_rules=desired_rules,
                action_name=desired_action["name"],
            ),
        )

    async def remove(
        self, creds: DeviceCredentials, *, action_name: str
    ) -> RemoteLoggingReadback:
        return await asyncio.to_thread(
            self._run,
            creds,
            lambda api: remove_remote_logging(api, action_name=action_name),
        )

    def _run(
        self, creds: DeviceCredentials, op: Callable[[Any], RemoteLoggingReadback]
    ) -> RemoteLoggingReadback:
        if creds.vendor != DeviceVendor.MIKROTIK:
            raise MikroTikDeviceError(
                creds.host, f"remote logging: unsupported vendor {creds.vendor}"
            )
        api = self._connect(creds)
        try:
            try:
                return op(api)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"remote logging: {exc}"
                ) from exc
        finally:
            MikroTikAdapter._safe_close(api)  # noqa: SLF001


__all__ = [
    "MikroTikRemoteLogging",
    "RemoteLoggingReadback",
    "apply_remote_logging",
    "read_remote_logging",
    "remove_remote_logging",
]
