"""Rate-limited log rules in front of Wyfy's own forward-chain drops, so a
blocked guest flow reaches NetLogs as a ``WYFY-FW`` line, over the RouterOS
API (8728).

## What is written

For each *target* -- a Wyfy-managed ``drop``/``reject`` row inside the
sentinel band of ``chain=forward`` -- one companion row directly before it::

    chain=forward action=log <the target's matchers, copied>
      limit=2/1s,5:packet log-prefix=WYFY-FW
      comment=cloudguest-fwlog:<the target's comment>

``action=log`` does not end rule processing, so the packet goes on to the
target and is dropped there. Because the companion carries the same matchers
and sits directly above the target, it sees exactly the packets the target
drops -- no more (a customer accept further up has already taken its traffic
out), no fewer -- up to the limit.

**Why never ``log=yes`` on the drop itself.** That logs every packet the
drop sees, unbounded. ``limit=`` on a separate ``action=log`` row is the
only per-rule rate cap RouterOS offers on a log; the cost is one row.

**Targets, and only these** (all of them written by this platform, all
inside the band):

* ``cloudguest-fw:<uuid>`` rows whose action is drop/reject -- the venue's
  Access Rules ("Block"), pushed by :mod:`mikrotik_firewall`;
* ``cloudguest-fw-guest-isolation`` -- the routed guard that stops one
  guest reaching another (:mod:`mikrotik_guest_isolation`);
* ``cloudguest-fw-flood-limit`` -- the per-guest connection cap.

Never a row without a Wyfy comment (the venue's own hand-written rules),
never a dynamic row (the hotspot's), never anything in ``input``/``output``.
The input chain is where internet scanners hit the router all day; logging
there would be pure volume about traffic that is not a guest's, and every
Wyfy drop that is about guests already lives in ``forward``. The DNS-bypass
and VPN drops (``cloudguest-dnsf-*``) and the content-filter drops are not
targets either, deliberately, for now: every Android phone retries DoT on
853 continuously, so those rows would fill the budget with lines nobody
acts on. Adding a family is one entry in :data:`TARGET_COMMENTS`.

**Never broader than the drop.** A matcher is copied only if it is in
:data:`_MATCHER_KEYS`. A target carrying any other field this module does
not know is *skipped* (and reported), never logged with a subset of its
matchers -- a companion with fewer matchers would log traffic that is not
dropped and NetLogs would call it "Traffic denied".

## Volume

``limit=2/1s,5:packet`` per companion and at most :data:`MAX_COMPANIONS`
companions per router: a hard ceiling of 20 lines/s (1200/min) after a
one-off burst of 50, against the collector's 3000/min-per-router throttle.
Platform rows (guard, flood) are chosen before Access Rules when the cap
bites; the rest are reported as skipped.

## Identity and convergence

A companion is identified by its comment, ``cloudguest-fwlog:`` + the
target's comment -- the ``cloudguest-`` family (so the provisioning
planner treats it as managed) but never ``cloudguest-fw:`` (colon), so the
Access Rules push neither counts nor refuses it. Rows that share a comment
(one guard row per guest network) are told apart by matchers and position.

:func:`sync_firewall_logging` converges by position: a companion is kept
only if it sits immediately above its target with exactly the desired
fields; otherwise a fresh one is added ``place-before=<target .id>`` and
every companion not kept is removed afterwards. A second sync of an
unchanged chain writes nothing. Turning it off removes every
``cloudguest-fwlog:`` row, wherever it sits, in any chain.

## Read-back, and failing towards silence

Every sync ends by re-reading the chain. If the device does not hold
exactly the desired companions -- a row that came back without its
``limit`` is the case that matters, because that row is unbounded -- every
companion is removed again and the result says ``ok=False`` with the
difference named. The failure mode of this module is "no firewall lines",
never "unbounded firewall lines".

Nothing here has been run against hardware; see the PR's rollout plan.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from librouteros.exceptions import LibRouterosError

from .contract import DeviceCredentials, DeviceVendor
from .mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError
from .mikrotik_firewall import (
    BAND_REASON_NOT_PLACED,
    FLOOD_LIMIT_COMMENT,
    _comment,
    _inspect_band,
    _is_truthy,
    _marker_uuid,
    _norm,
    _read,
)
from .mikrotik_guest_isolation import GUARD_COMMENT

__all__ = [
    "COMPANION_COMMENT_PREFIX",
    "LOG_LIMIT",
    "LOG_PREFIX",
    "MAX_COMPANIONS",
    "TARGET_COMMENTS",
    "FirewallLoggingResult",
    "MikroTikFirewallLogging",
    "companion_fields",
    "read_firewall_logging",
    "sync_firewall_logging",
]

_FILTER_PATH = ("ip", "firewall", "filter")
_CHAIN = "forward"

#: What NetLogs keys on (``device_logs.classifier``). Letters, digits and a
#: hyphen only: it is printed verbatim at the start of the log line.
LOG_PREFIX = "WYFY-FW"
#: Per companion: 2 packets/s sustained, a burst of 5.
LOG_LIMIT = "2/1s,5:packet"
#: Companions per router. With :data:`LOG_LIMIT`, 20 lines/s at most.
MAX_COMPANIONS = 10
COMPANION_COMMENT_PREFIX = "cloudguest-fwlog:"

#: Platform drop rows logged by exact comment, in the order they are chosen
#: when :data:`MAX_COMPANIONS` bites. Access Rules (``cloudguest-fw:<uuid>``)
#: come after these.
TARGET_COMMENTS: tuple[str, ...] = (GUARD_COMMENT, FLOOD_LIMIT_COMMENT)

_BLOCKING = frozenset({"drop", "reject"})

#: Firewall matchers a companion may copy. Every field Wyfy's targets use
#: today, plus the common ones a future target may.
_MATCHER_KEYS: tuple[str, ...] = (
    "protocol",
    "src-address",
    "dst-address",
    "src-port",
    "dst-port",
    "port",
    "in-interface",
    "out-interface",
    "in-interface-list",
    "out-interface-list",
    "src-address-list",
    "dst-address-list",
    "connection-state",
    "connection-limit",
    "hotspot",
)
#: Fields on a row that do not change what it matches.
_NON_MATCHER_KEYS = frozenset(
    {
        ".id",
        ".nextid",
        "chain",
        "action",
        "comment",
        "disabled",
        "dynamic",
        "invalid",
        "bytes",
        "packets",
        "log",
        "log-prefix",
        "reject-with",
    }
)

UNSUPPORTED_MATCHER = "UNSUPPORTED_MATCHER"
OVER_CAP = "OVER_CAP"


@dataclass(frozen=True)
class FirewallLoggingResult:
    """What the device holds after a sync (or a read)."""

    #: What was asked for: companions present (True) or none (False).
    enabled: bool
    #: The read-back matched what was asked for.
    ok: bool
    #: ``ready`` / ``missing`` / ``invalid`` -- the sentinel band.
    band_state: str
    #: Wyfy drop rows that have (or should have) a companion.
    targets: int
    #: ``cloudguest-fwlog:`` rows on the device after the operation.
    companions: int
    added: int = 0
    removed: int = 0
    #: ``(target comment, reason)`` for targets left without a companion.
    skipped: tuple[tuple[str, str], ...] = ()
    detail: str = ""


def _companion_comment(target_comment: str) -> str:
    return f"{COMPANION_COMMENT_PREFIX}{target_comment}"


def _is_companion(row: dict[str, Any]) -> bool:
    return _comment(row).startswith(COMPANION_COMMENT_PREFIX)


def _norm_limit(value: object) -> str | None:
    """RouterOS may print ``2/1s,5:packet`` back as ``2,5:packet`` (one
    second is the default interval)."""
    text = str(value or "").replace(" ", "")
    if not text:
        return None
    rate, _, rest = text.partition(",")
    if rate.endswith("/1s"):
        rate = rate[: -len("/1s")]
    return f"{rate},{rest}" if rest else rate


def _matchers(row: dict[str, Any]) -> dict[str, str] | None:
    """The target's matchers, or None if it carries a field this module
    does not know (it is then skipped, never logged more broadly)."""
    for key, value in row.items():
        if key in _NON_MATCHER_KEYS or key in _MATCHER_KEYS:
            continue
        if value in (None, "", False):
            continue
        return None
    out: dict[str, str] = {}
    for key in _MATCHER_KEYS:
        value = _norm(key, row.get(key))
        if value is not None:
            out[key] = value
    return out


def companion_fields(target: dict[str, Any]) -> dict[str, str] | None:
    """The companion row for ``target``, in API field names, or None when
    its matchers cannot be copied faithfully."""
    matchers = _matchers(target)
    if matchers is None:
        return None
    return {
        "chain": _CHAIN,
        "action": "log",
        **matchers,
        "limit": LOG_LIMIT,
        "log-prefix": LOG_PREFIX,
        "comment": _companion_comment(_comment(target)),
    }


def _is_target(row: dict[str, Any]) -> bool:
    if str(row.get("chain", "")) != _CHAIN:
        return False
    if str(row.get("action", "")) not in _BLOCKING:
        return False
    if _is_truthy(row.get("disabled")) or _is_truthy(row.get("dynamic")):
        return False
    comment = _comment(row)
    return comment in TARGET_COMMENTS or _marker_uuid(comment) is not None


def _companion_matches(row: dict[str, Any], desired: dict[str, str]) -> bool:
    if not _is_companion(row) or _is_truthy(row.get("disabled")):
        return False
    if _comment(row) != desired["comment"]:
        return False
    if str(row.get("action", "")) != "log" or str(row.get("chain", "")) != _CHAIN:
        return False
    if _norm_limit(row.get("limit")) != _norm_limit(desired["limit"]):
        return False
    if str(row.get("log-prefix") or "").strip() != desired["log-prefix"]:
        return False
    return all(
        _norm(key, row.get(key)) == _norm(key, desired.get(key))
        for key in _MATCHER_KEYS
    )


@dataclass(frozen=True)
class _Plan:
    band_state: str
    #: ``(target .id, desired companion)`` for every selected target.
    selected: tuple[tuple[str, dict[str, str]], ...]
    skipped: tuple[tuple[str, str], ...]


def _plan(forward: list[dict[str, Any]]) -> _Plan:
    found = _inspect_band(forward)
    if isinstance(found[0], str):
        state = "missing" if found[0] == BAND_REASON_NOT_PLACED else "invalid"
        return _Plan(band_state=state, selected=(), skipped=())
    begin, end = int(found[0]), int(found[1])
    platform: list[tuple[str, dict[str, str]]] = []
    access: list[tuple[str, dict[str, str]]] = []
    skipped: list[tuple[str, str]] = []
    for row in forward[begin + 1 : end]:
        if not _is_target(row):
            continue
        fields = companion_fields(row)
        if fields is None:
            skipped.append((_comment(row), UNSUPPORTED_MATCHER))
            continue
        bucket = platform if _comment(row) in TARGET_COMMENTS else access
        bucket.append((str(row[".id"]), fields))
    chosen = platform + access
    skipped.extend(
        (fields["comment"][len(COMPANION_COMMENT_PREFIX) :], OVER_CAP)
        for _, fields in chosen[MAX_COMPANIONS:]
    )
    return _Plan(
        band_state="ready",
        selected=tuple(chosen[:MAX_COMPANIONS]),
        skipped=tuple(skipped),
    )


def _kept(
    forward: list[dict[str, Any]], selected: Sequence[tuple[str, dict[str, str]]]
) -> tuple[set[str], list[tuple[str, dict[str, str]]]]:
    """``(companion .ids to keep, targets still needing one)``."""
    index = {str(r[".id"]): i for i, r in enumerate(forward)}
    keep: set[str] = set()
    missing: list[tuple[str, dict[str, str]]] = []
    for target_id, desired in selected:
        i = index[target_id]
        above = forward[i - 1] if i > 0 else None
        if above is not None and _companion_matches(above, desired):
            keep.add(str(above[".id"]))
        else:
            missing.append((target_id, desired))
    return keep, missing


def _all_companion_ids(rows: list[dict[str, Any]]) -> list[str]:
    return [str(r[".id"]) for r in rows if _is_companion(r)]


def _verify(api: Any, *, enabled: bool) -> tuple[_Plan, int, str]:
    """Re-read. Returns (plan, companions on device, problem or "")."""
    rows, forward = _read(api)
    on_device = _all_companion_ids(rows)
    plan = _plan(forward)
    if not enabled:
        problem = ""
        if on_device:
            problem = f"{len(on_device)} companion rule(s) still present"
        return plan, len(on_device), problem
    keep, missing = _kept(forward, plan.selected)
    problems: list[str] = []
    if missing:
        problems.append(
            f"{len(missing)} target(s) without a matching companion directly "
            "above them (a field may not have held, e.g. limit)"
        )
    extra = [i for i in on_device if i not in keep]
    if extra:
        problems.append(f"{len(extra)} unexpected companion rule(s)")
    return plan, len(on_device), "; ".join(problems)


def _remove_all(api: Any) -> int:
    rows, _ = _read(api)
    ids = _all_companion_ids(rows)
    if ids:
        api.path(*_FILTER_PATH).remove(*ids)
    return len(ids)


def read_firewall_logging(api: Any) -> FirewallLoggingResult:
    """Read-only: are companions on the router, and are they exactly what a
    sync would leave? ``enabled`` is "companions present"."""
    rows, forward = _read(api)
    on_device = _all_companion_ids(rows)
    plan = _plan(forward)
    keep, missing = _kept(forward, plan.selected)
    consistent = bool(on_device) and not missing and set(on_device) == keep
    return FirewallLoggingResult(
        enabled=bool(on_device),
        ok=consistent or not on_device,
        band_state=plan.band_state,
        targets=len(plan.selected),
        companions=len(on_device),
        skipped=plan.skipped,
        detail=(
            "off"
            if not on_device
            else "consistent"
            if consistent
            else "companions present but not in the shape a sync leaves"
        ),
    )


def sync_firewall_logging(api: Any, *, enabled: bool) -> FirewallLoggingResult:
    """Converge the companions onto ``enabled``. Adds before removes; a
    read-back that does not match removes every companion again (fail
    towards silence) and reports ``ok=False``."""
    menu = api.path(*_FILTER_PATH)
    rows, forward = _read(api)
    if not enabled:
        ids = _all_companion_ids(rows)
        if ids:
            menu.remove(*ids)
        plan, left, problem = _verify(api, enabled=False)
        return FirewallLoggingResult(
            enabled=False,
            ok=not problem,
            band_state=plan.band_state,
            targets=len(plan.selected),
            companions=left,
            removed=len(ids),
            detail=problem or "removed",
        )

    plan = _plan(forward)
    keep, missing = _kept(forward, plan.selected)
    stale = [i for i in _all_companion_ids(rows) if i not in keep]
    try:
        for target_id, desired in missing:
            menu.add(**desired, **{"place-before": target_id})
        if stale:
            menu.remove(*stale)
        after, count, problem = _verify(api, enabled=True)
    except Exception as exc:  # noqa: BLE001 -- cleaned up, then re-raised
        try:
            _remove_all(api)
        except Exception:  # noqa: BLE001
            raise FirewallLoggingFailed(
                f"{exc}; removing the companion rules also failed", cleaned=False
            ) from exc
        raise FirewallLoggingFailed(str(exc), cleaned=True) from exc

    if problem:
        removed = _remove_all(api)
        _, left, _ = _verify(api, enabled=False)
        return FirewallLoggingResult(
            enabled=True,
            ok=False,
            band_state=after.band_state,
            targets=len(after.selected),
            companions=left,
            added=len(missing),
            removed=len(stale) + removed,
            skipped=after.skipped,
            detail=f"read-back failed: {problem}; every companion rule was "
            "removed again",
        )
    detail = "verified"
    if after.band_state != "ready":
        detail = f"verified; band {after.band_state}, nothing to log"
    elif not after.selected:
        detail = "verified; no Wyfy drop rule to log yet"
    return FirewallLoggingResult(
        enabled=True,
        ok=True,
        band_state=after.band_state,
        targets=len(after.selected),
        companions=count,
        added=len(missing),
        removed=len(stale),
        skipped=after.skipped,
        detail=detail,
    )


class FirewallLoggingFailed(Exception):
    """A write failed part-way. ``cleaned`` says whether every companion was
    removed afterwards (the router then logs nothing extra)."""

    def __init__(self, detail: str, *, cleaned: bool) -> None:
        self.detail = detail
        self.cleaned = cleaned
        super().__init__(detail)


class MikroTikFirewallLogging:
    """Async entry points; ``connect`` is injectable for tests, as in
    :class:`~wyfy_device_gateway.mikrotik_remote_logging.MikroTikRemoteLogging`."""

    def __init__(
        self, connect: Callable[[DeviceCredentials], Any] | None = None
    ) -> None:
        self._connect = connect or MikroTikAdapter()._connect_api  # noqa: SLF001

    async def sync(
        self, creds: DeviceCredentials, *, enabled: bool
    ) -> FirewallLoggingResult:
        return await asyncio.to_thread(
            self._run, creds, lambda api: sync_firewall_logging(api, enabled=enabled)
        )

    async def read(self, creds: DeviceCredentials) -> FirewallLoggingResult:
        return await asyncio.to_thread(self._run, creds, read_firewall_logging)

    def _run(
        self,
        creds: DeviceCredentials,
        op: Callable[[Any], FirewallLoggingResult],
    ) -> FirewallLoggingResult:
        if creds.vendor != DeviceVendor.MIKROTIK:
            raise MikroTikDeviceError(
                creds.host, f"firewall logging: unsupported vendor {creds.vendor}"
            )
        api = self._connect(creds)
        try:
            try:
                return op(api)
            except FirewallLoggingFailed as exc:
                raise MikroTikDeviceError(
                    creds.host, f"firewall logging: {exc.detail}"
                ) from exc
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"firewall logging: {exc}"
                ) from exc
        finally:
            MikroTikAdapter._safe_close(api)  # noqa: SLF001
