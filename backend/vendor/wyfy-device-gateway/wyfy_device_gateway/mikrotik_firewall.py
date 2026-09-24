"""Customer firewall rules on a MikroTik router, over the RouterOS API (8728),
inside the platform's own sentinel band.

## Why a separate module

``mikrotik_adapter.py`` is seven thousand lines and every write in it is a
method that opens its own connection. The firewall writer is the one piece of
this package whose correctness is almost entirely about *ordering* on a live
chain, so it is kept as plain functions over an already-open ``api`` object:
the whole algorithm can be read top to bottom here, and tested against the
write-capable fake transport without a connection helper in the way.
``MikroTikAdapter.sync_firewall_rules`` / ``install_firewall_band`` are the
thin, connection-owning entry points.

## The contract this implements

``cloud-guest-repo/backend/docs/security/PRD.md`` §37.2 and
``docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md`` §5.2-§5.4, §6:

* **Position is never an integer.** Every rule is written
  ``place-before=<.id of cloudguest-fw-band-end>``, ascending by priority.
  A stored index is stale the moment the hotspot service adds or removes one
  of its own dynamic rules, which it does continuously.
* **A push that cannot find both sentinels refuses**
  (``ACCESS_RULES_BAND_MISSING``) and never creates the band mid-push. The
  band is placed by :func:`install_band`, a separate, explicit operation.
* **Identity is the comment** ``cloudguest-fw:<rule uuid>`` and nothing
  else. The customer's name and free-text comment are never written into it.
* **Only our own rows are ever touched**, and only inside the band. A marked
  row outside the band, a malformed marker, or a marker whose uuid this
  platform has no record of refuses the whole push before any write.
* **Fail closed.** Every add is issued before any remove, so a window holds
  two identical rules rather than none.

## Why the band sits where it does

:func:`install_band` places the two sentinels immediately above
``cloudguest-fw-fwd-established`` (the ``connection-state=established,
related`` accept) and nowhere else. Two constraints decide that:

1. **Above the established accept, or the rule is theatre for open flows.**
   A drop below it only ever sees new connections -- a flow already
   established when the rule was pushed keeps flowing. PRD §37.1 records the
   content-filter drop failing exactly this way when it was appended to the
   tail.
2. **The forward chain only, never input.** The 2026-08-16 outage on router
   ``gurugram`` was a blanket WAN-input drop that a plain ``add`` appended
   *above* the WireGuard management accept in ``chain=input``: it ate the
   tunnel's own inbound handshake and the management tunnel never came up
   again. The management tunnel, 8728 and RADIUS are traffic *to* or *from*
   the router itself (``input``/``output``), which ``forward`` never sees.
   This module therefore refuses every chain but ``forward``
   (``ACCESS_RULES_CHAIN_UNSUPPORTED``), and in addition refuses any
   drop/reject that names a ``wg*`` interface or a management port, so a
   rule that looks like it is aimed at the platform's own path is stopped
   even though ``forward`` should never carry it.

The band is anchored on a rule this platform itself writes at provisioning,
found by comment, required to exist exactly once. If it is absent or
duplicated the band is not placed -- the device is not in a shape anyone has
reasoned about, and guessing a position on a live firewall is the failure
this whole design exists to prevent.

## What this does NOT do (stated, not implied)

* **No connectivity-tested auto-revert.** Before converging, the push
  snapshots our own marked rules, and if any write or the post-write
  verification fails it puts that snapshot back. That covers a RouterOS
  error or a half-applied push on a live connection. It does not cover a
  push that *succeeds* and turns out to break traffic, and it cannot restore
  anything if the connection itself dies mid-push -- the caller is told
  ``restored=False`` in that case, never that it was fine.
* **No ``move``.** ``librouteros`` exposes none; a misplaced or changed rule
  is re-added at the right position and the old row removed after.
  Hit counters for that rule restart.
* **No hardware verification yet.** Everything here is exercised against the
  fake RouterOS transport in ``tests/test_mikrotik_firewall.py`` only.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Iterable, Sequence
from typing import Any

from .contract import FirewallBandResult, FirewallFilterRuleConfig, FirewallSyncResult

__all__ = [
    "BAND_ANCHOR_COMMENT",
    "BAND_BEGIN_COMMENT",
    "BAND_END_COMMENT",
    "RULE_MARKER_PREFIX",
    "FirewallPushFailed",
    "FirewallRefusal",
    "install_band",
    "rule_marker",
    "sync_rules",
]

_FILTER_PATH = ("ip", "firewall", "filter")
_MANAGED_CHAIN = "forward"

BAND_BEGIN_COMMENT = "cloudguest-fw-band-begin"
BAND_END_COMMENT = "cloudguest-fw-band-end"
#: The provisioning-time accept the band is placed above. Written by the
#: router setup script; see PRD §37.1's forward-chain print.
BAND_ANCHOR_COMMENT = "cloudguest-fw-fwd-established"
#: ``cloudguest-fw:`` -- note the colon. Every other platform marker in this
#: family (``cloudguest-fw-band-*``, ``cloudguest-fw-fwd-*``,
#: ``cloudguest-fw-allow-wg-mgmt``) uses a hyphen, so none of them can be
#: mistaken for a customer rule.
RULE_MARKER_PREFIX = "cloudguest-fw:"
_MARKER_RE = re.compile(
    r"^cloudguest-fw:"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)

# Refusal codes, named as in TRUSTED_DEVICES_AND_ACCESS_RULES.md §6 where one
# exists there.
BAND_MISSING = "ACCESS_RULES_BAND_MISSING"
BAND_ANCHOR_MISSING = "ACCESS_RULES_BAND_ANCHOR_MISSING"
BAND_PARTIAL = "ACCESS_RULES_BAND_PARTIAL"
MARKER_MALFORMED = "ACCESS_RULES_MARKER_MALFORMED"
MARKER_OUTSIDE_BAND = "ACCESS_RULES_MARKER_OUTSIDE_BAND"
ORPHAN_MARKER = "ACCESS_RULES_ORPHAN_MARKER"
CHAIN_UNSUPPORTED = "ACCESS_RULES_CHAIN_UNSUPPORTED"
WOULD_ORPHAN_MANAGEMENT = "ACCESS_RULES_WOULD_ORPHAN_MANAGEMENT"
WOULD_BREAK_GUEST_PATH = "ACCESS_RULES_WOULD_BREAK_GUEST_PATH"
RULE_INVALID = "ACCESS_RULES_RULE_INVALID"
VERIFY_FAILED = "ACCESS_RULES_VERIFY_FAILED"

_ACTIONS = frozenset({"accept", "drop", "reject"})
_PROTOCOLS = frozenset({"tcp", "udp", "icmp"})
_PORT_PROTOCOLS = frozenset({"tcp", "udp"})
#: Ports whose traffic is this platform's own path to, or through, the
#: router: SSH, Winbox, the RouterOS API (plain and TLS), RADIUS auth/acct,
#: RADIUS CoA, and WireGuard (RouterOS default and the common default).
_MANAGEMENT_PORTS = frozenset({22, 8291, 8728, 8729, 1812, 1813, 3799, 13231, 51820})
_BLOCKING_ACTIONS = frozenset({"drop", "reject"})

#: RouterOS fields this writer owns on its rows, and compares on re-push.
_MANAGED_KEYS = (
    "chain",
    "action",
    "protocol",
    "src-address",
    "dst-address",
    "src-port",
    "dst-port",
    "in-interface",
)
_ADDRESS_KEYS = frozenset({"src-address", "dst-address"})


class FirewallRefusal(Exception):
    """The push was refused before (or instead of) touching the device."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


class FirewallPushFailed(Exception):
    """A write or the post-write verification failed after writing began.

    ``restored`` says whether our own marked rules were put back to the
    snapshot taken before the first write. It is only ``True`` when the
    restore itself completed; a dead connection cannot restore anything.
    """

    def __init__(self, detail: str, *, restored: bool) -> None:
        self.detail = detail
        self.restored = restored
        suffix = (
            "the previous platform rules were restored"
            if restored
            else "the previous platform rules could NOT be restored; the "
            "router may hold a partial rule set"
        )
        super().__init__(f"{detail} ({suffix})")


def rule_marker(rule_id: str) -> str:
    return f"{RULE_MARKER_PREFIX}{rule_id}"


def _is_truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes"}


def _norm_address(value: object) -> str | None:
    """One spelling per network, so a device read-back compares equal.

    RouterOS prints a single host without ``/32``; an operator may type one
    with it, or with host bits set on a network. Both sides of every
    comparison go through here.
    """
    text = str(value or "").strip()
    if not text:
        return None
    network = ipaddress.ip_network(text, strict=False)
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def _norm(key: str, value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if key in _ADDRESS_KEYS:
        try:
            return _norm_address(text)
        except ValueError:
            return text
    return text


def _canonical_uuid(rule_id: str) -> str:
    try:
        return str(uuid.UUID(str(rule_id)))
    except ValueError as exc:
        raise FirewallRefusal(
            RULE_INVALID, f"rule id {rule_id!r} is not a UUID"
        ) from exc


def _validate(rules: Sequence[FirewallFilterRuleConfig]) -> list[FirewallFilterRuleConfig]:
    """Every desired rule checked before a single write, and returned in the
    order they must sit in the band: ascending priority, ties by id."""
    seen: set[str] = set()
    for rule in rules:
        rid = _canonical_uuid(rule.rule_id)
        if rid != rule.rule_id:
            raise FirewallRefusal(
                RULE_INVALID, f"rule id {rule.rule_id!r} is not in canonical form"
            )
        if rid in seen:
            raise FirewallRefusal(RULE_INVALID, f"rule {rid} appears twice")
        seen.add(rid)
        if rule.chain != _MANAGED_CHAIN:
            raise FirewallRefusal(
                CHAIN_UNSUPPORTED,
                f"rule {rid} is in chain={rule.chain}; only chain=forward has a "
                "sentinel band, and input/output rules can cut the platform "
                "off from the router",
            )
        if rule.action not in _ACTIONS:
            raise FirewallRefusal(
                RULE_INVALID, f"rule {rid} has unsupported action {rule.action!r}"
            )
        if rule.protocol is not None and rule.protocol not in _PROTOCOLS:
            raise FirewallRefusal(
                RULE_INVALID,
                f"rule {rid} has unsupported protocol {rule.protocol!r}",
            )
        has_port = rule.src_port is not None or rule.dst_port is not None
        if has_port and rule.protocol not in _PORT_PROTOCOLS:
            raise FirewallRefusal(
                RULE_INVALID,
                f"rule {rid} matches a port without protocol tcp or udp; "
                "RouterOS rejects that",
            )
        addresses: list[str | None] = []
        for label, value in (
            ("source address", rule.src_address),
            ("destination address", rule.dst_address),
        ):
            try:
                addresses.append(_norm_address(value))
            except ValueError as exc:
                raise FirewallRefusal(
                    RULE_INVALID, f"rule {rid} has an invalid {label} {value!r}"
                ) from exc
        if rule.action in _BLOCKING_ACTIONS:
            interface = (rule.in_interface or "").strip().lower()
            ports = {p for p in (rule.src_port, rule.dst_port) if p is not None}
            if interface.startswith("wg") or ports & _MANAGEMENT_PORTS:
                raise FirewallRefusal(
                    WOULD_ORPHAN_MANAGEMENT,
                    f"rule {rid} would {rule.action} traffic on the platform's "
                    "management path (a WireGuard interface or a management "
                    "port). Losing that path is a site visit to recover.",
                )
            narrowing = [
                a
                for a in addresses
                if a is not None and ipaddress.ip_network(a).prefixlen > 0
            ]
            if not narrowing:
                raise FirewallRefusal(
                    WOULD_BREAK_GUEST_PATH,
                    f"rule {rid} would {rule.action} forwarded traffic with no "
                    "source or destination address to narrow it -- on a guest "
                    "network that is a site-wide outage that reads back as a "
                    "correctly created rule",
                )
    return sorted(rules, key=lambda r: (r.priority, r.rule_id))


def _desired_fields(rule: FirewallFilterRuleConfig) -> dict[str, str]:
    fields: dict[str, str] = {"chain": _MANAGED_CHAIN, "action": rule.action}
    if rule.protocol:
        fields["protocol"] = rule.protocol
    src = _norm_address(rule.src_address)
    if src:
        fields["src-address"] = src
    dst = _norm_address(rule.dst_address)
    if dst:
        fields["dst-address"] = dst
    if rule.src_port is not None:
        fields["src-port"] = str(int(rule.src_port))
    if rule.dst_port is not None:
        fields["dst-port"] = str(int(rule.dst_port))
    if rule.in_interface and rule.in_interface.strip():
        fields["in-interface"] = rule.in_interface.strip()
    fields["comment"] = rule_marker(rule.rule_id)
    return fields


def _matches(row: dict[str, Any], desired: dict[str, str]) -> bool:
    if _is_truthy(row.get("disabled")):
        return False
    return all(
        _norm(key, row.get(key)) == _norm(key, desired.get(key))
        for key in _MANAGED_KEYS
    )


def _read(api) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:  # noqa: ANN001
    """All filter rows, and the forward-chain rows, from ONE read."""
    rows = [dict(row) for row in api.path(*_FILTER_PATH)]
    forward = [r for r in rows if str(r.get("chain", "")) == _MANAGED_CHAIN]
    return rows, forward


def _comment(row: dict[str, Any]) -> str:
    return str(row.get("comment", "") or "")


def _locate_band(forward: list[dict[str, Any]]) -> tuple[int, int]:
    begins = [i for i, r in enumerate(forward) if _comment(r) == BAND_BEGIN_COMMENT]
    ends = [i for i, r in enumerate(forward) if _comment(r) == BAND_END_COMMENT]
    if len(begins) != 1 or len(ends) != 1:
        raise FirewallRefusal(
            BAND_MISSING,
            f"chain=forward has {len(begins)} '{BAND_BEGIN_COMMENT}' and "
            f"{len(ends)} '{BAND_END_COMMENT}' rules; exactly one of each is "
            "required. The band is placed once, deliberately, and is never "
            "created at a guessed position during a push.",
        )
    begin, end = begins[0], ends[0]
    if begin > end:
        raise FirewallRefusal(
            BAND_MISSING, "the band's end sentinel sits above its begin sentinel"
        )
    for index in (begin, end):
        if str(forward[index].get("action", "")) != "passthrough":
            raise FirewallRefusal(
                BAND_MISSING,
                f"sentinel '{_comment(forward[index])}' is not "
                "action=passthrough; a sentinel with any other action changes "
                "what the chain does",
            )
    return begin, end


def _marker_uuid(comment: str) -> str | None:
    match = _MARKER_RE.match(comment)
    return match.group(1) if match else None


def _preflight_markers(
    rows: list[dict[str, Any]],
    forward: list[dict[str, Any]],
    begin: int,
    end: int,
    *,
    desired_ids: set[str],
    known_rule_ids: frozenset[str],
) -> None:
    """Refuse the whole push, naming the row, when a marker is not one this
    push can reason about. Nothing is written if this raises."""
    band_ids = {forward[i].get(".id") for i in range(begin + 1, end)}
    for row in rows:
        comment = _comment(row)
        if not comment.startswith(RULE_MARKER_PREFIX):
            continue
        rid = _marker_uuid(comment)
        if rid is None:
            raise FirewallRefusal(
                MARKER_MALFORMED,
                f"row {row.get('.id')} carries {comment!r}, which starts like a "
                "platform marker but is not one; someone edited it by hand",
            )
        if row.get(".id") not in band_ids:
            raise FirewallRefusal(
                MARKER_OUTSIDE_BAND,
                f"platform rule {rid} (row {row.get('.id')}, "
                f"chain={row.get('chain')}) sits outside the sentinel band; "
                "something other than this writer put it there",
            )
        if rid not in desired_ids and rid not in known_rule_ids:
            raise FirewallRefusal(
                ORPHAN_MARKER,
                f"platform rule {rid} (row {row.get('.id')}) is on the device "
                "but in no firewall rule this platform holds for this router; "
                "either a second system is writing here or the rule outlived "
                "its record",
            )


_RESTORE_KEYS = (*_MANAGED_KEYS, "comment")


def _snapshot(forward: list[dict[str, Any]], begin: int, end: int) -> list[dict[str, str]]:
    snapshot: list[dict[str, str]] = []
    for row in forward[begin + 1 : end]:
        if _marker_uuid(_comment(row)) is None:
            continue
        copy = {
            key: str(row[key])
            for key in _RESTORE_KEYS
            if row.get(key) not in (None, "")
        }
        copy["disabled"] = "yes" if _is_truthy(row.get("disabled")) else "no"
        snapshot.append(copy)
    return snapshot


def _ours_in_band(
    forward: list[dict[str, Any]], begin: int, end: int
) -> list[tuple[str, str]]:
    """``(row .id, rule uuid)`` for every platform rule inside the band, in
    chain order."""
    out: list[tuple[str, str]] = []
    for row in forward[begin + 1 : end]:
        rid = _marker_uuid(_comment(row))
        if rid is not None:
            out.append((str(row[".id"]), rid))
    return out


def _converge(
    menu,  # noqa: ANN001
    forward: list[dict[str, Any]],
    begin: int,
    end: int,
    desired: list[FirewallFilterRuleConfig],
) -> tuple[int, int]:
    """Bring the band to exactly ``desired``, in order. Returns (added, removed).

    Walks the desired list from the LAST rule to the first. The anchor starts
    as band-end; a rule already on the device with identical fields that sits
    anywhere above the current anchor is kept and becomes the new anchor,
    otherwise a fresh copy is added ``place-before=<anchor>``. That makes the
    final order correct without ever needing ``move``, and makes an unchanged
    re-push issue no writes at all.

    Every add happens before any remove.
    """
    order = [str(row[".id"]) for row in forward]
    rows_by_id = {str(row[".id"]): row for row in forward}
    candidates: dict[str, list[str]] = {}
    for row_id, rid in _ours_in_band(forward, begin, end):
        candidates.setdefault(rid, []).append(row_id)

    kept: set[str] = set()
    added = 0
    anchor = str(forward[end][".id"])
    for rule in reversed(desired):
        want = _desired_fields(rule)
        anchor_pos = order.index(anchor)
        chosen = None
        for row_id in reversed(candidates.get(rule.rule_id, [])):
            if row_id in kept:
                continue
            if order.index(row_id) < anchor_pos and _matches(rows_by_id[row_id], want):
                chosen = row_id
                break
        if chosen is None:
            new_id = str(menu.add(**want, disabled="no", **{"place-before": anchor}))
            order.insert(anchor_pos, new_id)
            rows_by_id[new_id] = {**want, ".id": new_id, "disabled": "no"}
            chosen = new_id
            added += 1
        kept.add(chosen)
        anchor = chosen

    stale = [
        row_id
        for row_ids in candidates.values()
        for row_id in row_ids
        if row_id not in kept
    ]
    for row_id in stale:
        menu.remove(row_id)
    return added, len(stale)


def _verify(api, expected: list[str]) -> tuple[str, ...]:  # noqa: ANN001
    """Re-read and check the structural result. Not a data-plane test."""
    rows, forward = _read(api)
    try:
        begin, end = _locate_band(forward)
    except FirewallRefusal as exc:
        raise FirewallRefusal(VERIFY_FAILED, f"after writing: {exc.detail}") from exc
    in_band = [rid for _, rid in _ours_in_band(forward, begin, end)]
    if in_band != expected:
        raise FirewallRefusal(
            VERIFY_FAILED,
            f"after writing, the band holds {in_band} but {expected} was "
            "expected, in that order",
        )
    total_marked = sum(
        1 for row in rows if _comment(row).startswith(RULE_MARKER_PREFIX)
    )
    if total_marked != len(expected):
        raise FirewallRefusal(
            VERIFY_FAILED,
            f"after writing, {total_marked} platform rules exist but only "
            f"{len(expected)} are inside the band",
        )
    return tuple(in_band)


def _restore(api, snapshot: list[dict[str, str]]) -> None:  # noqa: ANN001
    """Put our own marked rules back to ``snapshot``, fail-closed: the
    snapshot rows are added first, and only then is every other marked row
    in the band removed."""
    menu = api.path(*_FILTER_PATH)
    _, forward = _read(api)
    begin, end = _locate_band(forward)
    end_id = str(forward[end][".id"])
    before = [row_id for row_id, _ in _ours_in_band(forward, begin, end)]
    for fields in snapshot:
        menu.add(**fields, **{"place-before": end_id})
    for row_id in before:
        menu.remove(row_id)


def sync_rules(
    api,  # noqa: ANN001
    rules: Sequence[FirewallFilterRuleConfig],
    *,
    known_rule_ids: Iterable[str],
) -> FirewallSyncResult:
    """Converge the router's forward-chain band onto ``rules``.

    ``rules`` is the complete desired set for this router -- a platform rule
    in the band whose id is not in it is removed. ``known_rule_ids`` is every
    rule id this platform holds for the router, including disabled and
    deleted ones: a marker outside that set is an orphan and refuses the push.

    Order of operations: one read; locate the band; validate every rule;
    preflight every marker; snapshot our rows; converge (adds, then removes);
    verify by re-reading. A failure after writing began restores the
    snapshot and raises :class:`FirewallPushFailed`.
    """
    menu = api.path(*_FILTER_PATH)
    rows, forward = _read(api)
    begin, end = _locate_band(forward)
    desired = _validate(rules)
    desired_ids = {rule.rule_id for rule in desired}
    known = frozenset(str(k) for k in known_rule_ids)
    _preflight_markers(
        rows, forward, begin, end, desired_ids=desired_ids, known_rule_ids=known
    )
    snapshot = _snapshot(forward, begin, end)
    expected = [rule.rule_id for rule in desired]

    try:
        added, removed = _converge(menu, forward, begin, end, desired)
        ordered = _verify(api, expected)
    except Exception as exc:  # noqa: BLE001 -- restored, then re-raised typed
        detail = exc.detail if isinstance(exc, FirewallRefusal) else str(exc)
        try:
            _restore(api, snapshot)
        except Exception as restore_exc:  # noqa: BLE001
            raise FirewallPushFailed(
                f"{detail}; restore also failed: {restore_exc}", restored=False
            ) from exc
        raise FirewallPushFailed(detail, restored=True) from exc

    return FirewallSyncResult(
        added=added,
        removed=removed,
        unchanged=len(desired) - added,
        ordered_rule_ids=ordered,
    )


def install_band(api) -> FirewallBandResult:  # noqa: ANN001
    """Place the forward-chain sentinel band, once, immediately above the
    platform's own established/related accept. See the module docstring for
    why there and only there.

    * Both sentinels already present, once each, in order, passthrough: left
      exactly where they are (``created=False``). A later call never
      recomputes the band's position.
    * One present without the other, or duplicates: refused
      (``ACCESS_RULES_BAND_PARTIAL``). Someone removed half of it by hand,
      and which half to trust is a human decision.
    * The anchor absent or present more than once: refused
      (``ACCESS_RULES_BAND_ANCHOR_MISSING``). Nothing is written.
    """
    menu = api.path(*_FILTER_PATH)
    _, forward = _read(api)
    begins = [r for r in forward if _comment(r) == BAND_BEGIN_COMMENT]
    ends = [r for r in forward if _comment(r) == BAND_END_COMMENT]
    if begins or ends:
        if len(begins) != 1 or len(ends) != 1:
            raise FirewallRefusal(
                BAND_PARTIAL,
                f"chain=forward has {len(begins)} begin and {len(ends)} end "
                "sentinels; a partial band is not repaired automatically",
            )
        # Present once each: still refused if inverted or not passthrough.
        begin, end = _locate_band(forward)
        return FirewallBandResult(
            created=False,
            begin_id=str(forward[begin][".id"]),
            end_id=str(forward[end][".id"]),
            anchor_id=None,
        )

    anchors = [r for r in forward if _comment(r) == BAND_ANCHOR_COMMENT]
    if len(anchors) != 1 or str(anchors[0].get("action", "")) != "accept":
        raise FirewallRefusal(
            BAND_ANCHOR_MISSING,
            f"expected exactly one accept rule commented "
            f"'{BAND_ANCHOR_COMMENT}' in chain=forward, found {len(anchors)}; "
            "the band is only ever placed relative to that rule",
        )
    anchor_id = str(anchors[0][".id"])
    begin_id = str(
        menu.add(
            chain=_MANAGED_CHAIN,
            action="passthrough",
            comment=BAND_BEGIN_COMMENT,
            **{"place-before": anchor_id},
        )
    )
    end_id = str(
        menu.add(
            chain=_MANAGED_CHAIN,
            action="passthrough",
            comment=BAND_END_COMMENT,
            **{"place-before": anchor_id},
        )
    )

    _, after = _read(api)
    ids = [str(r[".id"]) for r in after]
    placed = (
        begin_id in ids
        and end_id in ids
        and anchor_id in ids
        and ids.index(begin_id) + 1 == ids.index(end_id)
        and ids.index(end_id) + 1 == ids.index(anchor_id)
    )
    if not placed:
        # Passthrough rules change nothing, so removing them is safe; leaving
        # a band in an unverified place is not.
        for row_id in (end_id, begin_id):
            if row_id in ids:
                menu.remove(row_id)
        raise FirewallRefusal(
            VERIFY_FAILED,
            "the sentinels did not land directly above "
            f"'{BAND_ANCHOR_COMMENT}' and were removed again",
        )
    return FirewallBandResult(
        created=True, begin_id=begin_id, end_id=end_id, anchor_id=anchor_id
    )
