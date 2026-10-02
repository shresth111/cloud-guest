"""Guest (client) isolation on a MikroTik router -- "guests can't see each
other" -- over the RouterOS API (8728).

## What a guest-to-guest path looks like, and who can stop it

Guests on one hotspot LAN reach each other in three ways, and a router can
only stop the ones that pass through it:

(a) **Across bridge ports** -- a phone on the access point plugged into
    ``ether2`` talking to a laptop on the access point in ``ether3``. The
    frames cross the router's bridge, so the router can stop them. The
    mechanism is the bridge port ``horizon``: "Set the same value for a group
    of ports, to prevent them from sending data to ports with the same
    horizon value" (RouterOS manual, Bridging and Switching, port
    properties). Every guest-facing port gets the same value; the bridge's
    own CPU port (the ``bridge`` interface, where the router's address,
    DHCP server and hotspot live) has no horizon and so still talks to every
    port. ``/interface bridge filter`` was considered and rejected: bridge
    filter only sees frames that reach the CPU, so on an offloaded port it
    silently filters nothing, and a drop rule written there is a second thing
    to place and clean up.

(b) **Inside one external access point** -- two phones on the same TP-Link.
    The access point switches that itself; the frames never reach the
    router. Nothing here can stop it. Only the access point's own "AP
    isolation" / "client isolation" setting can, and the status says so in
    those words rather than implying otherwise.

(c) **On the router's own radios**, on a model that has them. The radio
    driver forwards client-to-client itself, below the bridge. Legacy
    ``/interface wireless``: ``default-forwarding=no``. RouterOS 7
    ``/interface wifi``: ``datapath.client-isolation=yes`` ("Traffic from an
    isolated client will not be forwarded to other clients", WiFi manual,
    datapath). Neither is on any router of the current fleet (hEX lite has
    no radio), so this half is exercised against the fake transport only.

Plus one routed path: a guest that sends a packet for another guest's
address to the router's MAC (a hand-set route) is forwarded by the router
at layer 3, which no horizon sees. When the router's firewall band is
placed, one ``chain=forward action=drop src-address=<guest net>
dst-address=<guest net>`` row per guest network closes that, at the top of
the band (comment ``cloudguest-fw-guest-isolation``). Without a band it is
not written and the status says ``routed_guard=False`` -- the layer-2
isolation does not depend on it.

## Hardware offload, and why the switch may blink

"Split horizon is a software feature that disables hardware offloading"
(Bridging and Switching, ``horizon``). Once a port carries a horizon its
frames go through the CPU instead of the switch chip. For guest traffic
that costs almost nothing: everything a guest does goes to the internet,
which is routed through the CPU anyway; only port-to-port bridging lost its
fast path, and that is exactly the traffic being stopped.

Turning offload off or on for a port re-programs the switch chip, and the
manual warns that changing switch-related port properties "can trigger a
switch chip reset, temporarily disabling all Ethernet ports that are on the
switch chip". On the fleet's hEX lite (Atheros8227, all five ports on one
chip) that may include the WAN port, so the management connection can
blink. That is why the horizon writes are issued LAST, after every other
write and its read-back, and why a write that loses the connection
reports ``restored=False`` rather than guessing.

## What is never touched

* **The WAN / management path.** A port is excluded when it (or a VLAN on
  it) is an internet uplink: a DHCP or PPPoE client's interface, the
  default route's interface, or a member of the ``WAN`` interface list. A
  port that carries a VLAN interface of its own, or holds an IP address, is
  excluded too -- those are how an access point's own management address is
  usually reached.
* **The bridge's CPU port.** Only ``/interface bridge port`` rows are
  written; the bridge interface itself is never a bridge port and never
  gets a horizon, so DHCP, DNS and the hotspot login keep working.
* **A bridge with VLAN filtering, or a hotspot on a VLAN.** Its ports are
  trunks carrying other networks; isolating them isolates those too. The
  write is refused (``ISOLATION_VLAN_BRIDGE``). VLAN filtering already broke
  a guest LAN once on this fleet (``docs/vlan/BRIDGE_VLAN_FILTERING.md``).
* **A horizon someone else set.** If any port of the guest bridge already
  carries a horizon other than this platform's, the write is refused
  (``ISOLATION_HORIZON_IN_USE``): someone built split-horizon by hand and
  joining their group would change what it does.

## How "only undo what we set" is kept without a comment field

Bridge ports are found by interface, and this platform's horizon is a
fixed, unusual value (:data:`ISOLATION_HORIZON`). A port is only ever moved
from ``none`` to that value -- any other starting value is refused above --
so the previous state of every port this module changed is exactly
``none``, and "ours" is exactly "carries :data:`ISOLATION_HORIZON`". Turning
off returns those ports, and only those, to ``none``.

A radio's previous setting is not implied that way (``default-forwarding``
may have been either value), so it is RECORDED on the router before the
write: an interface list :data:`RECORD_LIST` holds one member per radio
this platform changed, its comment carrying the previous value. The list is
referenced by nothing, so it changes no traffic; it is removed on off.

Every write is read back. A write that fails part-way puts back what this
call changed and reports whether that worked.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from librouteros.exceptions import LibRouterosError

from .contract import (
    GuestIsolationPort,
    GuestIsolationRadio,
    GuestIsolationResult,
    GuestIsolationStatus,
)
from .mikrotik_firewall import (
    BAND_REASON_NOT_PLACED,
    VERIFY_FAILED,
    FirewallPushFailed,
    FirewallRefusal,
    _first_customer_index,
    _inspect_band,
    _is_truthy,
    _norm,
    _read,
    read_router_networks,
)

__all__ = [
    "GUARD_COMMENT",
    "ISOLATION_BRIDGE_CARRIES_WAN",
    "ISOLATION_HORIZON",
    "ISOLATION_HORIZON_IN_USE",
    "ISOLATION_NOTHING_TO_ISOLATE",
    "ISOLATION_NO_HOTSPOT",
    "ISOLATION_VLAN_BRIDGE",
    "RECORD_LIST",
    "apply_guest_isolation",
    "read_guest_isolation",
    "remove_guest_isolation",
]

#: This platform's split-horizon group. Any integer works for RouterOS; an
#: unusual one keeps it from colliding with a hand-built group (people pick
#: 1 or 2), and doubles as the marker for "this platform set it".
ISOLATION_HORIZON = 7319
#: Interface list recording the radios this platform changed, with their
#: previous value in each member's comment.
RECORD_LIST = "cloudguest-guest-isolation"
_RECORD_PREFIX = "cloudguest-iso"
#: The routed-path guard rows, one per guest network, top of the band.
GUARD_COMMENT = "cloudguest-fw-guest-isolation"

ISOLATION_NO_HOTSPOT = "ISOLATION_NO_HOTSPOT"
ISOLATION_VLAN_BRIDGE = "ISOLATION_VLAN_BRIDGE"
ISOLATION_BRIDGE_CARRIES_WAN = "ISOLATION_BRIDGE_CARRIES_WAN"
ISOLATION_HORIZON_IN_USE = "ISOLATION_HORIZON_IN_USE"
ISOLATION_NOTHING_TO_ISOLATE = "ISOLATION_NOTHING_TO_ISOLATE"

_PHYSICAL_TYPES = frozenset({"ether", "wlan", "wifi"})
_RADIO_TYPES = frozenset({"wlan", "wifi"})
_FILTER_PATH = ("ip", "firewall", "filter")


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _rows(api, *segments: str) -> list[dict[str, Any]]:  # noqa: ANN001
    """A menu's rows; ``[]`` for a menu this router does not have (no
    wireless / wifi package, no PPPoE)."""
    try:
        return [dict(r) for r in api.path(*segments)]
    except LibRouterosError:
        return []


def _horizon(row: dict[str, Any]) -> str:
    value = str(row.get("horizon") or "none").strip()
    return value or "none"


def _ours(row: dict[str, Any]) -> bool:
    return _horizon(row) == str(ISOLATION_HORIZON)


@dataclass
class _Radio:
    row_id: str
    interface: str
    kind: str  # "wireless" | "wifi"
    isolated: bool
    supported: bool
    excluded_reason: str | None
    current: str  # the raw value of the field we own, "" when unset


@dataclass
class _View:
    hotspot_interfaces: list[str]
    guest_bridges: list[str]
    guest_networks: tuple[str, ...]
    ports: list[GuestIsolationPort]
    port_ids: dict[str, str]  # interface -> bridge-port .id
    foreign_horizon: list[str]
    radios: list[_Radio]
    record_list_id: str | None
    records: list[dict[str, Any]]
    forward: list[dict[str, Any]]
    band: tuple[int, int] | None
    band_state: str
    refusal: tuple[str, str] | None = None
    stray_ours: list[str] = field(default_factory=list)  # ours outside guest bridges


def _wan_interfaces(
    api,  # noqa: ANN001
    interfaces: dict[str, dict[str, Any]],
    vlans: dict[str, str],
    bridge_ports: list[dict[str, Any]],
) -> set[str]:
    """Every interface that carries the internet uplink (and so the
    management tunnel riding on it). Over-inclusive on purpose: a port wrongly
    kept out of isolation costs a little isolation; a WAN port wrongly put in
    a horizon group costs the router."""
    wan: set[str] = set()
    for row in _rows(api, "ip", "dhcp-client"):
        if row.get("interface"):
            wan.add(str(row["interface"]))
    for row in _rows(api, "interface", "pppoe-client"):
        if row.get("interface"):
            wan.add(str(row["interface"]))
        if row.get("name"):
            wan.add(str(row["name"]))
    for row in _rows(api, "ip", "route"):
        if str(row.get("dst-address")) not in {"0.0.0.0/0", "::/0"}:
            continue
        for key in ("immediate-gw", "gateway"):
            value = str(row.get(key) or "")
            name = value.split("%", 1)[1] if "%" in value else value
            if name in interfaces:
                wan.add(name)
    for row in _rows(api, "interface", "list", "member"):
        if str(row.get("list", "")).upper() == "WAN" and row.get("interface"):
            wan.add(str(row["interface"]))
    # A VLAN or bridge on the uplink: its parent / its ports carry it too.
    changed = True
    while changed:
        changed = False
        for name in list(wan):
            parent = vlans.get(name)
            if parent and parent not in wan:
                wan.add(parent)
                changed = True
            for port in bridge_ports:
                if str(port.get("bridge")) == name and str(port.get("interface")) not in wan:
                    wan.add(str(port.get("interface")))
                    changed = True
    return wan


def _read_view(api) -> _View:  # noqa: ANN001
    interfaces = {str(r.get("name")): r for r in _rows(api, "interface") if r.get("name")}
    bridges = {
        str(r.get("name")): r for r in _rows(api, "interface", "bridge") if r.get("name")
    }
    bridge_ports = _rows(api, "interface", "bridge", "port")
    vlans = {
        str(r.get("name")): str(r.get("interface"))
        for r in _rows(api, "interface", "vlan")
        if r.get("name")
    }
    addressed = {
        str(r.get("interface"))
        for r in _rows(api, "ip", "address")
        if r.get("interface") and not _is_truthy(r.get("disabled"))
    }
    hotspot_interfaces = [
        str(r.get("interface"))
        for r in _rows(api, "ip", "hotspot")
        if r.get("interface") and not _is_truthy(r.get("disabled"))
    ]
    wan = _wan_interfaces(api, interfaces, vlans, bridge_ports)
    vlan_parents = set(vlans.values())
    guest_networks, _, _ = read_router_networks(api)

    _, forward = _read(api)
    found = _inspect_band(forward)
    if isinstance(found[0], str):
        band = None
        band_state = "missing" if found[0] == BAND_REASON_NOT_PLACED else "invalid"
    else:
        band = (int(found[0]), int(found[1]))
        band_state = "ready"

    refusal: tuple[str, str] | None = None
    guest_bridges: list[str] = []
    radio_names: list[str] = []
    for hs in hotspot_interfaces:
        if hs in bridges:
            guest_bridges.append(hs)
        elif hs in vlans and vlans[hs] in bridges:
            refusal = refusal or (
                ISOLATION_VLAN_BRIDGE,
                f"the hotspot runs on VLAN {hs} of bridge {vlans[hs]}; that "
                "bridge's ports are trunks carrying other networks too",
            )
        elif str(interfaces.get(hs, {}).get("type")) in _RADIO_TYPES:
            radio_names.append(hs)
    for name in guest_bridges:
        if _is_truthy(bridges[name].get("vlan-filtering")):
            refusal = refusal or (
                ISOLATION_VLAN_BRIDGE,
                f"bridge {name} has VLAN filtering on; its ports may carry "
                "other networks and are not isolated by this switch",
            )
        if name in wan:
            refusal = refusal or (
                ISOLATION_BRIDGE_CARRIES_WAN,
                f"the guest bridge {name} also carries the internet uplink",
            )

    ports: list[GuestIsolationPort] = []
    port_ids: dict[str, str] = {}
    foreign: list[str] = []
    stray: list[str] = []
    for row in bridge_ports:
        iface = str(row.get("interface") or "")
        bridge = str(row.get("bridge") or "")
        if bridge not in guest_bridges:
            if _ours(row):
                stray.append(iface)
            continue
        info = interfaces.get(iface, {})
        itype = str(info.get("type") or "")
        if iface in wan:
            reason: str | None = "wan"
        elif _is_truthy(row.get("dynamic")):
            reason = "dynamic"
        elif itype not in _PHYSICAL_TYPES:
            reason = "not_physical"
        elif iface in vlan_parents:
            reason = "carries_vlan"
        elif iface in addressed:
            reason = "has_address"
        elif _is_truthy(row.get("disabled")) or _is_truthy(info.get("disabled")):
            reason = "disabled"
        else:
            reason = None
        horizon = _horizon(row)
        if horizon not in ("none", str(ISOLATION_HORIZON)):
            foreign.append(iface)
        hw = row.get("hw-offload")
        ports.append(
            GuestIsolationPort(
                interface=iface,
                bridge=bridge,
                interface_type=itype,
                running=_is_truthy(info.get("running")),
                isolatable=reason is None,
                isolated=_ours(row),
                horizon=horizon,
                excluded_reason=reason,
                hw_offload=None if hw is None else _is_truthy(hw),
            )
        )
        port_ids[iface] = str(row.get(".id"))
        if itype in _RADIO_TYPES and reason in (None, "not_physical"):
            radio_names.append(iface)
    if foreign:
        refusal = refusal or (
            ISOLATION_HORIZON_IN_USE,
            f"port(s) {', '.join(sorted(foreign))} already carry a split-horizon "
            "value someone set by hand",
        )
    if not hotspot_interfaces:
        refusal = (
            ISOLATION_NO_HOTSPOT,
            "this router runs no hotspot, so there is no guest network to isolate",
        )

    radios = _read_radios(api, radio_names)
    lists = [r for r in _rows(api, "interface", "list") if r.get("name") == RECORD_LIST]
    records = [
        r for r in _rows(api, "interface", "list", "member") if r.get("list") == RECORD_LIST
    ]
    view = _View(
        hotspot_interfaces=hotspot_interfaces,
        guest_bridges=guest_bridges,
        guest_networks=tuple(
            n
            for n in guest_networks
            if ipaddress.ip_network(n, strict=False).prefixlen > 0
        ),
        ports=ports,
        port_ids=port_ids,
        foreign_horizon=foreign,
        radios=radios,
        record_list_id=str(lists[0][".id"]) if lists else None,
        records=records,
        forward=forward,
        band=band,
        band_state=band_state,
        refusal=refusal,
        stray_ours=stray,
    )
    if view.refusal is None and len(_isolatable(view)) < 2 and not _supported_radios(view):
        view.refusal = (
            ISOLATION_NOTHING_TO_ISOLATE,
            "the guest network has fewer than two ports this router can "
            "separate and no radio of its own; isolation can only be set on "
            "the access points",
        )
    return view


def _read_radios(api, names: list[str]) -> list[_Radio]:  # noqa: ANN001
    wanted = set(names)
    out: list[_Radio] = []
    for row in _rows(api, "interface", "wireless"):
        name = str(row.get("name") or "")
        if name not in wanted:
            continue
        value = "no" if not _is_truthy(row.get("default-forwarding", "yes")) else "yes"
        out.append(
            _Radio(
                row_id=str(row.get(".id")),
                interface=name,
                kind="wireless",
                isolated=value == "no",
                supported=not _is_truthy(row.get("disabled")),
                excluded_reason="disabled" if _is_truthy(row.get("disabled")) else None,
                current=value,
            )
        )
    profiles = {
        str(r.get("name")): r for r in _rows(api, "interface", "wifi", "datapath")
    }
    for row in _rows(api, "interface", "wifi"):
        name = str(row.get("name") or "")
        if name not in wanted:
            continue
        inline = row.get("datapath.client-isolation")
        profile = profiles.get(str(row.get("datapath") or ""), {})
        effective = inline if inline is not None else profile.get("client-isolation", "no")
        reason = None
        if _is_truthy(row.get("dynamic")):
            reason = "dynamic"
        elif str(row.get("configuration.manager") or "") == "capsman":
            # The controller owns this interface's settings; a local write
            # is overwritten on the next provisioning.
            reason = "capsman"
        elif _is_truthy(row.get("disabled")):
            reason = "disabled"
        out.append(
            _Radio(
                row_id=str(row.get(".id")),
                interface=name,
                kind="wifi",
                isolated=_is_truthy(effective),
                supported=reason is None,
                excluded_reason=reason,
                current="" if inline is None else ("yes" if _is_truthy(inline) else "no"),
            )
        )
    return out


def _isolatable(view: _View) -> list[GuestIsolationPort]:
    return [p for p in view.ports if p.isolatable]


def _supported_radios(view: _View) -> list[_Radio]:
    return [r for r in view.radios if r.supported]


def _guard_fields(network: str) -> dict[str, str]:
    net = _norm("src-address", network) or network
    return {
        "chain": "forward",
        "action": "drop",
        "src-address": net,
        "dst-address": net,
        "comment": GUARD_COMMENT,
    }


def _guard_rows(forward: list[dict[str, Any]]) -> list[int]:
    return [i for i, r in enumerate(forward) if str(r.get("comment") or "") == GUARD_COMMENT]


def _guard_shape(view: _View) -> tuple[dict[str, str], list[str]]:
    """``(network -> kept row .id, stale row .ids)``: a row is kept only when
    it is enabled, matches exactly, and sits inside the band above every
    customer rule (a customer accept above it would exempt traffic)."""
    kept: dict[str, str] = {}
    stale: list[str] = []
    if view.band is None:
        return kept, [str(view.forward[i][".id"]) for i in _guard_rows(view.forward)]
    begin, end = view.band
    first_customer = _first_customer_index(view.forward, begin, end)
    for index in _guard_rows(view.forward):
        row = view.forward[index]
        match = None
        if begin < index < first_customer and not _is_truthy(row.get("disabled")):
            for network in view.guest_networks:
                want = _guard_fields(network)
                if network not in kept and all(
                    _norm(k, row.get(k)) == _norm(k, want[k])
                    for k in ("chain", "action", "src-address", "dst-address")
                ):
                    match = network
                    break
        if match is None:
            stale.append(str(row[".id"]))
        else:
            kept[match] = str(row[".id"])
    return kept, stale


def _status(view: _View) -> GuestIsolationStatus:
    isolatable = _isolatable(view)
    radios = _supported_radios(view)
    between = len(isolatable) >= 2 and all(p.isolated for p in isolatable)
    kept, stale = _guard_shape(view)
    routed = bool(view.guest_networks) and set(kept) == set(view.guest_networks)
    enabled = (
        any(p.isolated for p in view.ports)
        or bool(view.stray_ours)
        or bool(view.records)
        or view.record_list_id is not None
        or bool(_guard_rows(view.forward))
    )
    radios_ok = all(r.isolated for r in radios)
    ports_ok = between or len(isolatable) < 2
    guard_ok = (routed and not stale) if view.band is not None else not stale
    consistent = (
        enabled
        and ports_ok
        and radios_ok
        and guard_ok
        and not view.stray_ours
        and not any(p.isolated and not p.isolatable for p in view.ports)
    )
    return GuestIsolationStatus(
        enabled=enabled,
        consistent=consistent,
        between_ports=between,
        routed_guard=routed,
        band_state=view.band_state,
        hotspot_interfaces=tuple(view.hotspot_interfaces),
        guest_bridges=tuple(view.guest_bridges),
        guest_networks=view.guest_networks,
        ports=tuple(view.ports),
        radios=tuple(
            GuestIsolationRadio(
                interface=r.interface,
                kind=r.kind,
                isolated=r.isolated,
                supported=r.supported,
                excluded_reason=r.excluded_reason,
            )
            for r in view.radios
        ),
        refusal=view.refusal[0] if view.refusal else None,
        refusal_detail=view.refusal[1] if view.refusal else None,
    )


def read_guest_isolation(api) -> GuestIsolationStatus:  # noqa: ANN001
    """Read-only: what the router holds now. Never writes, never repairs."""
    return _status(_read_view(api))


# ---------------------------------------------------------------------------
# Radio writes
# ---------------------------------------------------------------------------


def _radio_set(api, radio: _Radio, *, isolate: bool, previous: str = "") -> None:  # noqa: ANN001
    if radio.kind == "wireless":
        api.path("interface", "wireless").update(
            **{
                ".id": radio.row_id,
                "default-forwarding": "no" if isolate else (previous or "yes"),
            }
        )
        return
    menu = api.path("interface", "wifi")
    if isolate:
        menu.update(**{".id": radio.row_id, "datapath.client-isolation": "yes"})
    elif previous:
        menu.update(**{".id": radio.row_id, "datapath.client-isolation": previous})
    else:
        # It was inherited (unset) before we wrote it. `unset` puts the
        # inheritance back; if this RouterOS refuses it, "no" is the same
        # effective value, because a radio whose profile already isolated
        # it was never changed by this module.
        try:
            list(
                menu(
                    "unset",
                    **{".id": radio.row_id, "value-name": "datapath.client-isolation"},
                )
            )
        except LibRouterosError:
            menu.update(**{".id": radio.row_id, "datapath.client-isolation": "no"})


def _record_comment(radio: _Radio) -> str:
    key = "default-forwarding" if radio.kind == "wireless" else "client-isolation"
    return f"{_RECORD_PREFIX} {radio.kind} {key}={radio.current or 'unset'}"


def _parse_record(comment: str) -> tuple[str, str] | None:
    """``(kind, previous)`` from a record member's comment."""
    parts = comment.split()
    if len(parts) != 3 or parts[0] != _RECORD_PREFIX or "=" not in parts[2]:
        return None
    previous = parts[2].split("=", 1)[1]
    return parts[1], ("" if previous == "unset" else previous)


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def apply_guest_isolation(api) -> GuestIsolationResult:  # noqa: ANN001
    """Turn guest isolation on. Idempotent: an already-isolated router gets
    no write.

    Refuses, writing nothing, on any ``ISOLATION_*`` precondition (see the
    module docstring). Then, in this order: record and isolate the router's
    own radios; add the routed guard rows (band placed only); read all of
    that back; and LAST put the guest ports in the horizon group, one port
    at a time, reading back after. Ports go last because each may reset the
    switch chip for a moment. Any failure undoes what this call wrote and
    raises :class:`FirewallPushFailed` with ``restored`` saying whether the
    undo itself was confirmed."""
    view = _read_view(api)
    if view.refusal is not None:
        raise FirewallRefusal(*view.refusal)

    isolatable = _isolatable(view)
    ports_todo = (
        [p for p in isolatable if not p.isolated] if len(isolatable) >= 2 else []
    )
    # A port that carries our horizon but may no longer be isolated (it
    # became the uplink, got a VLAN or an address) goes back to ``none``.
    ports_release = [p for p in view.ports if p.isolated and not p.isolatable]
    radios_todo = [r for r in _supported_radios(view) if not r.isolated]
    kept, stale = _guard_shape(view)
    guard_todo = (
        [n for n in view.guest_networks if n not in kept] if view.band is not None else []
    )

    filter_menu = api.path(*_FILTER_PATH)
    list_menu = api.path("interface", "list")
    member_menu = api.path("interface", "list", "member")
    port_menu = api.path("interface", "bridge", "port")

    created_list: str | None = None
    added_members: list[str] = []
    changed_radios: list[_Radio] = []
    added_guard: list[str] = []
    changed_ports: list[str] = []
    released_ports: list[str] = []
    try:
        if radios_todo:
            if view.record_list_id is None:
                created_list = str(
                    list_menu.add(
                        name=RECORD_LIST,
                        comment="Wyfy Guest: radios set to guest isolation, "
                        "previous values in member comments",
                    )
                )
            recorded = {str(m.get("interface")) for m in view.records}
            for radio in radios_todo:
                if radio.interface not in recorded:
                    # Recorded BEFORE the write: a connection lost after it
                    # still leaves the previous value on the router.
                    added_members.append(
                        str(
                            member_menu.add(
                                list=RECORD_LIST,
                                interface=radio.interface,
                                comment=_record_comment(radio),
                            )
                        )
                    )
                _radio_set(api, radio, isolate=True)
                changed_radios.append(radio)
        if guard_todo and view.band is not None:
            anchor = str(view.forward[view.band[0] + 1][".id"])
            for network in guard_todo:
                added_guard.append(
                    str(filter_menu.add(**_guard_fields(network), **{"place-before": anchor}))
                )
        if changed_radios or added_guard:
            after = _read_view(api)
            not_isolated = [
                r.interface
                for r in after.radios
                if r.interface in {c.interface for c in changed_radios} and not r.isolated
            ]
            if not_isolated:
                raise FirewallRefusal(
                    VERIFY_FAILED,
                    f"after writing, radio(s) {not_isolated} still forward "
                    "client-to-client",
                )
            now_kept, _ = _guard_shape(after)
            if added_guard and set(now_kept) != set(view.guest_networks):
                raise FirewallRefusal(
                    VERIFY_FAILED,
                    "after writing, the guest-isolation guard rows for "
                    f"{sorted(set(view.guest_networks) - set(now_kept))} were not "
                    "found at the top of the band",
                )
        for port in ports_release:
            port_menu.update(**{".id": view.port_ids[port.interface], "horizon": "none"})
            released_ports.append(port.interface)
        for port in ports_todo:
            port_menu.update(
                **{".id": view.port_ids[port.interface], "horizon": str(ISOLATION_HORIZON)}
            )
            changed_ports.append(port.interface)
        if ports_todo or ports_release:
            after = _read_view(api)
            missing = [
                p.interface
                for p in after.ports
                if p.interface in changed_ports and not p.isolated
            ]
            missing += [
                p.interface
                for p in after.ports
                if p.interface in released_ports and p.isolated
            ]
            if missing:
                raise FirewallRefusal(
                    VERIFY_FAILED,
                    f"after writing, port(s) {missing} are not in the state "
                    "written (horizon on a guest port, none on an excluded one)",
                )
    except Exception as exc:  # noqa: BLE001 -- undone, then re-raised typed
        detail = exc.detail if isinstance(exc, FirewallRefusal) else str(exc)
        restored = _undo(
            api,
            view,
            ports=changed_ports,
            released=released_ports,
            radios=changed_radios,
            guard=added_guard,
            members=added_members,
            created_list=created_list,
        )
        raise FirewallPushFailed(detail, restored=restored) from exc

    # Stale guard rows go only after the new ones are confirmed (fail closed).
    try:
        for row_id in stale:
            filter_menu.remove(row_id)
        if stale:
            _, final = _read(api)
            left = {str(final[i][".id"]) for i in _guard_rows(final)} & set(stale)
            if left:
                raise FirewallRefusal(
                    VERIFY_FAILED, f"stale guard rows {sorted(left)} are still there"
                )
    except Exception as exc:  # noqa: BLE001
        detail = exc.detail if isinstance(exc, FirewallRefusal) else str(exc)
        raise FirewallPushFailed(detail, restored=False) from exc

    return GuestIsolationResult(
        ports_changed=tuple(changed_ports + released_ports),
        radios_changed=tuple(r.interface for r in changed_radios),
        guard_rows_added=len(added_guard),
        guard_rows_removed=len(stale),
    )


def _undo(
    api,  # noqa: ANN001
    before: _View,
    *,
    ports: list[str],
    released: list[str],
    radios: list[_Radio],
    guard: list[str],
    members: list[str],
    created_list: str | None,
) -> bool:
    """Put back exactly what one apply call wrote, then confirm by reading.
    Returns False when any step failed or the re-read disagrees."""
    try:
        port_menu = api.path("interface", "bridge", "port")
        for iface in ports:
            port_menu.update(**{".id": before.port_ids[iface], "horizon": "none"})
        for iface in released:
            port_menu.update(
                **{".id": before.port_ids[iface], "horizon": str(ISOLATION_HORIZON)}
            )
        for radio in radios:
            _radio_set(api, radio, isolate=False, previous=radio.current)
        filter_menu = api.path(*_FILTER_PATH)
        for row_id in guard:
            filter_menu.remove(row_id)
        member_menu = api.path("interface", "list", "member")
        for row_id in members:
            member_menu.remove(row_id)
        if created_list is not None:
            api.path("interface", "list").remove(created_list)
        after = _read_view(api)
    except Exception:  # noqa: BLE001 -- reported as restored=False
        return False
    ports_back = all(
        not p.isolated for p in after.ports if p.interface in set(ports)
    ) and all(p.isolated for p in after.ports if p.interface in set(released))
    radios_back = all(
        r.isolated == next(o.isolated for o in radios if o.interface == r.interface)
        for r in after.radios
        if r.interface in {o.interface for o in radios}
    )
    guard_back = not ({str(after.forward[i][".id"]) for i in _guard_rows(after.forward)} & set(guard))
    list_back = created_list is None or after.record_list_id is None
    return ports_back and radios_back and guard_back and list_back


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------


def remove_guest_isolation(api) -> GuestIsolationResult:  # noqa: ANN001
    """Turn guest isolation off: put back exactly what this platform set.

    * every guard row (by comment, wherever it sits);
    * every recorded radio whose field still holds the value this platform
      wrote goes back to its recorded previous value; one someone changed
      since is left alone and named in ``left_alone``; the record goes;
    * the record list goes;
    * LAST, every bridge port carrying :data:`ISOLATION_HORIZON` -- and only
      those -- goes back to ``none``.

    Needs no band and refuses nothing: taking our own changes off must work
    on a router whose other state someone broke. Confirmed by a re-read; a
    trace left behind raises :class:`FirewallPushFailed` (``restored=False``)
    and a second call continues from where this one stopped."""
    view = _read_view(api)
    filter_menu = api.path(*_FILTER_PATH)
    member_menu = api.path("interface", "list", "member")
    port_menu = api.path("interface", "bridge", "port")

    try:
        guard_ids = [str(view.forward[i][".id"]) for i in _guard_rows(view.forward)]
        for row_id in guard_ids:
            filter_menu.remove(row_id)

        radios_by_name = {r.interface: r for r in view.radios}
        all_radios = {r.interface: r for r in _read_radios(api, [
            str(m.get("interface")) for m in view.records
        ])}
        radios_by_name.update(all_radios)
        restored_radios: list[str] = []
        left_alone: list[str] = []
        for member in view.records:
            iface = str(member.get("interface") or "")
            parsed = _parse_record(str(member.get("comment") or ""))
            radio = radios_by_name.get(iface)
            if parsed is not None and radio is not None:
                kind, previous = parsed
                ours_now = (
                    radio.current == "no" if kind == "wireless" else radio.current == "yes"
                )
                if ours_now:
                    _radio_set(api, radio, isolate=False, previous=previous)
                    restored_radios.append(iface)
                else:
                    left_alone.append(iface)
            elif radio is None and iface:
                left_alone.append(iface)
            member_menu.remove(str(member[".id"]))
        if view.record_list_id is not None:
            api.path("interface", "list").remove(view.record_list_id)

        ports_back: list[str] = []
        for row in _rows(api, "interface", "bridge", "port"):
            if _ours(row):
                port_menu.update(**{".id": str(row[".id"]), "horizon": "none"})
                ports_back.append(str(row.get("interface")))

        after = _read_view(api)
    except FirewallPushFailed:
        raise
    except Exception as exc:  # noqa: BLE001
        raise FirewallPushFailed(str(exc), restored=False) from exc

    left: list[str] = []
    if any(p.isolated for p in after.ports) or after.stray_ours:
        left.append("ports still carry the guest-isolation horizon")
    if _guard_rows(after.forward):
        left.append("guard rows still on the forward chain")
    if after.record_list_id is not None or after.records:
        left.append("the record list is still on the router")
    still = [
        r.interface
        for r in after.radios
        if r.interface in restored_radios and r.current == ("no" if r.kind == "wireless" else "yes")
    ]
    if still:
        left.append(f"radio(s) {still} still isolate clients")
    if left:
        raise FirewallPushFailed("after removing: " + "; ".join(left), restored=False)
    return GuestIsolationResult(
        ports_changed=tuple(ports_back),
        radios_changed=tuple(restored_radios),
        guard_rows_added=0,
        guard_rows_removed=len(guard_ids),
        left_alone=tuple(left_alone),
    )
