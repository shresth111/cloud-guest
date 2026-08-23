"""RouterOS script renderers for basic WAN profiles.

THIS MODULE IS THE SECOND GENERATOR OF THE SAME SIX SCRIPT SECTIONS
==================================================================
The first is ``buildRouterSetupScriptChunks`` in the frontend's
``src/components/routers/RouterDetailTabs.tsx``. The two are NOT
interchangeable and neither can be deleted in favour of the other:

* the frontend one renders from a form, for a technician to PASTE into a
  WinBox/SSH console on a factory-fresh box that has no tunnel and no
  agent -- the only path that can get a bare router onto the network at
  all;
* this one renders from stored ``isp_links`` rows, is recorded as an
  audited provisioning *version*, and is PUSHED unattended over the
  device gateway (``MikroTikAdapter.push_config`` -> SFTP upload +
  ``/import file-name=...``). It is what the Fleet Wizard's "WAN Apply"
  step runs. It also renders a link's ``pppoe_password``, which is
  exactly why it must not be built in a browser.

They therefore drift, and they did: this module was a copy of the
frontend chunks taken before frontend PRs #129-#132 and then frozen, so
for three days every fix landed on the paste path and none of them
reached the wizard. ``tests/unit/test_wan_render_invariants.py`` is the
answer to that -- it enforces, by name, the same guard list the frontend
suite's own sections enforce. When a guard changes on either side, add
it there too and say so.

WHAT ``/import`` MEANS FOR THIS FILE, MEASURED NOT ASSUMED
----------------------------------------------------------
``push_config`` uploads this text as a file and runs ``/import`` on it
(``vendor/wyfy-device-gateway/wyfy_device_gateway/mikrotik_adapter.py``
:meth:`push_config`). Three consequences drive every shape below.

1. ``/import`` NEVER PAUSES. The frontend learned this on a
   factory-fresh hEX (2026-08-21): reading a DHCP lease immediately
   after adding the client returns nothing, because the lease does not
   exist yet, and the route below it then lands with gateway
   ``0.0.0.0``, flag ``Is`` (Inactive), on a router whose WAN is
   perfectly healthy. A human pasting chunk-by-chunk never sees this --
   typing delay is what lets DHCP bind. An ``/import`` has no typing
   delay, so this path is MORE exposed than the paste path, not less,
   and every asynchronous source here polls.

2. ``/import`` ABORTS THE REST OF THE FILE ON THE FIRST ERROR. So every
   read that can legitimately fail on a healthy router -- ``dhcp-client
   get`` on a client with no lease yet, ``pppoe-client monitor`` on a
   session still dialing, ``/ip route set`` on a *dynamic* route -- is
   wrapped in ``:do {} on-error={}``. Unwrapped, one of them takes every
   later section down with it and the push still reports success.

3. NOTHING THIS SCRIPT ``:put``s IS EVER SEEN BY ANYONE.
   ``_run_ssh_command`` binds the result and checks ``exit_status``
   only; stdout is discarded and never stored on the job. So the device
   log is the ONLY channel that reaches a human here, and every
   diagnostic below is ``:log``, not ``:put``. (The frontend's chunks
   use ``:put`` because a technician is standing at the console reading
   it. That is the one place the two generators deliberately differ.)

SHAPE RULES, kept identical to the frontend's even where ``/import``
would tolerate more, so this output is safe if it is ever pasted too:
every ``:local`` is bound and read on the SAME emitted line, and every
``do={}`` body holds exactly ONE statement.

THE ``routing-mark=""`` DEFECT
------------------------------
Measured on the founder's hEX lite, RouterOS 7.23.3 (factory-software
6.44.6, so it shipped on v6 and was upgraded)::

    :put [:len [/ip route find where routing-table="main"]]  ->  1
    :put [:len [/ip route find where routing-mark=""]]       ->  0

``routing-mark=`` is RouterOS 6 vocabulary for a route's table. On v7 it
does not error -- it is taken as an unknown filter and SILENTLY MATCHES
AN EMPTY SET. Every default-route lookup this module emitted returned
nothing on every v7 router in the fleet and nothing anywhere said so.
Renaming the token fixes today's instance and nothing about the next
one, so every route lookup here also COUNTS its filter and branches on
zero, saying out loud that the filter matched nothing and naming a stale
filter name as one of the two possible causes.

``new-routing-mark=`` on ``/ip firewall mangle`` is a DIFFERENT property
and keeps its name on v7 -- only ``/ip route``'s own property was
renamed. :func:`render_wan_mangle_section` is deliberately untouched.
"""

from __future__ import annotations

from app.domains.isp.constants import IspConnectionMode, WanRoutingMode

from .context import WanRenderContext, WanRenderLink
from .pcc import build_weighted_pcc_plan

WAN_RENAME_WARNING = (
    "# WAN interfaces must already exist on the device under the names "
    "configured in WyFyGuest -- do NOT rename interfaces to match this script."
)

#: RouterOS 7's name for a route's routing table, and the filter that
#: selects the MAIN one. See this module's docstring for the measurement.
ROUTE_MAIN_TABLE_FILTER = 'routing-table="main"'

#: The property name used when CREATING a route in a non-main table.
#: Same v7 rename as :data:`ROUTE_MAIN_TABLE_FILTER`.
ROUTE_TABLE_PROPERTY = "routing-table"

#: How many times a DHCP WAN is asked for its gateway before giving up,
#: and how long between attempts. ``/import`` never pauses (docstring
#: point 1), so without this the route lands on an unbound lease.
WAN_DHCP_GW_POLL_ATTEMPTS = 6
WAN_DHCP_GW_POLL_DELAY_S = 5

#: Same, for PPPoE: ``remote-address`` on a session still in
#: ``dialing``/``authenticating`` is not there to read.
WAN_PPPOE_GW_POLL_ATTEMPTS = 6
WAN_PPPOE_GW_POLL_DELAY_S = 5

#: Chunk-wide waiting budget shared across every WAN with an asynchronous
#: source. A single-WAN router gets the lot. Bounded because the gateway
#: holds an SSH session open for the whole ``/import`` and a four-WAN
#: script with a full ladder each would sit there for minutes.
WAN_GW_POLL_BUDGET_S = 45

#: Comments tagging the two objects bound to the interface this script
#: DISCOVERED, as opposed to the one stored on the ISP link. They are
#: also the only handle used to find those objects again on a re-run: an
#: operator's own masquerade or list member carries neither tag and is
#: therefore never read, re-pointed or removed.
DISCOVERED_WAN_LIST_COMMENT = "cloudguest-wanlist-live"
DISCOVERED_NAT_COMMENT = "cloudguest-nat-live"


def _escape_routeros_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _gateway_usable_expr(var_name: str) -> str:
    """RouterOS boolean: ``$<var>`` holds something usable as a gateway.

    ``"0.0.0.0" != ""`` is TRUE, and a zero gateway is exactly what
    ``/ip route add`` accepts and then silently flags Inactive -- so the
    zero case is rejected by name rather than by an emptiness test."""
    return f'${var_name} != "" && ${var_name} != "0.0.0.0"'


def _bounded_retry_ladder(
    *,
    attempt: str,
    unresolved: str,
    attempts: int,
    delay: str,
    attempt_precondition: str | None = None,
) -> list[str]:
    """An unrolled attempt/wait ladder.

    Not a ``:for`` loop: a loop cannot express "attempt, and only wait if
    it did not work" while keeping every ``do={}`` body to one statement,
    and a ``;``-chained pair inside an inline ``do={}`` threw a real
    syntax error on live hardware. ``attempt_precondition`` is folded
    into the SAME ``:if`` rather than nested, for the same rule."""
    retry_when = f"({unresolved}) && {attempt_precondition}" if attempt_precondition else unresolved
    stmts: list[str] = []
    for _ in range(1, attempts):
        stmts.append(f":if ({unresolved}) do={{ :delay {delay} }}")
        stmts.append(f":if ({retry_when}) do={{ {attempt} }}")
    return stmts


def _poll_attempts(*, maximum: int, delay_seconds: int, polling_wans: int) -> int:
    """This WAN's share of :data:`WAN_GW_POLL_BUDGET_S`, floored at 2 so a
    busy multi-WAN router still retries at least once."""
    share = 1 + WAN_GW_POLL_BUDGET_S // (delay_seconds * max(polling_wans, 1))
    return max(2, min(maximum, share))


def _routeros_version_check_statements() -> list[str]:
    """Say which RouterOS dialect this script speaks, and check the device
    agrees.

    Not a fork. This module emits v7 vocabulary only (see
    :data:`ROUTE_MAIN_TABLE_FILTER`); this exists so a device that is NOT
    v7 -- or whose version cannot be read at all -- leaves a log line
    naming what will not work, instead of running a script that reports
    success having matched nothing. Both the wrong-version and the
    unknown-version cases take the loud branch; only a confirmed "7" is
    quiet. ``[:find]`` returning nothing would make ``:pick`` error, so
    the major-version parse is wrapped rather than trusted."""
    return [
        ':local rosVer ""',
        ':do { :set rosVer [:tostr [/system resource get version]] } '
        'on-error={ :set rosVer "" }',
        ':local rosMajor ""',
        ':do { :set rosMajor [:pick $rosVer 0 [:find $rosVer "."]] } '
        'on-error={ :set rosMajor "" }',
        ':if ($rosMajor = "7") do={ :log info ("cloudguest: RouterOS " . $rosVer '
        '. " -- using routing-table= route syntax") }',
        ':if ($rosMajor != "7") do={ :log warning ("cloudguest: RouterOS major version '
        'is \\"" . $rosMajor . "\\", not 7 -- this script uses v7 route syntax '
        '(routing-table=). On v6 the property is routing-mark=, and a find using the '
        'wrong one MATCHES NOTHING WITHOUT ERRORING, so this run\'s route lookups may '
        'have silently matched nothing") }',
    ]


def _routing_table_preamble_lines(table_names: list[str]) -> list[str]:
    """v7 will not accept a route into a routing table that has not been
    declared, so every ``to_wan<N>`` table routed into is created first.

    Idempotent by explicit count, and the count is branched on zero:
    ``/routing table add`` on an existing name errors, and a ``find``
    against a menu a RouterOS version does not have returns empty in
    silence, so "we made it" is never inferred -- it is counted and
    stated. The tables are NOT removed anywhere, including by the
    failover-only cleanup: an empty routing table costs nothing, and a
    name another operator might also be using is not this script's to
    delete."""
    lines: list[str] = []
    for name in table_names:
        missing = f'[:len [/routing table find where name="{name}"]] = 0'
        lines.append(
            f":if ({missing}) do={{ :do {{ /routing table add name=\"{name}\" fib }} "
            f'on-error={{ :log warning "cloudguest: could not create routing table {name} '
            "-- on RouterOS 7 a route cannot enter a table that does not exist, so this "
            'WAN\'s load-balancing routes will not be created" } }'
        )
        lines.append(
            f':if ({missing}) do={{ :log warning "cloudguest: routing table {name} does '
            'not exist after trying to create it -- load balancing will not work" }'
        )
    return lines


def _uplink_discovery_statements(prefix: str, *, with_gateway: bool = False) -> list[str]:
    """Work out, live on the device, which interface is actually carrying
    the internet -- and optionally its next hop.

    This is the authoritative source, and it is authoritative for every
    WAN mode alike: if there is an ACTIVE default route in the MAIN table
    then that route IS how this router reaches the internet right now,
    and its next hop IS a usable gateway. No assumption about a named
    port is involved, which is what makes it the correct fallback for a
    link running on a VLAN sub-interface, an SFP port, a renamed port, or
    a link the operator brought up some other way entirely.

    Both qualifiers on every lookup, and neither is stylistic:

    * ``active=yes`` -- RouterOS keeps an unreachable default route in
      the table and flags it Inactive rather than removing it, so an
      unqualified count says "1 route, looks healthy" about a router
      whose every ping says ``no route to host``.
    * ``routing-table="main"`` -- this module itself adds a
      ``routing-table="to_wan<N>"`` default route per WAN plus a
      ``distance=2`` crossover backup per WAN in load-balance mode.
      Those live in their own tables and are active there
      simultaneously, so an unqualified find returns a handful of routes
      across several tables and "the first one" is whichever table
      happened to sort first.

    THE ZERO BRANCH IS PART OF THIS BUILDER'S CONTRACT, not an optional
    extra. A ``find`` whose filter name RouterOS no longer recognises
    returns an empty set without erroring, so "0 routes" and "this script
    is speaking the wrong dialect" are indistinguishable from the value
    alone. The branch is emitted HERE rather than left to the caller,
    because a caller that binds the count and forgets to read it is
    exactly how a silent empty match ships.

    Distances are swept 1..255 ASCENDING and the first hit wins -- the
    lowest-distance route, which is the one RouterOS itself prefers -- so
    the choice cannot silently depend on route order. The result is then
    VERIFIED to be a real interface (``/interface find where name=...``)
    or discarded back to ``""``: every inference degrades to "not
    resolved", a state the caller reports as a distinct fault, rather
    than to a plausible-looking wrong interface name.

    Every local is prefixed so several copies can coexist on one emitted
    line."""
    p = prefix
    qualified = f'/ip route find where dst-address="0.0.0.0/0" active=yes {ROUTE_MAIN_TABLE_FILTER}'
    if_exists = f"[:len [/interface find where name=${p}If]] > 0"
    stmts = [
        f':local {p}If ""',
        f":local {p}DefCount [:len [{qualified}]]",
        f':if (${p}DefCount = 0) do={{ :log warning "cloudguest: 0 active main-table '
        'default routes -- no uplink, or a filter name this RouterOS build rejects" }',
        f":for {p}Dist from=1 to=255 do={{ :if (${p}If = \"\") do={{ "
        f":foreach {p}R in=[{qualified} distance=${p}Dist] do={{ "
        f':if (${p}If = "") do={{ :do {{ :set {p}If [:tostr [/ip route get ${p}R '
        f"immediate-gw]] }} on-error={{ :do {{ :set {p}If [:tostr [/ip route get "
        f'${p}R gateway]] }} on-error={{ :set {p}If "" }} }} }} }} }} }}',
        f':if ([:typeof [:find ${p}If "%"]] != "nil") do={{ :set {p}If '
        f'[:pick ${p}If ([:find ${p}If "%"] + 1) [:len ${p}If]] }}',
        f':if (${p}If != "" && !({if_exists})) do={{ :do {{ :set {p}If '
        f"[:tostr [/ip arp get [find where address=${p}If] interface]] }} "
        f'on-error={{ :set {p}If "" }} }}',
        f':if (${p}If != "" && !({if_exists})) do={{ :set {p}If "" }}',
    ]
    if with_gateway:
        stmts.extend(
            [
                f':local {p}Gw ""',
                f":for {p}GwDist from=1 to=255 do={{ :if (${p}Gw = \"\") do={{ "
                f":foreach {p}GwR in=[{qualified} distance=${p}GwDist] do={{ "
                f':if (${p}Gw = "") do={{ :do {{ :set {p}Gw [:tostr [/ip route get '
                f'${p}GwR gateway]] }} on-error={{ :set {p}Gw "" }} }} }} }} }}',
            ]
        )
    return stmts


def _wan_existence_check_lines(physical_names: list[str]) -> list[str]:
    """Note, without aborting, any configured WAN interface that does not
    exist on this device under that exact name.

    THIS USED TO ``:error``, and that was wrong. A perfectly online
    router legitimately carries its uplink on a name this platform's
    ``isp_links`` row does not have -- a VLAN sub-interface, an SFP port,
    a renamed port, a PPPoE virtual interface an engineer named
    themselves. Under ``/import`` an ``:error`` here aborted the ENTIRE
    remaining script (addressing, routing, mangle, DNS -- everything) on
    a router that needed none of it aborted. :func:`render_wan_routing_section`
    now resolves the live uplink from the routing table instead, which is
    correct whatever the interface is called, so this is a log line and
    the script continues."""
    lines: list[str] = []
    for name in physical_names:
        expr = f'"{_escape_routeros_string(name)}"'
        missing = f"[:len [/interface find where name={expr}]] = 0"
        lines.append(
            f":if ({missing}) do={{ :log warning (\"cloudguest: configured WAN interface \" "
            f". {expr} . \" does not exist on this device -- continuing, and resolving the \" "
            f'. "real uplink from the active default route instead") }}'
        )
    return lines


def render_wan_bridge_section(ctx: WanRenderContext) -> list[str]:
    lines = [WAN_RENAME_WARNING]
    lan = _escape_routeros_string(ctx.lan_bridge)
    lines.append(
        ':if ([:len [/interface list find where name="WAN"]] = 0) do={ '
        '/interface list add name="WAN" }'
    )
    lines.append(
        f':if ([:len [/interface bridge find where name="{lan}"]] = 0) do={{ '
        f'/interface bridge add name="{lan}" }}'
    )
    lines.append(f'/interface bridge set [find name="{lan}"] disabled=no')
    # COUNT BOTH, DO NOT INFER EITHER. A router reset with the hardware
    # button held long enough comes up with NO default configuration: no
    # bridge, no WAN/LAN interface lists, no defconf firewall. Both adds
    # above are `:if ([:len [find]] = 0) do={ add }`, silent when they
    # fire AND silent when they do not, and the `set [find ...]` on an
    # empty match succeeds while touching nothing. Every section below
    # binds to one or both of these by name, so if either is missing here
    # a dozen later finds quietly match nothing and the push reports
    # success having built nothing.
    lines.append(
        "; ".join(
            [
                ':local wanListN [:len [/interface list find where name="WAN"]]',
                f':local lanBrN [:len [/interface bridge find where name="{lan}"]]',
                ":if ($wanListN > 0 && $lanBrN > 0) do={ :log info "
                f'("cloudguest: WAN interface list and LAN bridge {lan} both present") }}',
                ":if (!($wanListN > 0 && $lanBrN > 0)) do={ :log warning "
                f'"cloudguest: WAN interface list or LAN bridge {lan} is missing after the '
                "WAN + Bridge section -- every later section matches on these two by name, "
                'and a find that matches nothing is SILENT on RouterOS" }',
            ]
        )
    )
    lines.extend(
        _wan_existence_check_lines([link.physical_interface for link in ctx.links])
    )
    for link in ctx.links:
        n = link.slot
        phys = _escape_routeros_string(link.physical_interface)
        # `:foreach` over the find-set, NOT `:local wan<N>Port` on one line
        # and `:if ([:len $wan<N>Port] > 0)` on the next. `/import` would
        # tolerate the split, but the same renderer output must stay safe
        # if it is ever pasted into a console, where each entered line is
        # its own program and the second line references a `:local` that no
        # longer exists -- a syntax error that left the WAN port attached
        # to the factory-default bridge, i.e. WAN and guest LAN on one L2
        # segment. `:foreach` carries no state across lines at all, is a
        # no-op on an empty find, and its body is one statement.
        lines.append(
            f':foreach wanPort in=[/interface bridge port find where interface="{phys}"] '
            "do={ /interface bridge port remove $wanPort }"
        )
        if link.connection_mode is IspConnectionMode.PPPOE:
            # Deferred to render_wan_addressing_section, which creates this
            # WAN's virtual interface: `/interface list member add` errors
            # on a name nothing currently matches.
            continue
        eff = _escape_routeros_string(link.effective_interface)
        lines.append(
            f':if ([:len [/interface list member find where interface="{eff}" list="WAN"]] '
            f'= 0) do={{ /interface list member add list="WAN" interface="{eff}" }}'
        )
        lines.append(
            f':if ([:len [/ip firewall nat find where chain=srcnat out-interface="{eff}" '
            f'action=masquerade]] = 0) do={{ /ip firewall nat add chain=srcnat '
            f'out-interface="{eff}" action=masquerade comment="cloudguest-nat-wan{n}" }}'
        )
    return lines


def render_stale_defconf_dhcp_cleanup() -> list[str]:
    """Remove the factory-default dhcp-client bound to ``bridgeLocal``.

    Confirmed live (2026-08-17, router "gurugram"): that client keeps its
    last-leased address bound to ``bridgeLocal`` even after every
    physical port is detached, so the router ends up with one IP on two
    interfaces at once -- seen as ~65% packet loss to the WAN gateway
    with no cabling or ISP fault at all.

    THE COUNT IS THE POINT, NOT THE REMOVAL. A router reset with no
    default configuration has no ``bridgeLocal``, so this find matches
    nothing -- correct, and previously indistinguishable from "matched
    and removed": an empty ``:foreach`` is a no-op that logs nothing and
    exits clean. Bound and read on ONE emitted line."""
    return [
        "; ".join(
            [
                ':local staleDefconfN [:len [/ip dhcp-client find where '
                'interface="bridgeLocal"]]',
                ":foreach staleDefconfClient in=[/ip dhcp-client find where "
                'interface="bridgeLocal"] do={ /ip dhcp-client remove $staleDefconfClient }',
                ':if ($staleDefconfN > 0) do={ :log info ("cloudguest: removed " . '
                '[:tostr $staleDefconfN] . " stale factory-default dhcp-client(s) on '
                'bridgeLocal") }',
                ':if ($staleDefconfN = 0) do={ :log info "cloudguest: no dhcp-client on '
                "bridgeLocal to remove -- expected, and not a fault, on a router reset "
                'with no default configuration" }',
            ]
        )
    ]


def render_wan_addressing_section(ctx: WanRenderContext) -> list[str]:
    lines: list[str] = []
    for link in ctx.links:
        n = link.slot
        phys = _escape_routeros_string(link.physical_interface)
        if link.connection_mode is IspConnectionMode.STATIC:
            address = link.static_address
            if not address:
                continue
            addr = _escape_routeros_string(address)
            lines.append(
                f':foreach staleAddr in=[/ip address find where interface="{phys}" '
                'dynamic=yes] do={ /ip address remove $staleAddr }'
            )
            lines.append(
                f':if ([:len [/ip address find where interface="{phys}" '
                f'address="{addr}"]] = 0) do={{ /ip address add address="{addr}" '
                f'interface="{phys}" comment="cloudguest-addr-wan{n}" }}'
            )
        elif link.connection_mode is IspConnectionMode.DHCP:
            # `add-default-route=no` deliberately: render_wan_routing_section
            # owns every default route (the routing-table'd load-balancing
            # ones and the plain fallback alike), the same way it owns a
            # static WAN's route. Letting RouterOS's own dhcp-client add a
            # second, unmarked, unmonitored default route would silently
            # fight that section's check-gateway-driven failover.
            lines.append(
                "; ".join(
                    [
                        f":local wan{n}Mine [:len [/ip dhcp-client find where "
                        f'interface="{phys}" comment="cloudguest-dhcp-wan{n}"]]',
                        f":if ($wan{n}Mine = 0) do={{ :foreach c in=[/ip dhcp-client find "
                        f'where interface="{phys}"] do={{ /ip dhcp-client remove $c }} }}',
                        f":if ($wan{n}Mine = 0) do={{ :foreach staleAddr in=[/ip address "
                        f'find where interface="{phys}" dynamic=yes] do={{ '
                        "/ip address remove $staleAddr } }",
                        f":if ($wan{n}Mine = 0) do={{ /ip dhcp-client add "
                        f'interface="{phys}" disabled=no add-default-route=no '
                        f'use-peer-dns=no comment="cloudguest-dhcp-wan{n}" }}',
                    ]
                )
            )
        elif link.connection_mode is IspConnectionMode.PPPOE:
            eff = _escape_routeros_string(link.effective_interface)
            user = _escape_routeros_string(link.pppoe_username or "")
            password = _escape_routeros_string(link.pppoe_password or "")
            lines.append(
                "; ".join(
                    [
                        f":local wan{n}MinePppoe [:len [/interface pppoe-client find where "
                        f'interface="{phys}" comment="cloudguest-pppoe-wan{n}"]]',
                        f":if ($wan{n}MinePppoe = 0) do={{ :foreach c in=[/interface "
                        f'pppoe-client find where interface="{phys}"] do={{ '
                        "/interface pppoe-client remove $c } }",
                        f":if ($wan{n}MinePppoe = 0) do={{ :foreach staleAddr in=[/ip "
                        f'address find where interface="{phys}" dynamic=yes] do={{ '
                        "/ip address remove $staleAddr } }",
                        f":if ($wan{n}MinePppoe = 0) do={{ /interface pppoe-client add "
                        f'name="{eff}" interface="{phys}" user="{user}" '
                        f'password="{password}" disabled=no add-default-route=no '
                        f'comment="cloudguest-pppoe-wan{n}" }}',
                    ]
                )
            )
            lines.append(
                f':if ([:len [/interface list member find where interface="{eff}" '
                f'list="WAN"]] = 0) do={{ /interface list member add list="WAN" '
                f'interface="{eff}" }}'
            )
            lines.append(
                f':if ([:len [/ip firewall nat find where chain=srcnat '
                f'out-interface="{eff}" action=masquerade]] = 0) do={{ /ip firewall nat '
                f'add chain=srcnat out-interface="{eff}" action=masquerade '
                f'comment="cloudguest-nat-wan{n}" }}'
            )
    return lines


def _wan_gateway_source_statements(
    link: WanRenderLink, *, polling_wans: int
) -> list[str]:
    """Resolve ``$wan<N>Gw`` from the source this WAN's MODE implies.

    Every one of these is an assumption about where the WAN lives -- a
    named port, a pppoe-client with a known name, a gateway an operator
    typed in -- and every one can be wrong on a router that is
    nonetheless perfectly online. That is why the caller falls through to
    :func:`_uplink_discovery_statements`, which asks the device instead.
    """
    n = link.slot
    if link.connection_mode is IspConnectionMode.STATIC:
        return [f':local wan{n}Gw "{_escape_routeros_string(link.gateway or "")}"']

    if link.connection_mode is IspConnectionMode.PPPOE:
        eff = _escape_routeros_string(link.effective_interface)
        exists = f'[:len [/interface pppoe-client find where name="{eff}"]] > 0'
        attempt = (
            f":do {{ :set wan{n}Gw ([/interface pppoe-client monitor "
            f'[find name="{eff}"] once as-value]->"remote-address") }} '
            f'on-error={{ :set wan{n}Gw "" }}'
        )
        unresolved = f'[:len $wan{n}Gw] = 0 || $wan{n}Gw = "0.0.0.0"'
        return [
            f':local wan{n}Gw ""',
            f":if ({exists}) do={{ {attempt} }}",
            *_bounded_retry_ladder(
                attempt=attempt,
                unresolved=unresolved,
                attempts=_poll_attempts(
                    maximum=WAN_PPPOE_GW_POLL_ATTEMPTS,
                    delay_seconds=WAN_PPPOE_GW_POLL_DELAY_S,
                    polling_wans=polling_wans,
                ),
                delay=f"{WAN_PPPOE_GW_POLL_DELAY_S}s",
                attempt_precondition=exists,
            ),
        ]

    phys = _escape_routeros_string(link.physical_interface)
    # WRAPPED: `dhcp-client get ... gateway` on a client that has not
    # bound a lease yet errors, and under `/import` an unwrapped error
    # here takes every later section down with it.
    attempt = (
        f":do {{ :set wan{n}Gw [:tostr [/ip dhcp-client get "
        f'[find where interface="{phys}"] gateway]] }} on-error={{ :set wan{n}Gw "" }}'
    )
    unresolved = f'[:len $wan{n}Gw] = 0 || $wan{n}Gw = "0.0.0.0"'
    return [
        f':local wan{n}Gw ""',
        attempt,
        *_bounded_retry_ladder(
            attempt=attempt,
            unresolved=unresolved,
            attempts=_poll_attempts(
                maximum=WAN_DHCP_GW_POLL_ATTEMPTS,
                delay_seconds=WAN_DHCP_GW_POLL_DELAY_S,
                polling_wans=polling_wans,
            ),
            delay=f"{WAN_DHCP_GW_POLL_DELAY_S}s",
        ),
    ]


def render_wan_routing_section(ctx: WanRenderContext) -> list[str]:
    """Give every WAN a plain default route with ``check-gateway=ping``,
    and (in load-balance mode) its own routing-table'd routes.

    ``check-gateway=ping`` is what the dashboard's ISP-health and
    bandwidth signals actually read. Found live on WYFY-GUEST
    (2026-08-18): its only default route had no ``check-gateway`` at all,
    months after provisioning, so nothing could distinguish "the internet
    is fine" from "nobody ever wired up monitoring".

    THREE EMITTED LINES PER WAN, each a different question:

    1. the source this WAN's MODE implies, plus the plain default route;
    2. the ROUTING TABLE, consulted only when line 1 produced nothing --
       authoritative for every mode alike, and the answer for a renamed,
       VLAN, SFP or otherwise-unexpected uplink;
    3. this WAN's load-balance routes, derived from the plain route
       rather than from ``$wan<N>Gw``, so the marked routes cannot
       disagree with the plain one whichever line established it.
    """
    lines: list[str] = []
    multi = len(ctx.links) > 1
    load_balance = ctx.wan_routing_mode is WanRoutingMode.LOAD_BALANCE
    polling_wans = sum(
        1 for link in ctx.links if link.connection_mode is not IspConnectionMode.STATIC
    )

    # FIRST: say which dialect this section speaks and check the device
    # agrees -- the v6 spelling does not error on v7, it matches nothing.
    lines.append("; ".join(_routeros_version_check_statements()))
    # SECOND: on v7 a route cannot enter a table that has not been declared.
    if multi and load_balance:
        lines.extend(
            _routing_table_preamble_lines([f"to_wan{link.slot}" for link in ctx.links])
        )

    # Keyed on `link.slot`, not on list position: the slot is what every
    # comment tag, routing table and mangle mark on the device is named
    # after, and a disabled link elsewhere in the fleet must not renumber
    # the rest.
    for link in ctx.links:
        n = link.slot
        eff = _escape_routeros_string(link.effective_interface)
        gw_ok = _gateway_usable_expr(f"wan{n}Gw")

        # ---- FIRST LINE: mode-implied source, then the plain route -----
        lines.append(
            "; ".join(
                [
                    *_wan_gateway_source_statements(link, polling_wans=polling_wans),
                    # PARENTHESISED. A concatenation passed as a command
                    # ARGUMENT must be wrapped in `( ... )`: without them
                    # RouterOS parses `:log warning "<string>"` as a
                    # complete command and then hits `. $wan1Gw . "..."` as
                    # a second, meaningless command -- a hard syntax error.
                    f':if (!({gw_ok})) do={{ :log warning ("cloudguest: WAN{n} gateway did '
                    f'not resolve (value \\"" . $wan{n}Gw . "\\") -- no plain route added '
                    'from this WAN\'s own mode; falling through to the routing table") }',
                    # Adopt-don't-duplicate. RouterOS's duplicate-route
                    # check is on dst-address+gateway alone, and `/ip route
                    # add` onto an occupied slot throws "failure: already
                    # have such route" -- which under `/import` aborts
                    # everything after it. A foreign dhcp-client's
                    # auto-route (`add-default-route=yes`, the factory
                    # default) is the realistic occupant.
                    f':local plainRoute{n} [/ip route find where '
                    f'comment="cloudguest-plain-wan{n}"]',
                    # `routing-table="main"` on the fallback find so this
                    # only ever adopts an unmarked route, never one of this
                    # same WAN's own routing-table'd routes below, which
                    # share this exact dst-address+gateway by design.
                    #
                    # AND NO `active=yes` HERE, DELIBERATELY -- the one
                    # default-route lookup in this module without it. Every
                    # other asks "which uplink is live", where an Inactive
                    # route is a trap. This one asks "is this
                    # dst-address+gateway SLOT occupied", and an Inactive
                    # route occupies the slot exactly as much as an active
                    # one does.
                    f":if ({gw_ok} && [:len $plainRoute{n}] = 0) do={{ :set plainRoute{n} "
                    f'[/ip route find where dst-address="0.0.0.0/0" gateway=$wan{n}Gw '
                    f"{ROUTE_MAIN_TABLE_FILTER}] }}",
                    f":if ({gw_ok} && [:len $plainRoute{n}] = 0) do={{ /ip route add "
                    f"dst-address=0.0.0.0/0 gateway=$wan{n}Gw distance={n} "
                    f'check-gateway=ping comment="cloudguest-plain-wan{n}" }}',
                    # WRAPPED: the route being adopted is very often
                    # DYNAMIC (RouterOS's own dhcp-client auto-route), and
                    # `/ip route set` on a dynamic entry is refused. The
                    # router keeps the default route it already had either
                    # way; what is lost is `check-gateway=ping`, and that
                    # is what the message names.
                    f":if ({gw_ok} && [:len $plainRoute{n}] > 0) do={{ :do {{ /ip route "
                    f"set $plainRoute{n} gateway=$wan{n}Gw distance={n} "
                    f'check-gateway=ping comment="cloudguest-plain-wan{n}" }} '
                    f'on-error={{ :log warning "cloudguest: WAN{n} default route cannot be '
                    "modified (likely dynamic, from RouterOS's own DHCP client). Internet "
                    'works; check-gateway=ping is unset, so ISP health has nothing to read" '
                    "} }",
                ]
            )
        )

        # ---- SECOND LINE: the routing table, for every WAN mode alike --
        #
        # ONLY WHEN THE LINE ABOVE PRODUCED NOTHING. The trigger is a fact
        # read off the device (`[:len [find where comment=...]] = 0`), not
        # a variable carried across a line boundary, so this never fights
        # the line above and is a no-op on every healthy re-run.
        #
        # MATCHED BY INTERFACE, NOT ADOPTED BLIND. On a multi-WAN router
        # the discovered uplink belongs to exactly ONE of the WANs; handing
        # its gateway to a different WAN would build a route that sends
        # WAN2's marked traffic out of WAN1, which is worse than no route
        # at all. Single-WAN is the one deliberate exception: there is no
        # other WAN to confuse it with, and "the configured name is not
        # what the device uses" is precisely the case this exists for.
        p = f"w{n}f"
        disc = f"${p}If"
        disc_gw = f"${p}Gw"
        disc_gw_ok = _gateway_usable_expr(f"{p}Gw")
        matches_this_wan = f'{disc} = "{eff}"'
        match = f'{disc} != ""' if len(ctx.links) == 1 else matches_this_wan
        no_route_yet = f"${p}Have = 0"
        use_it = f"${p}Use = true"
        route_props = (
            f"gateway={disc_gw} distance={n} check-gateway=ping "
            f'comment="cloudguest-plain-wan{n}"'
        )
        fallback: list[str] = [
            *_uplink_discovery_statements(p, with_gateway=True),
            f':local {p}Have [:len [/ip route find where comment="cloudguest-plain-wan{n}"]]',
            # HOISTED INTO A BOOLEAN, once, and read below: the literal
            # guard is ~70 characters and every statement has to restate it
            # (one statement per `do={}` body, and a `:local` must sit with
            # its readers). `:set` is a use, not a binding.
            f":local {p}Use false",
            f":if ({no_route_yet} && {match} && {disc_gw_ok}) do={{ :set {p}Use true }}",
            f':local {p}Slot ""',
            f':if ({use_it}) do={{ :set {p}Slot [/ip route find where '
            f'dst-address="0.0.0.0/0" gateway={disc_gw} {ROUTE_MAIN_TABLE_FILTER}] }}',
            f':if ({use_it}) do={{ :log info ("cloudguest: WAN{n} gateway " . {disc_gw} '
            f'. " taken from the live route on " . {disc} . " -- this WAN\'s own '
            f'{link.connection_mode.value} lookup found none") }}',
            f":if ({use_it} && [:len ${p}Slot] = 0) do={{ /ip route add "
            f"dst-address=0.0.0.0/0 {route_props} }}",
            # WRAPPED for the same reason as the adopt branch above: the
            # gateway came OUT of a live default route, so the realistic
            # way one exists that this script did not create is RouterOS's
            # own dhcp-client auto-route, which is dynamic.
            f":if ({use_it} && [:len ${p}Slot] > 0) do={{ :do {{ /ip route set ${p}Slot "
            f"{route_props} }} on-error={{ :log warning (\"cloudguest: WAN{n} route via \" "
            f'. {disc} . " cannot be modified (likely dynamic, from RouterOS\'s own DHCP '
            'client). Internet works; check-gateway=ping is not set, so ISP health and '
            'bandwidth have nothing to read") } }',
        ]
        if len(ctx.links) == 1:
            fallback.append(
                f':if ({no_route_yet} && {disc} != "" && !({matches_this_wan}) && '
                f'{disc_gw_ok}) do={{ :log warning ("cloudguest: WAN1 is configured as '
                f'\\"{eff}\\" but the live default route leaves via " . {disc} . " -- used '
                'the live route; re-check this link\'s interface name") }'
            )
        # ---- three faults that must not collapse into one --------------
        #
        # "no gateway" is three different situations to whoever reads the
        # device log, and one generic message sends them to the wrong
        # place:
        #  A. nothing is routing at all -- cable, link, or ISP.
        #  B. something IS routing, but the interface behind it could not
        #     be named -- a RouterOS-version/link-type problem, not
        #     connectivity.
        #  C. the interface is real and known and still has no usable next
        #     hop -- a link that is up and unconfigured, the one of the
        #     three usually fixable on the spot.
        fallback.extend(
            [
                f":if ({no_route_yet} && ${p}DefCount = 0) do={{ :log warning "
                f'"cloudguest: no active default route in the main routing table -- WAN{n} '
                'has no gateway, no route added" }',
                f':if ({no_route_yet} && ${p}DefCount > 0 && {disc} = "") do={{ '
                ':log warning "cloudguest: active default route found but its WAN interface '
                f'could not be resolved -- WAN{n} has no route" }}',
                f':if ({no_route_yet} && {disc} != "" && !({disc_gw_ok})) do={{ '
                f':log warning ("cloudguest: WAN interface " . {disc} . " resolved but '
                f'carries no usable gateway -- WAN{n} has no route") }}',
            ]
        )
        lines.append("; ".join(fallback))

        # ---- THIRD LINE: this WAN's routing-table'd routes -------------
        #
        # DERIVED FROM THE PLAIN ROUTE, not from `$wan<N>Gw`: the plain
        # route is the single record of what this WAN's gateway actually
        # turned out to be, whichever of the two lines above established
        # it. Reading it back means the marked routes CANNOT disagree with
        # the plain one.
        if multi and load_balance:
            # Crossover backup ring: wan1 backs up wan2, ..., last backs up
            # wan1 -- one route per WAN however many there are, rather than
            # every pair. Two WANs degenerates to mutual backup.
            next_n = (n % len(ctx.links)) + 1
            g = f"w{n}m"
            gw_ok_m = _gateway_usable_expr(f"{g}Gw")
            own = f'[:len [/ip route find where comment="cloudguest-route-wan{n}"]]'
            backup = (
                "[:len [/ip route find where "
                f'comment="cloudguest-backup-wan{next_n}-via-wan{n}"]]'
            )
            lines.append(
                "; ".join(
                    [
                        f':local {g}Plain [/ip route find where '
                        f'comment="cloudguest-plain-wan{n}"]',
                        f':local {g}Gw ""',
                        # `get` on a multi-element find errors; our own
                        # comment matches at most one, but the read is
                        # wrapped rather than assumed.
                        f":if ([:len ${g}Plain] > 0) do={{ :do {{ :set {g}Gw "
                        f"[:tostr [/ip route get ${g}Plain gateway]] }} "
                        f'on-error={{ :set {g}Gw "" }} }}',
                        f':if (!({gw_ok_m})) do={{ :log warning "cloudguest: WAN{n} has no '
                        "usable plain default route, so its load-balancing routes were not "
                        "created -- guest traffic assigned to this WAN by the mangle rules "
                        'would have nowhere to go" }',
                        f":if ({gw_ok_m} && {own} = 0) do={{ /ip route add "
                        f"dst-address=0.0.0.0/0 gateway=${g}Gw "
                        f'{ROUTE_TABLE_PROPERTY}="to_wan{n}" distance=1 check-gateway=ping '
                        f'comment="cloudguest-route-wan{n}" }}',
                        # WRAPPED, unlike the frontend's copy of this same
                        # statement. On the paste path an error aborts one
                        # entered line; under `/import` it aborts every
                        # remaining section of the file -- DNS, firewall,
                        # mangle and all -- while the push still reports
                        # success. This is one of the two places the push
                        # path must be MORE defensive than the paste path,
                        # not merely equal to it.
                        f":if ({gw_ok_m} && {own} > 0) do={{ :do {{ /ip route set "
                        f'[find comment="cloudguest-route-wan{n}"] gateway=${g}Gw }} '
                        f'on-error={{ :log warning "cloudguest: could not re-point WAN{n}\'s '
                        'load-balance route at its current gateway -- traffic the mangle '
                        'rules assign to this WAN may still use the previous next hop" } }',
                        f":if ({gw_ok_m} && {backup} = 0) do={{ /ip route add "
                        f"dst-address=0.0.0.0/0 gateway=${g}Gw "
                        f'{ROUTE_TABLE_PROPERTY}="to_wan{next_n}" distance=2 '
                        f"check-gateway=ping "
                        f'comment="cloudguest-backup-wan{next_n}-via-wan{n}" }}',
                        # Wrapped for the same reason as the line above.
                        f":if ({gw_ok_m} && {backup} > 0) do={{ :do {{ /ip route set "
                        f'[find comment="cloudguest-backup-wan{next_n}-via-wan{n}"] '
                        f"gateway=${g}Gw }} on-error={{ :log warning "
                        f'"cloudguest: could not re-point the WAN{next_n}-via-WAN{n} '
                        'crossover backup route at its current gateway -- failover for '
                        'that WAN may still use the previous next hop" } }',
                    ]
                )
            )

    if multi and ctx.wan_routing_mode is WanRoutingMode.FAILOVER_ONLY:
        # Clean up routing-table'd routes a PREVIOUS load-balance
        # provisioning of this same router may have left behind: without
        # this, old PCC-marked traffic would still be routed via those
        # stale tables even though the mangle section is never rendered in
        # this mode, silently reintroducing a load-balance-shaped split
        # under a "failover only" script. The routing TABLES themselves are
        # deliberately not removed -- see _routing_table_preamble_lines.
        lines.append(
            ':foreach r in=[/ip route find where comment~"^cloudguest-route-wan"] '
            "do={ /ip route remove $r }"
        )
        lines.append(
            ':foreach r in=[/ip route find where comment~"^cloudguest-backup-wan"] '
            "do={ /ip route remove $r }"
        )

    # ---- bind the Wyfy-managed objects to the DISCOVERED interface -----
    #
    # render_wan_bridge_section adds the WAN interface-list membership and
    # the NAT masquerade against the interface NAME stored on the ISP
    # link. That name can be wrong -- a renamed port, a VLAN or SFP
    # sub-interface, an ISP that moved -- and when it is, the router ends
    # up with a masquerade pointing at an interface carrying no traffic
    # and a WAN list that does not contain the real uplink, which breaks
    # the firewall's own `in-interface-list=WAN` matching.
    #
    # EVERY OBJECT HERE IS WYFY-MANAGED AND COMMENT-TAGGED. Nothing is
    # removed, nothing not carrying this module's own comment is read or
    # written, and every add is gated on an explicit count so a re-run
    # updates rather than duplicates.
    p = "wanChk"
    if_resolved = f'${p}If != ""'
    lines.append(
        "; ".join(
            [
                *_uplink_discovery_statements(p, with_gateway=True),
                f":local {p}InList 0",
                f":if ({if_resolved}) do={{ :set {p}InList [:len [/interface list member "
                f'find where interface=${p}If list="WAN"]] }}',
                f":if ({if_resolved} && ${p}InList = 0) do={{ /interface list member add "
                f'list="WAN" interface=${p}If comment="{DISCOVERED_WAN_LIST_COMMENT}" }}',
                f":if ({if_resolved} && ${p}InList = 0) do={{ :log info "
                f'("cloudguest: added live uplink " . ${p}If . " to the WAN interface list '
                '-- the configured WAN port name is not the interface this router actually '
                'uses") }',
                f':local {p}Nat [/ip firewall nat find where '
                f'comment="{DISCOVERED_NAT_COMMENT}"]',
                f":if ({if_resolved} && [:len ${p}Nat] = 0) do={{ /ip firewall nat add "
                f"chain=srcnat out-interface=${p}If action=masquerade "
                f'comment="{DISCOVERED_NAT_COMMENT}" }}',
                f":if ({if_resolved} && [:len ${p}Nat] > 0) do={{ :do {{ /ip firewall nat "
                f"set ${p}Nat chain=srcnat out-interface=${p}If action=masquerade }} "
                f'on-error={{ :log warning ("cloudguest: could not re-point the '
                f'Wyfy-managed masquerade at " . ${p}If . " -- guests may not get NAT over '
                'the live uplink") } }',
                f":if (!({if_resolved})) do={{ :log warning \"cloudguest: no uplink "
                "interface resolved, so the Wyfy-managed WAN list membership and "
                'masquerade were left exactly as they are -- nothing was guessed" }',
                f':if (${p}DefCount > 0 && {if_resolved} && {_gateway_usable_expr(p + "Gw")}) '
                f'do={{ :log info ("cloudguest: live uplink is " . ${p}If . " (gateway " . '
                f'${p}Gw . ", " . [:tostr ${p}DefCount] . " active default route(s))") }}',
            ]
        )
    )
    return lines


def render_wan_mangle_section(ctx: WanRenderContext) -> list[str]:
    """PCC connection-marking and routing-mark assignment for load balance.

    DELIBERATELY STILL ``new-routing-mark=``. That is a
    ``/ip firewall mangle`` property and it keeps its name on RouterOS 7;
    only ``/ip route``'s own property was renamed to ``routing-table``.
    The value must match the table names
    :func:`_routing_table_preamble_lines` creates and
    :func:`render_wan_routing_section` routes into."""
    if len(ctx.links) < 2 or ctx.wan_routing_mode is not WanRoutingMode.LOAD_BALANCE:
        return []
    weights = [link.load_balance_weight for link in ctx.links]
    weighted_plan = None
    if all(w is not None and w > 0 for w in weights):
        weighted_plan = build_weighted_pcc_plan([int(w) for w in weights if w is not None])
    lines: list[str] = []
    lan = _escape_routeros_string(ctx.lan_bridge)
    if weighted_plan is not None:
        lines.append(
            ':foreach r in=[/ip firewall mangle find where '
            'comment~"^cloudguest-mangle-pcc-wan"] do={ /ip firewall mangle remove $r }'
        )
    for idx, link in enumerate(ctx.links):
        n = link.slot
        wan_if = _escape_routeros_string(link.effective_interface)
        lines.append(
            f':if ([:len [/ip firewall mangle find where '
            f'comment="cloudguest-mangle-input-wan{n}"]] = 0) do={{ /ip firewall mangle '
            f'add chain=input in-interface="{wan_if}" action=mark-connection '
            f'new-connection-mark="wan{n}_conn" passthrough=yes '
            f'comment="cloudguest-mangle-input-wan{n}" }}'
        )
        if weighted_plan is not None:
            for i in weighted_plan.indices_by_wan[idx]:
                lines.append(
                    f':if ([:len [/ip firewall mangle find where '
                    f'comment="cloudguest-mangle-pcc-wan{n}-idx{i}"]] = 0) do={{ '
                    f'/ip firewall mangle add chain=prerouting in-interface="{lan}" '
                    f"dst-address-type=!local connection-mark=no-mark "
                    f"per-connection-classifier=both-addresses-and-ports:"
                    f"{weighted_plan.total}/{i} action=mark-connection "
                    f'new-connection-mark="wan{n}_conn" passthrough=yes '
                    f'comment="cloudguest-mangle-pcc-wan{n}-idx{i}" }}'
                )
        else:
            lines.append(
                f':if ([:len [/ip firewall mangle find where '
                f'comment="cloudguest-mangle-pcc-wan{n}"]] = 0) do={{ /ip firewall mangle '
                f'add chain=prerouting in-interface="{lan}" dst-address-type=!local '
                f"connection-mark=no-mark per-connection-classifier="
                f"both-addresses-and-ports:{len(ctx.links)}/{idx} action=mark-connection "
                f'new-connection-mark="wan{n}_conn" passthrough=yes '
                f'comment="cloudguest-mangle-pcc-wan{n}" }}'
            )
        lines.append(
            f':if ([:len [/ip firewall mangle find where '
            f'comment="cloudguest-mangle-route-wan{n}"]] = 0) do={{ /ip firewall mangle '
            f'add chain=prerouting connection-mark="wan{n}_conn" action=mark-routing '
            f'new-routing-mark="to_wan{n}" passthrough=yes '
            f'comment="cloudguest-mangle-route-wan{n}" }}'
        )
    return lines


def render_wan_dns_section(ctx: WanRenderContext) -> list[str]:
    servers = _escape_routeros_string(ctx.dns_servers)
    return [
        f'/ip dns set servers="{servers}" allow-remote-requests=yes',
        ':if ([:len [/ip firewall filter find where '
        'comment="cloudguest-fw-block-wan-dns"]] = 0) do={ /ip firewall filter add '
        "chain=input in-interface-list=WAN protocol=udp dst-port=53 action=drop "
        'comment="cloudguest-fw-block-wan-dns" }',
        ':if ([:len [/ip firewall filter find where '
        'comment="cloudguest-fw-block-wan-dns-tcp"]] = 0) do={ /ip firewall filter add '
        "chain=input in-interface-list=WAN protocol=tcp dst-port=53 action=drop "
        'comment="cloudguest-fw-block-wan-dns-tcp" }',
    ]
