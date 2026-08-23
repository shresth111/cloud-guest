"""Shape and safety invariants for the server-side WAN script renderer.

WHY THIS FILE EXISTS
====================
``app/domains/network_config/wan/renderers.py`` is the SECOND generator
of the same six RouterOS sections the frontend's
``buildRouterSetupScriptChunks`` produces (see that module's own
docstring). The two cannot be merged -- one renders from a form for a
console paste on a router with no tunnel, the other renders from
``isp_links`` rows and is pushed unattended over the device gateway --
so the only thing that can be shared is the GUARD LIST. This file is
that list, enforced by name, mirroring the frontend suite
(``scripts/test-setup-script-generator.mjs``) section for section:

    frontend section                        -> test here
    1.  console scope     -> test_every_local_is_bound_and_read_on_one_line
    2.  do={} arity       -> test_no_multi_statement_do_body
    11. concat parens     -> test_every_concatenated_argument_is_parenthesised
    12. route lookups     -> test_every_default_route_lookup_is_qualified
                             test_no_v6_routing_mark_on_any_route_statement
                             test_every_route_lookup_count_has_a_zero_branch

Plus two guards this path needs that the paste path does not, both
forced by ``/import`` semantics (see the renderer's docstring):

    test_every_failable_read_is_wrapped   -- /import aborts on first error
    test_no_put_diagnostics               -- stdout is discarded by the gateway

And one that is pure hygiene but caught a real bug while this file was
being written: ``test_braces_balance``.

WHEN A GUARD CHANGES ON EITHER SIDE, ADD IT TO BOTH. That is the whole
mechanism; there is no cleverer one available across two repositories.

MUTATION-TESTED. Every guard below has been broken deliberately and the
named test confirmed to catch it -- see each test's own docstring for
the mutation it was verified against.
"""

from __future__ import annotations

import re
import uuid

import pytest

from app.domains.isp.constants import IspConnectionMode, WanRoutingMode
from app.domains.network_config.wan import render_basic_wan_config
from app.domains.network_config.wan.context import WanRenderContext, WanRenderLink

# ---------------------------------------------------------------------------
# The variants every guard is swept over. Not a single happy-path render:
# the routing section branches on mode, on WAN count and on routing mode,
# and a guard that holds for one shape and not another is exactly how the
# frontend's own suite found two real holes.
# ---------------------------------------------------------------------------


def _link(slot: int, mode: IspConnectionMode, **kw: object) -> WanRenderLink:
    base: dict[str, object] = {
        "link_id": uuid.uuid4(),
        "slot": slot,
        "connection_mode": mode,
        "physical_interface": f"ether{slot}",
        "effective_interface": (
            f"cloudguest-pppoe-wan{slot}"
            if mode is IspConnectionMode.PPPOE
            else f"ether{slot}"
        ),
    }
    if mode is IspConnectionMode.STATIC:
        base["static_address"] = f"203.0.113.{slot}/24"
        base["gateway"] = "203.0.113.254"
    if mode is IspConnectionMode.PPPOE:
        base["pppoe_username"] = "user@isp"
        base["pppoe_password"] = "secret"
    base.update(kw)
    return WanRenderLink(**base)  # type: ignore[arg-type]


def _variants() -> dict[str, str]:
    """Every rendered shape, keyed by a name that names the shape."""
    dhcp1 = [_link(1, IspConnectionMode.DHCP)]
    static1 = [_link(1, IspConnectionMode.STATIC)]
    pppoe1 = [_link(1, IspConnectionMode.PPPOE)]
    dual_dhcp = [_link(1, IspConnectionMode.DHCP), _link(2, IspConnectionMode.DHCP)]
    mixed3 = [
        _link(1, IspConnectionMode.DHCP),
        _link(2, IspConnectionMode.STATIC),
        _link(3, IspConnectionMode.PPPOE),
    ]
    weighted = [
        _link(1, IspConnectionMode.DHCP, load_balance_weight=70),
        _link(2, IspConnectionMode.DHCP, load_balance_weight=30),
    ]
    return {
        "single-dhcp": render_basic_wan_config(WanRenderContext(links=dhcp1)),
        "single-static": render_basic_wan_config(WanRenderContext(links=static1)),
        "single-pppoe": render_basic_wan_config(WanRenderContext(links=pppoe1)),
        "dual-dhcp-load-balance": render_basic_wan_config(
            WanRenderContext(
                links=dual_dhcp, wan_routing_mode=WanRoutingMode.LOAD_BALANCE
            )
        ),
        "dual-dhcp-failover-only": render_basic_wan_config(
            WanRenderContext(
                links=dual_dhcp, wan_routing_mode=WanRoutingMode.FAILOVER_ONLY
            )
        ),
        "triple-mixed-load-balance": render_basic_wan_config(
            WanRenderContext(links=mixed3, wan_routing_mode=WanRoutingMode.LOAD_BALANCE)
        ),
        "weighted-pcc": render_basic_wan_config(
            WanRenderContext(
                links=weighted, wan_routing_mode=WanRoutingMode.LOAD_BALANCE
            )
        ),
        "quoted-interface-names": render_basic_wan_config(
            WanRenderContext(
                links=[
                    _link(
                        1,
                        IspConnectionMode.DHCP,
                        physical_interface='eth"1',
                        effective_interface='eth"1',
                    )
                ],
                lan_bridge='br"1',
            )
        ),
    }


VARIANTS = _variants()


def _script_lines(script: str) -> list[str]:
    """Emitted lines that carry RouterOS statements -- `#` headers are
    ``/import`` comments and are not statements."""
    return [
        line
        for line in script.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_every_variant_actually_rendered() -> None:
    """Guard on the guards: a variant that silently renders empty would
    make every sweep below vacuously pass.

    MUTATION: made ``render_wan_routing_section`` return ``[]``
    unconditionally -> this test fails first, before the others go quiet.
    """
    assert len(VARIANTS) == 8
    for name, script in VARIANTS.items():
        assert len(_script_lines(script)) >= 10, f"{name} rendered almost nothing"
        assert "WAN Routing" in script, f"{name} has no WAN Routing section"


# ---------------------------------------------------------------------------
# String-aware scanning. Every guard below must skip the contents of
# RouterOS string literals: a `do={` inside a log message is prose, not
# syntax, and counting it is how a guard starts reporting phantom
# offenders (and, worse, stops reporting real ones once someone "fixes"
# it by loosening the pattern).
# ---------------------------------------------------------------------------


def _strip_routeros_strings(line: str) -> str:
    """Replace the contents of every double-quoted RouterOS string with
    spaces, preserving length and the quotes themselves. ``\\"`` is an
    escaped quote inside a string and does not close it."""
    out: list[str] = []
    in_string = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_string and ch == "\\" and i + 1 < len(line):
            out.append("  ")
            i += 2
            continue
        if ch == '"':
            in_string = not in_string
            out.append('"')
        elif in_string:
            out.append(" ")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def test_braces_balance() -> None:
    """Every emitted line closes every brace it opens.

    Not cosmetic. The renderer builds these lines out of f-strings where
    a literal brace must be written ``{{``/``}}``; a fragment that is not
    an f-string but was edited as though it were emits a stray ``}}``
    that RouterOS reads as an extra statement terminator, silently
    changing which statements sit inside which ``do={}`` body.

    MUTATION (real, not hypothetical -- this is the bug that prompted the
    test): the ``:foreach staleAddr ... do={ ... }`` fragment in the DHCP
    addressing branch was written as a plain string containing ``}} }}``,
    so the rendered line carried two extra closing braces. Caught here,
    on ``single-dhcp`` and three other variants.
    """
    offenders: list[str] = []
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            code = _strip_routeros_strings(line)
            depth = 0
            for ch in code:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth < 0:
                        break
            if depth != 0:
                offenders.append(f"{name}: depth {depth:+d} on {line[:110]}")
    assert not offenders, "unbalanced braces:\n" + "\n".join(offenders)


def test_no_v6_routing_mark_on_any_route_statement() -> None:
    """No ``/ip route`` statement anywhere uses the RouterOS 6 spelling.

    Measured on a live hEX lite 7.23.3::

        :put [:len [/ip route find where routing-table="main"]]  ->  1
        :put [:len [/ip route find where routing-mark=""]]       ->  0

    The v6 spelling does not error on v7 -- it is taken as an unknown
    filter and silently matches an empty set. ``new-routing-mark=`` on
    ``/ip firewall mangle`` is a DIFFERENT property that keeps its name
    on v7 and is explicitly allowed.

    MUTATION: changed ``ROUTE_MAIN_TABLE_FILTER`` back to
    ``routing-mark=""`` -> fails on all 8 variants. Separately, changed
    ``ROUTE_TABLE_PROPERTY`` back to ``routing-mark`` -> fails on the 3
    load-balance variants.
    """
    offenders: list[str] = []
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            code = _strip_routeros_strings(line)
            # Blank out the one legitimate mangle property before looking.
            code = code.replace("new-routing-mark", "new-XXXXXXX-XXXX")
            if "routing-mark" in code:
                offenders.append(f"{name}: {line[:110]}")
    assert not offenders, (
        "RouterOS 6 `routing-mark=` reached a route statement -- on v7 this "
        "matches nothing WITHOUT erroring:\n" + "\n".join(offenders)
    )


#: A default-route lookup: a `/ip route find` filtered on the default
#: destination. Every one of these must carry both qualifiers, with one
#: named exception (below).
RE_DEFAULT_ROUTE_FIND = re.compile(
    r"/ip route find where dst-address=\"0\.0\.0\.0/0\"[^\]]*"
)


def test_every_default_route_lookup_is_qualified() -> None:
    """Every default-route lookup carries ``routing-table="main"``, and
    every one that asks "which uplink is LIVE" also carries ``active=yes``.

    ``active=yes`` matters because RouterOS keeps an unreachable default
    route in the table and flags it Inactive rather than removing it, so
    an unqualified count says "1 route, looks healthy" about a router
    whose every ping says `no route to host`.

    THE ONE DELIBERATE EXCEPTION is the slot-occupancy lookup
    (``gateway=$...`` with no ``active=yes``): it asks "is this
    dst-address+gateway slot already taken", because RouterOS's own
    duplicate check is on dst-address+gateway alone and ``/ip route add``
    onto an occupied slot throws. An Inactive route occupies the slot
    exactly as much as an active one, so filtering it out would turn a
    silent no-op into a hard error mid-``/import``. The exception is
    pinned in BOTH directions -- it must carry the table filter, and it
    must still exist -- so neither the rule nor its exception can quietly
    go away.

    MUTATION: dropped ``active=yes`` from the gateway sweep only (one of
    two sweeps in ``_uplink_discovery_statements``) -> fails on all 8
    variants. Dropped ``routing-table="main"`` from the slot-occupancy
    lookup only -> fails on all 8.
    """
    # RAW lines, not string-stripped: the qualifiers this test is looking
    # for (`dst-address="0.0.0.0/0"`, `routing-table="main"`) are quoted
    # VALUES, so blanking string contents would blank the very thing being
    # asserted -- and would do it silently, leaving the sweep matching
    # nothing and passing vacuously. That is exactly the failure this
    # suite exists to prevent, so the exemption is pinned instead:
    # `test_route_find_literal_never_appears_in_prose` below proves no log
    # message contains the literal, which is what makes raw scanning safe.
    unqualified: list[str] = []
    slot_lookups = 0
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            for found in RE_DEFAULT_ROUTE_FIND.findall(line):
                if 'routing-table="main"' not in found:
                    unqualified.append(f"{name}: no table filter: {found[:100]}")
                    continue
                if "gateway=$" in found and "active=yes" not in found:
                    slot_lookups += 1
                    continue
                if "active=yes" not in found:
                    unqualified.append(f"{name}: no active=yes: {found[:100]}")
    assert not unqualified, "under-qualified default-route lookups:\n" + "\n".join(
        unqualified
    )
    assert slot_lookups > 0, (
        "the slot-occupancy lookup (gateway=$..., deliberately without "
        "active=yes) has disappeared -- see this test's docstring; if it was "
        "removed on purpose, remove this assertion in the same commit"
    )


def test_route_find_literal_never_appears_in_prose() -> None:
    """The exemption that lets ``test_every_default_route_lookup_is_qualified``
    scan raw lines: no ``:log``/``:put`` message text contains a literal
    ``/ip route find``, so every occurrence the raw sweep finds is real
    code rather than a sentence about code.

    MUTATION: added ``/ip route find where dst-address="0.0.0.0/0"`` to a
    warning message body -> fails here, which is the signal to make the
    other test string-aware rather than to loosen it.
    """
    offenders: list[str] = []
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            code = _strip_routeros_strings(line)
            if line.count("/ip route find") != code.count("/ip route find"):
                offenders.append(f"{name}: {line[:110]}")
    assert not offenders, (
        "a log/put message contains the literal `/ip route find` -- the "
        "raw-line sweep in test_every_default_route_lookup_is_qualified would "
        "now count prose as code:\n" + "\n".join(offenders)
    )


def test_every_route_lookup_count_has_a_zero_branch() -> None:
    """Every ``DefCount`` bound from a default-route filter is READ on the
    same line with an explicit ``= 0`` branch that logs.

    This is the guard the whole exercise is for. A ``find`` whose filter
    name RouterOS no longer recognises returns an empty set WITHOUT
    erroring, so "0 routes" and "this script is speaking the wrong
    dialect" are indistinguishable from the value alone. Renaming
    ``routing-mark`` -> ``routing-table`` fixes today's instance and
    nothing about the next rename; counting and branching on zero is what
    makes the next one fail visibly.

    MUTATION: deleted the ``:if ($<p>DefCount = 0) do={ :log warning ... }``
    statement from ``_uplink_discovery_statements`` -> fails on all 8
    variants. Separately, changed the branch to bind the count but log
    nothing (``do={ :set x 1 }``) -> still fails, because the assertion
    requires a ``:log`` in the zero branch, not merely a branch.
    """
    offenders: list[str] = []
    binds = 0
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            code = _strip_routeros_strings(line)
            counts = re.findall(r":local (\w*DefCount) \[:len \[/ip route find", code)
            for var in counts:
                binds += 1
                zero_branch = re.search(
                    rf":if \(\${var} = 0\) do=\{{ :log ", line
                )
                if not zero_branch:
                    offenders.append(f"{name}: {var} bound with no logging zero branch")
    assert binds > 0, (
        "no default-route count is bound at all -- the sweep found nothing"
    )
    assert not offenders, (
        "a route-lookup count was bound without a zero branch that says so:\n"
        + "\n".join(offenders)
    )


def test_every_local_is_bound_and_read_on_one_line() -> None:
    """Every ``$var`` read on an emitted line was bound on that same line.

    ``/import`` would tolerate a split -- it runs the whole file as one
    program -- but the same renderer output must stay safe if it is ever
    pasted into a console, where each entered line is its own program and
    a ``:local`` from the previous line no longer exists. This is the
    frontend suite's section 1, kept here so the two generators obey the
    same rule.

    MUTATION: split the DHCP addressing branch back into a bare
    ``:local wan1Mine ...`` line followed by a separate ``:if ($wan1Mine
    = 0) ...`` line -> fails on 5 variants naming ``wan1Mine``.
    """
    bind_re = re.compile(r":(?:local|global|for|foreach)\s+([A-Za-z_]\w*)")
    read_re = re.compile(r"\$([A-Za-z_]\w*)")
    offenders: list[str] = []
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            code = _strip_routeros_strings(line)
            bound = set(bind_re.findall(code))
            for var in read_re.findall(code):
                if var not in bound:
                    offenders.append(
                        f"{name}: ${var} read but not bound on: {line[:100]}"
                    )
    assert not offenders, (
        "a variable is read on a line that does not bind it -- fatal if this "
        "script is ever pasted rather than imported:\n" + "\n".join(offenders[:20])
    )


def _do_bodies(line: str) -> list[str]:
    """Every ``do={ ... }`` / ``on-error={ ... }`` / ``else={ ... }`` body
    on a line, string-aware and brace-matched."""
    code = _strip_routeros_strings(line)
    bodies: list[str] = []
    for opener in re.finditer(r"(?:do|on-error|else)=\{", code):
        start = opener.end()
        depth = 1
        i = start
        while i < len(code) and depth:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        if depth == 0:
            bodies.append(line[start : i - 1])
    return bodies


def _top_level_statement_count(body: str) -> int:
    """Statements in a body, counting only ``;`` at brace depth 0 and
    outside strings."""
    code = _strip_routeros_strings(body)
    depth = 0
    count = 1 if code.strip() else 0
    for ch in code:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif ch == ";" and depth == 0:
            count += 1
    return count


def test_no_multi_statement_do_body() -> None:
    """Every ``do={}`` body holds exactly one statement.

    A ``;``-chained pair inside an inline ``do={ ... }`` threw a real
    syntax error on live hardware. Under ``/import`` that error aborts
    every remaining section of the script.

    MUTATION: folded the gateway-resolve and the plain-route add into one
    ``do={ :set wan1Gw ...; /ip route add ... }`` body -> fails on all 8
    variants naming that body.
    """
    offenders: list[str] = []
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            for body in _do_bodies(line):
                n = _top_level_statement_count(body)
                if n > 1:
                    offenders.append(f"{name}: {n} statements in do={{{body[:90]}}}")
    assert not offenders, (
        "multi-statement do={} body -- this shape threw a real syntax error on "
        "live hardware:\n" + "\n".join(offenders)
    )


def test_every_concatenated_argument_is_parenthesised() -> None:
    """A concatenation passed as a command ARGUMENT is wrapped in ``(...)``.

    Without them RouterOS parses ``:log warning "<string>"`` as a
    complete command and then hits ``. $wan1Gw . "..."`` as a second,
    meaningless command -- a hard syntax error. Confirmed live on the
    founder's hEX (2026-08-23) on the frontend's copy of this same line,
    where it aborted the entire WAN Routing chunk and left the router
    with no default route at all.

    MUTATION: removed the parentheses from the "gateway did not resolve"
    warning in ``render_wan_routing_section`` -> fails on all 8 variants.
    """
    # `:log <level> "..." . $x` / `:put "..." . $x` / `:error "..." . $x`
    # with the opening paren missing.
    #
    # THE STRING BODY MUST TOLERATE ESCAPED QUOTES. Written as `"[^"]*"`
    # this matched nothing on the very line it exists to protect: that
    # message embeds `\"` around the offending value, so a naive body
    # stopped at the backslash-quote and the `.` never lined up. A guard
    # that silently matches nothing is the same defect class as the
    # `routing-mark=""` filter it sits next to -- found by mutation M9,
    # which the naive pattern did not catch.
    bad = re.compile(r':(?:log\s+\w+|put|error)\s+"(?:[^"\\]|\\.)*"\s*\.')
    offenders: list[str] = []
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            for match in bad.finditer(line):
                start = max(0, match.start() - 30)
                offenders.append(f"{name}: {line[start : match.end() + 40]}")
    assert not offenders, (
        "unparenthesised concatenation passed as a command argument -- a hard "
        "syntax error that aborts the rest of the /import:\n" + "\n".join(offenders)
    )


def test_every_failable_read_is_wrapped() -> None:
    """Every read that can legitimately fail on a HEALTHY router sits
    inside ``:do { ... } on-error={ ... }``.

    ``/import`` aborts the whole remaining file on the first error, and
    the push still reports success, so an unwrapped read here silently
    costs the router its DNS, its firewall and its mangle rules. The
    three that can fail on a healthy device: ``dhcp-client get`` before
    the lease binds, ``pppoe-client monitor`` while the session is still
    dialing, and ``/ip route set`` on a route that turns out to be
    dynamic (RouterOS's own dhcp-client auto-route).

    MUTATION: unwrapped the ``dhcp-client get`` attempt (removed its
    ``:do``/``on-error``) -> fails on 5 variants. Separately, unwrapped
    the ``/ip route set`` in the slot-adopt branch -> fails on all 8.
    """
    failable = (
        "/ip dhcp-client get",
        "pppoe-client monitor",
        "/ip route set",
        "/ip arp get",
    )
    offenders: list[str] = []
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            code = _strip_routeros_strings(line)
            for needle in failable:
                for match in re.finditer(re.escape(needle), code):
                    # Walk back to the nearest enclosing `:do {`: the read
                    # is protected only if it sits inside one whose body
                    # has not already closed before this point.
                    prefix = code[: match.start()]
                    depth_from_do = None
                    for do_match in re.finditer(r":do \{", prefix):
                        segment = code[do_match.end() : match.start()]
                        if segment.count("{") - segment.count("}") >= 0:
                            depth_from_do = do_match
                    if depth_from_do is None:
                        offenders.append(f"{name}: unwrapped {needle} in {line[:100]}")
    assert not offenders, (
        "a read that can fail on a healthy router is unwrapped -- under /import "
        "this aborts every later section:\n" + "\n".join(offenders)
    )


def test_no_put_diagnostics() -> None:
    """No diagnostic uses ``:put``.

    ``MikroTikAdapter._run_ssh_command`` binds the SSH result and checks
    ``exit_status`` only -- stdout is discarded and never stored on the
    provisioning job. A ``:put`` on this path is therefore written to
    nobody. The device log is the only channel that reaches a human, so
    every diagnostic is ``:log``. (The frontend's copies of these
    sections DO use ``:put``, correctly, because a technician is reading
    the console. That is the one place the two generators deliberately
    differ, and it is why this test exists rather than being copied from
    the frontend suite.)

    MUTATION: changed the "0 active main-table default routes" warning
    from ``:log warning`` to ``:put`` -> fails on all 8 variants.
    """
    offenders: list[str] = []
    for name, script in VARIANTS.items():
        for line in _script_lines(script):
            if ":put " in _strip_routeros_strings(line):
                offenders.append(f"{name}: {line[:110]}")
    assert not offenders, (
        "a :put diagnostic reaches nobody on the push path -- use :log:\n"
        + "\n".join(offenders)
    )


def test_gateway_zero_is_rejected_by_name() -> None:
    """Every gateway usability test rejects ``0.0.0.0`` explicitly.

    ``"0.0.0.0" != ""`` is TRUE, so an emptiness test alone passes a zero
    gateway into ``/ip route add``, which RouterOS accepts and then
    silently flags Inactive. Confirmed live on a factory-fresh hEX
    (2026-08-21): the route landed with gateway ``0.0.0.0``, flag ``Is``,
    and every ping said `no route to host` on a healthy WAN.

    MUTATION: reduced ``_gateway_usable_expr`` to ``$x != ""`` -> fails
    on all 8 variants.
    """
    for name, script in VARIANTS.items():
        code = "\n".join(_script_lines(script))
        empties = len(re.findall(r"\$(\w*Gw) != \"\"", code))
        zeros = len(re.findall(r"\$(\w*Gw) != \"0\.0\.0\.0\"", code))
        assert empties > 0, f"{name}: no gateway usability test at all"
        assert zeros == empties, (
            f"{name}: {empties} emptiness tests but only {zeros} zero-address "
            "tests -- a gateway of 0.0.0.0 passes an emptiness test and lands "
            "an Inactive route"
        )


def test_asynchronous_gateway_sources_poll() -> None:
    """DHCP and PPPoE gateway reads retry; a static one does not.

    ``/import`` never pauses, so a lease that has not bound yet is read
    as nothing and the route below it lands on ``0.0.0.0``. A human
    pasting chunk-by-chunk never sees this -- typing delay is what lets
    DHCP bind -- which is why the push path needs the ladder even more
    than the paste path does.

    COUNTED, NOT MERELY PRESENT. Setting ``WAN_DHCP_GW_POLL_ATTEMPTS`` to
    1 does NOT remove the ladder -- ``_poll_attempts`` floors at 2 on
    purpose, so a busy multi-WAN router still retries once -- and a bare
    "is there a ``:delay``" assertion therefore passed a mutation that
    gutted the constant (mutation M14). The count is what makes the
    difference between "the ladder exists" and "the ladder is one
    attempt".

    MUTATION: dropped the ``_bounded_retry_ladder`` spread from the DHCP
    branch of ``_wan_gateway_source_statements`` -> fails on 5 variants
    (no ``:delay`` at all). Separately, set
    ``WAN_DHCP_GW_POLL_ATTEMPTS = 1`` -> the floor takes it to 2, which
    emits 1 delay, which fails the ``>= 2`` below.
    """
    for name in ("single-dhcp", "dual-dhcp-load-balance"):
        delays = VARIANTS[name].count(":delay 5s")
        assert delays >= 2, (
            f"{name}: DHCP gateway read retries {delays} time(s) -- one attempt "
            "plus one retry is not a ladder, and /import gives a fresh lease no "
            "time at all to bind"
        )
    assert VARIANTS["single-pppoe"].count(":delay 5s") >= 2, (
        "PPPoE gateway read does not retry enough -- remote-address on a "
        "session still dialing is not there to read"
    )
    # A static gateway is a value, not a lookup -- nothing to wait for.
    static_routing = VARIANTS["single-static"].split("# --- WAN Routing ---")[1]
    assert ":delay" not in static_routing, (
        "a static WAN's gateway is typed in, not discovered -- it must not "
        "hold the /import open waiting for anything"
    )


def test_routing_tables_are_declared_before_being_routed_into() -> None:
    """Every ``to_wan<N>`` table a route enters is created first, and the
    creation is counted and branched on zero.

    RouterOS 7 refuses a route into a routing table that has not been
    declared. ``/routing table add`` on an existing name errors, and a
    ``find`` against a menu a RouterOS version does not have returns
    empty in silence -- so "we made it" is never inferred.

    MUTATION: removed the ``_routing_table_preamble_lines`` call from
    ``render_wan_routing_section`` -> fails on the 3 load-balance
    variants.
    """
    for name in ("dual-dhcp-load-balance", "triple-mixed-load-balance", "weighted-pcc"):
        script = VARIANTS[name]
        tables = set(re.findall(r'routing-table="(to_wan\d+)"', script))
        assert tables, f"{name}: load balance mode created no routing-table'd routes"
        for table in sorted(tables):
            assert f'/routing table add name="{table}"' in script, (
                f"{name}: routes enter {table} but it is never created -- v7 "
                "refuses a route into an undeclared table"
            )
            verified = (
                f':if ([:len [/routing table find where name="{table}"]] = 0) '
                "do={ :log"
            )
            assert verified in script, (
                f"{name}: {table} creation is not verified with a zero branch"
            )


def test_a_missing_wan_interface_does_not_abort_the_import() -> None:
    """A configured interface name that does not exist on the device logs
    a warning and the script CONTINUES.

    This used to ``:error``. Under ``/import`` that aborted the entire
    remaining script -- addressing, routing, mangle, DNS -- on a router
    whose uplink was merely on a VLAN sub-interface, an SFP port, a
    renamed port, or a PPPoE interface an engineer named themselves. The
    routing-table fallback resolves the real uplink whatever it is
    called, so aborting here throws away a script that would have worked.

    SCOPED TO THE WHOLE SCRIPT, NOT TO THE EXISTENCE-CHECK LINE. Scoped
    to the line carrying the "does not exist on this device" wording,
    this test passed a mutation that restored the ``:error`` as a
    SEPARATE, differently-worded line right beside it (mutation M16).
    There is no legitimate ``:error`` anywhere on the push path: under
    ``/import`` it aborts every remaining section while the push still
    reports success, so every failure mode this renderer has is designed
    to log and continue. Asserting that directly is both stronger and
    simpler than trying to enumerate the wordings.

    MUTATION: appended a second ``:if ({missing}) do={{ :error (...) }}``
    line inside ``_wan_existence_check_lines`` -> fails on all 8
    variants.
    """
    for name, script in VARIANTS.items():
        existence = [
            line
            for line in _script_lines(script)
            if "does not exist on this device" in line
        ]
        assert existence, f"{name}: no WAN-interface existence check at all"
        offenders = [
            line
            for line in _script_lines(script)
            if ":error" in _strip_routeros_strings(line)
        ]
        assert not offenders, (
            f"{name}: a hard :error reached the push path -- under /import it "
            "aborts every later section (DNS, firewall, mangle) while the push "
            "still reports success:\n" + "\n".join(line[:110] for line in offenders)
        )


def test_static_wan_without_gateway_falls_through_to_the_routing_table() -> None:
    """A static link with no gateway recorded renders an empty string and
    falls through to the routing table, rather than emitting a literal
    ``None``.

    MUTATION: interpolated ``link.gateway`` directly instead of
    ``link.gateway or ""`` -> the rendered script contains ``:local
    wan1Gw "None"``, which passes the usability test and lands a route to
    a host called "None". Caught here.
    """
    script = render_basic_wan_config(
        WanRenderContext(
            links=[
                WanRenderLink(
                    link_id=uuid.uuid4(),
                    slot=1,
                    connection_mode=IspConnectionMode.STATIC,
                    physical_interface="ether1",
                    effective_interface="ether1",
                    static_address="203.0.113.5/24",
                    gateway=None,
                )
            ]
        )
    )
    assert ':local wan1Gw ""' in script
    assert "None" not in script


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_interface_names_are_escaped(name: str) -> None:
    """An interface or bridge name carrying a quote cannot close a
    RouterOS string literal early.

    MUTATION: dropped ``_escape_routeros_string`` from the bridge name in
    ``render_wan_bridge_section`` -> the ``quoted-interface-names``
    variant renders an unbalanced string and fails.
    """
    for line in _script_lines(VARIANTS[name]):
        stripped = _strip_routeros_strings(line)
        assert stripped.count('"') % 2 == 0, (
            f"{name}: unbalanced quotes -- an unescaped name closed a string "
            f"literal early: {line[:110]}"
        )
