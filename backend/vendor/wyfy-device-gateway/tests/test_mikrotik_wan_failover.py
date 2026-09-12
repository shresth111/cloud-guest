"""WAN failover on RouterOS: reading the default-route layout, moving the
preferred uplink by administrative distance, and making sure traffic that
leaves the newly-preferred interface is actually NATed.

Every menu shape here is the one a real hEX lite / RB750r2 on RouterOS
7.23.3 answers with -- the two-WAN cases are the same router with a second
uplink added, since the lab box has exactly one.

No test in this file opens a socket.
"""

from __future__ import annotations

import pytest
from librouteros.exceptions import LibRouterosError
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikAmbiguousRouteError,
    MikroTikDeviceError,
    MikroTikImmutableRouteError,
    MikroTikRouteNotFoundError,
    MikroTikWanInterfaceError,
)

from tests.fake_write_transport import FakeRouterOSApi


def _dual_wan_menus(overrides: dict | None = None) -> dict:
    """A two-WAN router provisioned the way this platform's own setup
    script provisions one: a static ``0.0.0.0/0`` per uplink with
    ``check-gateway=ping`` and ``distance`` equal to the WAN slot, plus one
    masquerade rule per WAN bound to that WAN's own out-interface.

    ether1 (distance 1) is preferred; ether2 (distance 2) is the backup.
    """
    menus = {
        ("interface",): [
            {".id": "*1", "name": "ether1"},
            {".id": "*2", "name": "ether2"},
            {".id": "*3", "name": "bridgeLocal"},
        ],
        ("ip", "address"): [
            {".id": "*1", "address": "192.168.1.100/24", "interface": "ether1"},
            {".id": "*2", "address": "192.168.2.100/24", "interface": "ether2"},
            {".id": "*3", "address": "10.0.0.1/24", "interface": "bridgeLocal"},
        ],
        ("ip", "route"): [
            {
                ".id": "*r1",
                "dst-address": "0.0.0.0/0",
                "gateway": "192.168.1.1",
                "distance": "1",
                "active": "true",
                "disabled": "false",
                "dynamic": "false",
                "comment": "cloudguest-plain-wan1",
            },
            {
                ".id": "*r2",
                "dst-address": "0.0.0.0/0",
                "gateway": "192.168.2.1",
                "distance": "2",
                "active": "true",
                "disabled": "false",
                "dynamic": "false",
                "comment": "cloudguest-plain-wan2",
            },
            {
                ".id": "*r3",
                "dst-address": "10.0.0.0/24",
                "gateway": "bridgeLocal",
                "active": "true",
                "dynamic": "true",
            },
        ],
        ("ip", "dhcp-client"): [],
        ("interface", "list", "member"): [
            {".id": "*m1", "list": "WAN", "interface": "ether1"},
            {".id": "*m2", "list": "WAN", "interface": "ether2"},
        ],
        ("ip", "firewall", "nat"): [
            {
                ".id": "*n1",
                "chain": "srcnat",
                "action": "masquerade",
                "out-interface": "ether1",
                "comment": "cloudguest-nat-wan1",
                "disabled": "false",
            },
            {
                ".id": "*n2",
                "chain": "srcnat",
                "action": "masquerade",
                "out-interface": "ether2",
                "comment": "cloudguest-nat-wan2",
                "disabled": "false",
            },
        ],
    }
    menus.update(overrides or {})
    return menus


# ============================================================================
# read_default_routes
# ============================================================================


@pytest.mark.asyncio
async def test_reads_every_default_route_resolved_to_its_own_interface(
    patch_connect, mikrotik_creds
):
    """The default routes come back one per uplink, each named by the
    interface it actually leaves by -- and the connected LAN route, which
    is not a default route, does not."""
    api = FakeRouterOSApi(menus=_dual_wan_menus())
    patch_connect(api)

    routes = await MikroTikAdapter().read_default_routes(mikrotik_creds)

    assert [(r.interface, r.distance, r.gateway) for r in routes] == [
        ("ether1", 1, "192.168.1.1"),
        ("ether2", 2, "192.168.2.1"),
    ]
    assert all(r.active and not r.disabled and not r.dynamic for r in routes)


@pytest.mark.asyncio
async def test_an_inactive_backup_is_returned_flagged_not_filtered_out(
    patch_connect, mikrotik_creds
):
    """A backup whose check-gateway probe is failing is exactly the fact a
    caller has to see before it moves traffic. Dropping the row would turn
    "this target is down" into "there is no such route", which points an
    operator at the wrong problem."""
    menus = _dual_wan_menus()
    menus[("ip", "route")][1]["active"] = "false"
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    routes = await MikroTikAdapter().read_default_routes(mikrotik_creds)

    backup = next(r for r in routes if r.interface == "ether2")
    assert backup.active is False


@pytest.mark.asyncio
async def test_routing_table_marked_routes_are_not_candidates(
    patch_connect, mikrotik_creds
):
    """Load-balance mode gives every WAN its own ``to_wan<N>`` default
    route, active in its own table simultaneously. Counting those would
    make every load-balanced router look permanently ambiguous."""
    menus = _dual_wan_menus()
    menus[("ip", "route")].append(
        {
            ".id": "*r9",
            "dst-address": "0.0.0.0/0",
            "gateway": "192.168.1.1",
            "distance": "1",
            "routing-table": "to_wan1",
            "active": "true",
            "dynamic": "false",
        }
    )
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    routes = await MikroTikAdapter().read_default_routes(mikrotik_creds)

    assert len(routes) == 2


@pytest.mark.asyncio
async def test_a_dhcp_wan_route_naming_no_interface_still_resolves(
    patch_connect, mikrotik_creds
):
    """The lab router's own shape: a dynamic default route with no
    ``interface`` field, whose gateway sits in the subnet of the address on
    ether1. Tier 3 of the shared resolution rule is what names it."""
    api = FakeRouterOSApi(
        menus=_dual_wan_menus(
            {
                ("ip", "route"): [
                    {
                        ".id": "*r1",
                        "dst-address": "0.0.0.0/0",
                        "gateway": "192.168.1.1",
                        "distance": "1",
                        "active": "true",
                        "dynamic": "true",
                    }
                ]
            }
        )
    )
    patch_connect(api)

    routes = await MikroTikAdapter().read_default_routes(mikrotik_creds)

    assert [(r.interface, r.dynamic) for r in routes] == [("ether1", True)]


# ============================================================================
# set_default_route_distances
# ============================================================================


@pytest.mark.asyncio
async def test_a_swap_makes_the_backup_preferred_and_writes_both_routes(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus=_dual_wan_menus())
    patch_connect(api)

    await MikroTikAdapter().set_default_route_distances(
        mikrotik_creds, distances={"ether2": 1, "ether1": 2}
    )

    assert api.update_calls == [
        (("ip", "route"), {".id": "*r2", "distance": "1"}),
        (("ip", "route"), {".id": "*r1", "distance": "2"}),
    ]
    assert api.add_calls == []
    assert api.remove_calls == []


@pytest.mark.asyncio
async def test_re_applying_the_same_distances_writes_nothing(
    patch_connect, mikrotik_creds
):
    """The idempotency that makes re-triggering an already-active failover
    a genuine no-op. The comparison is on parsed integers: RouterOS answers
    a read with ``"1"`` and accepts ``1`` on write, and comparing those raw
    would issue an update on every single push forever."""
    api = FakeRouterOSApi(menus=_dual_wan_menus())
    patch_connect(api)

    await MikroTikAdapter().set_default_route_distances(
        mikrotik_creds, distances={"ether1": 1, "ether2": 2}
    )

    assert api.update_calls == []


@pytest.mark.asyncio
async def test_an_unknown_interface_is_refused_before_any_route_is_written(
    patch_connect, mikrotik_creds
):
    """A half-applied swap can leave two default routes tied at the lowest
    distance, which is RouterOS load sharing across an uplink that may be
    down -- strictly worse than the state it started from. So every named
    interface is validated before the first write, not as it is reached."""
    api = FakeRouterOSApi(menus=_dual_wan_menus())
    patch_connect(api)

    with pytest.raises(MikroTikRouteNotFoundError):
        await MikroTikAdapter().set_default_route_distances(
            mikrotik_creds, distances={"ether2": 1, "sfp1": 2}
        )

    assert api.update_calls == []


@pytest.mark.asyncio
async def test_two_default_routes_on_one_interface_are_refused(
    patch_connect, mikrotik_creds
):
    menus = _dual_wan_menus()
    menus[("ip", "route")].append(
        {
            ".id": "*r4",
            "dst-address": "0.0.0.0/0",
            "gateway": "192.168.2.254",
            "distance": "5",
            "active": "true",
            "dynamic": "false",
        }
    )
    menus[("ip", "address")].append(
        {".id": "*a4", "address": "192.168.2.100/24", "interface": "ether2"}
    )
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    with pytest.raises(MikroTikAmbiguousRouteError):
        await MikroTikAdapter().set_default_route_distances(
            mikrotik_creds, distances={"ether2": 1}
        )

    assert api.update_calls == []


@pytest.mark.asyncio
async def test_a_dynamic_route_is_refused_rather_than_attempted(
    patch_connect, mikrotik_creds
):
    """RouterOS refuses ``/ip route set`` on a route it created itself.
    Checked here so the error names the interface and the reason, instead
    of surfacing as the device's own message about an unmodifiable item
    attributed to whichever write went first."""
    menus = _dual_wan_menus()
    menus[("ip", "route")][1]["dynamic"] = "true"
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    with pytest.raises(MikroTikImmutableRouteError):
        await MikroTikAdapter().set_default_route_distances(
            mikrotik_creds, distances={"ether2": 1, "ether1": 2}
        )

    assert api.update_calls == []


@pytest.mark.asyncio
async def test_a_dynamic_route_already_at_the_wanted_distance_is_not_refused(
    patch_connect, mikrotik_creds
):
    """Immutability only matters for a route this is about to write. One
    already carrying the requested distance is skipped before the dynamic
    check, so a router with a dynamic route on an uplink nothing is moving
    is not blocked by it."""
    menus = _dual_wan_menus()
    menus[("ip", "route")][0]["dynamic"] = "true"
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    await MikroTikAdapter().set_default_route_distances(
        mikrotik_creds, distances={"ether1": 1, "ether2": 2}
    )

    assert api.update_calls == []


# ============================================================================
# ensure_wan_egress -- the NAT half
# ============================================================================


@pytest.mark.asyncio
async def test_an_uplink_that_already_has_nat_and_wan_membership_is_untouched(
    patch_connect, mikrotik_creds
):
    """The provisioned two-WAN router already has ``cloudguest-nat-wan2``
    and ether2 in the WAN list. Nothing is added, and in particular
    ``cloudguest-nat-wan1`` is not read for permission, edited or removed."""
    api = FakeRouterOSApi(menus=_dual_wan_menus())
    patch_connect(api)

    await MikroTikAdapter().ensure_wan_egress(mikrotik_creds, interface="ether2")

    assert api.add_calls == []
    assert api.update_calls == []
    assert api.remove_calls == []


@pytest.mark.asyncio
async def test_an_uplink_with_no_masquerade_gets_its_own_rule_added(
    patch_connect, mikrotik_creds
):
    """The failure this exists to prevent: the lab router carries exactly
    one masquerade rule, ``out-interface=ether1``. Move the default route
    to ether2 without this and every guest is NATed by nothing -- traffic
    leaves from an RFC1918 source and dies at the first upstream hop, which
    looks exactly like the outage the failover was meant to end.

    Note what is NOT done: ``cloudguest-nat-wan1`` is left exactly as it
    is. Widening it to ``out-interface-list=WAN`` would be a mutation of a
    live router-wide NAT rule, performed during an outage; a masquerade
    rule matches only traffic leaving its own out-interface, so an added
    rule for ether2 cannot affect ether1's traffic at all.
    """
    menus = _dual_wan_menus()
    menus[("ip", "firewall", "nat")] = [
        {
            ".id": "*n1",
            "chain": "srcnat",
            "action": "masquerade",
            "out-interface": "ether1",
            "comment": "cloudguest-nat-wan1",
            "disabled": "false",
        }
    ]
    menus[("interface", "list", "member")] = [
        {".id": "*m1", "list": "WAN", "interface": "ether1"}
    ]
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    await MikroTikAdapter().ensure_wan_egress(mikrotik_creds, interface="ether2")

    assert api.add_calls == [
        (
            ("interface", "list", "member"),
            {
                "list": "WAN",
                "interface": "ether2",
                "comment": "cloudguest-wanlist-uplink-ether2",
                "disabled": "no",
            },
        ),
        (
            ("ip", "firewall", "nat"),
            {
                "chain": "srcnat",
                "action": "masquerade",
                "out-interface": "ether2",
                "comment": "cloudguest-nat-uplink-ether2",
                "disabled": "no",
            },
        ),
    ]
    # The primary's own rule is still there, unchanged.
    assert api.update_calls == []
    assert menus[("ip", "firewall", "nat")][0]["out-interface"] == "ether1"


@pytest.mark.asyncio
async def test_a_vlan_scoped_masquerade_does_not_count_as_covering(
    patch_connect, mikrotik_creds
):
    """One VLAN's own rule carries a ``src-address`` and therefore NATs
    less than all guest traffic. Counting it would leave every other subnet
    on the router un-NATed after a failover, with the push reporting
    success."""
    menus = _dual_wan_menus()
    menus[("ip", "firewall", "nat")] = [
        {
            ".id": "*n1",
            "chain": "srcnat",
            "action": "masquerade",
            "out-interface": "ether2",
            "src-address": "10.100.0.0/24",
            "comment": "WyfyGuest VLAN 100",
            "disabled": "false",
        }
    ]
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    await MikroTikAdapter().ensure_wan_egress(mikrotik_creds, interface="ether2")

    assert [segments for segments, _ in api.add_calls] == [("ip", "firewall", "nat")]
    assert api.add_calls[0][1]["comment"] == "cloudguest-nat-uplink-ether2"


@pytest.mark.asyncio
async def test_a_disabled_covering_rule_written_by_this_method_is_re_enabled(
    patch_connect, mikrotik_creds
):
    """Booleans, never string comparison: RouterOS answers a read with a
    real ``bool`` and accepts ``"no"`` on write, so comparing the raw value
    against ``"no"`` reports a difference on every push and issues a
    pointless update forever."""
    menus = _dual_wan_menus()
    menus[("ip", "firewall", "nat")] = [
        {
            ".id": "*n1",
            "chain": "srcnat",
            "action": "masquerade",
            "out-interface": "ether2",
            "comment": "cloudguest-nat-uplink-ether2",
            "disabled": True,
        }
    ]
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    await MikroTikAdapter().ensure_wan_egress(mikrotik_creds, interface="ether2")

    assert api.update_calls == [
        (("ip", "firewall", "nat"), {".id": "*n1", "disabled": "no"})
    ]
    assert api.add_calls == []


@pytest.mark.asyncio
async def test_someone_elses_disabled_rule_is_left_alone_and_not_counted(
    patch_connect, mikrotik_creds
):
    """A rule an operator deliberately switched off is their decision, so
    it is not re-enabled -- and it is not providing NAT either, so it is
    not counted as covering. One of this method's own is added alongside
    it."""
    menus = _dual_wan_menus()
    menus[("ip", "firewall", "nat")] = [
        {
            ".id": "*n1",
            "chain": "srcnat",
            "action": "masquerade",
            "out-interface": "ether2",
            "comment": "operator's own, off on purpose",
            "disabled": True,
        }
    ]
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    await MikroTikAdapter().ensure_wan_egress(mikrotik_creds, interface="ether2")

    assert api.update_calls == []
    assert api.add_calls[-1][1]["comment"] == "cloudguest-nat-uplink-ether2"
    assert menus[("ip", "firewall", "nat")][0]["disabled"] is True


@pytest.mark.asyncio
async def test_an_interface_that_does_not_exist_is_named_not_left_to_routeros(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(menus=_dual_wan_menus())
    patch_connect(api)

    with pytest.raises(MikroTikWanInterfaceError) as excinfo:
        await MikroTikAdapter().ensure_wan_egress(mikrotik_creds, interface="sfp1")

    assert "sfp1" in str(excinfo.value)
    assert api.add_calls == []


@pytest.mark.asyncio
async def test_wan_list_membership_is_ensured_because_the_firewall_reads_it(
    patch_connect, mikrotik_creds
):
    """Moving the route is not enough on a router whose firewall matches
    ``in-interface-list=WAN``: an uplink outside that list is one the
    input/forward rules treat as an internal segment."""
    menus = _dual_wan_menus()
    menus[("interface", "list", "member")] = [
        {".id": "*m1", "list": "WAN", "interface": "ether1"}
    ]
    api = FakeRouterOSApi(menus=menus)
    patch_connect(api)

    await MikroTikAdapter().ensure_wan_egress(mikrotik_creds, interface="ether2")

    assert api.add_calls[0][0] == ("interface", "list", "member")
    assert api.add_calls[0][1]["interface"] == "ether2"


@pytest.mark.asyncio
async def test_a_device_error_partway_names_the_route_already_written(
    patch_connect, mikrotik_creds, monkeypatch
):
    """RouterOS has no multi-row atomic update, so the second write failing
    leaves the first one applied -- two default routes tied at the lowest
    distance. The error has to say so: an operator staring at a failed
    failover otherwise cannot tell a no-op from a half-applied swap without
    reading the router back, which is what an outage leaves no time for."""
    api = FakeRouterOSApi(menus=_dual_wan_menus())
    patch_connect(api)

    from tests.fake_write_transport import FakePath

    real_update = FakePath.update
    calls = {"n": 0}

    def flaky_update(self, **fields):
        if self._segments == ("ip", "route"):
            calls["n"] += 1
            if calls["n"] == 2:
                raise LibRouterosError("could not set distance")
        return real_update(self, **fields)

    monkeypatch.setattr(FakePath, "update", flaky_update)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await MikroTikAdapter().set_default_route_distances(
            mikrotik_creds, distances={"ether1": 2, "ether2": 1}
        )

    message = str(excinfo.value)
    assert "already applied" in message
    # Names the interface and the distance that landed, not just a count.
    assert "ether1->distance 2" in message


@pytest.mark.asyncio
async def test_a_device_error_on_the_first_write_says_nothing_changed(
    patch_connect, mikrotik_creds, monkeypatch
):
    api = FakeRouterOSApi(menus=_dual_wan_menus())
    patch_connect(api)

    from tests.fake_write_transport import FakePath

    def always_fails(self, **fields):
        if self._segments == ("ip", "route"):
            raise LibRouterosError("could not set distance")
        return None

    monkeypatch.setattr(FakePath, "update", always_fails)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await MikroTikAdapter().set_default_route_distances(
            mikrotik_creds, distances={"ether1": 2, "ether2": 1}
        )

    assert "no route was changed" in str(excinfo.value)
