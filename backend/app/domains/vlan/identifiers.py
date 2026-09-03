"""The one place that answers "which interface is this VLAN actually on".

A free function in its own module, not a ``VlanService`` method, because
two domains need the same answer and neither may import the other's
service: ``app.domains.dhcp.service`` has to know which interface a
captive-portal VLAN occupies before it pushes a DHCP pool onto it, and
``app.domains.vlan.service`` composes the DHCP *repository* back the other
way. Mirrors ``app.domains.qos.identifiers``'s own precedent, which exists
for the same reason -- two callers deriving one RouterOS identifier that
must agree.

Getting this wrong is silent. The conflict check would compare a pool's
interface against a name no object on the device uses, find nothing, and
let both features create a DHCP server on the same interface -- the exact
collision the check exists to prevent.
"""

from __future__ import annotations


def vlan_bind_interface(*, port_mode: str, vlan_id: int, interface: str | None) -> str:
    """The interface a VLAN's address, DHCP and captive portal sit on.

    In trunk mode the VLAN is a tagged sub-interface named
    deterministically from its tag -- ``vlan_id`` is the real, collision-
    free identity, and the VLAN's display name never appears in a RouterOS
    object name. In access mode there is no ``/interface vlan`` entry at
    all: the VLAN is realized as the physical port itself and everything
    binds there.

    Both branches mirror ``network_config.renderers.render_vlan``, which is
    what the operator was shown when they chose the mode. An access row
    with no ``interface`` falls back to the trunk name rather than
    returning ``None``: the push refuses such a row long before this is
    read, and a nullable return would push that impossible case into every
    caller.
    """
    if port_mode == "access" and interface:
        return interface
    return f"vlan{vlan_id}"


__all__ = ["vlan_bind_interface"]
