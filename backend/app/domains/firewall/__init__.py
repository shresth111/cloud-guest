"""Firewall Rule Management domain: per-router generic ALLOW/DROP/REJECT
packet-filter rule inventory (RouterOS's own ``/ip firewall filter``).

Distinct from ``app.domains.port_forwarding``, which owns NAT/DSTNAT
redirection only (no ``action``/``chain`` concept at all -- see that
domain's own module docstring) and already, deliberately, reuses this same
``PermissionModule.FIREWALL`` permission key for its own NAT concern. This
domain is the sibling that actually owns generic packet filtering.

A pure inventory/rules domain -- no ``device_adapters.py``, no live device
push. Mirrors ``app.domains.dhcp``/``app.domains.vlan``'s own "config
resource, realized onto a device later by a provisioning pass" precedent
(real RouterOS firewall-filter provisioning happens through
``app.domains.network_config``'s existing push pipeline, not this one).

Rule *order* is semantically significant in a real RouterOS firewall
filter (rules are evaluated top-to-bottom, first match wins) -- modeled
here as an explicit ``priority`` integer (lower evaluates first), rendered
into the pushed script in ascending-priority order. This is a real,
documented modeling choice, not database row order (which SQL never
guarantees), mirroring ``app.domains.qos.models.QosTrafficRule.priority``'s
identical precedent.
"""

from __future__ import annotations
