"""QoS & VOIP Priority domain: per-router traffic-classification rules
(protocol/port-range match for VOIP signaling/media, or DSCP value,
mapped to a RouterOS priority level) -- one of the "config resource,
realized onto a device later" family alongside ``app.domains.dhcp``/
``app.domains.vlan``/``app.domains.port_forwarding``/``app.domains
.hotspot``.

``app.domains.queue_management`` already is the real, complete
bandwidth/priority engine (rate limits, RouterOS priority 1-8, real
device push); this domain fills the one genuinely missing piece --
traffic classification -- and reuses ``queue_management``'s own priority
bounds for validation rather than redeclaring them.

Both RouterOS objects a QoS rule becomes -- the ``/ip firewall mangle``
packet mark and the ``/queue tree`` entry that references it -- are pushed
by this domain's own ``device_adapters.py`` through
``POST /qos-rules/{rule_id}/push``. ``app.domains.network_config`` also
renders the mangle half into its config script, and that remains true, but
it is not what a customer's Apply button reaches; see
``service.py``'s own module docstring for why relying on it meant shipping
half a mechanism under a badge claiming the whole one.
"""

from __future__ import annotations
