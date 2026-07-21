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

Real RouterOS ``/ip firewall mangle`` packet-marking is composed via
``app.domains.network_config`` in the same pass this domain was built
(rather than deferred to a future domain, mirroring ``app.domains
.hotspot``'s own identical "compose immediately, don't defer" precedent
now that Network Configuration Management already exists) -- see
``docs/qos/FLOW.md`` for the full design write-up, including why pairing
the resulting packet-mark with an actual ``/queue tree`` entry is a
real, separate, currently-manual device-side step, not automated in this
pass.
"""

from __future__ import annotations
