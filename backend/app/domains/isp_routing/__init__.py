"""ISP Routing domain: per-router traffic-steering rules deciding which
``app.domains.isp.models.IspLink`` (WAN uplink) a given piece of traffic
should route through -- VLAN/user/IP/source/interface/policy routing.

A pure inventory/rules domain -- no ``device_adapters.py``, no live device
push. Mirrors ``app.domains.policy``'s own "priority + enable/disable,
realized onto a device later by a provisioning pass" precedent exactly
(RouterOS policy routing needs real ``/ip firewall mangle``/``/routing
table``/``/ip route`` plumbing, which belongs to the not-yet-built Network
Configuration Management domain's own provisioning-integration layer, not
this one). See ``docs/isp_routing/FLOW.md`` for the full design write-up.
"""

from __future__ import annotations
