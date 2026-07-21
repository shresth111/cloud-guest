"""Port Forwarding Management domain: per-router port-forwarding (NAT
DSTNAT) rule inventory -- source/destination address, destination port,
internal address/port, protocol, enable/disable, description.

A pure inventory/rules domain -- no ``device_adapters.py``, no live device
push. Mirrors ``app.domains.dhcp``/``app.domains.vlan``'s own "config
resource, realized onto a device later by a provisioning pass" precedent
(real RouterOS ``/ip firewall nat`` DSTNAT provisioning belongs to the
not-yet-built Network Configuration Management domain's own
provisioning-integration layer, not this one). See
``docs/port_forwarding/FLOW.md`` for the full design write-up.
"""

from __future__ import annotations
