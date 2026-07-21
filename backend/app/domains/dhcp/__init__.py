"""DHCP Pool Management domain: per-router DHCP pool inventory (address
range, gateway, DNS, lease time, interface, enable/disable).

A pure inventory/rules domain -- no ``device_adapters.py``, no live device
push. Mirrors ``app.domains.vlan``/``app.domains.isp_routing``'s own
"config resource, realized onto a device later by a provisioning pass"
precedent (real RouterOS DHCP server + pool provisioning belongs to the
not-yet-built Network Configuration Management domain's own
provisioning-integration layer, not this one). See ``docs/dhcp/FLOW.md``
for the full design write-up.
"""

from __future__ import annotations
