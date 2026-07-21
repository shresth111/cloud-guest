"""VLAN Management domain: per-router VLAN inventory (VLAN ID, name,
gateway, CIDR, parent interface, description, enable/disable).

A pure inventory/rules domain -- no ``device_adapters.py``, no live device
push. Mirrors ``app.domains.isp_routing``/``app.domains.policy``'s own
"priority-less config resource, realized onto a device later by a
provisioning pass" precedent (real RouterOS VLAN interface + IP address
provisioning belongs to the not-yet-built Network Configuration
Management domain's own provisioning-integration layer, not this one).
See ``docs/vlan/FLOW.md`` for the full design write-up.
"""

from __future__ import annotations
