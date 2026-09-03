"""VLAN Management domain: per-router VLAN inventory (VLAN ID, name,
gateway, CIDR, parent interface, description, enable/disable).

Not a pure inventory domain: ``device_adapters.py`` realizes a VLAN on its
own router over the RouterOS API (interface, address, NAT, captive
portal), and ``POST /vlans/{id}/push`` is the operator-facing trigger.
This paragraph said the opposite -- "no ``device_adapters.py``, no live
device push ... realized onto a device later by a provisioning pass" --
and stayed after the adapter landed, which is the kind of stale claim
that makes a docstring worse than none.

See ``docs/vlan/FLOW.md`` for the full design write-up, and
``service.py``'s own module docstring for what the push does and refuses.
"""

from __future__ import annotations
