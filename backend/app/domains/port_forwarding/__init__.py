"""Port Forwarding Management domain: per-router port-forwarding (NAT
DSTNAT) rule inventory -- source/destination address, destination port,
internal address/port, protocol, enable/disable, description.

Rules are inventory *and* are realized on real hardware:
``device_adapters.py`` issues the actual ``/ip firewall nat`` DSTNAT
operations over the RouterOS API on port 8728, and
``POST /port-forwarding/rules/{id}/push`` is what an operator presses. This
paragraph previously described the domain as "a pure inventory/rules domain
-- no ``device_adapters.py``, no live device push", deferring real
provisioning to the not-yet-built Network Configuration Management domain;
the effect was that publishing a port wrote a row and contacted nothing.
See ``docs/port_forwarding/FLOW.md`` for the full design write-up.
"""

from __future__ import annotations
