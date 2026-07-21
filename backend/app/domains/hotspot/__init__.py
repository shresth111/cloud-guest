"""Hotspot Settings domain: per-router hotspot user-profile inventory
(session/idle timeout, upload/download rate limits, a walled-garden
allowed-hosts list) -- one of the "config resource, realized onto a
device later" family alongside ``app.domains.dhcp``/``app.domains.vlan``/
``app.domains.port_forwarding``.

Real RouterOS ``/ip hotspot`` provisioning is composed via
``app.domains.network_config`` in the same pass this domain was built
(rather than deferred to a future domain, since Network Configuration
Management already existed) -- see ``docs/hotspot/FLOW.md`` for the full
design write-up, including why only the ``/ip hotspot user profile`` +
walled-garden slice is modeled, not a full ``/ip hotspot`` server bind.
"""

from __future__ import annotations
