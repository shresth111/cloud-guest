"""Module 008: Router domain (MikroTik device management + zero-touch
provisioning).

Builds on Module 002 (``app.database``) for persistence primitives, Module
003 (``app.domains.auth``) for identity, Module 004 (``app.domains.rbac``)
for authorization -- the already-seeded ``routers.*``/``router_provisioning.*``
permission keys gate every mutating endpoint here, no new permission keys
are invented -- and Module 006 (``app.domains.location``) for hierarchy
validation (a router must belong to a real, non-archived location; composed
via ``LocationService``, never re-queried directly). See
``backend/docs/router/ROUTER_ARCHITECTURE.md`` for the full design.

This module covers the Router *device record* and its provisioning
lifecycle only -- not the guest-facing captive portal/hotspot/network-
service configuration layered on top of a router (Captive Portal, Guest
WiFi, Guest Users, Guest Sessions, Radius, WireGuard, Firewall, DHCP, DNS,
Hotspot, Bandwidth, Monitoring, Alerts are all separate, already-seeded
permission modules reserved for future domains).
"""
