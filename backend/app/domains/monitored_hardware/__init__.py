"""Monitored Hardware domain: a real, persisted registry of a venue's own
network infrastructure (Access Points, Printers, Routers, Cameras, Other)
that an admin registers by MAC address, distinct from both
``app.domains.network_device`` (a NAC identity/compliance registry --
admin-assessed compliance status, nothing to do with reachability) and
``app.domains.connected_devices`` (live guest/LAN presence telemetry
synced from a router's own DHCP-lease/ARP/wireless tables).

## Why this domain exists

The frontend previously "tracked" this hardware entirely in browser
``localStorage`` (a Zustand store, no backend underneath at all) --
devices an admin added would vanish on a different browser/device, or if
localStorage was ever cleared, since nothing was ever persisted anywhere
real. This domain replaces that with genuine server-side persistence.

## Status is derived, never fabricated

There is no real mechanism to reach out and ping an arbitrary printer or
camera's MAC address from this backend. But ``app.domains
.connected_devices.models.ConnectedDevice`` already holds a real,
continuously-synced record of every MAC address a router's own
DHCP-lease/ARP/wireless-registration sweep has observed on a location's
network (guest or not -- ``ConnectedDevice.guest_id`` is nullable), each
with a genuine ``last_seen_at`` and an ``is_active`` flag ("present in the
most recent sync sweep").

``MonitoredHardwareService.get_status`` is a read-time lookup against that
existing, already-synced data -- never a new polling/ping mechanism of its
own. Three honest states result:

- ``UP`` -- a ``ConnectedDevice`` row exists for this MAC at this
  location and its own ``is_active`` is ``True``.
- ``DOWN`` -- a row exists but ``is_active`` is ``False`` (it *was* seen,
  isn't currently).
- ``UNKNOWN`` -- no row exists at all yet. A device just registered, or
  one this router's sync has simply never observed, reads as "not yet
  observed" -- never defaulting to a fabricated "up", the same honesty
  posture ``app.domains.network_device``'s own ``compliance_status
  .UNKNOWN`` default already establishes for this codebase.
"""

from __future__ import annotations
