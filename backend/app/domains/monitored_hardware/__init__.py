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

## Uptime is a second, separate fact -- never the age of ``last_seen_at``

``last_seen_at`` above says "we heard from it recently". It does **not**
say "it has been running that long", and the dashboard read it as though
it did: a router with 7h28m of real uptime and a two-minute-old heartbeat
was rendered as "4 mins up".

The difference is not cosmetic. The router that prompted this rebooted
three times in two hours (03:50, 04:18, 05:43 UTC on 2026-09-07, each
confirmed by ``/system/resource`` and a cold-boot log entry with NTP
correcting the clock). It came back and resumed heartbeating each time, so
time-since-heartbeat stayed healthy through all three and hid every one of
them. Uptime is the only one of the two measurements that makes a reboot
visible at all, and "this access point has restarted 3 times today" is
what a venue owner actually needs to know.

``MonitoredHardwareResponse.uptime_seconds`` therefore carries real device
uptime, alongside ``uptime_recorded_at`` (when the reading was taken -- a
seven-hour uptime read forty minutes ago is not a seven-hour uptime now).
It is sourced, like status, entirely from data the platform already
collects:

- ``run_router_health_poll_sweep`` reads ``/system/resource`` over the
  RouterOS API on port 8728 every 600s and writes ``uptime_seconds`` into
  ``router_health_snapshots``; the SNMP sweep does the same every 300s.
  This domain does a plain ``DISTINCT ON`` read of that table. **Nothing
  here contacts a device at request time**, so a list render costs two
  extra queries for the whole page regardless of its size -- see
  ``MonitoredHardwareService._uptime_by_mac``.
- A hardware row is matched to a router by MAC (``Router.mac_address`` is
  ``NOT NULL`` and unique, and is org-scoped on lookup so one tenant can
  never read another's uptime), or by an explicit ``router_id`` where one
  is set.

And where no real reading exists, the field is ``None``. That is the whole
answer for a third-party access point, printer or camera: **there is no
mechanism anywhere in this platform that can learn their uptime.** A
TP-Link EAP225 runs no RouterOS API and has no SNMP agent this platform
configures. ``None`` is not a gap waiting to be filled with the
``last_seen_at`` age -- substituting that back in is precisely the bug
this field was added to end.
"""

from __future__ import annotations
