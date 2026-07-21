"""Connected Device Management domain: a per-router inventory of every
device currently (or recently) seen on the network -- DHCP leases, ARP
entries, and wireless registration-table clients merged by MAC address --
with real device sync, a manual disconnect action, and admin actions
(comment, block/unblock/whitelist).

Composes, never duplicates:

* ``app.domains.router`` -- device connection credentials (identical
  ``RouterLookupProtocol`` composition-over-duplication pattern every
  domain in this codebase establishes).
* ``app.domains.guest_access`` -- block/unblock/whitelist create/delete a
  real ``DeviceAccessRule`` row there; this domain never reimplements
  access-rule precedence.
* ``app.domains.guest`` -- "Session Association"/"Guest Association" are
  a read-only cross-reference against ``GuestDevice``/``GuestSession``,
  resolved fresh at every sync; this domain never creates or mutates a
  guest, device, or session row.

See ``docs/connected_devices/FLOW.md`` for the full design write-up.
"""

from __future__ import annotations
