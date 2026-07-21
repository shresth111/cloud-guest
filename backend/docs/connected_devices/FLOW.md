# Connected Device Management -- Design Write-Up

## 1. Real device discovery: three RouterOS menus merged by MAC address

A single RouterOS menu cannot answer "every device currently connected" --
this domain queries three and merges them by MAC address
(`device_adapters._merge_discovered_devices`):

* `/ip/dhcp-server/lease` -- the best source for a client-reported
  `host-name` and its currently `active-address` (IP), but only ever
  covers devices that actually used DHCP.
* `/ip/arp` -- catches static/non-DHCP devices the lease table misses
  (IP + interface, never a hostname).
* `/interface/wireless/registration-table` -- wireless-only; the sole
  source of real signal-strength data and the authoritative signal for
  "is this device actually wireless" (`is_wireless`).

A device present in more than one source is a single merged row, never
duplicated -- the wireless table's own `interface`/signal data wins over
the ARP/lease-reported interface when both exist, since it is the more
specific, authoritative source for a genuinely wireless client.

**Legacy wireless registration table, not CAPsMAN.** This adapter
queries the legacy wireless package's own table. A CAPsMAN-managed
deployment's `/caps-man/registration-table` is a real, documented gap --
a genuine future seam, not silently assumed equivalent.

## 2. Vendor detection: a small, honest OUI table, never fabricated

No MAC-OUI lookup existed anywhere in this codebase before this domain.
A complete, authoritative OUI database has tens of thousands of entries
(IEEE's own public registry) -- reproducing it here would be either an
unmaintained data dump or an invitation to guess at vendor names for
prefixes an incomplete table doesn't recognize. `constants
.OUI_VENDOR_PREFIXES` therefore contains only entries this codebase can
state with real confidence (the well-documented Raspberry Pi Foundation
OUI blocks) -- mirroring `app.domains.guest.models.RadiusNasClient
.vendor`'s own "a real, true default, not a fabricated placeholder"
discipline. A MAC prefix absent from this table returns `None` (unknown),
never a guessed vendor. Extending this table with more real, verified OUI
entries is a legitimate, explicitly-scoped future seam.

## 3. Why "(Future)" on Signal Information doesn't mean the column is unused

Signal strength is only ever real data for a wireless client -- a wired
device structurally has no such measurement. Since this domain already
queries the wireless registration table (for `connection_type`/
`interface` classification), populating `signal_strength_dbm`
opportunistically from that same query costs nothing extra and is
honestly derived, never fabricated for a wired device (`NULL` there).
The roadmap's own "(Future)" marker reflects that a *complete* signal
strength feature (e.g. historical trending, weak-signal alerting) is out
of this pass's scope, not that the column itself is a placeholder.

## 4. Sync semantics: a device that drops off is marked inactive, never deleted

A device absent from the router's own DHCP-lease/ARP/wireless tables on
a given sync tick has `is_active` flipped to `False` -- its row survives
(so "guest association"/"comment"/history-adjacent context isn't lost
the moment someone unplugs a laptop), never soft-deleted by the sync
itself. Only an explicit admin `delete_device` call removes a row --
mirrors `app.domains.router.models.Router.status`'s own "offline is a
real, persisted state, not a deletion" convention. `connected_at` is
only reset when a device transitions from inactive back to active (a
genuinely new connection), not on every sync tick that merely confirms
"still here."

## 5. Disconnect: a real, but partial, action

Removing a device from `/interface/wireless/registration-table` is a
genuine wireless "kick" -- the client must re-associate. There is no
equivalent forced disconnect for a *wired* client on RouterOS; removing
its ARP/DHCP-lease entry only prevents easy re-association on the same
IP, it does not sever an existing wired link. This is a real, honest
limitation, documented in `device_adapters.py`'s own module docstring
rather than silently overstated as a guaranteed kick.

## 6. Composition with three other domains, never duplication

* **`app.domains.router`** -- identical `RouterLookupProtocol`
  composition-over-duplication pattern every domain in this codebase
  establishes.
* **`app.domains.guest_access`** -- block/unblock/whitelist create or
  remove a real `DeviceAccessRule` row via `GuestAccessService
  .create_device_rule`/`list_device_rules`/`deactivate_device_rule`.
  This domain never reimplements `AccessDecisionResolver`'s own
  precedence logic (`VIP > TEMPORARY > BLOCKLIST > WHITELIST`) -- it
  only ever creates/removes rows that resolver already knows how to
  interpret.
* **`app.domains.guest`** -- "Session Association"/"Guest Association"
  are a read-only cross-reference (`_resolve_guest_association`):
  `GuestRepositoryProtocol.get_device_by_mac` finds the `GuestDevice`
  for a MAC, then `list_active_sessions_for_guest` finds any session on
  *this* router for that guest. This domain never creates or mutates a
  `Guest`/`GuestDevice`/`GuestSession` row -- `guest_id`/
  `guest_session_id` on `ConnectedDevice` are a synced snapshot,
  refreshed at every sync tick, never the source of truth.

## 7. Audit-volume judgment call

Mirrors `app.domains.isp.service`'s own tiering exactly: routine sync
discovery/updates (potentially hundreds of devices per tick,
platform-wide) are **not** audited -- only real admin-initiated actions
(disconnect, delete, comment, block/unblock/whitelist) are, the identical
"moderate-volume, admin-relevant" profile every other domain's own
lifecycle events already carry.

## 8. Per-router failure isolation in the platform-wide sweep

`run_device_sync_sweep` mirrors `app.domains.isp.service
.run_health_check_sweep`'s own per-item isolation contract exactly -- a
single router that's unreachable/misconfigured is caught, logged
(`connected_device_sync_sweep_router_failed`), and skipped, never
aborting the sweep for every other router. Enumerating "every router
platform-wide" is a hand-written query directly against the `Router`
model inside this domain's own repository
(`list_routers_for_sync`), mirroring
`app.domains.monitoring.repository.MonitoringRepository.list_routers`'s
identical precedent -- `RouterRepository` itself has no platform-wide
"list every router" method to delegate to.
