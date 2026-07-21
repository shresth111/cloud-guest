# Connected Device Management Domain -- Database Schema

Migration: `alembic/versions/0042_create_connected_devices_tables.py`.
See `FLOW.md` for the full design reasoning behind each decision below.

## `connected_devices` (new table)

One row per device seen on a router's own network. A row's own state
*is* its most recently synced state -- see `FLOW.md` §4 for why there is
no history table and why a dropped-off device is marked inactive, never
deleted.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `mac_address` | `VARCHAR(17)` | No | Canonical uppercase colon-separated form, normalized before every write. |
| `ip_address` | `VARCHAR(45)` | Yes | From the most recent DHCP lease/ARP reply. |
| `hostname` | `VARCHAR(255)` | Yes | Client-reported (DHCP option 12), often blank. |
| `vendor` | `VARCHAR(100)` | Yes | Best-effort MAC-OUI lookup -- see `FLOW.md` §2. `NULL` means genuinely unknown. |
| `connection_type` | `VARCHAR(10)` | No | `server_default 'unknown'` -- one of `constants.ConnectionType`'s values (wired/wireless/unknown). |
| `interface` | `VARCHAR(100)` | Yes | The router's own interface/SSID this device was last seen on. |
| `signal_strength_dbm` | `INTEGER` | Yes | Only ever populated for a wireless device -- see `FLOW.md` §3. |
| `is_active` | `BOOLEAN` | No | `server_default true`. Flipped to `false` when a device drops off the router's own sync sources -- never deleted by the sync itself. |
| `connected_at` | `TIMESTAMPTZ` | Yes | Start of this device's *current* active streak -- reset only on an inactive -> active transition, not every sync tick. |
| `last_seen_at` | `TIMESTAMPTZ` | Yes | Updated on every sync tick this device is discovered. |
| `comment` | `TEXT` | Yes | Admin-facing note (the "Add Comment" action). |
| `guest_id` | `UUID` | Yes | FK -> `guests.id`, `ondelete="SET NULL"`. A synced snapshot of a read-only cross-reference against `app.domains.guest` -- never authoritative itself, see `FLOW.md` §6. |
| `guest_session_id` | `UUID` | Yes | FK -> `guest_sessions.id`, `ondelete="SET NULL"`. Same synced-snapshot convention. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_connected_devices_router_id`,
`ix_connected_devices_organization_id`,
`ix_connected_devices_location_id`, `ix_connected_devices_mac_address`,
`ix_connected_devices_is_active`, `ix_connected_devices_guest_id`, plus
the partial unique index enforcing "a router may not hold two
non-deleted rows for the same MAC address":

```sql
CREATE UNIQUE INDEX uq_connected_devices_router_id_mac_address
  ON connected_devices (router_id, mac_address)
  WHERE is_deleted = false;
```

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0041`'s identical note.

## No schema change to any existing table

This is a wholly new, additive table. `app.domains.guest.models
.GuestDevice`/`GuestSession` and `app.domains.guest_access.models
.DeviceAccessRule` are all read/composed, never modified.

## RBAC schema change: a brand-new, additive module

This feature's edit to `app.domains.rbac` is a brand-new, additive
`PermissionModule.CONNECTED_DEVICES` seeded module (`enums.py`/
`seed.py`) with `READ`/`UPDATE`/`DELETE`/`EXECUTE`/`MANAGE` actions (no
`CREATE` -- rows only ever come into existence via sync, see `FLOW.md`
§4), `ScopeType.ROUTER` narrowest scope (mirroring
`PermissionModule.ISP`/`VLAN`/`DHCP`'s own identical scope), plus
additive `AuditAction` enum values (`CONNECTED_DEVICE_DISCONNECTED`/
`_DELETED`/`_COMMENT_ADDED`/`_BLOCKED`/`_UNBLOCKED`/`_WHITELISTED`) and a
`FULL` grant on the "Network Administrator" system role. No migration is
needed for any of this -- `permission_groups`/`permissions`/
`permission_scopes`/`role_permissions` rows are all seeded idempotently
at application/CLI startup by `seed_rbac`, never by a migration, per
this codebase's own established convention -- see e.g. migration
`0041`'s identical note.
