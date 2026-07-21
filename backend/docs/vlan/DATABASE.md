# VLAN Management Domain -- Database Schema

Migration: `alembic/versions/0038_create_vlan_tables.py`. See `FLOW.md`
for the full design reasoning behind each decision below.

## `vlans` (new table)

One row per VLAN a router carries. A row's own state *is* its current
state -- see `FLOW.md` §4 for why there is no history table.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `vlan_id` | `INTEGER` | No | The real IEEE 802.1Q VLAN tag, 1-4094 -- see `constants.py` and `FLOW.md` §3. |
| `name` | `VARCHAR(200)` | No | Admin-facing label. |
| `gateway_ip_address` | `VARCHAR(45)` | Yes | Validated at the service layer via `ipaddress.ip_address` when supplied. |
| `cidr` | `VARCHAR(64)` | Yes | e.g. `"192.168.10.0/24"`. Validated at the service layer via `ipaddress.ip_network` when supplied. |
| `interface` | `VARCHAR(100)` | Yes | The router's own parent interface this VLAN is tagged on (e.g. `"ether1"`). Informational only. |
| `description` | `TEXT` | Yes | |
| `is_enabled` | `BOOLEAN` | No | `server_default true`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_vlans_router_id`, `ix_vlans_organization_id`,
`ix_vlans_location_id`, `ix_vlans_is_enabled`, plus the partial unique
index enforcing "a router may not hold two non-deleted VLANs with the
same vlan_id" (see `FLOW.md` §1):

```sql
CREATE UNIQUE INDEX uq_vlans_router_id_vlan_id
  ON vlans (router_id, vlan_id)
  WHERE is_deleted = false;
```

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0037`'s identical note.

## No RBAC schema change beyond a brand-new, additive module

This feature's only edit to `app.domains.rbac` is a brand-new, additive
`PermissionModule.VLAN` seeded module (`enums.py`/`seed.py`) plus additive
`AuditAction` enum values (`VLAN_CREATED`/`VLAN_UPDATED`/`VLAN_DELETED`)
-- no migration needed for any of those (`permission_groups`/
`permissions`/`permission_scopes`/`role_permissions` rows are all seeded
idempotently at application/CLI startup by `seed_rbac`, never by a
migration, per this codebase's own established convention -- see e.g.
migration `0037`'s identical note).
