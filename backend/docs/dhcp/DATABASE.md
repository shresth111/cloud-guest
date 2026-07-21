# DHCP Pool Management Domain -- Database Schema

Migration: `alembic/versions/0039_create_dhcp_pool_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `dhcp_pools` (new table)

One row per DHCP address pool a router serves. A row's own state *is* its
current state -- see `FLOW.md` §5 for why there is no history table.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `name` | `VARCHAR(200)` | No | Admin-facing label. |
| `interface` | `VARCHAR(100)` | Yes | The router's own interface this pool serves (e.g. `"ether2"`, `"vlan10"`). Conflict detection only compares ranges between pools sharing the same value -- see `FLOW.md` §3. |
| `address_range_start` | `VARCHAR(45)` | No | Validated at the service layer via `ipaddress.ip_address`. |
| `address_range_end` | `VARCHAR(45)` | No | Same validation; must be >= `address_range_start` (same IP family). |
| `gateway_ip_address` | `VARCHAR(45)` | Yes | Validated at the service layer via `ipaddress.ip_address` when supplied. |
| `dns_primary` / `dns_secondary` | `VARCHAR(45)` | Yes | Same validation when supplied. |
| `lease_time_seconds` | `INTEGER` | No | `server_default 86400` (1 day, RouterOS's own default) -- see `constants.py`. |
| `is_enabled` | `BOOLEAN` | No | `server_default true`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_dhcp_pools_router_id`, `ix_dhcp_pools_organization_id`,
`ix_dhcp_pools_location_id`, `ix_dhcp_pools_interface`,
`ix_dhcp_pools_is_enabled`.

No range-overlap database constraint -- see `FLOW.md` §1 for why this is
a service-layer check only (`DhcpPoolRangeConflictError`), not a database
`EXCLUDE` constraint.

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0038`'s identical note.

## No RBAC schema change beyond reusing an already-seeded module

Unlike every prior domain in this Phase 2 batch (`isp`/`isp_routing`/
`vlan`, each of which minted a brand-new `PermissionModule`),
`PermissionModule.DHCP` already existed -- seeded ahead of any real
domain, mirroring `PermissionModule.BANDWIDTH`'s own pre-existing posture
before `app.domains.queue_management` filled it in. This feature's only
edit to `app.domains.rbac` is reusing that existing module's action tuple
as-is, upgrading its display name (`"DHCP"` -> `"DHCP Pool Management"`),
and adding additive `AuditAction` enum values (`DHCP_POOL_CREATED`/
`DHCP_POOL_UPDATED`/`DHCP_POOL_DELETED`) -- no migration needed for any
of those (`permission_groups`/`permissions`/`permission_scopes`/
`role_permissions` rows are all seeded idempotently at application/CLI
startup by `seed_rbac`, never by a migration, per this codebase's own
established convention -- see e.g. migration `0038`'s identical note).
