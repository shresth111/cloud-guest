# Hotspot Settings Domain -- Database Schema

Migration: `alembic/versions/0044_create_hotspot_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `hotspot_profiles` (new table)

One row per hotspot user-profile a router serves. A row's own state *is*
its current state -- there is no history table; real device provisioning
is composed via `app.domains.network_config`, not tracked here.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `name` | `VARCHAR(200)` | No | Admin-facing label. No uniqueness constraint -- mirrors `dhcp_pools.name`'s own identical posture. |
| `session_timeout_minutes` | `INTEGER` | Yes | `NULL` means no session limit (RouterOS's own "0" convention for unlimited). |
| `idle_timeout_minutes` | `INTEGER` | Yes | Same nullable-means-unlimited convention. |
| `upload_limit_kbps` | `INTEGER` | Yes | RouterOS rate-limit `rx-rate` -- see `FLOW.md` §2 for the rx=upload/tx=download convention this mirrors. |
| `download_limit_kbps` | `INTEGER` | Yes | RouterOS rate-limit `tx-rate`. |
| `walled_garden_hosts` | `JSONB` | No | `server_default '[]'::jsonb`. A list of allowed hostnames/IPs; validated at the service layer (`validators.validate_walled_garden_hosts`), not a database constraint. |
| `is_enabled` | `BOOLEAN` | No | `server_default true`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_hotspot_profiles_router_id`,
`ix_hotspot_profiles_organization_id`, `ix_hotspot_profiles_location_id`,
`ix_hotspot_profiles_is_enabled`.

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0039`'s identical note.

## No RBAC schema change beyond reusing an already-seeded module

`PermissionModule.HOTSPOT` (`rbac/enums.py`) was already seeded ahead of
this domain's own build -- only its `MODULE_DISPLAY_NAMES` entry was
upgraded (`"Hotspot"` -> `"Hotspot Settings"`). Three additive
`AuditAction` enum values (`HOTSPOT_PROFILE_CREATED`/`_UPDATED`/
`_DELETED`) were added to `rbac/enums.py` -- no migration needed for any
of this, since `permission_groups`/`permissions`/`permission_scopes`/
`role_permissions` rows are all seeded idempotently at application/CLI
startup by `seed_rbac`, never by a migration (see migration `0039`'s
identical note).
