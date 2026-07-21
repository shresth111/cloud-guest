# MAC Authorization Domain -- Database Schema

Migration: `alembic/versions/0041_create_mac_authorization_tables.py`.
See `FLOW.md` for the full design reasoning behind each decision below.

## `mac_authorization_entries` (new table)

One row per whitelisted MAC address. A row's own state *is* its current
state -- there is no history table (nothing about a whitelist entry
benefits from an append-only log the way e.g. a health check does).

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Unlike `Policy.organization_id`, there is no platform-wide ("NULL") concept here -- see `FLOW.md` §3. |
| `location_id` | `UUID` | Yes | FK -> `locations.id`, `ondelete="CASCADE"`. `NULL` = organization-wide. Filterable, but deliberately **not** part of the uniqueness index -- see `FLOW.md` §4. |
| `mac_address` | `VARCHAR(17)` | No | Canonical uppercase colon-separated form (`"AA:BB:CC:DD:EE:FF"`), normalized at the service layer before every write -- never stored in whatever mixed case/separator the caller submitted. |
| `authorization_type` | `VARCHAR(20)` | No | `server_default 'permanent'` -- one of `constants.MacAuthorizationType`'s values (permanent/temporary). |
| `expires_at` | `TIMESTAMPTZ` | Yes | Required and validated in-the-future iff `authorization_type == "temporary"`; forbidden iff `"permanent"` -- enforced at the service layer (`validators.validate_expiry`), not a database `CHECK` constraint. |
| `comment` | `TEXT` | Yes | Admin-facing note (e.g. "Front desk manager's personal phone"). |
| `is_enabled` | `BOOLEAN` | No | `server_default true`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_mac_authorization_entries_organization_id`,
`ix_mac_authorization_entries_location_id`,
`ix_mac_authorization_entries_mac_address`,
`ix_mac_authorization_entries_is_enabled`, plus the partial unique index
enforcing "an organization may not hold two non-deleted entries for the
same MAC address":

```sql
CREATE UNIQUE INDEX uq_mac_authorization_entries_org_id_mac_address
  ON mac_authorization_entries (organization_id, mac_address)
  WHERE is_deleted = false;
```

No circular/deferred foreign keys are needed -- both FKs here are
one-directional and declared inline at table-creation time, mirroring
migration `0040`'s identical note.

## No schema change to any existing table

This is a wholly new, additive table -- `app.domains.guest_access
.models.DeviceAccessRule` (the pre-existing, related-but-distinct
domain, see `FLOW.md` §1) is untouched.

## RBAC schema change: a brand-new, additive module

This feature's edit to `app.domains.rbac` is a brand-new, additive
`PermissionModule.MAC_AUTHORIZATION` seeded module (`enums.py`/
`seed.py`) with `CREATE`/`READ`/`UPDATE`/`DELETE`/`IMPORT`/`EXPORT`/
`MANAGE` actions (mirroring `PermissionModule.VOUCHER`'s own inclusion of
both `IMPORT`/`EXPORT` for the identical "bulk-load/download" shape),
`ScopeType.LOCATION` narrowest scope (mirroring
`PermissionModule.GUEST_ACCESS`'s own identical scope, the closest
analogous domain), plus additive `AuditAction` enum values
(`MAC_AUTHORIZATION_ENTRY_CREATED`/`_UPDATED`/`_DELETED`) and grants on
the same five system roles that already grant `GUEST_ACCESS`
(`Platform Admin`, `Location Manager`, `Reception Staff`, `Helpdesk`,
`Guest Operator`) at the identical grant level each already has for
`GUEST_ACCESS`. No migration is needed for any of this --
`permission_groups`/`permissions`/`permission_scopes`/`role_permissions`
rows are all seeded idempotently at application/CLI startup by
`seed_rbac`, never by a migration, per this codebase's own established
convention -- see e.g. migration `0040`'s identical note.
