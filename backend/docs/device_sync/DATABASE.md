# Device Synchronization Domain -- Database Schema

Migration: `alembic/versions/0043_create_device_sync_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `device_sync_runs` (new table)

One immutable row per orchestrated "sync this router" attempt. No
`update`/soft-delete anywhere in this domain's own repository -- see
`FLOW.md` §5 for why "Sync History" is simply querying this table.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `status` | `VARCHAR(10)` | No | `server_default 'success'` -- one of `constants.SyncRunStatus`'s values (success/partial/failed), computed from `component_results` -- see `FLOW.md` §4. |
| `component_results` | `JSONB` | No | `server_default '{}'::jsonb`. Keyed by `constants.SyncComponent`'s values (connected_devices/queue_management/provisioning/dhcp/vlan/port_forwarding), each `{"status": ..., "summary": ...}` -- see `FLOW.md` §6. |
| `started_at` | `TIMESTAMPTZ` | No | |
| `completed_at` | `TIMESTAMPTZ` | No | |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`) --
present for schema uniformity even though this domain's own service
never calls `soft_delete` (see `models.py`'s own module docstring).

Indexes: `ix_device_sync_runs_router_id`,
`ix_device_sync_runs_organization_id`,
`ix_device_sync_runs_location_id`, `ix_device_sync_runs_started_at`,
`ix_device_sync_runs_status`.

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0042`'s identical note.

## No schema change to any existing table

This migration creates one wholly new, additive table. It has no
bearing on `app.domains.queue_management`'s own tables -- the new
`reapply_assignments_for_router` method added to that domain's service
reuses its existing `queue_assignments` schema unchanged, issuing the
exact same `reset_queue` calls any other caller would.

## RBAC schema change: a brand-new, additive module

This feature's edit to `app.domains.rbac` is a brand-new, additive
`PermissionModule.DEVICE_SYNC` seeded module (`enums.py`/`seed.py`) with
`READ`/`EXECUTE`/`MANAGE` actions (no `CREATE`/`UPDATE`/`DELETE` --
`DeviceSyncRun` rows are immutable and only ever created by the sync
action itself), `ScopeType.ROUTER` narrowest scope (mirroring
`PermissionModule.CONNECTED_DEVICES`'s own identical scope), plus one
additive `AuditAction` enum value (`DEVICE_SYNC_RUN_COMPLETED`, always
audited -- a router-wide sync is always an admin-triggered,
operationally significant action regardless of outcome) and a `FULL`
grant on the "Network Administrator" system role. No migration is needed
for any of this -- `permission_groups`/`permissions`/`permission_scopes`/
`role_permissions` rows are all seeded idempotently at application/CLI
startup by `seed_rbac`, never by a migration, per this codebase's own
established convention -- see e.g. migration `0042`'s identical note.
