# Network Diagnostics Domain -- Database Schema

Migration: `alembic/versions/0046_create_network_diagnostics_tables.py`.
See `FLOW.md` for the full design reasoning behind each decision below.

## `diagnostic_runs` (new table)

One row per executed `ping`/`traceroute` attempt. Immutable and
append-only once created -- there is no `update`/soft-delete method
anywhere in this domain's own repository, only `create` and reads
(mirrors `app.domains.device_sync.models.DeviceSyncRun`'s own identical
"new row, not mutate" convention).

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `diagnostic_type` | `VARCHAR(20)` | No | `"ping"`/`"traceroute"` (see `constants.DiagnosticType`). |
| `target` | `VARCHAR(255)` | No | The admin-supplied hostname/IP the diagnostic was run against. |
| `status` | `VARCHAR(10)` | No | `server_default 'success'` -- `"success"`/`"failed"` (see `constants.DiagnosticStatus`); reflects whether the diagnostic *executed*, not whether the target was reachable (see `FLOW.md` §5). |
| `result` | `JSONB` | No | `server_default '{}'::jsonb`. Real, structured, but variably-shaped per `diagnostic_type` -- a ping's `sent`/`received`/`packet_loss_percentage`/`avg_rtt_ms` vs. a traceroute's ordered `hops` list. Empty on a `FAILED` run. |
| `error_message` | `VARCHAR(500)` | Yes | The real device-connection/operation failure reason, populated only on a `FAILED` run. |
| `executed_by_user_id` | `UUID` | Yes | The admin who triggered this run, if any. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_diagnostic_runs_router_id`,
`ix_diagnostic_runs_organization_id`, `ix_diagnostic_runs_location_id`,
`ix_diagnostic_runs_diagnostic_type`, `ix_diagnostic_runs_status`.

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0045`'s identical note.

## RBAC schema change: a genuinely new permission module

Unlike `PermissionModule.HOTSPOT` (already pre-seeded before its domain
was built), `PermissionModule.NETWORK_DIAGNOSTICS` (`rbac/enums.py`) is a
brand-new, additive enum member -- no pre-existing, unclaimed module fit
this domain's own scope (see `FLOW.md` §6). One additive `AuditAction`
enum value (`NETWORK_DIAGNOSTIC_RUN_COMPLETED`) was also added. No
migration needed for any of this, since `permission_groups`/
`permissions`/`permission_scopes`/`role_permissions` rows are all seeded
idempotently at application/CLI startup by `seed_rbac`, never by a
migration (see migration `0039`'s identical note).
