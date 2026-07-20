# Router Provisioning: Database Schema

Migration: `alembic/versions/0009_create_router_provisioning_tables.py`
(revises `0008_add_router_fk_to_rbac_tables`). Every table extends
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- eight new
tables, no changes to any existing table's columns (unlike Modules 005/006/
008's own RBAC FK follow-ups, this module needed no such follow-up: every
new table references existing tables, none of them need a new FK pointed
*at* them from RBAC).

**Provisioning Engine addendum** (migration
`alembic/versions/0031_add_vendor_to_router_and_template.py`, revises
`0030_extend_radius_nas_clients`): adds `vendor` to both `config_templates`
(below) and `routers` (see `docs/router/README.md`) -- see
`PROVISIONING_ENGINE.md` for the full design write-up.

## `config_templates`

A reusable device config script/template with `{{variable_name}}`
placeholders.

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, nullable, FK `organizations.id` (`CASCADE`) | `NULL` = platform-wide system template |
| `name` | String(200) | |
| `description` | Text, nullable | |
| `is_system_template` | Boolean | Always `organization_id IS NULL` (enforced in `validators.py`, not a DB `CHECK`) |
| `applicable_router_model` | String(100), nullable | `NULL` = any model |
| `vendor` | String(50), default `mikrotik` | Which device vendor's config language `template_content` is written in (migration `0031`) -- validated against the target router's own `vendor` by `adapters.get_provisioning_adapter` before assignment. Immutable after creation (not on `ConfigTemplateUpdateRequest`) |
| `template_content` | Text | The template script itself |
| `is_active` | Boolean | `DELETE` deactivates + soft-deletes, never hard-deletes |

Indexes: `organization_id`, `is_system_template`, `applicable_router_model`,
`vendor`, `is_active`, `name`.

## `config_variables`

Key/value pairs for template rendering, scoped `ORGANIZATION`/`LOCATION`/
`ROUTER` (see `FLOW.md` §1 for the full resolution-order reasoning).

| Column | Type | Notes |
|---|---|---|
| `scope_type` | String(20) | `constants.ConfigVariableScope` value |
| `organization_id` | UUID, nullable, FK `organizations.id` (`CASCADE`) | Populated (denormalized) at every scope; `NULL` at `ORGANIZATION` scope means a global default |
| `location_id` | UUID, nullable, FK `locations.id` (`CASCADE`) | Populated at `LOCATION`/`ROUTER` scope |
| `router_id` | UUID, nullable, FK `routers.id` (`CASCADE`) | Populated only at `ROUTER` scope |
| `key` | String(150) | |
| `value` | Text | Plaintext, or Fernet ciphertext when `is_secret` |
| `is_secret` | Boolean | Encrypted via BE-008's `app.domains.router.crypto`, not a new mechanism |

Indexes: `scope_type`, `organization_id`, `location_id`, `router_id`, `key`.
Uniqueness (per exact scope + key) is enforced in the service layer
(`RouterProvisioningRepository.find_variable`), not a DB constraint --
nullable FKs in a composite unique constraint don't behave usefully in
Postgres (`NULL <> NULL`), so this follows the same app-layer-enforcement
convention `RouterStatus` transitions already use.

## `config_profiles`

The binding "this router runs this template."

| Column | Type | Notes |
|---|---|---|
| `router_id` | UUID, FK `routers.id` (`CASCADE`), **unique** | One profile per router -- reassigning updates this row |
| `template_id` | UUID, FK `config_templates.id` (`RESTRICT`) | `RESTRICT` is a defensive backstop never actually exercised (templates are only ever soft-deleted via the API, never hard-deleted) |
| `assigned_by_user_id` | UUID, nullable | |
| `assigned_at` | DateTime | |

Indexes: `router_id` (also the unique constraint), `template_id`.

## `config_versions`

An immutable, versioned snapshot of a *rendered* configuration. See
`FLOW.md` §2 for the full status-transition graph.

| Column | Type | Notes |
|---|---|---|
| `router_id` | UUID, FK `routers.id` (`CASCADE`) | |
| `profile_id` | UUID, nullable, FK `config_profiles.id` (`SET NULL`) | |
| `version_number` | Integer | Sequential per router, assigned by the service layer |
| `rendered_content` | Text | Template + resolved variables, baked together |
| `status` | String(20) | `constants.ConfigVersionStatus` |
| `created_by_user_id` | UUID, nullable | |
| `applied_at` | DateTime, nullable | |
| `rollback_of_version_id` | UUID, nullable, **self-FK** `config_versions.id` (`SET NULL`) | Set when this row was created by `rollback_to_version` |
| `is_backup` | Boolean | See "Backup design decision" below |

Constraints: `UNIQUE (router_id, version_number)`. Indexes: `router_id`,
`status`, `rollback_of_version_id`, `is_backup`.

**Backup design decision.** A backup is not a separate table
(`RouterBackup`) -- it is a `ConfigVersion` row with `is_backup=True`. A
backup is, structurally, exactly the same thing as any other version: a
full point-in-time snapshot of rendered config text for one router. The
only fact that distinguishes it (excluded from "what is this router's
current live config" resolution -- see
`RouterProvisioningRepository.get_latest_applied_version`, which filters
`is_backup=False`) is expressed completely by one boolean column. A second
table would duplicate every other column for no new information captured.

## `router_enrollment_requests`

Device-initiated enrollment, before any `Router` record exists.

| Column | Type | Notes |
|---|---|---|
| `serial_number` | String(100) | |
| `mac_address` | String(17) | |
| `model` | String(100) | |
| `requested_at` | DateTime | |
| `status` | String(20) | `constants.EnrollmentStatus` |
| `reviewed_by_user_id` | UUID, nullable | |
| `reviewed_at` | DateTime, nullable | |
| `rejection_reason` | Text, nullable | |
| `approved_router_id` | UUID, nullable, FK `routers.id` (`SET NULL`) | Additive beyond the module brief's literal column list -- traces an approved request to the `Router` row it produced |

Indexes: `serial_number`, `mac_address`, `status`.

## `provisioning_jobs`

A durable job record for a device-affecting action. See `FLOW.md` §4 for the
Redis-transport/Postgres-source-of-truth split.

| Column | Type | Notes |
|---|---|---|
| `router_id` | UUID, FK `routers.id` (`CASCADE`) | |
| `job_type` | String(30) | `constants.ProvisioningJobType` |
| `status` | String(20) | `constants.ProvisioningJobStatus` |
| `payload` | JSONB | e.g. `{"config_version_id": ...}`, `{"backup_version_id": ...}` |
| `attempts` | Integer | |
| `max_attempts` | Integer | Default 3 |
| `scheduled_at` | DateTime | |
| `started_at` | DateTime, nullable | |
| `completed_at` | DateTime, nullable | |
| `error_message` | Text, nullable | |
| `requested_by_user_id` | UUID, nullable | |

Indexes: `router_id`, `job_type`, `status`, `scheduled_at`.

## `router_health_snapshots`

Time-series health/metrics history -- BE-008's own `Router.health_status`/
`last_health_check_at` are a "current snapshot" only, deliberately not
history (see `docs/router/ROUTER_ARCHITECTURE.md` §4).

| Column | Type | Notes |
|---|---|---|
| `router_id` | UUID, FK `routers.id` (`CASCADE`) | |
| `recorded_at` | DateTime | |
| `health_status` | String(20), nullable | Copied from `Router.health_status` at recording time |
| `cpu_usage_percent` | Float, nullable | |
| `memory_usage_percent` | Float, nullable | |
| `uptime_seconds` | Integer, nullable | |
| `connected_clients_count` | Integer, nullable | |

Indexes: `router_id`, `recorded_at`.

## `router_events`

Device-history log (reboot, config applied, error, factory reset,
enrollment approved, secret rotated, ...). See `event_metadata` naming note
below.

| Column | Type | Notes |
|---|---|---|
| `router_id` | UUID, FK `routers.id` (`CASCADE`) | |
| `event_type` | String(30) | `constants.RouterEventType` |
| `message` | Text, nullable | |
| `occurred_at` | DateTime | |
| `event_metadata` (column `metadata`) | JSONB | Python attribute renamed -- `metadata` is reserved by SQLAlchemy's `DeclarativeBase`, exactly mirroring `AuditLogEntry.event_metadata`'s own convention |

Indexes: `router_id`, `event_type`, `occurred_at`.

## Why `RouterEvent`/`RouterHealthSnapshot` are separate from `audit_log_entries`

`audit_log_entries` (RBAC, Module 004) is scoped to accountable,
human-attributable, moderate-volume platform actions -- its own module
docstring documents it as a table "other domains could plausibly reuse,"
not a general telemetry sink. `RouterEvent`/`RouterHealthSnapshot` are a
different volume/retention profile entirely: device-originated history that
can arrive far more frequently (a health snapshot could be recorded every
few minutes per router, across every router on the platform) and is
meaningful even with no human actor at all (a queued job failing is not
"someone did something"). Mixing the two would force `audit_log_entries`
to either grow a lot of nullable device-telemetry-shaped columns it doesn't
need, or force high-volume device history to inherit an audit table's
implicit "every row is a security-relevant admin action" semantics.

They are kept separate, but every event judged genuinely significant at the
*admin action* level -- enrollment approved/rejected, secret rotated, config
version applied/rolled back, backup created, restore completed, factory
reset -- is written to **both** tables in the same service method call
(`RouterProvisioningService._record_event` + `_audit`/`_audit_router`), so
the two call sites can never drift out of sync with each other. High-
frequency device telemetry (health snapshots, individual queue-job
queued/running ticks) is deliberately **not** audited -- the same "frequent
telemetry, not an admin-driven event" reasoning BE-008 already documents
for why heartbeats are never audited either.

## No `RouterSecretRotationLog` table

Considered and rejected: a rotation is already fully captured by one
`RouterEvent` row (`event_type="secret_rotated"`, `router_id`,
`occurred_at`) plus one `audit_log_entries` row
(`AuditAction.ROUTER_SECRET_ROTATED`) -- a bespoke third table with the same
three facts (router, actor, timestamp) would duplicate data already
captured twice over, for no distinct query need. See `models.py`'s module
docstring for the full reasoning.

## Entity-relationship summary

```text
organizations --< config_templates (organization_id nullable)
organizations --< config_variables (organization_id nullable, scope=organization)
locations     --< config_variables (location_id nullable, scope=location)
routers       --< config_variables (router_id nullable, scope=router)

routers       --< config_profiles (unique per router)
config_templates --< config_profiles

routers          --< config_versions
config_profiles  --< config_versions (nullable)
config_versions  --< config_versions (self-FK: rollback_of_version_id, nullable)

routers --< router_enrollment_requests (approved_router_id, nullable, reverse direction)
routers --< provisioning_jobs
routers --< router_health_snapshots
routers --< router_events
```
