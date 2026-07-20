# Provisioning Engine Domain -- Database Schema

Migration: `alembic/versions/0032_create_provisioning_engine_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `provision_templates` (new table)

Created first -- `provision_jobs` FKs to it.

| Column               | Type            | Nullable | Notes |
|----------------------|-----------------|----------|-------|
| `organization_id`    | `UUID`          | Yes      | FK -> `organizations.id`, `ondelete="CASCADE"`. `NULL` means a platform-wide system package (mirrors `ConfigTemplate.organization_id`'s identical convention). |
| `name`               | `VARCHAR(200)`  | No       | Display name. |
| `site_type`          | `VARCHAR(20)`   | No       | One of `constants.ProvisionSiteType`'s values (hotel/apartment/corporate/hospital/school/airport/restaurant/cafe). |
| `description`        | `TEXT`          | Yes      | |
| `config_template_id` | `UUID`          | Yes      | FK -> `config_templates.id`, `ondelete="SET NULL"` -- the actual device script this package composes. |
| `default_policy_id`  | `UUID`          | Yes      | FK -> `policies.id`, `ondelete="SET NULL"` -- the default session/authN policy for sites using this package. |
| `settings`           | `JSONB`         | No       | `server_default '{}'::jsonb`. DHCP/DNS/hotspot/WireGuard/firewall/NTP/logging preset values -- flattened and seeded as `ConfigVariable` rows by `GENERATE_CONFIG` (see `FLOW.md` §4). |
| `is_active`          | `BOOLEAN`       | No       | `server_default true`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_provision_templates_organization_id`,
`ix_provision_templates_site_type`, `ix_provision_templates_is_active`.

## `provision_jobs` (new table)

The top-level, end-to-end orchestration run for one router.

| Column                        | Type            | Nullable | Notes |
|-------------------------------|-----------------|----------|-------|
| `organization_id`             | `UUID`          | No       | FK -> `organizations.id`, `ondelete="CASCADE"`. |
| `location_id`                 | `UUID`          | No       | FK -> `locations.id`, `ondelete="CASCADE"` -- denormalized from the target router at job-creation time. |
| `router_id`                   | `UUID`          | No       | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `provision_template_id`       | `UUID`          | Yes      | FK -> `provision_templates.id`, `ondelete="SET NULL"`. `NULL` iff the job runs against a router with a `ConfigProfile` already assigned directly, outside this orchestrator. |
| `status`                      | `VARCHAR(20)`   | No       | `server_default 'pending'` -- one of `constants.ProvisionJobStatus`'s values. |
| `current_step`                | `VARCHAR(30)`   | Yes      | One of `constants.ProvisionStepType`'s values, or `NULL` before the job's first step. |
| `progress_percent`            | `INTEGER`       | No       | `server_default 0`. |
| `policy_snapshot`             | `JSONB`         | No       | `server_default '{}'::jsonb`. A "copy, not reference" freeze of the effective `Policy` rules resolved at job-creation time -- mirrors `Invoice.billing_snapshot`'s identical convention. |
| `requested_by_user_id`        | `UUID`          | Yes      | Plain column, not a FK. |
| `started_at` / `completed_at` | `TIMESTAMPTZ`   | Yes      | |
| `error_message`               | `TEXT`          | Yes      | |
| `retry_count`                 | `INTEGER`       | No       | `server_default 1` -- which attempt number in this job's own retry lineage this row is. |
| `max_retries`                 | `INTEGER`       | No       | `server_default 3`. |
| `retry_of_job_id`             | `UUID`          | Yes      | FK -> `provision_jobs.id` (self), `ondelete="SET NULL"`. Set iff this row was created by `retry_job` -- points at the immediately-prior attempt, never mutated back onto the original. |
| `is_rollback`                 | `BOOLEAN`       | No       | `server_default false`. |
| `rollback_of_job_id`          | `UUID`          | Yes      | FK -> `provision_jobs.id` (self), `ondelete="SET NULL"`. Set iff `is_rollback` -- points at the `SUCCESS` job this rollback job reverts. |
| `applied_config_version_id`   | `UUID`          | Yes      | FK -> `config_versions.id`, `ondelete="SET NULL"`. Set once this job's own `PUSH_CONFIG` step successfully applies a `router_provisioning` `ConfigVersion`. |
| `rollback_target_version_id`  | `UUID`          | Yes      | FK -> `config_versions.id`, `ondelete="SET NULL"`. Set only when `is_rollback` -- which `ConfigVersion` this rollback job's own `PUSH_CONFIG` should reapply, computed once at `rollback_job` creation time. |

Plus the standard `BaseModel` columns.

Indexes: `ix_provision_jobs_organization_id`, `ix_provision_jobs_location_id`,
`ix_provision_jobs_router_id`, `ix_provision_jobs_status`,
`ix_provision_jobs_retry_of_job_id`, `ix_provision_jobs_rollback_of_job_id`.

No circular/deferred foreign keys are needed -- every FK here (including the
two self-referencing columns) is one-directional and declared inline at
table-creation time (unlike migration `0029`'s `policies`/`policy_versions`
mutual reference).

## `provision_steps` (new table)

One row per stage in a job's ordered sequence (see `FLOW.md` §3).

| Column            | Type            | Nullable | Notes |
|-------------------|-----------------|----------|-------|
| `job_id`          | `UUID`          | No       | FK -> `provision_jobs.id`, `ondelete="CASCADE"`. |
| `step_type`       | `VARCHAR(30)`   | No       | One of `constants.ProvisionStepType`'s values. |
| `sequence_number` | `INTEGER`       | No       | 1-7, matching `PROVISION_STEP_SEQUENCE`'s order. |
| `status`          | `VARCHAR(20)`   | No       | `server_default 'pending'` -- one of `constants.ProvisionStepStatus`'s values. |
| `started_at` / `completed_at` | `TIMESTAMPTZ` | Yes | |
| `output`          | `JSONB`         | No       | `server_default '{}'::jsonb`. Real, step-specific structured output (e.g. `DeviceDiscoveryResult` fields, `VERIFY_CONFIG`'s boolean match result). |
| `error_message`   | `TEXT`          | Yes      | |

Plus the standard `BaseModel` columns.

Indexes: `ix_provision_steps_job_id`, `ix_provision_steps_step_type`,
`ix_provision_steps_status`.

## `provision_logs` (new table)

An append-only log line for a job (optionally attributed to one of its
steps) -- separate from RBAC's `audit_log_entries` for the same high-
volume/non-human-attributable reason `router_provisioning.router_events`
already documents.

| Column      | Type          | Nullable | Notes |
|-------------|---------------|----------|-------|
| `job_id`    | `UUID`        | No       | FK -> `provision_jobs.id`, `ondelete="CASCADE"`. |
| `step_id`   | `UUID`        | Yes      | FK -> `provision_steps.id`, `ondelete="SET NULL"`. |
| `level`     | `VARCHAR(10)` | No       | `server_default 'info'` -- one of `constants.ProvisionLogLevel`'s values. |
| `message`   | `TEXT`        | No       | |
| `logged_at` | `TIMESTAMPTZ` | No       | No default -- always supplied explicitly by the caller (`ProvisioningEngineService._log`). |

Plus the standard `BaseModel` columns.

Indexes: `ix_provision_logs_job_id`, `ix_provision_logs_step_id`,
`ix_provision_logs_logged_at`.

## No RBAC schema change

This feature's only edit to `app.domains.rbac` is additive
`PermissionModule.PROVISIONING_ENGINE`/`AuditAction` enum values
(`enums.py`) plus their corresponding seed data (`seed.py`) -- no migration
needed. `permission_groups`/`permissions`/`permission_scopes`/
`role_permissions` rows are all seeded idempotently at application/CLI
startup by `seed_rbac`, never by a migration, per this codebase's own
established convention (see e.g. migration `0029`'s identical note).
