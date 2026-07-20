# Queue Management Engine Domain -- Database Schema

Migration: `alembic/versions/0033_create_queue_management_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `queue_profiles` (new table)

Created first -- `queue_templates`/`queue_assignments` both FK to it.

| Column                | Type            | Nullable | Notes |
|-----------------------|-----------------|----------|-------|
| `organization_id`     | `UUID`          | Yes      | FK -> `organizations.id`, `ondelete="CASCADE"`. `NULL` means a platform-wide system profile (mirrors `ConfigTemplate.organization_id`'s identical convention). |
| `name`                | `VARCHAR(200)`  | No       | |
| `description`         | `TEXT`          | Yes      | |
| `download_rate_kbps`  | `INTEGER`       | No       | `0` means unlimited -- RouterOS's own real `max-limit` semantics. |
| `upload_rate_kbps`    | `INTEGER`       | No       | Same convention. |
| `burst_download_kbps` / `burst_upload_kbps` | `INTEGER` | Yes | |
| `burst_threshold_kbps` | `INTEGER`      | Yes      | |
| `burst_time_seconds`  | `INTEGER`       | Yes      | |
| `priority`            | `INTEGER`       | No       | `server_default 8` -- RouterOS priority range 1 (highest) - 8 (lowest). |
| `queue_type`          | `VARCHAR(20)`   | No       | `server_default 'simple'` -- one of `constants.QueueType`'s values (`simple`/`pcq`/`tree`). |
| `is_system_profile`   | `BOOLEAN`       | No       | `server_default false`. |
| `is_active`           | `BOOLEAN`       | No       | `server_default true`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_queue_profiles_organization_id`,
`ix_queue_profiles_is_system_profile`, `ix_queue_profiles_is_active`,
`ix_queue_profiles_name`.

## `queue_schedules` (new table)

Created second, independent of `queue_profiles`.

| Column          | Type            | Nullable | Notes |
|-----------------|-----------------|----------|-------|
| `organization_id` | `UUID`        | Yes      | FK -> `organizations.id`, `ondelete="CASCADE"`. `NULL` means platform-wide. |
| `name`          | `VARCHAR(200)`  | No       | |
| `schedule_type` | `VARCHAR(20)`   | No       | One of `constants.QueueScheduleType`'s values (office_hours/night_mode/weekend/holiday/custom). |
| `days_of_week`  | `JSONB`         | No       | `server_default '[]'::jsonb`. ISO weekday integers (`0`=Monday..`6`=Sunday), for recurring windows. |
| `start_time` / `end_time` | `VARCHAR(5)` | Yes | `"HH:MM"` 24-hour strings. |
| `specific_dates` | `JSONB`       | No       | `server_default '[]'::jsonb`. ISO `"YYYY-MM-DD"` date strings, for `HOLIDAY`. |
| `timezone`      | `VARCHAR(50)`   | No       | `server_default 'UTC'`. |
| `is_active`     | `BOOLEAN`       | No       | `server_default true`. |

Plus the standard `BaseModel` columns.

Indexes: `ix_queue_schedules_organization_id`,
`ix_queue_schedules_schedule_type`, `ix_queue_schedules_is_active`.

## `queue_templates` (new table)

| Column                       | Type            | Nullable | Notes |
|------------------------------|-----------------|----------|-------|
| `organization_id`            | `UUID`          | Yes      | FK -> `organizations.id`, `ondelete="CASCADE"`. `NULL` means a platform-wide system template. |
| `name`                       | `VARCHAR(200)`  | No       | |
| `persona`                    | `VARCHAR(20)`   | No       | One of `constants.QueueTemplatePersona`'s values (hotel_guest/vip_guest/staff/corporate/student/premium/trial/unlimited). |
| `description`                | `TEXT`          | Yes      | |
| `queue_profile_id`           | `UUID`          | Yes      | FK -> `queue_profiles.id`, `ondelete="SET NULL"`. |
| `default_queue_schedule_id`  | `UUID`          | Yes      | FK -> `queue_schedules.id`, `ondelete="SET NULL"`. |
| `is_active`                  | `BOOLEAN`       | No       | `server_default true`. |

Plus the standard `BaseModel` columns.

Indexes: `ix_queue_templates_organization_id`,
`ix_queue_templates_persona`, `ix_queue_templates_is_active`.

## `queue_assignments` (new table)

Attaches a profile to a polymorphic target -- see
`constants.QueueTargetType`'s own docstring.

| Column                        | Type            | Nullable | Notes |
|-------------------------------|-----------------|----------|-------|
| `organization_id`             | `UUID`          | No       | FK -> `organizations.id`, `ondelete="CASCADE"`. |
| `location_id`                 | `UUID`          | Yes      | FK -> `locations.id`, `ondelete="CASCADE"` -- denormalized from the target router where resolvable; `NULL` for an organization-level default. |
| `router_id`                   | `UUID`          | Yes      | FK -> `routers.id`, `ondelete="CASCADE"`. Required (validator-level, not DB-level) for every device-bound target type; `NULL` for an organization/location-level default. |
| `target_type`                 | `VARCHAR(20)`   | No       | One of `constants.QueueTargetType`'s values. |
| `target_id`                   | `UUID`          | Yes      | Polymorphic -- deliberately **not** a real foreign key (its target table depends on `target_type`). `NULL` iff `target_type == "organization"`. |
| `device_target`               | `VARCHAR(64)`   | Yes      | The resolved RouterOS `target` value (an IP/CIDR or interface) -- supplied by the caller, never resolved by this domain itself. |
| `device_queue_id`             | `VARCHAR(32)`   | Yes      | The device-side queue id (e.g. RouterOS's own `"*1"`) once applied at least once. |
| `queue_profile_id`            | `UUID`          | Yes      | FK -> `queue_profiles.id`, `ondelete="SET NULL"`. |
| `queue_schedule_id`           | `UUID`          | Yes      | FK -> `queue_schedules.id`, `ondelete="SET NULL"`. |
| `status`                      | `VARCHAR(20)`   | No       | `server_default 'pending'` -- one of `constants.QueueStatus`'s values. |
| `priority_override`           | `INTEGER`       | Yes      | Overrides the profile's own `priority` for this one assignment only. |
| `applied_at` / `expires_at`   | `TIMESTAMPTZ`   | Yes      | |
| `error_message`               | `TEXT`          | Yes      | |
| `superseded_by_assignment_id` | `UUID`          | Yes      | FK -> `queue_assignments.id` (self), `ondelete="SET NULL"`. Set iff this row was superseded by a "Move Queue" operation -- points at the new row, never mutated back. |
| `created_by_user_id`          | `UUID`          | Yes      | Plain column, not a FK. |

Plus the standard `BaseModel` columns.

Indexes: `ix_queue_assignments_organization_id`,
`ix_queue_assignments_location_id`, `ix_queue_assignments_router_id`,
`ix_queue_assignments_target_type`, `ix_queue_assignments_target_id`,
`ix_queue_assignments_status`,
`ix_queue_assignments_superseded_by_assignment_id`.

No circular/deferred foreign keys are needed -- every FK here (including
the self-referencing column) is one-directional and declared inline at
table-creation time, mirroring migration `0032`'s identical note.

## No RBAC schema change beyond extending an existing module

This feature's only edit to `app.domains.rbac` is extending
`MODULE_ACTIONS[PermissionModule.BANDWIDTH]` (already seeded, ahead of any
real domain, specifically for this concern) plus additive `AuditAction`
enum values (`enums.py`/`seed.py`) -- no migration needed
(`permission_groups`/`permissions`/`permission_scopes`/`role_permissions`
rows are all seeded idempotently at application/CLI startup by
`seed_rbac`, never by a migration, per this codebase's own established
convention -- see e.g. migration `0029`'s identical note).
