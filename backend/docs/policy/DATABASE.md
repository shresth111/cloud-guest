# Policy Domain -- Database Schema

Migration: `alembic/versions/0029_create_policy_tables.py`. See `FLOW.md`
for the full design reasoning behind each decision below.

## `policies` (new table)

| Column                | Type            | Nullable | Notes                                                                                          |
|-----------------------|-----------------|----------|-----------------------------------------------------------------------------------------------------|
| `organization_id`     | `UUID`          | Yes      | FK -> `organizations.id`, `ondelete="CASCADE"`. `NULL` means a platform-wide policy definition (mirrors `notification_templates.organization_id`'s identical convention). |
| `policy_type`         | `VARCHAR(30)`   | No       | One of `constants.PolicyType`'s values (`session`/`authn`/`bandwidth`/`fup`/`business_hours`/`access`/`vlan`/`qos`/`routing`). |
| `name`                | `VARCHAR(200)`  | No       | Display name.                                                                                        |
| `description`         | `TEXT`          | Yes      |                                                                                                        |
| `is_active`           | `BOOLEAN`       | No       | `server_default true`. Flipped to `false` by `deactivate_policy` -- a retired definition, not deleted. |
| `current_version_id`  | `UUID`          | Yes      | FK -> `policy_versions.id`, `ondelete="SET NULL"`, added via a deferred `op.create_foreign_key` (see `FLOW.md` §2 and the migration's own module docstring for the circular-FK handling). `NULL` until the first version is published. |
| `created_by_user_id`  | `UUID`          | Yes      | Plain column, not a FK (mirrors `VoucherBatch.created_by_user_id`'s/`GuestTeam.created_by_user_id`'s identical convention). |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_policies_organization_id`, `ix_policies_policy_type`,
`ix_policies_is_active` (all plain btree).

## `policy_versions` (new table)

| Column               | Type            | Nullable | Notes                                                                 |
|----------------------|-----------------|----------|-------------------------------------------------------------------------|
| `policy_id`          | `UUID`          | No       | FK -> `policies.id`, `ondelete="CASCADE"`.                                |
| `version_number`     | `INTEGER`       | No       | `1`, `2`, `3`, ... per `policy_id` (see `repository.get_next_version_number`). |
| `status`             | `VARCHAR(20)`   | No       | `draft` / `published` -- see `constants.PolicyVersionStatus`. Terminal once `published`. |
| `rules`              | `JSONB`         | No       | `server_default '{}'::jsonb`. Validated against `schemas.POLICY_RULE_SCHEMAS[policy_type]` before being persisted (see `FLOW.md` §3). Immutable once created -- never updated in place except the `status`/`published_at` transition itself. |
| `published_at`       | `TIMESTAMPTZ`   | Yes      | Set by `publish_version`.                                                 |
| `created_by_user_id` | `UUID`          | Yes      | Plain column, not a FK.                                                    |

Plus the standard `BaseModel` columns.

Indexes: `ix_policy_versions_policy_id`, `ix_policy_versions_status` (plain
btree), and `uq_policy_versions_policy_id_version_number` -- a real `UNIQUE`
index on `(policy_id, version_number)`.

## `policy_assignments` (new table)

| Column               | Type            | Nullable | Notes                                                                              |
|----------------------|-----------------|----------|----------------------------------------------------------------------------------------|
| `policy_id`          | `UUID`          | No       | FK -> `policies.id`, `ondelete="CASCADE"`.                                               |
| `scope_type`         | `VARCHAR(20)`   | No       | One of `app.domains.rbac.enums.ScopeType`'s values (`global`/`organization`/`location`). |
| `scope_id`           | `UUID`          | Yes      | `NULL` iff `scope_type == 'global'`. Deliberately not a real FK -- it points at either `organizations.id` or `locations.id` depending on `scope_type` (the same polymorphic-scope shape `app.domains.rbac`'s own role assignments already use). |
| `priority`           | `INTEGER`       | No       | `server_default 0`. Tie-breaker for two active assignments matching the same resolved scope -- higher wins.  |
| `is_active`          | `BOOLEAN`       | No       | `server_default true`. Flipped to `false` by `deactivate_assignment`.                     |
| `created_by_user_id` | `UUID`          | Yes      | Plain column, not a FK.                                                                     |

Plus the standard `BaseModel` columns.

Indexes: `ix_policy_assignments_policy_id`, `ix_policy_assignments_scope_type`,
`ix_policy_assignments_scope_id`, `ix_policy_assignments_is_active` (all
plain btree). No uniqueness constraint on
`(policy_id, scope_type, scope_id)` -- multiple assignments may legitimately
target the same scope simultaneously (that is exactly what `priority`
resolves), so uniqueness would be actively wrong here, unlike
`guest_team_members`' partial-unique-index precedent.

## The circular foreign key

`policies.current_version_id` -> `policy_versions.id` and
`policy_versions.policy_id` -> `policies.id` reference each other. The
migration creates `policies` first with `current_version_id` as a plain,
FK-less `UUID` column, then creates `policy_versions` (whose own FK to
`policies` is not circular), then adds `policies.current_version_id`'s
foreign key constraint (`fk_policies_current_version_id_policy_versions`)
via a separate `op.create_foreign_key` call once both tables exist.
`downgrade()` drops that constraint first, then both tables in reverse
order. See `FLOW.md` §2 for why an explicit "current version" pointer (not
an inferred "highest `version_number`" query) is what makes `rollback` a
real, one-column operation.

## Not migrated

* `app.domains.rbac.enums.PermissionModule.POLICY` and `AuditAction`'s new
  `policy_*` members -- both are plain `String` columns/enum members
  underneath (`permission_groups.key`, `permissions.key`,
  `audit_log_entries.action`), never native Postgres enum types, so adding
  new values is a code-only change. The corresponding
  `permission_groups`/`permissions`/`permission_scopes`/`role_permissions`
  rows are seeded idempotently by `seed_rbac` (application/CLI startup),
  never by a migration -- same convention every other domain's own additive
  RBAC change already follows.
* No changes to any `app.domains.guest`/`app.domains.guest_access`/
  `app.domains.voucher` table -- this module has zero schema dependency on
  any feature domain (see `README.md`'s "leaf module" write-up). No
  `applied_session_policy_version_id`-style column has been added to
  `guest_sessions` in this pass; that is explicitly future wiring, not part
  of this module's own scope (see `README.md`'s "What This Module Does Not
  Do Yet").
* `alembic/env.py` also gained a `from app.domains.guest_access import
  models as guest_access_models` import alongside this module's own -- a
  real gap found while touching this file: the `guest_access` domain's own
  migration had landed without ever registering its models for
  autogenerate. Fixed alongside, since it was a one-line, zero-risk
  correction to a file this change already had to touch.
