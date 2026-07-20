# Guest Teams Domain -- Database Schema

Migration: `alembic/versions/0027_create_guest_team_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `guest_teams` (new table)

| Column                  | Type            | Nullable | Notes                                                                                                  |
|-------------------------|-----------------|----------|----------------------------------------------------------------------------------------------------------|
| `organization_id`       | `UUID`          | No       | FK -> `organizations.id`, `ondelete="CASCADE"`. A team belongs to exactly one organization.               |
| `location_id`           | `UUID`          | Yes      | FK -> `locations.id`, `ondelete="SET NULL"` (not `CASCADE` -- see `FLOW.md` §12). `NULL` means an org-wide team. |
| `name`                  | `VARCHAR(200)`  | No       | Display name (e.g. "Smith-Jones Wedding").                                                                |
| `team_code`             | `VARCHAR(32)`   | No       | Globally unique join code, reusing `app.domains.voucher.constants.VOUCHER_CODE_ALPHABET`'s exact alphabet (see `FLOW.md` §11). |
| `status`                | `VARCHAR(20)`   | No       | `active` / `expired` / `revoked` -- see `constants.GuestTeamStatus`.                                       |
| `max_members`           | `INTEGER`       | Yes      | `NULL` means unlimited membership.                                                                          |
| `shared_data_limit_mb`  | `INTEGER`       | Yes      | Pooled quota shared across every active member's own sessions. `NULL` means no team-level pooling.        |
| `expires_at`            | `TIMESTAMPTZ`   | Yes      | `NULL` means the team never expires. Checked lazily on read (see `FLOW.md` §3).                          |
| `created_by_user_id`    | `UUID`          | Yes      | Plain column, not a FK (mirrors `VoucherBatch.created_by_user_id`'s identical convention).                |
| `revoked_at`            | `TIMESTAMPTZ`   | Yes      | Set by `revoke_team`.                                                                                      |
| `revoked_reason`        | `TEXT`          | Yes      | Set by `revoke_team`.                                                                                      |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_guest_teams_organization_id`, `ix_guest_teams_location_id`,
`ix_guest_teams_status`, `ix_guest_teams_expires_at` (plain btree), and
`ix_guest_teams_team_code` -- a real `UNIQUE` index.

## `guest_team_members` (new table)

| Column            | Type            | Nullable | Notes                                                                              |
|-------------------|-----------------|----------|---------------------------------------------------------------------------------------|
| `team_id`         | `UUID`          | No       | FK -> `guest_teams.id`, `ondelete="CASCADE"`.                                          |
| `guest_id`        | `UUID`          | No       | FK -> `guests.id`, `ondelete="CASCADE"`.                                               |
| `joined_at`       | `TIMESTAMPTZ`   | No       | Set at row creation.                                                                    |
| `is_active`       | `BOOLEAN`       | No       | `server_default true`. Flipped to `false` on removal.                                   |
| `left_at`         | `TIMESTAMPTZ`   | Yes      | Set on removal.                                                                          |
| `removal_reason`  | `VARCHAR(500)`  | Yes      | Set on removal, if a reason was supplied.                                                |

Plus the standard `BaseModel` columns.

Indexes: `ix_guest_team_members_team_id`, `ix_guest_team_members_guest_id`,
`ix_guest_team_members_is_active` (plain btree), and
`uq_guest_team_members_team_guest_active` -- a **partial** unique index on
`(team_id, guest_id)` `WHERE is_active = true AND is_deleted = false`. This
is the real, DB-level constraint the module brief required ("a guest cannot
be an ACTIVE member of the same team twice"): it enforces uniqueness only
among currently-active rows, deliberately allowing several *terminal*
(`is_active = false`) rows for the same `(team_id, guest_id)` pair to
accumulate over the team's lifetime -- one per join/leave cycle, since
rejoining after removal creates a new row rather than reactivating the old
one (see `FLOW.md` §4.3 and `models.py`'s own "append-only-per-stint"
docstring). Mirrors migration `0026`'s own `uq_locations_location_code`
partial-unique-index precedent, and `organization_members`' own
membership-uniqueness index (migration `0003`), for the identical reason.

## Not migrated

* `app.domains.rbac.enums.PermissionModule.GUEST_TEAMS` and
  `AuditAction`'s new `guest_team_*` members -- both are plain `String`
  columns/enum members underneath (`permission_groups.key`,
  `permissions.key`, `audit_log_entries.action`), never native Postgres
  enum types, so adding new values is a code-only change. The corresponding
  `permission_groups`/`permissions`/`permission_scopes`/`role_permissions`
  rows are seeded idempotently by `seed_rbac` (application/CLI startup),
  never by a migration -- same convention every other domain's own additive
  RBAC change already follows (see e.g. migration `0026`'s identical note).
* No changes to `guests`/`guest_sessions`/`guest_devices`/any other
  `app.domains.guest` table -- this feature composes `GuestService`'s
  existing public methods exclusively; it never adds a column (e.g. no
  `team_id` on `GuestSession`) to any of them. A member's sessions are
  looked up by `guest_id` at the moment they're needed (removal/revocation/
  summary/quota-check), not tracked via a persistent link on the session
  row itself -- see `FLOW.md` §7 for why.
