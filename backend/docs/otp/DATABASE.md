# OTP: Database Schema

Migration: `alembic/versions/0012_create_otp_tables.py` (revises
`0011_create_wireguard_tables`). One new table, extending
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns.

## `otp_requests`

One row per generated OTP code and its verification lifecycle.

| Column | Type | Notes |
|---|---|---|
| `identifier` | String(255) | Plain phone number or email string -- not a FK; no `Guest` table exists yet (see `README.md`) |
| `channel` | String(20) | `constants.OtpChannel` (`sms`/`email`) |
| `purpose` | String(30) | `constants.OtpPurpose` (`guest_login` today; additive) |
| `code_hash` | String(128) | SHA-256 hex digest of the generated code -- never the plaintext code (see `FLOW.md` §1) |
| `expires_at` | DateTime(timezone=True) | `created_at + Settings.otp_expiry_seconds` at creation time |
| `verified_at` | DateTime(timezone=True), nullable | Set together with `is_consumed=True` on a successful verification; `NULL` until then |
| `attempt_count` | Integer, default `0` | Incremented on every hash-mismatch verification attempt |
| `max_attempts` | Integer | Snapshotted from `Settings.otp_max_verification_attempts` at creation time -- a later config change never retroactively changes an already-issued code's cap |
| `is_consumed` | Boolean, default `false` | One-way: once `true`, this row can never be presented successfully again |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), nullable | Real FK -- `Organization` already exists (Module 005); nullable, not validated by this module (see `FLOW.md` §9) |
| `location_id` | UUID, FK `locations.id` (`CASCADE`), nullable | Real FK -- `Location` already exists (Module 006); nullable, not validated by this module (see `FLOW.md` §9) |

Enums are stored as plain `String` columns, never a native PostgreSQL enum
type -- the same reason every other domain in this codebase documents
(`app.domains.wireguard.constants`, `app.domains.rbac.enums`): adding a new
channel/purpose value never requires an `ALTER TYPE` migration, only a new
additive `StrEnum` member.

Constraints: `ForeignKeyConstraint` on `organization_id` ->
`organizations.id` (`ondelete=CASCADE`), `ForeignKeyConstraint` on
`location_id` -> `locations.id` (`ondelete=CASCADE`). No `UNIQUE`
constraint on `identifier` -- a guest may hold many `OtpRequest` rows over
time (one per request), never one canonical row per identifier.

Indexes: `identifier`, `purpose`, a composite `(identifier, purpose)` (the
exact shape `OtpRepository.get_latest_for_identifier`'s lookup needs),
`expires_at`, `organization_id`, `location_id`, plus the standard
`BaseModel` indexes (`created_at`, `deleted_at`, `is_deleted`,
`created_by`, `updated_by`).

## Why one row per request, not a mutable "current code" row

Each `POST /otp/request` call creates a brand-new `OtpRequest` row rather
than overwriting a single "current OTP" row per identifier. This preserves
a genuine history: every code ever issued, whether it was consumed, and
why a verification attempt against it failed (via the request/verify
domain events in `events.py`, logged synchronously, and the audit rows a
subset of them produce) -- valuable for the admin-facing
`GET /otp/requests` listing and for diagnosing "is this identifier being
spammed or brute-forced" without needing a separate history table. This
mirrors `app.domains.router_provisioning.models.ConfigVersion`'s
append-only posture (every past version is independently meaningful audit
trail) rather than `app.domains.wireguard.models.WireGuardPeer`'s
mutated-in-place posture (where a superseded keypair has no standalone
value). `OtpRepository.get_latest_for_identifier` always resolves the most
recently created row for an identifier/purpose pair, which is the only one
that can ever be legally verified.

## Facts genuinely new vs. reused from elsewhere

* **New** (no existing column anywhere): every column on `otp_requests` --
  nothing elsewhere in this codebase models an OTP code's own lifecycle.
* **Reused, not duplicated**: `organizations.id`/`locations.id` as FK
  targets (Modules 005/006, no schema change to either table);
  `audit_log_entries` (RBAC, Module 002) as the audit sink, via 3 additive
  `AuditAction` values -- no new audit table.

## Entity-relationship summary

```text
organizations --< otp_requests (organization_id, nullable)
locations     --< otp_requests (location_id, nullable)
```

No other existing table gained a new column or FK for this module -- unlike
BE-008/BE-009's own follow-up migrations (0004/0006/0008 added FKs to
RBAC's scope tables), `otp_requests` is not referenced by any RBAC scope
column, so no RBAC follow-up migration is needed here.
