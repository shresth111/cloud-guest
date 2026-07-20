# Voucher: Database Schema

Migration: `alembic/versions/0013_create_voucher_tables.py` (revises
`0012_create_otp_tables`). Two new tables, both extending
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns.

## `voucher_batches`

One row per admin-initiated "generate N vouchers" request and its approval
lifecycle.

| Column | Type | Notes |
|---|---|---|
| `name` | String(200) | Admin-facing label for the batch |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), **not nullable** | A batch always belongs to a tenant -- unlike OTP's nullable scope columns (see `FLOW.md` §10) |
| `location_id` | UUID, FK `locations.id` (`CASCADE`), nullable | `NULL` means org-wide; a specific location otherwise |
| `quantity` | Integer | How many vouchers to platform-generate at creation time; `0` is legal (an import-only batch) |
| `code_length` | Integer | Bounded `[MIN_CODE_LENGTH, MAX_CODE_LENGTH]` = `[4, 20]` by `validators.validate_code_length` |
| `code_prefix` | String(20), nullable | Prepended verbatim to every generated code in this batch |
| `validity_minutes` | Integer | How long a voucher grants access **once redeemed** (not the batch's own shelf-life) -- see `FLOW.md` §4-5 |
| `batch_expires_at` | DateTime(timezone=True), nullable | The batch's own shelf-life: codes not redeemed by this timestamp become permanently invalid, independent of `validity_minutes` |
| `max_uses_per_voucher` | Integer, default `1` | Supports both single-use (default) and limited-multi-use vouchers |
| `data_limit_mb` | Integer, nullable | Bandwidth/data cap **hint** for a future session-management module -- not enforced here |
| `status` | String(20), default `draft` | `constants.VoucherBatchStatus` -- see `FLOW.md` §2 for the full transition graph |
| `created_by_user_id` | UUID, nullable | Plain UUID, no FK -- mirrors `RouterEnrollmentRequest.reviewed_by_user_id`'s identical "actor id, not a hard FK" convention |
| `approved_by_user_id` | UUID, nullable | Set together with `approved_at` by `_approve_and_activate` |
| `approved_at` | DateTime(timezone=True), nullable | |
| `notes` | Text, nullable | |

Indexes: `organization_id`, `location_id`, `status`, `batch_expires_at`,
plus the standard `BaseModel` indexes.

**Phase 1 BhaiFi-parity additions** (migration
`0035_create_voucher_plan_series_tables.py`, additive-only): `plan_id`
(UUID, FK `voucher_plans.id`, `SET NULL`, nullable) and `series_id` (UUID,
FK `voucher_series.id`, `SET NULL`, nullable) -- optional links to the
reusable "product" (`VoucherPlan`) and/or ongoing campaign
(`VoucherSeries`) this generation run belongs to. Every batch created
before this migration (and any created afterward with no plan/series in
mind) simply has both `NULL`, exactly today's behavior.

## `vouchers`

One row per generated (or imported) voucher code and its redemption
lifecycle.

| Column | Type | Notes |
|---|---|---|
| `batch_id` | UUID, FK `voucher_batches.id` (`CASCADE`) | |
| `code` | String(64), **`UNIQUE`** | Plaintext, never hashed -- see `FLOW.md` §1 for the full reasoning. Generated via `secrets.choice` over `constants.VOUCHER_CODE_ALPHABET` |
| `status` | String(20), default `unused` | `constants.VoucherStatus` -- see `FLOW.md` §6 for the redemption state machine |
| `use_count` | Integer, default `0` | Incremented on every successful redemption |
| `redeemed_at` | DateTime(timezone=True), nullable | Set once, at first redemption; never updated again |
| `last_used_at` | DateTime(timezone=True), nullable | Updated on every redemption (first and subsequent) |
| `redeemed_identifier` | String(255), nullable | The guest's self-reported identifier (phone/email/device-MAC) at first redemption -- plain string, **not a FK** (no `Guest` table exists yet; mirrors `otp_requests.identifier`) |
| `expires_at` | DateTime(timezone=True), nullable | **`NULL` until first redemption**, then set to `redeemed_at + batch.validity_minutes` -- see `FLOW.md` §4 for why this timing is deliberate, not a bug |

Constraints: `ForeignKeyConstraint` on `batch_id` -> `voucher_batches.id`
(`ondelete=CASCADE`), `UniqueConstraint` on `code`.

Indexes: `batch_id`, `code` (unique), `status`, plus the standard
`BaseModel` indexes.

**Phase 1 BhaiFi-parity addition:** `plan_id` (UUID, FK `voucher_plans.id`,
`SET NULL`, nullable) -- denormalized from `voucher_batches.plan_id` at
voucher-creation time, so a redeeming caller
(`GuestService._assign_voucher_queue`) can resolve this voucher's own
speed-link directly off the row already in hand (`redeem_voucher` already
loads the `Voucher`), no join through `voucher_batches` needed.

## `voucher_plans` (new table -- Phase 1 BhaiFi-parity)

Migration `0035_create_voucher_plan_series_tables.py` (revises
`0034_create_guest_quota_usage_table`). A reusable, named "voucher product"
definition (e.g. "1-Hour Premium", "Daily 5 Mbps Pass") -- the speed a
voucher grants once redeemed, plus the default post-redemption validity/
data-cap/use-count a `VoucherBatch` created under this plan carries. See
`FLOW.md` §7 for the full redemption-time speed-link write-up.

| Column | Type | Notes |
|---|---|---|
| `name` | String(200), not nullable | |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), **nullable** | `NULL` means a platform-wide template any organization may use -- mirrors `queue_profiles.organization_id`'s identical nullable-means-shared posture |
| `description` | Text, nullable | |
| `queue_profile_id` | UUID, FK `queue_profiles.id` (`SET NULL`), nullable | The speed this plan grants -- a plain, unenforced reference (`voucher` never composes `queue_management` directly); `NULL` means no speed entitlement at all |
| `default_validity_minutes` | Integer, not nullable | |
| `default_data_limit_mb` | Integer, nullable | |
| `default_max_uses_per_voucher` | Integer, default `1` | |
| `is_active` | Boolean, default `true` | A plain, reversible toggle -- unlike `VoucherBatch`/`Voucher`, a plan has no append-only redemption history of its own to preserve |

## `voucher_series` (new table -- Phase 1 BhaiFi-parity)

A named, ongoing campaign generated under exactly one `voucher_plans` row --
across which an admin may create many separate `VoucherBatch` generation
runs over time, for reporting ("how many vouchers has this campaign
produced/redeemed in total").

| Column | Type | Notes |
|---|---|---|
| `name` | String(200), not nullable | |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), **not nullable** | Unlike `voucher_plans`, a series is always one organization's own campaign, never platform-wide |
| `location_id` | UUID, FK `locations.id` (`CASCADE`), nullable | |
| `plan_id` | UUID, FK `voucher_plans.id` (`CASCADE`), not nullable | Every series is generated under exactly one plan |
| `description` | Text, nullable | |
| `is_active` | Boolean, default `true` | |

## Why `expires_at` starts `NULL` (repeated here, briefly)

This is called out on the column itself because it is easy to get
backwards: `expires_at` is **not** "generated_at + validity_minutes". It is
computed only once real access has actually been granted (first
redemption), because `validity_minutes` measures a *post-redemption*
window, not a wall-clock deadline from generation. See `FLOW.md` §4 for the
full write-up and `models.py`'s own module docstring for the identical
reasoning next to the code.

## Why one row per voucher, not a shared counter

Each generated/imported code gets its own `Voucher` row (never a single
"N codes remaining" counter per batch) so that per-code state
(`redeemed_at`, `redeemed_identifier`, `use_count`, `expires_at`) is
independently meaningful and auditable -- the same append-only,
per-instance posture `app.domains.router_provisioning.models.ConfigVersion`
established for config history, applied here to a redemption history
instead of a config history. `VoucherRepository.get_batch_status_counts`
(a single grouped-count query) is what makes per-batch aggregate stats
cheap despite the per-row granularity.

## Facts genuinely new vs. reused from elsewhere

* **New** (no existing column anywhere): every column on `voucher_batches`/
  `vouchers` -- nothing elsewhere in this codebase models a voucher's
  generation/approval/redemption lifecycle. Phase 1 BhaiFi-parity adds two
  more tables (`voucher_plans`/`voucher_series`) plus the additive
  `plan_id`/`series_id` linkage columns described above.
* **Reused, not duplicated**: `organizations.id`/`locations.id` as FK
  targets (Modules 005/006, no schema change to either table);
  `audit_log_entries` (RBAC, Module 002) as the audit sink, via 8
  original + `VOUCHER_PLAN_CREATED`/`VOUCHER_SERIES_CREATED` (Phase 1)
  additive `AuditAction` values -- no new audit table;
  `queue_profiles.id` (Queue Management Engine) as `voucher_plans`'
  speed-link FK target -- no schema change to that table either.

## Entity-relationship summary

```text
organizations --< voucher_batches (organization_id, NOT NULL)
locations     --< voucher_batches (location_id, nullable)
voucher_batches --< vouchers (batch_id, NOT NULL)
organizations --< voucher_plans (organization_id, nullable -- platform-wide when NULL)
queue_profiles --< voucher_plans (queue_profile_id, nullable)
organizations --< voucher_series (organization_id, NOT NULL)
locations     --< voucher_series (location_id, nullable)
voucher_plans --< voucher_series (plan_id, NOT NULL)
voucher_plans --< voucher_batches (plan_id, nullable)
voucher_series --< voucher_batches (series_id, nullable)
voucher_plans --< vouchers (plan_id, nullable, denormalized)
```

No other existing table gained a new column or FK for the original two
tables -- unlike BE-008/BE-009's own follow-up migrations (0004/0006/0008
added FKs to RBAC's scope tables), neither `voucher_batches` nor
`vouchers` is referenced by any RBAC scope column, so no RBAC follow-up
migration was needed there. Phase 1 BhaiFi-parity's two new tables are
likewise additive-only and need no RBAC schema change of their own --
`VoucherPlan`/`VoucherSeries` reuse the already-seeded
`voucher.create`/`voucher.read` permission keys rather than adding new
ones.
