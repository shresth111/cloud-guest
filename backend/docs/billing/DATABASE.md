# Billing: Database Schema

Migration: `alembic/versions/0022_create_billing_plan_license_usage_tables.py`
(revises `0021_create_report_tables`). Five new tables, all extending
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns, other than the FKs these new
tables point *at* (`organizations.id`).

## `plans`

The pricing/entitlement catalog.

| Column | Type | Notes |
|---|---|---|
| `name` | String(200), not nullable | |
| `slug` | String(150), not nullable, unique | |
| `plan_type` | String(20), not nullable | `constants.PlanType` -- `free_trial`/`starter`/`professional`/`business`/`enterprise`/`msp`/`custom` |
| `description` | Text, nullable | |
| `billing_cycle` | String(20), not nullable | `constants.BillingCycle` -- `monthly`/`yearly`/`none` (explicit "no fixed cadence" member, never `NULL`) |
| `base_price` | **Numeric(12, 2)**, not nullable | never `Float` -- see FLOW.md §3 |
| `currency` | String(3), not nullable, default `"USD"` | ISO 4217-shaped (e.g. `"INR"` for GST-relevant deployments) |
| `is_active` | Boolean, not nullable, default `true` | |
| `is_public` | Boolean, not nullable, default `true` | `false` = negotiated/custom plan, not shown on a general listing |
| `created_by_user_id` | UUID, nullable, no FK | mirrors `Alert.acknowledged_by_user_id`'s convention |
| `sort_order` | Integer, not nullable, default `0` | display ordering |

Indexes: `slug` (+ unique constraint `uq_plans_slug`), `plan_type`,
`is_active`, `is_public`, `sort_order`, plus the standard base-model
indexes.

## `plan_features`

One entitlement/limit row per `(plan_id, feature_key)`.

| Column | Type | Notes |
|---|---|---|
| `plan_id` | UUID, FK `plans.id` (`CASCADE`), not nullable | |
| `feature_key` | String(50), not nullable | `constants.PlanFeatureKey` -- 16-value closed set |
| `feature_type` | String(20), not nullable | `constants.PlanFeatureType` -- `limit`/`boolean`/`tier` |
| `limit_value` | Numeric(18, 2), nullable | populated only when `feature_type = limit` |
| `is_enabled` | Boolean, nullable | populated only when `feature_type = boolean` |
| `tier_value` | String(20), nullable | populated only when `feature_type = tier` (`constants.SupportTier`) |

See FLOW.md §2 for the full "three typed columns, not one JSONB blob"
write-up. `UniqueConstraint(plan_id, feature_key)` (`uq_plan_features_plan_feature`)
prevents two conflicting rows for the same feature on the same plan.
Indexes: `plan_id`, `feature_key`, plus base-model indexes.

## `licenses`

What one organization is actually entitled to, right now. **One row per
organization, ever** -- mirrors `wireguard_peers.router_id`'s identical
one-to-one, mutated-in-place cardinality (see FLOW.md / `models.License`'s
own docstring).

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable, **unique** | |
| `plan_id` | UUID, FK `plans.id` (`RESTRICT`), not nullable | a plan referenced by a license cannot be hard-deleted (this domain never hard-deletes plans anyway) |
| `status` | String(20), not nullable | `constants.LicenseStatus` -- see FLOW.md §4 for the full transition graph |
| `activated_at` | DateTime(tz), nullable | set the first time the license reaches `active` |
| `expires_at` | DateTime(tz), nullable | `NULL` = no fixed term |
| `suspended_at` | DateTime(tz), nullable | cleared on reactivation |
| `suspended_reason` | Text, nullable | cleared on reactivation |
| `cancelled_at` | DateTime(tz), nullable | set on cancellation, never cleared |

No `previous_plan_id` column -- see FLOW.md §5 for why (a single column
would lose history beyond one hop; `license_change_logs` records every
hop in full). Indexes: `organization_id` (unique), `plan_id`, `status`,
`expires_at`, plus base-model indexes.

## `license_change_logs`

The real, multi-hop upgrade/downgrade/assign audit history.

| Column | Type | Notes |
|---|---|---|
| `license_id` | UUID, FK `licenses.id` (`CASCADE`), not nullable | |
| `from_plan_id` | UUID, FK `plans.id` (`SET NULL`), nullable | `NULL` only for the initial `assigned` row |
| `to_plan_id` | UUID, FK `plans.id` (`RESTRICT`), not nullable | |
| `change_type` | String(20), not nullable | `constants.LicenseChangeType` -- `assigned`/`upgraded`/`downgraded` |
| `changed_at` | DateTime(tz), not nullable | |
| `changed_by_user_id` | UUID, nullable, no FK | mirrors `Plan.created_by_user_id`'s convention |
| `reason` | Text, nullable | |

Indexes: `license_id`, `changed_at`, plus base-model indexes.

## `usage_metrics`

Real, composed usage snapshots -- one row per `(organization_id,
metric_key, period_start)`, upserted in place on every
`record_current_usage` call within the same calendar month (see FLOW.md
§9's "upsert, not append-only" note).

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | |
| `metric_key` | String(30), not nullable | `constants.UsageMetricKey` -- 12-value closed set |
| `period_start` | DateTime(tz), not nullable | start of the current calendar month (UTC) at compute time |
| `period_end` | DateTime(tz), not nullable | "now" at compute time |
| `value` | **Numeric(18, 2)**, not nullable | never `Float` -- feeds limit-enforcement decisions, same correctness bar as money |
| `recorded_at` | DateTime(tz), not nullable | when this row was last computed/updated |

Indexes: `organization_id`, `metric_key`, `period_start`, plus a composite
`(organization_id, metric_key, period_start)` index (`ix_usage_metrics_org_metric_period`
-- the exact lookup `get_current_period_metric`/`list_current_period_metrics`
use), plus base-model indexes.

## No RBAC schema change

This part's only edit to `app.domains.rbac` is additive `AuditAction`
enum values (`enums.py`) -- no migration needed, `audit_log_entries.action`
already accepts any string. `PermissionModule.BILLING`/`SUBSCRIPTIONS` were
already seeded since BE-004; no new permission group/action/scope row is
seeded by this part.

---

# BE-013 Part 2: Subscription + Renewal + Coupon Engines

Migration: `alembic/versions/0023_create_billing_subscription_coupon_tables.py`
(revises `0022_create_billing_plan_license_usage_tables`). Four new
tables, all extending `BaseModel`. No `alembic/env.py` edit was needed --
that file already imports `app.domains.billing.models` as a whole module
(`from app.domains.billing import models as billing_models`), so these new
classes (defined in that same `models.py`) are registered on
`Base.metadata` automatically.

## `subscriptions`

One row per organization, ever (`organization_id` unique) -- see
FLOW.md §12.

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable, **unique** | |
| `license_id` | UUID, FK `licenses.id` (`RESTRICT`), not nullable | |
| `plan_id` | UUID, FK `plans.id` (`RESTRICT`), not nullable | denormalized from `license_id` -- see FLOW.md §12 |
| `status` | String(20), not nullable | `constants.SubscriptionStatus` -- see FLOW.md §13 for the full transition graph |
| `billing_cycle` | String(20), not nullable | snapshot copy of `Plan.billing_cycle` at creation time, never re-read afterward |
| `current_period_start` / `current_period_end` | DateTime(tz), not nullable | |
| `trial_end` | DateTime(tz), nullable | set only for a `TRIALING` subscription |
| `auto_renew` | Boolean, not nullable, default `true` | |
| `cancel_at_period_end` | Boolean, not nullable, default `false` | |
| `started_at` | DateTime(tz), not nullable | |
| `cancelled_at` | DateTime(tz), nullable | |
| `applied_coupon_id` | UUID, FK `coupons.id` (`SET NULL`), nullable | attribution only -- see FLOW.md §17 |
| `past_due_at` | DateTime(tz), nullable | additive -- when this subscription most recently entered `PAST_DUE`; drives the grace-period computation (FLOW.md §16) |
| `last_renewal_reminder_sent_at` / `last_expiry_reminder_sent_at` | DateTime(tz), nullable | additive -- reminder-sweep idempotency markers (FLOW.md §21) |

Indexes: `organization_id` (unique), `license_id`, `plan_id`, `status`,
`current_period_end` (the exact column `list_due_for_renewal` filters
on), `applied_coupon_id`, plus base-model indexes.

## `coupons`

| Column | Type | Notes |
|---|---|---|
| `code` | String(50), not nullable, unique | uppercase-normalized (`validators.normalize_coupon_code`) |
| `discount_type` | String(20), not nullable | `constants.DiscountType` -- `percentage`/`flat` |
| `discount_value` | **Numeric(12, 2)**, not nullable | never `Float` |
| `currency` | String(3), nullable | only meaningful for `flat` |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), nullable | `NULL` = GLOBAL coupon, usable by any organization |
| `max_uses` | Integer, nullable | `NULL` = unlimited |
| `current_uses` | Integer, not nullable, default `0` | atomically incremented -- see FLOW.md §19 |
| `valid_from` / `valid_until` | DateTime(tz) (`valid_until` nullable) | |
| `is_active` | Boolean, not nullable, default `true` | |

Indexes: `code`, `organization_id`, `is_active`, `valid_until`, plus
base-model indexes.

## `coupon_plans`

The `(coupon_id, plan_id)` join table backing `Coupon.applicable_plan_ids`
-- a real join table, not a JSONB list, for referential integrity (see
FLOW.md §18).

| Column | Type | Notes |
|---|---|---|
| `coupon_id` | UUID, FK `coupons.id` (`CASCADE`), not nullable | |
| `plan_id` | UUID, FK `plans.id` (`CASCADE`), not nullable | |

`UniqueConstraint(coupon_id, plan_id)` (`uq_coupon_plans_coupon_plan`).
No rows for a coupon means "applicable to every plan". Indexes:
`coupon_id`, `plan_id`, plus base-model indexes.

## `coupon_usages`

One row per coupon redemption.

| Column | Type | Notes |
|---|---|---|
| `coupon_id` | UUID, FK `coupons.id` (`CASCADE`), not nullable | |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | |
| `subscription_id` | UUID, FK `subscriptions.id` (`SET NULL`), nullable | nullable for a future part where a coupon might apply outside a subscription context |
| `used_at` | DateTime(tz), not nullable | |
| `discount_amount_applied` | **Numeric(12, 2)**, not nullable | the real, computed discount **at the moment of use** -- never re-derived later if the coupon's own `discount_value` changes afterward (copy, not reference) |

Indexes: `coupon_id`, `organization_id`, `subscription_id`, plus
base-model indexes.

## Table creation order (FK dependency chain)

`coupons` -> `coupon_plans` (needs `coupons` + `plans`) -> `subscriptions`
(needs `organizations`/`licenses`/`plans`/`coupons`) -> `coupon_usages`
(needs `coupons`/`organizations`/`subscriptions`). The migration's
`upgrade()`/`downgrade()` follow this order (and its exact reverse),
matching `0022`'s own dependency-ordered convention.

## No further RBAC schema change

Same as Part 1 -- this part's only RBAC edit is additive `AuditAction`
values (`SUBSCRIPTION_*`/`COUPON_*`), no migration needed.
