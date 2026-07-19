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

---

# BE-013 Part 3: Payment Service + Real Stripe/Razorpay Integration + Webhooks

Migration: `alembic/versions/0024_create_billing_payment_tables.py` (revises
`0023_create_billing_subscription_coupon_tables`). Two new tables, both
extending `BaseModel`. No `alembic/env.py` edit was needed -- same reason
as Part 2 (that file already imports `app.domains.billing.models` as a
whole module).

## `payments`

One row per real (or honestly-failed) charge attempt -- and, per this
part's own explicit decision, the **entire** "Payment History" query
surface (see FLOW.md §27 -- no second, append-only history table).

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | |
| `subscription_id` | UUID, FK `subscriptions.id` (`SET NULL`), nullable | set when this charge is a subscription renewal/manual retry; null for a standalone one-off charge |
| `amount` | **Numeric(12, 2)**, not nullable | never `Float` |
| `currency` | String(3), not nullable | |
| `status` | String(20), not nullable | `constants.PaymentStatus` -- `pending`/`succeeded`/`failed`/`refunded`/`partially_refunded` |
| `provider` | String(20), not nullable | `constants.PaymentProvider` -- `stripe`/`razorpay` |
| `provider_payment_id` | String(255), nullable | the external charge/payment-intent id -- unknown (`NULL`) until the provider assigns one |
| `idempotency_key` | String(255), not nullable, **unique** | the real, database-enforced backstop behind this module's "same key never double-charges" guarantee -- see FLOW.md §22 |
| `failure_reason` | Text, nullable | |
| `refunded_amount` | **Numeric(12, 2)**, not nullable, default `0` | running total across every `refund_payment` call against this row |

Indexes: `organization_id`, `subscription_id`, `status`, `provider`,
`provider_payment_id`, `idempotency_key` (unique, `uq_payments_idempotency_key`
+ `ix_payments_idempotency_key`), plus base-model indexes.

## `payment_methods`

A tokenized reference to a payment instrument -- **never** raw card data
(see FLOW.md §28 for the full "token only" discipline).

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | |
| `provider` | String(20), not nullable | `constants.PaymentProvider` |
| `provider_payment_method_id` | String(255), not nullable | the provider's own opaque token (e.g. a Stripe `pm_...` id) -- never a raw card number |
| `method_type` | String(20), not nullable | `constants.PaymentMethodType` -- `card`/`bank_account`/`upi`/`other` |
| `last4` | String(4), nullable | display-only, never used in any charge decision |
| `is_default` | Boolean, not nullable, default `false` | at most one `true` per organization -- enforced by `PaymentMethodRepository.set_as_default`, not a DB constraint (a real atomic `UPDATE` unsets every sibling first) |
| `is_active` | Boolean, not nullable, default `true` | |

`UniqueConstraint(organization_id, provider, provider_payment_method_id)`
(`uq_payment_methods_org_provider_token`) prevents registering the exact
same provider token twice for the same organization. Indexes:
`organization_id`, `provider`, `is_default`, `is_active`, plus base-model
indexes.

## Table creation order

`payments` (needs `organizations`/`subscriptions`) -> `payment_methods`
(needs `organizations` only) -- the migration's `upgrade()`/`downgrade()`
follow this order (and its exact reverse).

## No further RBAC schema change

Same as Parts 1-2 -- this part's only RBAC edit is additive `AuditAction`
values (`PAYMENT_*`), no migration needed. `PermissionModule.BILLING` (no
new module) covers every Part 3 endpoint -- see FLOW.md §32.

## Event-id dedup: Redis, not a table

Webhook event-id dedup (`webhooks.RedisWebhookEventDedup`) is deliberately
**not** a table at all -- see FLOW.md §24 for the full "Redis + TTL vs. a
dedicated table" write-up.

---

# BE-013 Part 4: Invoice Engine + Tax/GST

Migration: `alembic/versions/0025_create_billing_invoice_tax_tables.py`
(revises `0024_create_billing_payment_tables`). Six new tables, all
extending `BaseModel`. No `alembic/env.py` edit was needed -- same reason
as Parts 2/3 (that file already imports `app.domains.billing.models` as a
whole module).

## `tax_rates`

Super-Admin-managed tax jurisdiction config -- no FK.

| Column | Type | Notes |
|---|---|---|
| `name` | String(100), not nullable | e.g. "India GST" |
| `tax_type` | String(20), not nullable | `constants.TaxType` -- `gst`/`vat`/`sales_tax`/`none` |
| `rate_percentage` | **Numeric(5, 2)**, not nullable | never `Float` |
| `country_code` | String(2), not nullable | ISO 3166-1 alpha-2 |
| `is_active` | Boolean, not nullable, default `true` | |

Indexes: `country_code`, `tax_type`, `is_active`, plus base-model indexes.

## `billing_profiles`

One organization's billing address/GSTIN -- **entirely owned by this
domain**, not a column on `organizations` (see FLOW.md §36 for the full
storage-location decision). One row per organization, ever
(`organization_id` unique) -- mirrors `licenses`/`subscriptions`'
identical one-to-one cardinality.

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable, **unique** | |
| `billing_name` | String(200), not nullable | |
| `billing_address_line1` | String(255), not nullable | |
| `billing_address_line2` | String(255), nullable | |
| `billing_city` | String(100), not nullable | |
| `billing_state` | String(100), not nullable | compared against `Settings.platform_gst_state` for CGST/SGST vs. IGST |
| `billing_country` | String(2), not nullable | ISO 3166-1 alpha-2 |
| `billing_postal_code` | String(20), not nullable | |
| `gst_identifier` | String(20), nullable | GSTIN -- nullable for a non-Indian/no-GSTIN organization |
| `tax_exempt` | Boolean, not nullable, default `false` | short-circuits `compute_tax_breakdown` to zero regardless of any matched `TaxRate` |

Indexes: `organization_id` (unique), `billing_country`, plus base-model
indexes.

## `invoice_number_counters`

The dedicated, real, DB-level-atomic counter table backing every
sequential document number this part generates -- see FLOW.md §37 for the
exact `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` concurrency
mechanism this table's `counter_key` unique constraint enables.

| Column | Type | Notes |
|---|---|---|
| `counter_key` | String(50), not nullable, **unique** | `"<document_type>:<year>"`, e.g. `"invoice:2026"` |
| `last_value` | Integer, not nullable, default `0` | the real, atomically-incremented sequence value |

Indexes: `counter_key` (unique), plus base-model indexes.

## `invoices`

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | |
| `subscription_id` | UUID, FK `subscriptions.id` (`SET NULL`), nullable | |
| `payment_id` | UUID, FK `payments.id` (`SET NULL`), nullable | set once a real payment settles this invoice |
| `invoice_number` | String(50), not nullable, **unique** | `"INV-2026-00001"`-shaped -- see FLOW.md §37 |
| `status` | String(20), not nullable | `constants.InvoiceStatus` -- see FLOW.md §46 for the full transition graph |
| `issue_date` / `due_date` | DateTime(tz), not nullable | |
| `subtotal` | **Numeric(12, 2)**, not nullable | reuses `renewal_service.compute_renewal_charge_amount` -- see FLOW.md §38 |
| `cgst_amount` / `sgst_amount` / `igst_amount` | **Numeric(12, 2)**, not nullable, default `0` | three typed columns, not a separate `InvoiceTaxLine` table -- see FLOW.md §40 |
| `tax_amount` | **Numeric(12, 2)**, not nullable, default `0` | universal total across every tax regime |
| `tax_rate_percentage` | **Numeric(5, 2)**, not nullable, default `0` | the total rate actually applied, frozen at issue time |
| `total_amount` | **Numeric(12, 2)**, not nullable | `subtotal + tax_amount` |
| `currency` | String(3), not nullable | |
| `billing_snapshot` | JSONB, not nullable | a frozen copy of `BillingProfile` at issue time -- never re-read afterward, see FLOW.md §41 |

Indexes: `organization_id`, `subscription_id`, `payment_id`,
`invoice_number` (unique), `status`, `issue_date`, `due_date`, plus
base-model indexes.

## `invoice_items`

| Column | Type | Notes |
|---|---|---|
| `invoice_id` | UUID, FK `invoices.id` (`CASCADE`), not nullable | |
| `description` | String(500), not nullable | |
| `quantity` | **Numeric(12, 2)**, not nullable, default `1` | a real `Numeric`, not `Integer` -- a future prorated line item is fractional |
| `unit_price` | **Numeric(12, 2)**, not nullable | |
| `amount` | **Numeric(12, 2)**, not nullable | computed once at creation (`quantity * unit_price`), never recomputed on read |

Indexes: `invoice_id`, plus base-model indexes.

## `credit_debit_notes`

One discriminated table for both credit and debit notes -- see FLOW.md
§46 for the full "one table, not two" write-up.

| Column | Type | Notes |
|---|---|---|
| `invoice_id` | UUID, FK `invoices.id` (`CASCADE`), not nullable | |
| `note_type` | String(10), not nullable | `constants.NoteType` -- `credit`/`debit` |
| `note_number` | String(50), not nullable, **unique** | `"CN-2026-00001"`/`"DN-2026-00001"`-shaped -- its own independent sequence per `note_type`, never the invoice sequence |
| `amount` | **Numeric(12, 2)**, not nullable | |
| `reason` | Text, not nullable | |
| `issued_at` | DateTime(tz), not nullable | |

Indexes: `invoice_id`, `note_type`, `note_number` (unique), plus
base-model indexes.

## Table creation order (FK dependency chain)

`tax_rates` (no FK) -> `billing_profiles` (needs `organizations`) ->
`invoice_number_counters` (no FK) -> `invoices` (needs `organizations`/
`subscriptions`/`payments`) -> `invoice_items` (needs `invoices`) ->
`credit_debit_notes` (needs `invoices`). The migration's `upgrade()`/
`downgrade()` follow this order (and its exact reverse).

## No further RBAC schema change

Same as Parts 1-3 -- this part's only RBAC edit is additive `AuditAction`
values (`INVOICE_*`/`CREDIT_NOTE_ISSUED`/`DEBIT_NOTE_ISSUED`/`TAX_RATE_*`/
`BILLING_PROFILE_UPDATED`), no migration needed. `PermissionModule
.INVOICES` was already seeded since BE-004 (create/read/update/delete/
export/approve/manage); no new permission group/action/scope row is
seeded by this part -- see FLOW.md §44.

## Part 5: no new tables, no new columns, no migration

BE-013 Part 5 (Super Admin + Customer Billing Dashboards) is pure
computation/aggregation over the tables already described above --
`Payment`/`Subscription`/`Plan`/`Invoice`, plus a read-only join against
`app.domains.organization.models.Organization` for a display name on the
Customer Billing Dashboard's per-organization rows (the identical
read-another-domain's-table-directly precedent `usage_metrics`' own
`UsageRepository.count_locations`/`count_routers` already establish for
`Location`/`Router`). Nothing new is persisted by this part, so
`alembic/versions/` gains no new revision file, and no column is added to
any existing billing table -- including `Subscription.auto_renew`, which
the new `PATCH /subscriptions/{id}/renewal-settings` endpoint updates in
place (that column has existed since migration
`0023_create_billing_subscription_coupon_tables`, Part 2). No new
`AuditAction` enum member is added either (see FLOW.md §54's own write-up
of why this part's new audit-action labels are plain, domain-local string
constants instead).
