# BE-013 Part 1: Plan + License + Usage Core

**Part 1 of 5** in the Billing & Subscription module (BE-013). Builds
`app.domains.billing`, a brand-new domain: the pricing/entitlement catalog
(`Plan`/`PlanFeature`), what an organization is actually entitled to right
now (`License`/`LicenseChangeLog`), and real, composed usage tracking +
limit validation (`UsageMetric`). Later BE-013 parts (not built here) layer
Subscription/Renewal/Coupon, Payment/Stripe/Razorpay/webhooks, and
Invoice/Tax on top of this foundation.

See `FLOW.md` for every design decision in full detail and `DATABASE.md`
for the schema reference. This file is a short orientation.

## In One Paragraph

Five new tables (`plans`, `plan_features`, `licenses`,
`license_change_logs`, `usage_metrics`; migration
`0022_create_billing_plan_license_usage_tables`). A Super Admin (or any
`GLOBAL`-scoped `billing.manage` holder) creates unlimited `Plan` rows, each
with a typed set of `PlanFeature` entitlements/limits (`LIMIT`/`BOOLEAN`/
`TIER`-shaped, stored in three precisely-typed nullable columns rather than
one JSONB blob). An organization is assigned exactly one `License` row,
ever (one-to-one, mutated in place through a full, explicit
`pending_activation -> active -> suspended -> expired`/`cancelled`
transition graph), with every upgrade/downgrade/assignment recorded as a
real `LicenseChangeLog` row -- full history, not a lossy single
`previous_plan_id` column. `UsageMetric` rows are computed from **real**,
composed data: guest/session/bandwidth counts reuse
`app.domains.guest.service.GuestAnalyticsService.get_summary` directly (the
same aggregate `app.domains.analytics` itself already reuses for the same
figures); location/router/OTP-channel counts are narrow, read-only
`SELECT`s against those domains' own models (the same "read another
domain's table directly" precedent `app.domains.analytics`/
`app.domains.monitoring` already established); two metrics
(`STORAGE_USAGE_MB`/`API_REQUESTS`) are honest, undisguised placeholders
recorded as `0` -- no file-storage domain or API-request-logging table
exists anywhere in this codebase yet. `Organization.subscription_tier` --
reserved, unpopulated, "no pricing/entitlement logic" since Module 005 --
now gets real meaning: `License`/`Plan` are the actual source of truth, and
a narrow, additive `OrganizationService.sync_subscription_tier` hook keeps
the legacy column in sync as a denormalized convenience label, never read
back by this domain itself.

## What This Part Does NOT Do

* **It does not build a license-expiry Celery Beat sweep.** `expire_license`
  is a real, callable state-transition method, but nothing calls it
  automatically. Expiry policy (grace period? auto-downgrade? hard block?)
  belongs to the Renewal engine, a later BE-013 part -- see `FLOW.md` §5.
* **It does not build Subscription/Renewal/Coupon, Payment/Stripe/
  Razorpay/webhooks, or Invoice/Tax.** Those are BE-013 Parts 2-5.
* **It does not fabricate `STORAGE_USAGE_MB`/`API_REQUESTS`.** Both are
  honest `0` placeholders -- see `FLOW.md` §6.
* **It does not add a new `PermissionModule`.** `billing.*`/
  `subscriptions.*` were already seeded since BE-004 in anticipation of
  exactly this module -- see `FLOW.md` §7.
* **It does not touch `organization`/`guest`/`analytics`/`otp`/`location`/
  `router` internals**, other than one narrow, additive method on
  `OrganizationService` (`sync_subscription_tier`) -- every other
  cross-domain read is a public service call or a read-only `SELECT`
  against another domain's model, the same precedent
  `app.domains.analytics`/`app.domains.monitoring` already established.

## Folder Structure

```text
backend/
  alembic/versions/
    0022_create_billing_plan_license_usage_tables.py
  app/
    domains/billing/
      __init__.py
      models.py          # Plan, PlanFeature, License, LicenseChangeLog, UsageMetric
      constants.py        # PlanType, BillingCycle, PlanFeatureKey/Type, SupportTier,
                           # LicenseStatus, LicenseChangeType, UsageMetricKey
      schemas.py           # Pydantic request/response models (Decimal throughout)
      repository.py        # PlanRepository, LicenseRepository, UsageRepository
      service.py             # PlanService, LicenseService, UsageService
      router.py               # /plans, /licenses, /usage endpoints
      validators.py             # PlanFeature typed-value validation
      dependencies.py             # FastAPI DI wiring (composes organization/guest/analytics)
      exceptions.py                 # BillingError hierarchy
      events.py                      # LicenseAssigned/Activated/Suspended/... dataclasses
  docs/billing/
    README.md   # this file
    FLOW.md
    DATABASE.md
  tests/unit/
    test_billing_plans_licenses_usage.py
```
