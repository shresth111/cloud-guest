# BE-013: Billing & Subscription Module

**Parts 1-2 of 5** in the Billing & Subscription module (BE-013), both
living in `app.domains.billing` (one domain, extended, not a new one per
part).

* **Part 1** (this doc's original scope): the pricing/entitlement catalog
  (`Plan`/`PlanFeature`), what an organization is actually entitled to
  right now (`License`/`LicenseChangeLog`), and real, composed usage
  tracking + limit validation (`UsageMetric`).
* **Part 2** (this doc's addition): `Subscription` lifecycle (create/
  cancel/reactivate/pause/resume), the Renewal Engine
  (`renewal_service.py` -- due-date detection, real charge-amount
  computation, the `PaymentGatewayProtocol` seam, grace-period-then-expire
  composition with Part 1's deferred `LicenseService.expire_license`, and
  renewal/expiry reminder emails), and the Coupon Engine (validation,
  discount computation, atomic redemption tracking).

Later BE-013 parts (not built here) layer Payment/Stripe/Razorpay/
webhooks (Part 3 -- the real implementation behind this part's
`PaymentGatewayProtocol` seam) and Invoice/Tax (Parts 4-5) on top of this
foundation.

See `FLOW.md` for every design decision in full detail (§1-§11 Part 1,
§12-§21 Part 2) and `DATABASE.md` for the schema reference. This file is a
short orientation.

## In One Paragraph (Part 1)

Five tables (`plans`, `plan_features`, `licenses`, `license_change_logs`,
`usage_metrics`; migration `0022_create_billing_plan_license_usage_tables`).
A Super Admin (or any `GLOBAL`-scoped `billing.manage` holder) creates
unlimited `Plan` rows, each with a typed set of `PlanFeature`
entitlements/limits (`LIMIT`/`BOOLEAN`/`TIER`-shaped, stored in three
precisely-typed nullable columns rather than one JSONB blob). An
organization is assigned exactly one `License` row, ever (one-to-one,
mutated in place through a full, explicit `pending_activation -> active ->
suspended -> expired`/`cancelled` transition graph), with every upgrade/
downgrade/assignment recorded as a real `LicenseChangeLog` row -- full
history, not a lossy single `previous_plan_id` column. `UsageMetric` rows
are computed from **real**, composed data (see `FLOW.md` §9 for the full
per-metric source table); two metrics (`STORAGE_USAGE_MB`/`API_REQUESTS`)
are honest, undisguised placeholders recorded as `0`.
`Organization.subscription_tier` -- reserved since Module 005 -- now gets
real meaning via a narrow, additive `OrganizationService
.sync_subscription_tier` hook.

## In One Paragraph (Part 2)

Four more tables (`subscriptions`, `coupons`, `coupon_plans`,
`coupon_usages`; migration
`0023_create_billing_subscription_coupon_tables`). `SubscriptionService
.create_subscription` composes Part 1's `LicenseService.assign_license`/
`activate_license` (never duplicates license assignment) and starts a
`Subscription` `trialing` (a `FREE_TRIAL` plan) or `active`, optionally
redeeming a `Coupon` right then (`CouponService.apply_coupon` -- one real
`CouponUsage` row + an atomic `current_uses` increment; see `FLOW.md`
§17 for why a coupon applies **once**, at signup, never on renewal).
`RenewalService.process_renewal` determines a renewal is due, computes
the real charge amount, and calls the one-method
`PaymentGatewayProtocol` seam -- wired, honestly, to
`UnconfiguredPaymentGateway` (auto-succeeds for a genuinely zero-amount
charge, raises a clear `PaymentGatewayNotConfiguredError` for any real
one) until BE-013 Part 3 plugs in a real Stripe/Razorpay-backed
implementation via one dependency-injection override
(`dependencies.get_payment_gateway`). On success it extends
`current_period_end` by a real, calendar-correct billing cycle; on
failure it transitions to `PAST_DUE` and, after a configurable grace
period, finally calls Part 1's own real, unmodified, previously-deferred
`LicenseService.expire_license`. An hourly Celery Beat sweep
(`billing-subscription-renewal-sweep`) runs the whole thing --
due-renewal processing, grace-period expiry, and both renewal/expiry
reminder emails (reusing `app.domains.otp`'s `EmailProviderProtocol` --
no second email abstraction) -- with real per-subscription and per-phase
failure isolation, mirroring BE-012 Part 1's exact resilience pattern.

## What This Module Does NOT Do (as of Part 2)

* **It does not actually charge real money.** `PaymentGatewayProtocol`'s
  only implementation today is the honest `UnconfiguredPaymentGateway`
  placeholder -- see `FLOW.md` §15 for the full seam write-up and exactly
  what BE-013 Part 3 needs to plug in.
* **It does not re-apply a coupon on renewal.** A coupon is redeemed once,
  at subscription creation -- see `FLOW.md` §17.
* **It does not build Invoice/Tax.** Those are BE-013 Parts 4-5.
* **It does not add a new `PermissionModule`.** `billing.*`/
  `subscriptions.*` were already seeded since BE-004 -- see `FLOW.md` §7
  (Part 1) and the Coupon/Subscription endpoint mapping in `router.py`'s
  own module docstring (Part 2).
* **It does not touch `organization`/`otp`/`rbac` internals** beyond
  Part 1's one narrow `OrganizationService.sync_subscription_tier` method
  and reusing (never modifying) `otp`'s `EmailProviderProtocol`/
  `LoggingEmailProvider` and `rbac`'s `AuditAction` enum (additive values
  only).

## Folder Structure

```text
backend/
  alembic/versions/
    0022_create_billing_plan_license_usage_tables.py
    0023_create_billing_subscription_coupon_tables.py
  app/
    core/
      celery_app.py    # + billing-subscription-renewal-sweep Beat entry
      config.py        # + subscription_trial_period_days/renewal_grace_period_days/
                        #   renewal_reminder_days_before/expiry_reminder_days_before
    domains/billing/
      __init__.py
      models.py          # Plan, PlanFeature, License, LicenseChangeLog, UsageMetric,
                          # Subscription, Coupon, CouponPlan, CouponUsage
      constants.py        # + SubscriptionStatus, DiscountType, RENEWABLE_SUBSCRIPTION_STATUSES,
                           #   CYCLIC_BILLING_CYCLES, MAX_PERCENTAGE_DISCOUNT_VALUE,
                           #   TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP
      schemas.py           # + Subscription*/Coupon* request/response models
      repository.py        # + SubscriptionRepository, CouponRepository (atomic increment)
      service.py             # + SubscriptionService, CouponService
      renewal_service.py       # PaymentGatewayProtocol seam, UnconfiguredPaymentGateway,
                                # RenewalService (process_renewal, process_due_renewals,
                                # expire_lapsed_subscriptions, reminders)
      tasks.py                  # Celery task: run_subscription_renewal_sweep
      router.py                  # + /subscriptions, /coupons endpoints
      validators.py                # + normalize_coupon_code, validate_discount_value,
                                    #   compute_discount_amount, add_billing_cycle
      dependencies.py                # + get_subscription_service, get_coupon_service,
                                      #   get_payment_gateway, get_renewal_service
      exceptions.py                    # + Subscription*/Coupon*/PaymentGatewayNotConfiguredError
      events.py                         # + Subscription*/Coupon*/RenewalReminderSent/
                                         #   ExpiryReminderSent dataclasses
  docs/billing/
    README.md   # this file
    FLOW.md
    DATABASE.md
  tests/unit/
    test_billing_plans_licenses_usage.py
    test_billing_subscriptions_renewals_coupons.py
```
