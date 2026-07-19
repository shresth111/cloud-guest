# BE-013: Billing & Subscription Module

**Parts 1-3 of 5** in the Billing & Subscription module (BE-013), all
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
* **Part 3** (this doc's latest addition): the real implementation behind
  Part 2's `PaymentGatewayProtocol` seam -- `payment_gateways.py`
  (`StripePaymentGateway`/`RazorpayPaymentGateway`, real SDKs, real request
  shapes, honestly unconfigured in this sandbox), `Payment`/`PaymentMethod`
  models, `webhooks.py` (real HMAC-SHA256 signature verification for both
  providers + Redis-backed event-id dedup), refund/retry, and the
  `POST /payments`/`POST /payments/methods`/`POST /webhooks/*` API surface.

Later BE-013 parts (not built here) layer Invoice/Tax (Part 4) and
dashboards (Part 5) on top of this foundation.

See `FLOW.md` for every design decision in full detail (§1-§11 Part 1,
§12-§21 Part 2, §22-§34 Part 3) and `DATABASE.md` for the schema reference.
This file is a short orientation.

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

## In One Paragraph (Part 3)

Two more tables (`payments`, `payment_methods`; migration
`0024_create_billing_payment_tables.py`).
`payment_gateways.StripePaymentGateway`/`RazorpayPaymentGateway` are real
implementations of Part 2's `PaymentGatewayProtocol` seam -- real SDK calls
(`stripe.PaymentIntent.create`/`stripe.Refund.create`;
`razorpay Client.order.create`+`payment.createRecurring`/`payment.refund`),
real idempotency handling (Stripe's own native `idempotency_key` parameter;
Razorpay's SDK exposes none, so this module's own `Payment.idempotency_key`
unique constraint is that provider's entire idempotency guarantee -- see
`FLOW.md` §22/§25), and a real not-configured guard
(`Settings.stripe_secret_key`/`razorpay_key_id`+`razorpay_key_secret`, all
empty by default) that raises Part 2's exact
`PaymentGatewayNotConfiguredError` before any network attempt -- byte-for-
byte the same behavior `UnconfiguredPaymentGateway` already had, since no
real credentials are ever configured in this sandbox.
`dependencies.build_payment_gateway` is the real "wire it in" step Part 2
deferred, selecting Stripe vs. Razorpay via one platform-wide
`Settings.payment_default_provider` (see `FLOW.md` §29-§30).
`service.PaymentService` adds real idempotency-key enforcement
(`initiate_payment`, backed by a genuine database unique constraint, not
just an application-level check -- see `FLOW.md` §22), refund (full/
partial), and retry (a fresh idempotency key for Stripe, moot for Razorpay
-- see `FLOW.md` §25); `Payment` itself doubles as the entire "Payment
History" query surface (`FLOW.md` §27). `webhooks.py` implements real
HMAC-SHA256 signature verification for both providers (Stripe's real
timestamped-payload scheme via the installed SDK's own
`stripe.Webhook.construct_event`; Razorpay's real raw-body scheme via
`razorpay.Utility.verify_webhook_signature`) plus a Redis-backed,
TTL'd event-id dedup set (`FLOW.md` §23-§24), and composes with two small,
additive `RenewalService` methods
(`confirm_renewal_payment_succeeded`/`confirm_renewal_payment_failed`) to
resolve an asynchronously-confirmed renewal charge without reimplementing
any period-extension/past-due logic (`FLOW.md` §34).

## What This Module Does NOT Do (as of Part 3)

* **It cannot actually charge real money in this sandbox.** There are no
  real Stripe/Razorpay credentials anywhere in it, and there never will
  be -- `StripePaymentGateway`/`RazorpayPaymentGateway`'s own
  not-configured guard means every real charge attempt still raises
  `PaymentGatewayNotConfiguredError`, exactly as Part 2's honest
  placeholder already did. The request shapes, idempotency handling, and
  webhook signature verification are all real and correct regardless (see
  `FLOW.md` §22-§34) -- what is missing is credentials, not code.
* **It does not model a separate provider-side Customer entity.** Neither
  a Stripe `cus_...` nor the equivalent Razorpay concept is persisted --
  see `FLOW.md` §28's honest write-up of this scope simplification.
* **It does not re-apply a coupon on renewal.** A coupon is redeemed once,
  at subscription creation -- see `FLOW.md` §17 (unchanged by Part 3).
* **It does not build Invoice/Tax.** Those are BE-013 Part 4.
* **It does not add a new `PermissionModule`.** `billing.*` (no dedicated
  payment/invoice module) covers every Part 3 endpoint -- see `FLOW.md`
  §32.
* **It does not touch `organization`/`otp`/`rbac`/`router` internals**
  beyond Part 1's one narrow `OrganizationService.sync_subscription_tier`
  method, reusing (never modifying) `otp`'s `EmailProviderProtocol`,
  `rbac`'s `AuditAction` enum (additive values only), and
  `app.database.redis`'s existing shared Redis client (used, never
  modified, by `webhooks.RedisWebhookEventDedup`). `app.domains.router
  .crypto`'s Fernet helpers were evaluated for `PaymentMethod` and found
  unnecessary -- that table never stores a recoverable secret at all, only
  an opaque provider token (see `FLOW.md` §28).

## Folder Structure

```text
backend/
  alembic/versions/
    0022_create_billing_plan_license_usage_tables.py
    0023_create_billing_subscription_coupon_tables.py
    0024_create_billing_payment_tables.py
  app/
    core/
      celery_app.py    # + billing-subscription-renewal-sweep Beat entry
      config.py        # + subscription_trial_period_days/renewal_grace_period_days/
                        #   renewal_reminder_days_before/expiry_reminder_days_before/
                        #   stripe_secret_key/stripe_webhook_secret/
                        #   stripe_webhook_tolerance_seconds/razorpay_key_id/
                        #   razorpay_key_secret/razorpay_webhook_secret/
                        #   payment_default_provider/payment_webhook_event_dedup_ttl_seconds
    domains/billing/
      __init__.py
      models.py          # Plan, PlanFeature, License, LicenseChangeLog, UsageMetric,
                          # Subscription, Coupon, CouponPlan, CouponUsage, Payment,
                          # PaymentMethod
      constants.py        # + SubscriptionStatus, DiscountType, RENEWABLE_SUBSCRIPTION_STATUSES,
                           #   CYCLIC_BILLING_CYCLES, MAX_PERCENTAGE_DISCOUNT_VALUE,
                           #   TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP, PaymentProvider,
                           #   PaymentStatus, PaymentMethodType, ZERO_DECIMAL_CURRENCIES,
                           #   WEBHOOK_EVENT_DEDUP_KEY_PREFIX
      schemas.py           # + Subscription*/Coupon*/Payment*/PaymentMethod* request/
                           #   response models
      repository.py        # + SubscriptionRepository, CouponRepository (atomic increment),
                            #   PaymentRepository, PaymentMethodRepository (atomic
                            #   set_as_default)
      service.py             # + SubscriptionService, CouponService, PaymentService,
                              #   PaymentMethodService
      renewal_service.py       # PaymentGatewayProtocol seam, UnconfiguredPaymentGateway,
                                # RenewalService (process_renewal, process_due_renewals,
                                # expire_lapsed_subscriptions, reminders,
                                # confirm_renewal_payment_succeeded/failed)
      payment_gateways.py        # StripePaymentGateway, RazorpayPaymentGateway (real
                                  # stripe/razorpay SDK integration)
      webhooks.py                  # Real Stripe/Razorpay signature verification,
                                    # RedisWebhookEventDedup, process_stripe_event/
                                    # process_razorpay_event
      tasks.py                  # Celery task: run_subscription_renewal_sweep
      router.py                  # + /subscriptions, /coupons, /payments,
                                  #   /payments/methods, /webhooks/stripe,
                                  #   /webhooks/razorpay endpoints
      validators.py                # + normalize_coupon_code, validate_discount_value,
                                    #   compute_discount_amount, add_billing_cycle,
                                    #   to_minor_units, derive_retry_idempotency_key
      dependencies.py                # + get_subscription_service, get_coupon_service,
                                      #   build_payment_gateway, get_payment_gateway,
                                      #   get_renewal_service, get_payment_service,
                                      #   get_payment_method_service,
                                      #   get_webhook_event_dedup
      exceptions.py                    # + Subscription*/Coupon*/PaymentGatewayNotConfiguredError/
                                        #   Payment*/PaymentMethodNotFoundError/
                                        #   WebhookSignatureInvalidError/PaymentProviderError
      events.py                         # + Subscription*/Coupon*/RenewalReminderSent/
                                         #   ExpiryReminderSent/Payment*/WebhookProcessed/
                                         #   WebhookSignatureInvalid dataclasses
  docs/billing/
    README.md   # this file
    FLOW.md
    DATABASE.md
  tests/unit/
    test_billing_plans_licenses_usage.py
    test_billing_subscriptions_renewals_coupons.py
    test_billing_payments_webhooks.py
  requirements.txt / pyproject.toml   # + stripe==15.3.1, razorpay==2.0.1
```
