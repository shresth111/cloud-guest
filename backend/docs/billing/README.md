# BE-013: Billing & Subscription Module

**BE-013 is now complete, across five parts.** This section is a short
table of contents for the whole module; each part's own "In One Paragraph"
section below (and `FLOW.md`'s numbered §§) carries the full detail --
this is deliberately not a rewrite of any of it.

| Part | Name | What it contributed |
|---|---|---|
| 1 | Plan + License + Usage Core | The pricing/entitlement catalog (`Plan`/`PlanFeature`), what an organization is actually entitled to (`License`/`LicenseChangeLog`), real composed usage tracking (`UsageMetric`) |
| 2 | Subscription + Renewal + Coupon Engines | `Subscription` lifecycle, the Renewal Engine (due-date detection, the `PaymentGatewayProtocol` seam, grace-period-then-expire, reminder emails), the Coupon Engine |
| 3 | Payment Service + Real Stripe/Razorpay + Webhooks | Real `StripePaymentGateway`/`RazorpayPaymentGateway`, `Payment`/`PaymentMethod`, real HMAC-SHA256 webhook verification + Redis dedup, refund/retry |
| 4 | Invoice Engine + Tax/GST | `TaxRate`/`BillingProfile`/`Invoice`/`InvoiceItem`/`CreditDebitNote`, the real CGST/SGST/IGST GST split, a DB-atomic number generator, a `reportlab` invoice PDF renderer |
| 5 | Super Admin + Customer Billing Dashboards | Real Revenue/MRR/ARR + churn-rate dashboards, a unified Customer Billing Dashboard, the customer self-service upgrade/downgrade permission fix, `PATCH /subscriptions/{id}/renewal-settings` |

All five parts live in `app.domains.billing` -- one domain, extended, not
a new one per part.

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

* **Part 4** (this doc's latest addition): the Invoice Engine + Tax/GST --
  `TaxRate` (Super-Admin-managed tax jurisdiction config),
  `BillingProfile` (an organization's own billing address/GSTIN, entirely
  owned by this domain), `Invoice`/`InvoiceItem`/`CreditDebitNote`, a real,
  DB-level-atomic invoice/credit-note/debit-note number generator
  (`number_generator.py`), the real CGST/SGST/IGST-vs-IGST GST computation
  (`validators.compute_tax_breakdown`), a dedicated `reportlab`-based
  invoice PDF renderer (`invoice_pdf.py`), and the
  `POST /invoices/{id}/void`/`credit-note`/`debit-note`,
  `GET /invoices`/`{id}`/`{id}/download`, `POST`/`GET`/`PUT
  /billing/tax-rates`, and `POST`/`GET /billing/profile` API surface.

* **Part 5** (this doc's final addition): the Super Admin Billing
  Dashboard (`GET /billing/dashboard/super-admin` -- real Revenue/MRR/ARR,
  Subscription counts + a real churn-rate formula, paginated Customer
  Billing summary rows, a Failed Payments listing with retry-eligibility
  flagged), the Customer Billing Dashboard (`GET /billing/dashboard/me` /
  `/{organization_id}` -- a unified, pure-composition summary), the
  confirmed-and-fixed customer self-service upgrade/downgrade gap, and the
  genuinely-missing `PATCH /subscriptions/{id}/renewal-settings` endpoint.
  No new tables, no new migration.

See `FLOW.md` for every design decision in full detail (§1-§11 Part 1,
§12-§21 Part 2, §22-§34 Part 3, §35-§46 Part 4, §47-§55 Part 5) and
`DATABASE.md` for the schema reference. This file is a short orientation.

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

## In One Paragraph (Part 4)

Six more tables (`tax_rates`, `billing_profiles`, `invoice_number_counters`,
`invoices`, `invoice_items`, `credit_debit_notes`; migration
`0025_create_billing_invoice_tax_tables.py`). `BillingProfile` (billing
address + GSTIN) is **entirely owned by this domain** -- a new table keyed
to `organization_id`, not a column added to `Organization` -- since that
concept has exactly one consumer anywhere in this codebase (this domain's
own invoice generation); see `FLOW.md` §36 for the full write-up of why
this is judged the cleaner call than Part 1's own `subscription_tier`-sync
precedent. `service.InvoiceService.generate_invoice_for_subscription`
composes -- never recomputes -- `validators.compute_renewal_charge_amount`
(the exact same real charge-amount function `RenewalService` itself calls,
relocated there specifically to give both layers one shared function with
no import cycle -- see `FLOW.md` §38) for the invoice's own `subtotal`,
then applies the real, legally-defined GST rule via
`validators.compute_tax_breakdown`: intra-state (same state, same country
as this platform's own `Settings.platform_gst_state`/`platform_gst_country`)
splits the rate into equal CGST+SGST halves; inter-state charges the full
rate as IGST; `tax_exempt`/no-configured-rate/`TaxType.NONE` all
short-circuit to an honest zero, never a fabricated charge (`FLOW.md`
§39-§40). The created `Invoice` freezes a JSONB `billing_snapshot` copy of
the `BillingProfile` at issue time -- a later address edit never
retroactively changes an already-issued invoice (`FLOW.md` §41, the
identical "copy, not reference" principle this codebase already applies
repeatedly elsewhere). `number_generator.py` generates every
`"INV-2026-00001"`/`"CN-2026-00001"`/`"DN-2026-00001"`-shaped number via a
single, real, atomic `INSERT ... ON CONFLICT DO UPDATE ... RETURNING`
statement against a dedicated `invoice_number_counters` row -- genuinely
concurrency-safe, never a racy `SELECT MAX(...) + 1` (`FLOW.md` §37).
`webhooks.py`'s existing success-handling code gained one additive,
optional call into the new `InvoiceService.mark_invoice_paid_for_payment`
-- the natural continuation of a successful payment confirming its own
subscription's most recent unpaid invoice, never a second payment-side
reimplementation (`FLOW.md` §42). `invoice_pdf.py` is a **dedicated**
`reportlab`/`platypus` renderer (reusing the exact same library BE-012
Part 5 already added, never a second PDF dependency) rather than routing
through `analytics.export`'s generic report renderer -- an invoice's fixed,
legally-defined layout (CGST/SGST/IGST shown as separate lines, never
lumped) does not fit that renderer's own deliberately flexible, variable-
shaped report-section model (`FLOW.md` §43).

## In One Paragraph (Part 5 -- final part)

No new tables, no new migration. `service.SuperAdminBillingDashboardService`
composes a new `repository.BillingDashboardRepository` (real, hand-written
aggregate `SELECT`s -- `sum_captured_payments`, `revenue_by_month`,
`list_active_subscription_plans`, `count_subscriptions_by_status`/
`by_plan_type`, `count_subscriptions_active_before`/
`cancelled_between`, `paginate_subscriptions_with_org_and_plan`) into four
real dashboard sections: total revenue nets out refunds across every
"captured money" `Payment` status, not just `SUCCEEDED` (`FLOW.md` §48
explains exactly why the module brief's own literal wording would
undercount a partially-refunded payment); MRR/ARR sums every currently-
`ACTIVE` subscription's `validators.compute_renewal_charge_amount(plan)`,
normalized to a monthly figure by `billing_cycle` (`FLOW.md` §48); a real,
defined, documented churn-rate formula
(`cancelled_this_period / active_at_period_start` over the current
calendar month, `None` -- never a fabricated `0.0` -- when there is no
active base, `FLOW.md` §49); and a Failed Payments listing reusing Part
3's own `PaymentService.list_failed_payments` verbatim, with each row's
retry-eligibility reusing the exact rule
`PaymentService.retry_failed_payment` itself enforces
(`validators.is_payment_retry_eligible`, factored out of that existing
method rather than duplicated). `service.CustomerBillingDashboardService
.get_dashboard` is pure composition over six already-built Parts 1-4
service methods -- nothing is recomputed. This domain's own new Revenue
Dashboard is explicitly a **separate** capability from
`app.domains.analytics`'s own, still-untouched `RevenueMetricsResponse`
placeholder (`FLOW.md` §50). Two real findings from investigating the
module brief's own customer-self-service requirements: (1) `Organization
Owner`/`Admin` hold only `SUBSCRIPTIONS: READ` in RBAC's seed data,
blocking self-service upgrade/downgrade -- confirmed, and fixed *without*
touching RBAC internals by having `router
._require_subscription_self_service_permission` accept `billing.update`
(which `Organization Owner` already holds) as an alternative to
`subscriptions.update` (`FLOW.md` §51); (2) no endpoint existed to update
`Subscription.auto_renew` post-creation -- fixed by adding `PATCH
/subscriptions/{id}/renewal-settings`, the one subscription mutator in
this file that deliberately DOES enforce a real tenant check, since it is
explicitly a customer self-service action (`FLOW.md` §52). Dashboard views
are audited via the same throttled-Redis-dedup middle ground
`app.domains.analytics.dashboard_audit` already established, re-implemented
locally rather than imported (`FLOW.md` §53).

## What This Module Does NOT Do (as of Part 5 -- final)

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
* **It does not fix `app.domains.analytics`'s own `RevenueMetricsResponse`
  placeholder.** That is a separate, pre-existing, still-honest
  `available=False` placeholder in a different domain -- this Part builds
  its own, distinct Revenue Dashboard entirely inside `app.domains.billing`
  instead. See `FLOW.md` §50 for the full clarification; fixing Analytics'
  own placeholder (from inside `app.domains.analytics` itself) is an
  honest, explicitly out-of-scope follow-up for a future part/module.
* **It does not fix RBAC's own `Organization Owner`/`Admin` seed-data gap
  directly.** Those roles' `SUBSCRIPTIONS: READ`-only override (in
  `app.domains.rbac.seed.py`, outside this Part's directory) is what
  originally blocked customer self-service upgrade/downgrade. This Part
  works around it entirely from inside its own directory (accepting
  `billing.update` as an alternative permission -- see `FLOW.md` §51)
  rather than editing RBAC's seed data; a future RBAC-owning change could
  still loosen that override directly.
* **It does not sum revenue across currencies with real FX conversion.**
  No FX-conversion table or service exists anywhere in this codebase;
  every revenue/MRR/ARR figure is a raw sum across whatever `Plan.currency`/
  `Payment.currency` values are present, surfaced honestly via a
  `currency_note` -- see `FLOW.md` §48.
* **It does not add a new `PermissionModule` for tax rates/billing
  profile.** `billing.*` covers `/billing/tax-rates`/`/billing/profile`
  exactly like Plans/Coupons/Payments before them; `/invoices` reuses
  `PermissionModule.INVOICES`'s own seven actions, already seeded since
  BE-004 -- see `FLOW.md` §44.
* **It does not automatically Beat-schedule the invoice-overdue sweep.**
  `tasks.run_invoice_overdue_sweep` is a real, fully working, independently
  callable Celery task (mirrors Part 1's own `expire_license` deferral),
  but registering it in `app.core.celery_app`'s `beat_schedule` is a change
  to a file outside this Part's own directory-rule boundary -- see
  `FLOW.md` §45.
* **It does not touch `organization`/`otp`/`rbac`/`router` internals**
  beyond Part 1's one narrow `OrganizationService.sync_subscription_tier`
  method, reusing (never modifying) `otp`'s `EmailProviderProtocol`,
  `rbac`'s `AuditAction` enum (additive values only), and
  `app.database.redis`'s existing shared Redis client (used, never
  modified, by `webhooks.RedisWebhookEventDedup`). `app.domains.router
  .crypto`'s Fernet helpers were evaluated for `PaymentMethod` and found
  unnecessary -- that table never stores a recoverable secret at all, only
  an opaque provider token (see `FLOW.md` §28). Part 4 does not add any
  column to `app.domains.organization.models.Organization` -- billing
  address/GSTIN lives entirely in this domain's own `BillingProfile` table
  (see `FLOW.md` §36). Part 5 touches no file inside `app.domains
  .analytics`/`rbac`/`organization`/`otp`/`monitoring` at all -- not even
  an additive `AuditAction` enum value (see `FLOW.md` §54) -- with one
  narrow, read-only exception: `repository
  .BillingDashboardRepository.paginate_subscriptions_with_org_and_plan`
  reads `app.domains.organization.models.Organization` directly for a
  display name (the identical read-only, no-service-layer precedent
  `UsageRepository.count_locations`/`count_routers` already establish for
  `Location`/`Router`, and `app.domains.rbac.dependencies
  .CurrentOrganization` already establishes for this exact model).

## Folder Structure

```text
backend/
  alembic/versions/
    0022_create_billing_plan_license_usage_tables.py
    0023_create_billing_subscription_coupon_tables.py
    0024_create_billing_payment_tables.py
    0025_create_billing_invoice_tax_tables.py
  app/
    core/
      celery_app.py    # + billing-subscription-renewal-sweep Beat entry
                       #   (run_invoice_overdue_sweep NOT yet registered here --
                       #   see "What This Module Does NOT Do" above)
      config.py        # + subscription_trial_period_days/renewal_grace_period_days/
                        #   renewal_reminder_days_before/expiry_reminder_days_before/
                        #   stripe_secret_key/stripe_webhook_secret/
                        #   stripe_webhook_tolerance_seconds/razorpay_key_id/
                        #   razorpay_key_secret/razorpay_webhook_secret/
                        #   payment_default_provider/payment_webhook_event_dedup_ttl_seconds/
                        #   platform_gst_state/platform_gst_country/platform_gstin/
                        #   platform_legal_business_name/invoice_due_days/
                        #   invoice_overdue_sweep_interval_seconds
    domains/billing/
      __init__.py
      models.py          # Plan, PlanFeature, License, LicenseChangeLog, UsageMetric,
                          # Subscription, Coupon, CouponPlan, CouponUsage, Payment,
                          # PaymentMethod, TaxRate, BillingProfile,
                          # InvoiceNumberCounter, Invoice, InvoiceItem, CreditDebitNote
      constants.py        # + SubscriptionStatus, DiscountType, RENEWABLE_SUBSCRIPTION_STATUSES,
                           #   CYCLIC_BILLING_CYCLES, MAX_PERCENTAGE_DISCOUNT_VALUE,
                           #   TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP, PaymentProvider,
                           #   PaymentStatus, PaymentMethodType, ZERO_DECIMAL_CURRENCIES,
                           #   WEBHOOK_EVENT_DEDUP_KEY_PREFIX, TaxType, InvoiceStatus,
                           #   NoteType, INVOICE_NUMBER_PREFIX, CREDIT_NOTE_NUMBER_PREFIX,
                           #   DEBIT_NOTE_NUMBER_PREFIX, NUMBER_SEQUENCE_DIGITS,
                           #   TASK_RUN_INVOICE_OVERDUE_SWEEP
                           # + Part 5: DASHBOARD_CAPTURED_PAYMENT_STATUSES,
                           #   DEFAULT/MIN/MAX_DASHBOARD_REVENUE_TREND_MONTHS,
                           #   CUSTOMER_DASHBOARD_RECENT_INVOICES/PAYMENTS_LIMIT,
                           #   BILLING_DASHBOARD_AUDIT_THROTTLE_MINUTES/KEY_TEMPLATE,
                           #   AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED/CUSTOMER_VIEWED/
                           #   AUDIT_ACTION_SUBSCRIPTION_RENEWAL_SETTINGS_UPDATED
      schemas.py           # + Subscription*/Coupon*/Payment*/PaymentMethod* request/
                           #   response models, TaxRate*/BillingProfile*/Invoice*/
                           #   CreditDebitNote*/CreditNoteIssueRequest/DebitNoteIssueRequest
                           # + Part 5: SubscriptionRenewalSettingsUpdateRequest,
                           #   SuperAdminRevenueDashboardResponse/
                           #   SuperAdminSubscriptionDashboardResponse/
                           #   SuperAdminCustomerBillingDashboardResponse/
                           #   SuperAdminFailedPaymentsDashboardResponse/
                           #   SuperAdminBillingDashboardResponse,
                           #   CustomerBillingDashboardResponse
      repository.py        # + SubscriptionRepository, CouponRepository (atomic increment),
                            #   PaymentRepository, PaymentMethodRepository (atomic
                            #   set_as_default), NumberCounterRepository (atomic UPSERT),
                            #   TaxRateRepository, BillingProfileRepository,
                            #   InvoiceRepository, CreditDebitNoteRepository
                            # + Part 5: BillingDashboardRepository (sum_captured_payments,
                            #   revenue_by_month, list_active_subscription_plans,
                            #   count_subscriptions_by_status/by_plan_type,
                            #   count_subscriptions_active_before/cancelled_between,
                            #   paginate_subscriptions_with_org_and_plan)
      service.py             # + SubscriptionService, CouponService, PaymentService,
                              #   PaymentMethodService, TaxRateService,
                              #   BillingProfileService, InvoiceService
                              # + Part 5: SuperAdminBillingDashboardService,
                              #   CustomerBillingDashboardService,
                              #   SubscriptionService.update_renewal_settings
      number_generator.py      # generate_invoice_number/generate_credit_note_number/
                                # generate_debit_note_number -- see the real, atomic
                                # concurrency-safety mechanism in its own module docstring
      invoice_pdf.py            # render_invoice_pdf -- a dedicated reportlab/platypus
                                 # renderer (never routed through analytics.export)
      renewal_service.py       # PaymentGatewayProtocol seam, UnconfiguredPaymentGateway,
                                # RenewalService (process_renewal, process_due_renewals,
                                # expire_lapsed_subscriptions, reminders,
                                # confirm_renewal_payment_succeeded/failed)
      payment_gateways.py        # StripePaymentGateway, RazorpayPaymentGateway (real
                                  # stripe/razorpay SDK integration)
      webhooks.py                  # Real Stripe/Razorpay signature verification,
                                    # RedisWebhookEventDedup, process_stripe_event/
                                    # process_razorpay_event (+ optional invoice_service
                                    # composition -- InvoiceServiceProtocol)
      tasks.py                  # Celery tasks: run_subscription_renewal_sweep,
                                 # run_invoice_overdue_sweep
      router.py                  # + /subscriptions, /coupons, /payments,
                                  #   /payments/methods, /webhooks/stripe,
                                  #   /webhooks/razorpay, /invoices, /invoices/{id}/
                                  #   download|void|credit-note|debit-note,
                                  #   /billing/tax-rates, /billing/profile endpoints
                                  # + Part 5: /billing/dashboard/super-admin,
                                  #   /billing/dashboard/me, /billing/dashboard/{organization_id},
                                  #   PATCH /subscriptions/{id}/renewal-settings;
                                  #   _require_subscription_self_service_permission
                                  #   (the upgrade/downgrade self-service fix)
      validators.py                # + normalize_coupon_code, validate_discount_value,
                                    #   compute_discount_amount, add_billing_cycle,
                                    #   to_minor_units, derive_retry_idempotency_key,
                                    #   compute_renewal_charge_amount, normalize_region,
                                    #   compute_tax_breakdown, GstBreakdown
                                    # + Part 5: subtract_months, current_month_period
                                    #   (moved here from a private service.py helper),
                                    #   is_payment_retry_eligible (factored out of
                                    #   PaymentService.retry_failed_payment)
      dependencies.py                # + get_subscription_service, get_coupon_service,
                                      #   build_payment_gateway, get_payment_gateway,
                                      #   get_renewal_service, get_payment_service,
                                      #   get_payment_method_service,
                                      #   get_webhook_event_dedup, get_tax_rate_service,
                                      #   get_billing_profile_service, get_invoice_service
                                      # + Part 5: get_billing_dashboard_repository,
                                      #   get_super_admin_billing_dashboard_service,
                                      #   get_customer_billing_dashboard_service
      exceptions.py                    # + Subscription*/Coupon*/PaymentGatewayNotConfiguredError/
                                        #   Payment*/PaymentMethodNotFoundError/
                                        #   WebhookSignatureInvalidError/PaymentProviderError/
                                        #   TaxRateNotFoundError/InvalidTaxRateError/
                                        #   BillingProfileNotFoundError/InvoiceNotFoundError/
                                        #   InvalidInvoiceStatusTransitionError/
                                        #   InvalidNoteAmountError
                                        # (Part 5 adds no new exception -- reuses
                                        #   SubscriptionNotFoundError for the renewal-
                                        #   settings tenant-mismatch case)
      events.py                         # + Subscription*/Coupon*/RenewalReminderSent/
                                         #   ExpiryReminderSent/Payment*/WebhookProcessed/
                                         #   WebhookSignatureInvalid/Invoice*/
                                         #   CreditNoteIssued/DebitNoteIssued/TaxRate*/
                                         #   BillingProfileUpdated dataclasses
                                         # (Part 5 adds no new event -- see FLOW.md §53
                                         #   for its own structured-log-only dashboard
                                         #   view logging)
  docs/billing/
    README.md   # this file
    FLOW.md
    DATABASE.md
  tests/unit/
    test_billing_plans_licenses_usage.py
    test_billing_subscriptions_renewals_coupons.py
    test_billing_payments_webhooks.py
    test_billing_invoices_tax.py
    test_billing_dashboards.py   # Part 5
  requirements.txt / pyproject.toml   # + stripe==15.3.1, razorpay==2.0.1 (Part 3; no
                                       #   new dependency for Part 4 -- reportlab already
                                       #   present from BE-012 Part 5). Part 5 adds no
                                       #   new dependency either.
```
