# Billing (BE-013 Part 1): Design Decisions

## §1. `Organization.subscription_tier` relationship

`app.domains.organization.models.Organization`'s own module docstring has,
since Module 005, explicitly reserved `subscription_tier` for "a future
Billing domain" and disclaimed that it "carries no pricing/entitlement
logic itself." This part is that reserved domain arriving, and the
decision is explicit:

* **`License`/`Plan` become the real source of truth** for what an
  organization is entitled to. Every read that matters -- `validate_license`,
  `validate_usage_against_license`, a future gating middleware -- reads
  `License`/`PlanFeature`, never `Organization.subscription_tier`.
* **`subscription_tier` becomes a denormalized, best-effort convenience
  label**, kept in sync by a new, narrow, additive method on
  `OrganizationService`: `sync_subscription_tier(organization_id,
  subscription_tier)`. It writes exactly one column, performs no other
  validation (billing operations are already independently authorized by
  RBAC before this is ever called), and writes no audit entry of its own
  (`LicenseService` already writes its own `license_assigned`/
  `license_upgraded`/`license_downgraded` audit row for the event that
  triggers the sync -- a second, organization-flavoured audit row for the
  same moment would be pure duplication).
* `LicenseService.assign_license`/`upgrade_license`/`downgrade_license`
  each call this hook with the new plan's `slug` immediately after the
  license mutation succeeds (and its own `LicenseChangeLog` row is
  written).

**Why this is judged a narrow, additive exception to "never touch other
domains' internals" rather than a violation of it:** this module's entire
purpose is to give that reserved field real meaning. Every existing reader
of `subscription_tier` (e.g. BE-012 Analytics' `Plan Distribution` --a real
`GROUP BY Organization.subscription_tier`) continues to work completely
unmodified; it simply now reads a real, billing-backed value instead of a
hand-set (or `NULL`) approximation. No other `Organization` column, method,
or existing behavior is touched.

## §2. `PlanFeature` value-storage shape: three typed columns, not one JSONB blob

The spec gives a closed, 16-value `PlanFeatureKey` enum and three value
shapes (`LIMIT`/`BOOLEAN`/`TIER`). Two designs were considered:

1. One JSONB `value` column, shape determined by `feature_type` at read
   time.
2. Three plain, nullable, precisely-typed columns (`limit_value`
   `Numeric(18,2)`, `is_enabled` `Boolean`, `tier_value` `String(20)`),
   exactly one populated per row, enforced by `validators
   .validate_feature_value`.

**Chosen: (2).** A JSONB blob would make "give me every plan whose
`max_guests` limit is >= 500" an un-indexable JSON-path query, and would
require every reader to know, out of band, which shape to expect. Three
typed columns are directly queryable/indexable, self-documenting (a row's
own `feature_type` tells you which column to read), and `validate_feature_
value` (`validators.py`) rejects any row that doesn't match the closed
`FEATURE_KEY_TYPE` mapping (e.g. `MAX_GUESTS` can never legally be
`BOOLEAN`-shaped) -- a defensive check no single JSONB column could offer
without hand-rolled schema validation on every write anyway. `UniqueConstraint(plan_id, feature_key)`
prevents two conflicting rows for the same feature on the same plan.

## §3. Money: `Numeric`, never `Float`

`Plan.base_price` is `Numeric(12, 2)`. Binary floating point cannot
represent most decimal currency amounts exactly (`0.1 + 0.2 != 0.3` in
IEEE 754), and a billing system that used `Float` for money would
accumulate silent, compounding rounding error across every plan/invoice
computed from it. `PlanFeature.limit_value` and `UsageMetric.value` are
also `Numeric` (`18, 2`) for the identical reason: a usage count directly
gates a limit-enforcement decision, the same correctness bar as money.
Every service method that touches these columns uses Python's `Decimal`
throughout (`service.py`, `schemas.py`) -- never a bare `float` anywhere in
this domain.

## §4. `License` status transition graph

```text
PENDING_ACTIVATION --activate--> ACTIVE
PENDING_ACTIVATION --cancel----> CANCELLED

ACTIVE --suspend--> SUSPENDED
ACTIVE --expire---> EXPIRED
ACTIVE --cancel----> CANCELLED
ACTIVE --upgrade/downgrade--> ACTIVE (plan_id changes, status unchanged)

SUSPENDED --activate--> ACTIVE   (reactivation)
SUSPENDED --expire----> EXPIRED
SUSPENDED --cancel----> CANCELLED

EXPIRED    -- terminal, no transitions out
CANCELLED  -- terminal, no transitions out
```

Mirrors `app.domains.router.service.RouterService._validate_transition`'s
identical rigor: `service._LICENSE_TRANSITIONS` is the single, explicit
source of truth, and every method that changes `License.status`
(`activate_license`/`suspend_license`/`cancel_license`/`expire_license`)
calls `_assert_transition` first. Upgrade/downgrade deliberately do **not**
change `status` at all -- they only re-point `plan_id` and are legal only
while the license is already `ACTIVE` (an upgrade on a `PENDING_ACTIVATION`
or `SUSPENDED` license is rejected as an invalid `plan_change`
"transition").

## §5. Upgrade/downgrade history mechanism -- and why no `previous_plan_id` column

A single `previous_plan_id` column on `License` was considered and
rejected: it can only ever record the one most recent hop, silently losing
every earlier change the moment a second upgrade/downgrade happens --
exactly the "half-done" history the spec explicitly warns against ("License
Upgrade/Downgrade" is named as a first-class feature, implying real,
inspectable history, not just "what it is now").

**Chosen:** a real `LicenseChangeLog` table (`license_id`, `from_plan_id`
nullable, `to_plan_id`, `change_type` [`assigned`/`upgraded`/`downgraded`],
`changed_at`, `changed_by_user_id`, `reason`). Every `assign_license` call
writes one row (`from_plan_id = NULL`); every `upgrade_license`/
`downgrade_license` call writes one more. `LicenseService
.list_change_history(license_id)` reads the full, ordered history back
(exposed via `GET /licenses/{license_id}/history`). This is strictly more
complete than the single-column shortcut and costs one small table.

## §6. License-expiry sweep: out of scope for this part, by design

`LicenseService.expire_license` is a real, fully-built, tested
state-transition method -- the spec explicitly names "License Expiration"
as a first-class feature, so the method itself belongs here. **No Celery
Beat task calls it automatically in this part.** Two things were weighed:

* *Build it here*: "License Expiration" has no `Subscription`/`Payment`
  dependency yet, so a pure sweep (`SELECT licenses WHERE status = 'active'
  AND expires_at <= now()`, then call `expire_license` on each) is
  technically buildable today with zero missing pieces.
* *Defer it*: what should concretely happen the *instant* a license
  expires is a genuine policy question this part cannot answer honestly:
  a grace period before real enforcement? an automatic downgrade to a free
  tier instead of a hard block? does a pending renewal payment (a later
  part's concern) get one more chance before expiry takes effect? Wiring
  an automatic, unattended sweep now, ahead of that policy existing
  anywhere in this codebase, risks prematurely cutting off a real
  organization with no product-defined recovery path -- worse than not
  automating it yet.

**Decision: deferred.** `expire_license` is ready for BE-013's Renewal
engine (a later part) to schedule via `app.core.celery_app`'s Beat
schedule the moment that part defines the actual expiry policy -- no
change to this method's signature or behavior will be needed then, only a
new caller.

## §7. RBAC permission-key reuse

`app.domains.rbac.seed.py` confirms two modules already seeded since
BE-004 that map directly onto this spec, with no gaps requiring a new
`PermissionModule`:

* `PermissionModule.BILLING` -- seeded actions: `read`, `update`, `export`,
  `manage` (no dedicated `create`/`delete`). Already granted `FULL` at
  `GLOBAL` scope to `Super Admin`/`Platform Admin`/`Billing Manager`;
  `OPERATE`/`READ` to `MSP Owner`/`Organization Owner`/`Organization Admin`
  at `ORGANIZATION` scope.
* `PermissionModule.SUBSCRIPTIONS` -- seeded actions: `create`, `read`,
  `update`, `delete`, `manage`. Already granted at the same role/scope
  pattern as `BILLING`.

Mapping used (see `router.py`'s own module docstring for the full
reasoning, mirroring `app.domains.monitoring.router`'s established
"reuse the closest seeded action for an admin-gated write" precedent for
`alerts.manage`/`notifications.manage`):

| Operation | Permission key | Scope |
|---|---|---|
| Create/update/deactivate a `Plan` | `billing.manage` / `billing.update` / `billing.manage` | pinned to `GLOBAL` explicitly |
| Read a `Plan` | `billing.read` | inferred |
| Assign a `License` | `subscriptions.create` | inferred |
| Read a `License` | `subscriptions.read` | inferred |
| Activate/suspend/cancel/upgrade/downgrade a `License` | `subscriptions.update` | inferred |
| Read/refresh `Usage` | `billing.read` / `billing.update` | inferred |

Plan-catalog writes are the one place this part pins `scope=
ScopeType.GLOBAL` explicitly (composed via RBAC's own existing
`RequirePermission(key, scope=...)` factory, never reinvented) -- the
pricing catalog is a platform-wide resource, and per the spec, only a
Super-Admin-class role should create/edit it. License/Usage operations act
on one organization's own data and use the ordinary inferred
(`X-Organization-Id`-driven) scope resolution every other tenant-scoped
write in this codebase already uses.

**No new `PermissionModule`/action is added.** The only RBAC file edit
this part makes is additive `AuditAction` values (see §8) -- zero changes
to `enums.PermissionModule`/`PermissionAction`/`seed.py`.

## §8. `AuditAction` precedent followed

`app.domains.rbac.enums.AuditAction`'s own accumulated history shows every
prior domain -- brand new (Organization/Module 005, Location/Module 006,
User/Module 007, Router/Module 008, Router Provisioning/Module 009,
WireGuard/Module 009 Part 3, OTP/Voucher/Captive Portal/Guest/Module 010)
or an existing domain's own later Part -- adding its own additive block of
`AuditAction` values directly to this same enum, via the exact same narrow
`AuditLogWriter` protocol shape (`create_audit_log_entry(**fields)`) every
domain's service composes with. Billing (BE-013) is a brand-new domain,
so it follows that same precedent: a new, clearly-commented block
(`PLAN_CREATED`/`PLAN_UPDATED`/`PLAN_DEACTIVATED`/`LICENSE_ASSIGNED`/
`LICENSE_ACTIVATED`/`LICENSE_SUSPENDED`/`LICENSE_EXPIRED`/
`LICENSE_CANCELLED`/`LICENSE_UPGRADED`/`LICENSE_DOWNGRADED`) was added
directly to `app.domains.rbac.enums`, not a domain-local constants shadow
of the same concept (that alternative, seen in `app.domains.analytics`'
own Part 5 for `REPORTS`, is reserved for an *existing* domain adding
scoped audit strings for its own later Part, not the pattern a brand-new
domain follows at its first Part). Every Plan catalog mutation and every
License lifecycle transition is audited; Usage recording/limit-check reads
are never audited (a pure read/recompute triggers no state change a human
made, mirroring every other domain's own "reads aren't audited"
convention).

## §9. Usage-tracking composition sources

`UsageService.record_current_usage` computes every `UsageMetricKey` for
one organization over the current calendar month, from **real, composed**
data -- never fabricated:

| Metric | Source | How |
|---|---|---|
| `ORGANIZATIONS` | `app.domains.organization.service.OrganizationService` (via `OrganizationLookupProtocol`) | `1 + len(list_children(org_id))` if `org.is_msp()`, else `1` |
| `LOCATIONS` | `UsageRepository.count_locations` | read-only `SELECT COUNT(*) FROM locations WHERE organization_id = ...` |
| `ROUTERS` | `UsageRepository.count_routers` | read-only `SELECT COUNT(*) FROM routers WHERE organization_id = ...` (uses `Router.organization_id`'s own denormalized column) |
| `ACTIVE_DEVICES` | `app.domains.analytics.repository.AnalyticsRepository.count_active_guest_sessions` (via `ActiveSessionLookupProtocol`) | reused directly -- the exact real aggregate `app.domains.analytics.aggregation.compute_org_daily_summary` itself already calls for `session_count_active` |
| `GUESTS` / `GUEST_SESSIONS` / `BANDWIDTH_USAGE_MB` | `app.domains.guest.service.GuestAnalyticsService.get_summary` (via `GuestAnalyticsLookupProtocol`) | reused directly -- the exact real `SUM(bytes_uploaded + bytes_downloaded)`/`COUNT`/`COUNT(DISTINCT guest_id)` aggregate `app.domains.analytics.aggregation` itself already composes with for these same figures |
| `OTP_REQUESTS` / `SMS_USAGE` / `EMAIL_USAGE` | `UsageRepository.count_otp_requests_by_channel` | read-only, channel-grouped, date-ranged `SELECT ... GROUP BY channel FROM otp_requests` -- the real source the spec itself names |
| `STORAGE_USAGE_MB` / `API_REQUESTS` | **none** | honest placeholders, recorded as `0` |

**"Read another domain's model directly" precedent.** `count_locations`/
`count_routers`/`count_otp_requests_by_channel` query `Location`/`Router`/
`OtpRequest` directly via read-only `SELECT`s, never those domains' own
service or repository layers. This is not a new pattern invented here --
`app.domains.analytics.repository`'s own module docstring already
establishes it explicitly ("read another domain's *model* directly ...
never that domain's service or repository layer"), itself following
`app.domains.monitoring.repository`'s identical precedent. No file inside
`location`/`router`/`otp` is edited to make this work.

**Bandwidth/guest/session counts are deliberately *not* computed this same
"read the model directly" way.** `GuestAnalyticsService.get_summary`
already exists, is already the aggregate `app.domains.analytics` itself
reuses, and doing a fourth independent `SUM`/`COUNT` query against
`GuestSession` here would risk a subtly different answer from a
second, parallel implementation of the same arithmetic -- composing with
the existing service call is strictly more honest.

**`STORAGE_USAGE_MB`/`API_REQUESTS` are honest, undisguised placeholders**
(recorded as `Decimal(0)`, no special "unavailable" flag on the row since
`UsageMetric.value` has no such concept) -- there is no file-storage domain
and no API-request-logging table anywhere in this codebase, mirroring
`app.domains.analytics`'s own well-established "available: false"
convention for Revenue/ARR/MRR and similar figures with no real backing
data source.

**Upsert, not append-only.** Each metric key gets exactly one row per
`(organization_id, metric_key, period_start)` -- calling
`record_current_usage` again within the same calendar month updates the
existing row in place (`value`/`period_end`/`recorded_at`) rather than
inserting a second row, keeping the table's growth bounded to
"organizations x metrics x months," not "organizations x metrics x every
refresh ever triggered."

## §10. Downgrade-vs-usage enforcement

`LicenseService.downgrade_license` calls `UsageService
.check_usage_against_plan(organization_id, new_plan_id)` -- a **fresh**
recomputation (via `record_current_usage`, never a possibly-stale read of
already-persisted `UsageMetric` rows) compared against the *target* plan's
own `LIMIT` features. If any metric with a `LIMIT`-mapped feature
(`ORGANIZATIONS`/`LOCATIONS`/`ROUTERS`/`GUESTS`/`SMS_USAGE`/`EMAIL_USAGE`/
`STORAGE_USAGE_MB` -- see `constants.USAGE_METRIC_TO_LIMIT_FEATURE`) would
already exceed the target plan's limit, the downgrade is rejected
(`DowngradeBelowUsageError`, naming every exceeded metric) before any
state changes. Upgrades never run this check (a plan with equal-or-higher
limits cannot newly violate anything by definition, and the spec does not
call for it).

## §11. RBAC permission-key reuse for the Super-Admin-only Plan gate (test note)

`tests/unit/test_billing_plans_licenses_usage.py`'s
`TestPlanCatalogRbacGate` verifies `router.py`'s exact wiring
(`RequirePermission("billing.manage", scope=ScopeType.GLOBAL)`) using a
minimal fake `AccessValidator` (just the one `check` method
`RequirePermission`'s inner dependency calls), rather than re-exercising
RBAC's full grant-resolution stack (role assignments, permission
inheritance, deny overrides) -- that machinery already has its own
complete test coverage in `tests/unit/test_rbac.py`. This test's job is
narrower and different: prove *this domain's router* asks RBAC for the
right permission key at the right scope, not re-verify RBAC's own
correctness.

---

# BE-013 Part 2: Subscription + Renewal + Coupon Engines

## §12. `Subscription` cardinality + `plan_id` denormalization

`Subscription.organization_id` is **unique** -- exactly `License`'s own
one-row-per-organization decision (§ above), for the identical reason:
what matters is the organization's billing arrangement *now*, mutated in
place through a real transition graph, not a redundant "current
subscription" row alongside an append-only history table.

`plan_id` duplicates what `license_id -> License.plan_id` already tells
you. Kept anyway, deliberately: (1) every renewal-sweep query
(`RenewalService.process_renewal`/`process_due_renewals`) needs the
plan's `base_price`/`billing_cycle`/`currency` on every row it touches,
and joining through `licenses` on every sweep tick is real, avoidable
overhead for a value that's 1:1 with the license anyway; (2) this
module's own service methods keep the two in lockstep (a subscription's
plan is never changed independently of its license's), so the
duplication cannot silently drift. `Subscription.billing_cycle` makes the
same call, one level simpler: a plain **snapshot copy** of
`Plan.billing_cycle` at creation time, never re-read from `Plan`
afterward, so an in-flight subscription's billing cadence cannot change
out from under it if the referenced `Plan` is edited later.

## §13. `Subscription.status` transition graph + `PAUSED` vs. `CANCELLED`

```text
TRIALING  --convert (real charge succeeds)--> ACTIVE
TRIALING  --convert (charge fails/not configured)--> PAST_DUE
TRIALING  --cancel--------------------------------> CANCELLED

ACTIVE    --renewal fails/not configured--> PAST_DUE
ACTIVE    --pause--------------------------> PAUSED
ACTIVE    --cancel-------------------------> CANCELLED

PAST_DUE  --renewal retry succeeds--> ACTIVE
PAST_DUE  --grace period lapses-----> CANCELLED (License hard-expired)
PAST_DUE  --cancel-------------------> CANCELLED

PAUSED    --resume--> ACTIVE
PAUSED    --cancel--> CANCELLED

CANCELLED --reactivate--> ACTIVE   (ONLY if the License has not since
                                     been hard-expired by the grace-period
                                     sweep -- SubscriptionReactivationNotAllowedError
                                     otherwise)
```

`service._SUBSCRIPTION_TRANSITIONS`/`_assert_subscription_transition` is
the single, explicit source of truth -- mirrors `License`'s own
`_LICENSE_TRANSITIONS` rigor exactly.

**The real `PAUSED`-vs-`CANCELLED` distinction implemented here:**

* **`PAUSED`** is a *billing* pause only. No renewal attempts are made
  (`constants.RENEWABLE_SUBSCRIPTION_STATUSES` excludes it) while the
  organization keeps using the product on its current plan's
  entitlements exactly as before -- `pause_subscription`/
  `resume_subscription` never call any `LicenseService` method at all.
* **`CANCELLED`** is a *commercial* decision to stop. The underlying
  `License` is **suspended** (the same reversible state
  `LicenseService.suspend_license` already uses for a payment issue) the
  moment cancellation takes effect -- immediately
  (`cancel_subscription(immediate=True)`), or when a scheduled
  `cancel_at_period_end` period actually elapses
  (`RenewalService.process_renewal`'s fast path,
  `_finalize_scheduled_cancellation`). Suspension, not the terminal
  `EXPIRED` state -- `EXPIRED` is reserved exclusively for a lapsed grace
  period with no active recovery in progress (§16), keeping
  `reactivate_subscription` a meaningful, real reversal as long as that
  grace period hasn't run out.

## §14. `create_subscription` composition with Part 1's `LicenseService`

`SubscriptionService.create_subscription` never assigns/activates a
license itself -- it calls `LicenseService.assign_license` then
`activate_license` (Part 1, entirely unmodified), via the new
`LicenseLifecycleProtocol` (`service.py`) satisfied by the real
`LicenseService` directly. `FREE_TRIAL`-type plans get `TRIALING` with
`trial_end = now + Settings.subscription_trial_period_days`; every other
plan type goes straight to `ACTIVE` with `current_period_end` computed
by `validators.add_billing_cycle` (calendar-correct month/year addition,
stdlib `calendar` only -- no new dependency, clamps e.g. "Jan 31 + 1
month" to Feb 28/29).

**Scope boundary, explicitly:** the spec's "has a configured trial
period" case (as distinct from `plan_type == FREE_TRIAL`) is not
implemented -- it would require a new `Plan.trial_period_days` column
Part 1 never added, and retrofitting Plan's own schema is judged outside
this part's scope (Subscription/Renewal/Coupon, not Plan-catalog
changes). Only `FREE_TRIAL` triggers `TRIALING`; an honest boundary, not
an oversight.

## §15. The `PaymentGatewayProtocol` seam -- read `renewal_service.py`'s own module docstring first

A real renewal for a paid plan needs to actually charge money -- BE-013
Part 3 (real Stripe/Razorpay SDK integration + webhooks) does not exist
yet. This is the exact same kind of forward-looking seam BE-009 Part 2
built for BE-010's `router_agent` to call later
(`RouterProvisioningService.complete_provisioning_job`), and the same
shape `app.domains.otp`'s `EmailProviderProtocol`/`LoggingEmailProvider`
already establishes one level removed.

**The seam's exact shape:**

```python
class PaymentResult:
    success: bool
    reference: str | None
    failure_reason: str | None

class PaymentGatewayProtocol(Protocol):
    async def charge(
        self, *, organization_id, amount: Decimal, currency: str, subscription_id
    ) -> PaymentResult: ...
```

**The one default implementation this part ships,**
`UnconfiguredPaymentGateway`:

* A **zero-amount** charge (a `FREE_TRIAL` renewal, or any plan whose
  `base_price` is genuinely `0`) needs no real payment -- auto-succeeds
  (`PaymentResult(success=True)`).
* Any **real, non-zero** charge raises `PaymentGatewayNotConfiguredError`
  -- a clear, typed, honestly-labelled error (HTTP 503 if it ever
  escaped to a response, though `process_renewal` always catches it
  internally), never a silently-faked success.

`PaymentResult(success=False, failure_reason=...)` is the **separate**,
legitimate "a real gateway declined the charge" outcome --
`PaymentGatewayNotConfiguredError` is reserved purely for "this seam
itself was never wired to a real gateway", an infrastructure state, not
a payment decision.

**Wiring point:** `dependencies.get_payment_gateway()` is the single
FastAPI dependency both the HTTP API (`get_renewal_service`) and the
Celery worker (`tasks._run_renewal_sweep_async`) call to build a
`RenewalService`. BE-013 Part 3 overrides exactly this one function
(swapping `UnconfiguredPaymentGateway()` for a real Stripe/Razorpay-backed
class) -- nothing in `process_renewal`/`process_due_renewals`/any caller
needs to change.

## §16. `process_renewal` + grace period -> finally calling Part 1's deferred `expire_license`

`RenewalService.process_renewal(subscription_id)`:

1. Real due/eligibility check -- the subscription must be in a
   `RENEWABLE_SUBSCRIPTION_STATUSES` status (`TRIALING`/`ACTIVE`/
   `PAST_DUE`); `PAUSED`/`CANCELLED` raise
   `InvalidSubscriptionStatusForRenewalError`.
2. If `cancel_at_period_end` and the period has actually elapsed:
   finalizes the scheduled cancellation (License suspended, status ->
   `CANCELLED`) instead of renewing -- see §13.
3. Computes the real charge amount -- the plan's own `base_price` (never
   a per-renewal coupon recomputation; see §17).
4. Calls the `PaymentGatewayProtocol` seam.
5. **Success:** extends `current_period_end` by a real, calendar-correct
   billing cycle (`validators.add_billing_cycle`) and clears
   `PAST_DUE`/`past_due_at`.
6. **Failure** (declined, or `PaymentGatewayNotConfiguredError`):
   transitions to `PAST_DUE`, recording `past_due_at` (only on the
   *first* failure of an episode -- a retry that fails again does not
   reset the grace-period clock).

`process_due_renewals()` queries every subscription with
`current_period_end <= now`, `auto_renew=True`, a cyclic `billing_cycle`
(`MONTHLY`/`YEARLY` -- `BillingCycle.NONE` subscriptions are never
auto-renewed regardless of their own flag), and a renewable status --
processing each via `process_renewal` with **real per-subscription
failure isolation** (mirrors BE-012 Part 1's exact
`run_daily_aggregation_for_all_organizations` resilience pattern: one
subscription's exception is caught, logged, and recorded in the batch
result; every other due subscription still gets processed).

**Grace period -> hard expiry, finally composing Part 1's own deferred
seam:** Part 1's `docs/billing/FLOW.md` §6 explicitly left
`LicenseService.expire_license` uncalled by any automatic sweep, deferring
the real grace-period policy to "the Renewal engine (a later BE-013
part)". `RenewalService.expire_lapsed_subscriptions()` is that policy:
for every `PAST_DUE` subscription whose `past_due_at +
Settings.subscription_renewal_grace_period_days` has elapsed, it calls
**Part 1's real, entirely unmodified** `LicenseService.expire_license`
(the exact same state-transition method Part 1 built and tested, just
finally given a real caller) and transitions the `Subscription` itself to
`CANCELLED`. The default grace period is **7 days** -- long enough to
absorb a transient card-decline retry cycle without being so long that a
genuinely lapsed account keeps consuming entitlements indefinitely;
configurable via `Settings.subscription_renewal_grace_period_days` for
any deployment wanting a different balance.

## §17. Coupon-applies-once-vs-every-renewal: applies **once**, at signup

A coupon is redeemed -- a real `CouponUsage` row written,
`current_uses` atomically incremented -- exactly **once**, the moment
`SubscriptionService.create_subscription` creates the subscription it is
attached to. `RenewalService.process_renewal` charges the plan's full
`base_price` on every subsequent renewal; it never re-applies
`Subscription.applied_coupon_id`'s discount.

This mirrors the most common real-world coupon semantics ("50% off your
first month", not "50% off forever") and was chosen over recurring
re-application for two concrete reasons:

1. Recurring application raises a second, harder correctness question
   this spec never resolves: does a recurring discount count against
   `max_uses` once per subscription or once per renewal, and what
   happens to an in-flight recurring discount if the coupon is later
   deactivated? Neither has a defensible answer without inventing new
   product policy beyond this part's scope.
2. `CouponUsage` (one row per redemption, `discount_amount_applied`
   frozen at the moment of use) models a single, discrete event cleanly.
   A recurring discount would need an entirely different, ongoing
   "active discount" concept this part does not build.

`Subscription.applied_coupon_id` is kept purely for attribution/
reporting ("which coupon led to this subscription"), never as a live,
re-evaluated discount source.

## §18. Coupon `applicable_plan_ids` storage: a real join table, not JSONB

The spec's own suggested shape was a nullable JSONB list of plan UUIDs on
`Coupon`. This part instead uses a real join table, `CouponPlan`
(`coupon_id`, `plan_id`, unique together) -- the identical "typed,
referentially-integral columns over an untyped blob" judgment call
`PlanFeature` (§2 above) already makes for this same domain. A JSONB list
cannot be declared as a real foreign key (a plan referenced by a coupon
could later be hard-deleted with zero database-level protection), and
"does this coupon apply to plan X" would be an un-indexable JSON-path
query instead of a plain, indexed join. An empty/no-rows `CouponPlan` set
for a coupon means "applicable to all plans" -- the same "empty ==
unrestricted" semantics the spec's own JSONB suggestion described, just
enforced with real referential integrity.

## §19. Flat-discount clamp + atomic `current_uses` increment

**`validators.compute_discount_amount`**: `PERCENTAGE` ->
`base_amount * discount_value / 100`; `FLAT` -> `min(discount_value,
base_amount)`. The clamp is the real, important correctness detail the
spec calls out explicitly -- a flat discount larger than the charge
itself must never make the charge negative.

**`CouponRepository.increment_current_uses`**: a single, real, server-
evaluated `UPDATE coupons SET current_uses = current_uses + 1 WHERE id =
:id` (via SQLAlchemy's `update().values(current_uses=Coupon.current_uses
+ 1)`), never a read-`current_uses`-then-write-`value + 1` round trip in
Python. The latter would race under concurrent redemptions of the same
coupon (two requests could both read `current_uses=4` and both write
back `5`, silently losing one redemption's count); Postgres evaluates the
`SET` clause's right-hand side against the row's *current* value at
update time, making this a single atomic operation regardless of
concurrent callers. `CouponService.apply_coupon` calls this method
directly -- it never computes the increment itself.

## §20. Beat schedule interval: hourly

`billing-subscription-renewal-sweep` runs every 3600 seconds (see
`constants.SUBSCRIPTION_RENEWAL_SWEEP_INTERVAL_SECONDS`). Every billing
period this domain models is day/month/year granularity
(`BillingCycle`), so checking every 15 minutes (Analytics' own
near-real-time dashboard cadence) would mean dozens of no-op sweeps for
every one that actually finds a due subscription, for no freshness
benefit any real billing workflow needs. An hourly sweep still renews
every subscription within an hour of its `current_period_end`, expires a
lapsed grace period the same day it lapses, and sends both reminder
kinds well within their own multi-day windows -- the same reasoning
`app.domains.analytics.report_tasks`'s own hourly scheduler documents for
an identical "coarsest unit is a day" situation.

## §21. Reminder emails: reused `EmailProviderProtocol`, two real idempotency columns

Renewal/expiry reminders reuse `app.domains.otp`'s
`EmailProviderProtocol`/`LoggingEmailProvider` exactly as specified -- no
second email abstraction. `RenewalService.send_renewal_reminders`/
`send_expiry_reminders` need one thing beyond the literal spec's
`Subscription` column list to be honestly correct: an hourly sweep would
otherwise re-send the same reminder on every tick for its entire
multi-day window. `Subscription.last_renewal_reminder_sent_at`/
`last_expiry_reminder_sent_at` (additive columns, mirroring
`ScheduledReport.last_run_at`'s identical "a periodic sweep needs its own
bookkeeping" reasoning) make each reminder fire exactly once per billing
period / per past-due episode. A third additive column,
`Subscription.past_due_at`, is what makes the grace-period computation
(§16) and the expiry-reminder window computation possible at all -- "how
long has this subscription been unpaid" has no other real source.
`RenewalReminderSent`/`ExpiryReminderSent` events are logged (not
audited, mirroring every other domain's "reads/notifications aren't
audited" convention) on every real send.

---

# BE-013 Part 3: Payment Service + Real Stripe/Razorpay Integration + Webhooks

## Honesty framing (read this first)

There are no real Stripe/Razorpay API keys or test credentials anywhere in
this sandbox, and there never will be -- neither gateway can make a real
network call to either provider's live/sandbox API and get a real response
back, in this environment. What *is* real: `stripe`==15.3.1/`razorpay`==2.0.1
are the official, installable Python SDKs (added to `requirements.txt`/
`pyproject.toml`), and every request shape this part writes against them
(parameter names, units, idempotency handling, exception types, the exact
webhook-signature-verification scheme) was verified by introspecting the
*installed* packages' own source directly while writing this code -- not
recalled from memory. `Settings.stripe_secret_key`/`razorpay_key_id`/
`razorpay_key_secret`/`*_webhook_secret` all default to empty strings; when
empty (as they always are here), `payment_gateways.StripePaymentGateway`/
`RazorpayPaymentGateway` raise Part 2's exact
`exceptions.PaymentGatewayNotConfiguredError` before any network attempt --
reused verbatim, never a parallel exception. Webhook **signature
verification**, in contrast, is pure, deterministic HMAC-SHA256
cryptography that needs no live API access at all -- it is implemented and
tested for real, end to end, against real HMAC fixtures this codebase's own
test suite computes the same way each provider actually does it.

## §22. Idempotency-key enforcement mechanism: real, DB-unique-constraint-backed

`models.Payment.idempotency_key` is **unique, not nullable**. This is the
actual enforcement mechanism, not a comment:

1. `service.PaymentService.initiate_payment` checks
   `PaymentRepository.get_by_idempotency_key(key)` first -- the fast path
   for the overwhelming majority of calls (no concurrent racer).
2. If two concurrent requests both pass that check before either commits
   (a genuine race), the *second* `INSERT` collides with the real database
   unique constraint. `GenericRepository._flush_or_raise` (unmodified,
   Part 1's own infrastructure) translates that into
   `app.database.exceptions.DuplicateRecordError` exactly the way it
   already does for every other unique column in this codebase.
3. `PaymentService.initiate_payment` catches exactly that exception, re-reads
   by `idempotency_key`, and returns the *winning* row -- never a second
   charge attempt, never a raised error the caller has to handle specially.

The same `idempotency_key` presented twice therefore **always** resolves to
the same `Payment` row, enforced at the database level -- proven in
`tests/unit/test_billing_payments_webhooks.py::TestPaymentIdempotency
.test_concurrent_race_is_resolved_by_the_real_db_constraint`, which forces
exactly this race (a `FakeRacyPaymentRepository` whose first
`get_by_idempotency_key` lookup reports "not found" even though the row
already exists, combined with a real duplicate-detecting `create_payment`)
and asserts the gateway is never invoked a second time.

The narrow `renewal_service.PaymentGatewayProtocol.charge()` seam method
(no `idempotency_key` parameter in its signature -- it cannot change, see
§15) generates its own key internally
(`f"renewal:{subscription_id}:{uuid4().hex}"`) each call -- a fresh value
per invocation is *correct* here, not a gap: each `process_renewal` call is
a genuinely new billing event (a new period), so there is no "same logical
attempt, retry with the same key" concept for this specific seam the way
there is for the explicit, caller-driven `POST /payments` (which threads a
real, caller-supplied key straight through).

## §23. Webhook signature verification -- exact real schemes

Both implemented in `webhooks.py`, verified directly against the source of
the installed SDKs (not recalled from memory):

* **Stripe** (`verify_stripe_event`) -- uses the real, installed `stripe`
  SDK's `stripe.Webhook.construct_event` (`stripe._webhook
  .WebhookSignature.verify_header`'s source was read directly while writing
  this module). The `Stripe-Signature` header is
  `t=<unix-timestamp>,v1=<hex-hmac>[,v0=<hex-hmac>...]`; the *signed
  payload* is `f"{timestamp}.{raw_body}"`; the expected signature is
  `hmac.new(secret.encode(), signed_payload.encode(), sha256).hexdigest()`;
  comparison against every `v1=` value uses a constant-time compare
  (`hmac.compare_digest`); a request whose timestamp is older than
  `tolerance` seconds (default 300, `Settings.stripe_webhook_tolerance_seconds`)
  is rejected as a replay. Using the SDK's own real implementation directly
  (rather than a hand-rolled reimplementation that could subtly drift from
  it over time) was judged the more honest, more correct choice.
* **Razorpay** (`verify_razorpay_signature`) -- uses the real, installed
  `razorpay` SDK's `razorpay.Utility.verify_webhook_signature` (source read
  directly: `hmac.new(secret.encode(), raw_body.encode(), sha256).hexdigest()`,
  compared via `hmac.compare_digest` against the `X-Razorpay-Signature`
  header). Razorpay's real webhook scheme has **no** timestamp/replay-
  tolerance component at all (confirmed against the installed SDK -- there
  is simply none to check), so none is invented here.

Both are tested in `tests/unit/test_billing_payments_webhooks.py` against
real HMAC fixtures the test file computes independently (its own
`_stripe_signature_header`/`_razorpay_signature_header` helpers, not a call
into the module under test) -- valid signature accepted, tampered payload
rejected, wrong secret rejected, garbage signature rejected, and (Stripe
only, since Razorpay's scheme has none) an expired timestamp rejected.

## §24. Webhook event-id dedup: Redis + TTL, not a dedicated table

Both providers really do redeliver the same webhook event more than once
(timeout, an ambiguous `2xx`, a manual "resend" from either dashboard) --
webhook handlers must be idempotent themselves. `webhooks
.RedisWebhookEventDedup.mark_processed_if_new` tracks processed
`(provider, event_id)` pairs in Redis (reusing, never modifying,
`app.database.redis.get_redis_client` -- the same Redis instance every
other domain's own caching already uses) via a single atomic
`SET key value NX EX ttl`: the first delivery sets the key and proceeds;
every redelivery finds the key already set and is a no-op. `Settings
.payment_webhook_event_dedup_ttl_seconds` (default 7 days) is used rather
than a permanent record because (1) both providers' own real
redelivery/retry windows are measured in hours to a few days, not forever,
so a multi-day TTL comfortably covers every real redelivery without an
ever-growing key set, and (2) a dedicated `processed_webhook_events` table
would need its own migration and its own cleanup sweep to avoid unbounded
growth, buying no correctness a single atomic Redis command doesn't already
provide -- the same "simplest real mechanism, no new table for its own
sake" judgment call `events.py`'s own "no event bus" decision already makes
elsewhere in this domain. A dedicated table (unique constraint on
`(provider, event_id)`) was a real, legitimate alternative, equally atomic;
Redis was chosen for the free TTL-based cleanup alone.

## §25. Refund/retry idempotency-key strategy -- differs by provider, on purpose

`retry_failed_payment` re-attempts a charge for a `FAILED` `Payment`,
**reusing the same row** (this part's own "Payment doubles as history"
decision, §27) -- but what wire-level idempotency key each provider's SDK
call receives differs, deliberately:

* **Stripe** -- a **fresh, derived** key
  (`validators.derive_retry_idempotency_key`, `f"{original}:retry:{uuid4}"`).
  This is Stripe's own real, documented guidance: reusing an idempotency
  key returns the *cached* result of the original request, including a
  genuine decline, for a real window (currently 24h) -- resubmitting the
  same key for an intentional retry (e.g. after the customer updated their
  card) would silently just return the old decline again, never actually
  attempting a new charge.
* **Razorpay** -- moot at the wire level. The installed `razorpay` SDK's
  `Payment.createRecurring`/`Order.create`/`Payment.refund` resources
  expose **no** client-supplied idempotency parameter at all (confirmed by
  introspecting `razorpay.resources.Payment`/`Order` directly) -- so a
  retry is unconditionally a fresh provider-side attempt regardless of any
  key. All of this provider's idempotency protection is therefore enforced
  at this module's own `Payment.idempotency_key` unique-constraint level,
  not at Stripe's kind of SDK-native, provider-side deduplication.

Either way, `Payment.idempotency_key` **the column** never changes across a
retry -- it is this row's own permanent identity (the caller-facing "same
key -> same row" guarantee), not a per-attempt value. Only the value handed
to Stripe's own SDK call changes.

## §26. Both real gateways preserve the zero-amount auto-success shortcut

`renewal_service.UnconfiguredPaymentGateway.charge` auto-succeeds a
zero-(or negative-)amount charge with no configuration check at all (a
`FREE_TRIAL` renewal, or any plan whose `base_price` is genuinely `0`,
needs no real payment processor). `StripePaymentGateway`/
`RazorpayPaymentGateway.charge` preserve this **exact** short-circuit,
before even checking `_is_configured`. This is not cosmetic: a `TRIALING`
subscription on a cyclic (`MONTHLY`/`YEARLY`) billing cycle can reach
`process_renewal` via the hourly sweep before its trial ever converts to a
real paid plan, and it must not start raising
`PaymentGatewayNotConfiguredError` for a genuinely free renewal just
because Part 3 wired in a real (but still-unconfigured, in this sandbox)
gateway in place of Part 2's honest placeholder. Tested directly in
`TestGatewayNotConfigured.test_zero_amount_charge_auto_succeeds_even_when_not_configured`.

## §27. `Payment` doubles as "Payment History" -- a query surface, not a second table

The spec asks for both a `Payment` model and a "Payment History" surface.
This module builds exactly one table: every `Payment` row is already a
permanent, timestamped, status-tracked record of one charge attempt
(created once, mutated only by its own real lifecycle -- refund status/
retry -- never deleted). "Payment history" is simply
`PaymentRepository.list_payments(organization_id=...)` ordered by
`created_at` -- the identical "a query surface over existing rows, not a
second table" judgment call `UsageMetric`/`LicenseChangeLog` already
establish elsewhere in this domain for their own read surfaces. A second,
append-only `PaymentHistory` table would either duplicate every column
`Payment` already has, or need its own synchronization logic to stay
current -- neither buys anything a single, real, well-indexed table
doesn't already provide.

## §28. `PaymentMethod`: token-only storage, never raw card data

`PaymentMethod.provider_payment_method_id` is the provider's own opaque
token (e.g. a Stripe `pm_...` id, or a Razorpay saved-card token id) -- this
table stores only what the provider hands back after its own (client-side,
PCI-scoped) tokenization flow. Nowhere in this module -- models, schemas,
service, gateways -- does any code path accept, parse, log, or persist a
raw card number, CVV, or expiry date; the closest thing to a "look at the
card" field is `last4` (nullable, display-only, never used in any charge
decision). `is_default` is enforced as **at most one per organization** by
`PaymentMethodRepository.set_as_default` (a real, atomic
`UPDATE ... WHERE organization_id = :id` unsetting every sibling before
setting the target, mirroring `CouponRepository.increment_current_uses`'s
own "real statement, not a read-then-write-in-Python race" discipline).

A documented, honest scope simplification: neither `PaymentMethod` nor any
other model in this part persists a separate provider-side Customer object
id (a Stripe `cus_...`, or the equivalent Razorpay customer concept) that a
saved token is attached to -- BE-013's own column list for `PaymentMethod`
does not include one, and this part does not invent one out of scope (see
`payment_gateways.py`'s own module docstring for the full write-up). Both
gateways pass the stored token directly to their real charge APIs, which is
a valid call shape either provider's API accepts, though a fully mature
production rollout would typically also persist and pass a Customer id.
Neither code path is ever actually exercised end to end in this sandbox
regardless, since `_is_configured` always short-circuits first.

## §29. Provider-selection model: one platform-wide default

`dependencies.build_payment_gateway` selects Stripe vs. Razorpay via a
single `Settings.payment_default_provider` -- not a per-organization or
per-plan choice. Neither `Organization` nor `Plan` carries any "preferred
payment provider" column today, and inventing one now, with no real
multi-provider deployment to justify it and no way to actually exercise a
per-org routing decision against real credentials in this sandbox anyway,
would be speculative scope beyond what this part asks for. A future part
could add a nullable `Organization.preferred_payment_provider` (or similar)
and `build_payment_gateway` would become the one place that reads it -- the
seam is already isolated there for exactly that reason.

## §30. Wiring the seam for real -- `get_payment_gateway`, and the Celery-task gotcha

Part 2 explicitly deferred one function's body: `dependencies
.get_payment_gateway`. This part replaces it -- but not by simply changing
that one function's return value, because `tasks.py`'s Celery bridge calls
`get_payment_gateway` **directly** (`payment_gateway=get_payment_gateway()`
in the original Part 2 code), not through FastAPI's dependency-injection
container. If `get_payment_gateway`'s parameters needed real, resolved
`AsyncSession`/`Settings` objects (which building a real gateway does), a
bare call with no arguments from plain Celery-task Python code would pass
`fastapi.params.Depends` *instances* themselves as if they were real
values -- silently wrong, not an error. The fix: a new, plain,
DI-framework-free function, `dependencies.build_payment_gateway(*, db,
settings)`, holds the actual provider-selection logic; `get_payment_gateway`
is now a thin FastAPI-dependency wrapper around it (its own parameters
still default to `Depends(get_db_session)`/`Depends(get_settings)`, but only
ever resolved by FastAPI itself), and `tasks.py` was updated to call
`build_payment_gateway(db=session, settings=settings)` directly with its own
already-open session/settings, explicitly. Since no real API key is ever
actually configured in this sandbox, both concrete gateways' own
`_is_configured` guard means the platform's real, observed behavior is
byte-for-byte unchanged from Part 2's `UnconfiguredPaymentGateway` in
practice -- this is the entire "wire it in for real" step Part 2 deferred.

## §31. A genuine circular-import fix: a locally-defined Protocol, not a shared import

`service.py` needed a narrow, structural type for the richer surface
`PaymentService` calls on each gateway (`charge_via_provider`/`refund`/
`retry`) -- `payment_gateways.PaymentGatewayAdminProtocol` already defines
exactly this. Importing it directly into `service.py`, however, closes a
real import cycle: `payment_gateways.py` imports
`renewal_service.PaymentGatewayProtocol`, and `renewal_service.py` imports
this module's own `LicenseLifecycleProtocol`/`AuditLogWriter` from
`service.py`. The fix mirrors this codebase's own established precedent
for the identical shape of problem (`service.LicenseLifecycleProtocol`'s
own docstring, written by Part 2, already explains this exact "avoid a
construction cycle / keep the dependency structural" reasoning for the
`SubscriptionService` <-> `LicenseService` relationship): `service.py`
defines its own local `PaymentGatewayAdminProtocol` (same method
signatures, same name, zero import from `payment_gateways.py`) that both
concrete gateway classes already satisfy structurally, since Python
`Protocol`s are duck-typed. No behavior changed; only where the type is
*defined* changed.

## §32. RBAC permission-key reuse (Part 3)

No new `PermissionModule`. Payments/Payment Methods reuse `billing.*`
exactly like Plans/Coupons/Usage before them: `billing.manage` for every
write with no dedicated seeded action (initiate/refund/retry a payment,
register/remove a payment method), `billing.read` for every read. Unlike
Plans/Coupons (a platform-wide pricing catalog, pinned to
`scope=ScopeType.GLOBAL`), a `Payment`/`PaymentMethod` is a real,
tenant-owned resource (`organization_id` on every row) -- ordinary
inferred, tenant-scoped resolution applies, exactly like Licenses/
Subscriptions. `GET /payments`/`GET /payments/{id}` additionally enforce
real tenant isolation in the service layer
(`PaymentService.get_payment`'s `organization_id` filter) -- a payment
belonging to a different organization reports as not-found, never leaking
its existence (tested in `TestTenantIsolation`). Webhook endpoints are
provider-authenticated via real signature verification, **not** RBAC -- the
identical "no platform-user identity for this caller" reasoning BE-008's
device check-in and BE-010's RADIUS endpoints already establish.

## §33. Webhook response shape: plain dict, not the standard `ApiResponse` envelope

`POST /webhooks/stripe`/`POST /webhooks/razorpay` return a plain
`{"received": True}` dict on success (status `200`), not this codebase's
usual `ApiResponse`/`build_response` envelope -- neither provider parses
the response body at all, only the status code, and this is exactly the
minimal shape Stripe's own documented webhook-handler examples return. An
invalid signature raises `exceptions.WebhookSignatureInvalidError` (a real
`CloudGuestError`, `400`) rendered through the same global exception
handler every other domain's errors already go through -- there is no
reason for this one error case to bypass that uniform machinery just
because the success path is unwrapped. Any *other* unhandled exception
during processing propagates to a `500` -- deliberate: both providers' own
real retry policies re-deliver on a `5xx`, which is exactly right for a
genuine, possibly-transient internal failure (a database blip), whereas a
permanently-invalid signature (`400`) is correctly never retried into
succeeding.

## §34. Webhook-confirms-a-renewal composition -- two small, additive `RenewalService` methods

The spec asks for a succeeded webhook payment tied to a subscription
renewal to trigger `RenewalService`'s existing renewal-success path. Since
`renewal_service.RenewalService._mark_renewed`/`_mark_past_due` (Part 2,
unmodified) are private, this part adds exactly two small, additive public
methods to `RenewalService` --
`confirm_renewal_payment_succeeded`/`confirm_renewal_payment_failed` --
that do nothing but resolve the `Subscription`/`Plan` and call those same
existing private methods. No period-extension/past-due bookkeeping is
reimplemented anywhere in `webhooks.py`. Proven in
`TestWebhookRenewalComposition`, which drives a real `RenewalService`
(wired to fake repositories, exactly like Part 2's own test file) through
`webhooks.process_stripe_event`/`process_razorpay_event` and asserts the
subscription's real state transition (`PAST_DUE` -> `ACTIVE`, period
extended; or `PAST_DUE` with a fresh `past_due_at`) -- the exact same
transition `process_renewal`'s own synchronous path already produces.

This composition point exists because a real Stripe charge is not always
synchronous: an off-session renewal charge can require additional
authentication (SCA/3-D Secure) and only resolve asynchronously via a
later `payment_intent.succeeded`/`payment_intent.payment_failed` webhook.
`StripePaymentGateway`/`RazorpayPaymentGateway`'s own charge path leaves
such an intermediate-status `Payment` row `PENDING` (never fabricating a
final outcome); the corresponding webhook, once it arrives, is what
resolves it.

---

# Billing (BE-013 Part 4): Invoice Engine + Tax/GST -- Design Decisions

## §35. Part 4 overview

Six new tables (`tax_rates`, `billing_profiles`, `invoice_number_counters`,
`invoices`, `invoice_items`, `credit_debit_notes`; migration
`0025_create_billing_invoice_tax_tables.py`), three new modules
(`number_generator.py`, `invoice_pdf.py`, plus additions to every existing
module), three new services (`TaxRateService`, `BillingProfileService`,
`InvoiceService`), and a new `/invoices`/`/billing/tax-rates`/
`/billing/profile` API surface. The real, driving requirement this part
answers: an invoice is not a second, independent computation of "what does
this organization owe" -- it is a legal/financial *record* of the exact
same charge Parts 2/3's renewal engine already computes and (attempts to)
collect, with a real, India-specific GST tax rule applied on top.

## §36. Billing address/GSTIN storage: a new, billing-owned `BillingProfile`
## table -- not an `Organization` column extension

Two real candidates were considered for where an organization's billing
address/GSTIN should live:

1. A narrow, additive extension to `Organization` itself -- the same class
   of exception Part 1's own `subscription_tier` sync already established
   as acceptable ("this module's entire purpose is to give a reserved
   concept real meaning").
2. A new, purely-billing-owned table (`BillingProfile`) keyed to
   `organization_id`, entirely inside `app.domains.billing`.

This part chooses (2), and the distinguishing factor from Part 1's own
precedent is concrete: `subscription_tier` has *multiple* real readers
across this codebase (Analytics' own Plan Distribution `GROUP BY`,
potentially other future consumers) -- it is a genuinely shared,
cross-domain concept that happens to be populated by Billing. A billing
address/GSTIN has **exactly one** consumer anywhere in this codebase:
this domain's own invoice generation and PDF rendering. Adding five-plus
columns to `Organization` for a concept only Billing ever reads would
widen that table's surface for zero benefit any other domain needs, and
would require editing `organization`'s own `models.py`/migration/schemas --
a real cross-domain boundary crossing this part's own directory rule
explicitly minimizes to begin with. `BillingProfile` keeps 100% of this
concept's read/write surface inside `app.domains.billing`, the identical
"don't touch other domains' internals" discipline this codebase enforces
everywhere else. One row per organization, ever (`organization_id`
unique) -- mirrors `License`/`Subscription`'s identical one-to-one,
mutated-in-place cardinality; a superseded billing address has no
standalone historical value once updated (what *does* need preserving is
a historical invoice's own frozen copy of it -- see §41).

## §37. Invoice number generator: the real, DB-level-atomic concurrency
## mechanism

**The bug class avoided:** generating the next sequential number via
`SELECT MAX(sequence) + 1 FROM ...; INSERT ...` (or the identical
application-level pattern: read a "current count" into Python, increment
it there, write it back) is a real, well-known race. Two concurrent
requests can both execute the read before either commits its own write,
both observe the same "current" value, both compute the same "next"
value, and both persist a row with the identical number.

**This module's real mechanism:** `models.InvoiceNumberCounter` has a
unique `counter_key` column (`"<document_type>:<year>"`, e.g.
`"invoice:2026"`). `repository.NumberCounterRepository
.increment_and_get_next` issues **exactly one** SQL statement per call --
`INSERT ... ON CONFLICT (counter_key) DO UPDATE SET last_value =
invoice_number_counters.last_value + 1 ... RETURNING last_value`, via
SQLAlchemy's `postgresql.insert(...).on_conflict_do_update(...)`. This is
genuinely safe under concurrency, not merely apparently so, for two
concrete reasons:

1. **No read-then-write round trip from the application at all** -- the
   increment is computed by Postgres itself, evaluating the `SET` clause
   against the row's value *at the instant the statement executes*. There
   is no intervening moment where this module's own Python code could
   observe a stale value.
2. **Postgres serializes concurrent UPSERTs targeting the same row** -- a
   second transaction's `INSERT ... ON CONFLICT` against the same
   `counter_key` blocks on the first transaction's row lock until it
   commits or rolls back, then proceeds against the now-updated value.
   Two concurrent callers can never observe the same "before" value and
   therefore can never generate the same "next" number. This is the exact
   same class of guarantee `CouponRepository.increment_current_uses`'s own
   `UPDATE ... SET current_uses = current_uses + 1` already relies on for
   this domain's coupon-redemption counter -- the only difference here is
   the `ON CONFLICT` branch, needed because a brand-new calendar year's
   counter row does not exist yet the first time it is requested.

`counter_key` includes the calendar year, so each document type's own
sequence resets to 1 at the start of a new year (a real, common invoicing
convention); credit notes and debit notes each get their own,
entirely independent counter key -- never the invoice sequence, never
each other's.

`test_billing_invoices_tax.py`'s `TestInvoiceNumberGeneratorConcurrency`
tests this for real: 25 concurrent `generate_invoice_number` calls via
`asyncio.gather` against a fake repository whose own
`increment_and_get_next` holds an `asyncio.Lock` across a genuine
`await asyncio.sleep(0)` yield point (deliberately proving the lock does
real serialization work, not merely "no `await` happened to occur between
the read and the write" -- which would trivially pass under Python's
single-threaded cooperative scheduling even with zero real protection)
must, and does, produce 25 entirely distinct numbers.

## §38. `compute_renewal_charge_amount` relocated to `validators.py` --
## composition without an import cycle

The spec requires invoice generation to reuse -- never recompute -- the
exact real charge amount a subscription renewal would actually bill. That
computation (`plan.base_price`) was first written inline inside
`renewal_service.process_renewal`, then briefly factored into a named
function still living in `renewal_service.py`. That placement caused a
real import cycle once `service.InvoiceService` needed to call it:
`renewal_service.py` already imports `service.AuditLogWriter`/
`LicenseLifecycleProtocol`, so a second, reverse edge (`service.py`
importing from `renewal_service.py`) would close a genuine cycle.

The fix: `compute_renewal_charge_amount` now lives in `validators.py` --
a pure, side-effect-free, "depends on nothing else in this domain" module
by its own established discipline, which neither `service.py` nor
`renewal_service.py` need to avoid importing from. `renewal_service.py`
imports it from `.validators` (and re-exports it in its own `__all__` for
any caller still expecting to find it there); `service.py` imports the
identical function the same way. `RenewalService.process_renewal`/
`confirm_renewal_payment_succeeded` and `InvoiceService
.generate_invoice_for_subscription` therefore all call the exact same
function -- proven in `TestInvoiceGenerationComposesRenewalAmount` via a
`unittest.mock.patch` spy on `app.domains.billing.service
.compute_renewal_charge_amount`, asserting it is actually invoked with the
real `Plan` row, never independently reimplemented.

## §39. The real CGST/SGST/IGST rule + platform home-jurisdiction config

India's GST law splits a transaction's tax in exactly one of two ways,
determined by comparing the **seller's** (this platform's own) registered
jurisdiction against the **buyer's** (the organization's own
`BillingProfile`) billing jurisdiction:

* **Intra-state** (same state, same country) -- the total rate splits into
  two *equal* halves: `CGST` (Central GST) + `SGST` (State GST), each
  exactly `rate_percentage / 2`. `IGST` is zero.
* **Inter-state** (different state, or a different country entirely -- a
  different country is always inter-state, checked first) -- the *entire*
  rate is charged as one `IGST` (Integrated GST) line; `CGST`/`SGST` are
  both zero.

`validators.compute_tax_breakdown` implements this exactly (see its own
docstring). The platform's own registered jurisdiction is a plain,
documented pair of `Settings` fields -- `platform_gst_state` (default
`"Maharashtra"`) and `platform_gst_country` (default `"IN"`) -- modeled as
Settings, not a config table, because there is exactly one "home
jurisdiction" for this platform at any given time (the same "a plain,
documented Settings field, never a hardcoded magic number" pattern every
other tunable in `config.py` already follows). `platform_gstin`/
`platform_legal_business_name` are cosmetic-only fields shown on the
invoice PDF's seller line; they gate no computation.

Non-GST tax types (`VAT`/`SALES_TAX`) have no CGST/SGST/IGST concept at
all -- `compute_tax_breakdown` applies a flat, single-amount computation
for those instead (populates only `tax_amount`). `TaxType.NONE`,
`tax_exempt=True`, a non-positive `rate_percentage`, or no active
`TaxRate` configured for the organization's billing country all
short-circuit to an honest all-zero result -- never a fabricated non-zero
charge.

## §40. Tax breakdown storage shape: three typed columns, not a separate
## `InvoiceTaxLine` table

India's GST regime has **exactly** three possible tax-line components for
any one invoice -- CGST/SGST (intra-state) or IGST (inter-state) -- never
more, never a variable-length list the way e.g. US sales tax across many
overlapping local jurisdictions might need. Given that closed, fixed
shape, `models.Invoice` makes the identical judgment call `PlanFeature`'s
own docstring already makes for this domain ("three typed columns, not
one JSONB blob"): `cgst_amount`/`sgst_amount`/`igst_amount` are three
plain, precisely-typed `Numeric` columns -- directly queryable, summable,
indexable -- with exactly the legal subset populated per
`compute_tax_breakdown`'s own rule. A separate `InvoiceTaxLine` table (one
row per tax component) was a real, legitimate alternative -- rejected
because it would model a *variable-cardinality* concept for a domain
where this part only ever produces at most 2 populated components per
invoice, at a fixed, known set of names; the extra join buys no real
flexibility this part's own scope needs. `tax_amount` is the universal
total (`cgst_amount + sgst_amount + igst_amount` for GST; the flat
computed value for VAT/SALES_TAX) so every caller has one column to read
regardless of tax regime; `tax_rate_percentage` freezes the total rate
actually applied (see §41 for why).

## §41. `billing_snapshot`: a frozen copy, not a live reference

`Invoice.billing_snapshot` (JSONB) is a plain-dict copy of the
organization's `BillingProfile` fields **at the moment the invoice was
issued** -- never re-read from `BillingProfile` afterward.
`tax_rate_percentage` is frozen the same way, for the identical reason.
This is the same "copy, not reference" principle already established
repeatedly in this codebase: `guest`'s voucher-derived session quotas
frozen at redemption time, `monitoring.Alert.severity` copied at trigger
time, `CouponUsage.discount_amount_applied` frozen at redemption time,
this domain's own `Subscription.billing_cycle` snapshot-copied from `Plan`
at subscription-creation time. If a customer later updates their billing
address/GSTIN, every invoice already issued must keep showing the address
it was legally issued against -- a real, non-negotiable requirement for
any financial/legal document. `TestBillingSnapshotFrozenAtIssueTime`
proves this directly: it generates an invoice, mutates the organization's
`BillingProfile` afterward, and asserts the already-issued invoice's own
`billing_snapshot` is completely unaffected.

## §42. Payment-webhook-to-invoice composition

The spec asks for a successful payment to trigger invoice generation/
marking-paid. This part's actual composition, precisely: `webhooks.py`'s
existing `process_stripe_event`/`process_razorpay_event` handlers gained
one new, optional keyword parameter, `invoice_service:
InvoiceServiceProtocol | None = None` (defaulting to `None` -- an
entirely backward-compatible, additive change; every existing caller/test
that omits it observes byte-for-byte the same behavior these handlers had
before Part 4). When a real success is resolved
(`payment_intent.succeeded`/`payment.captured`) and `invoice_service` is
supplied (the real, wired case, via `router.py`'s own
`get_invoice_service` dependency), the handler calls
`invoice_service.mark_invoice_paid_for_payment(payment)` -- a single,
narrow, additive `InvoiceService` method that finds the most recently
issued unpaid (`ISSUED`/`OVERDUE`) invoice for the payment's own
`subscription_id` and marks it `PAID` via the exact same
`mark_invoice_paid` transition a manual reconciliation would use. A
payment with no `subscription_id`, or no matching unpaid invoice, is a
safe, deliberate no-op (`None` returned) -- a real payment not tied to any
invoice (e.g. a manual, standalone `POST /payments` charge) is a
legitimate outcome, never an error. No period-extension/past-due
bookkeeping, and no new payment-side reimplementation of "what does a
successful payment mean," is added anywhere -- this is a pure, additive
composition, mirroring `RenewalService.confirm_renewal_payment_succeeded`'s
own identical shape from Part 3.

## §43. Invoice PDF: a dedicated `reportlab` renderer, not the generic
## analytics report renderer

`app.domains.analytics.export.render_report`/`_render_pdf` (BE-012 Part 5)
already builds real PDFs via `reportlab`'s `platypus` layout engine, and
was evaluated for direct reuse before writing `invoice_pdf.py`. The
conclusion: build a **dedicated** invoice PDF renderer using the same
`reportlab`/`platypus` primitives, not the generic report renderer --

* `export._render_pdf` is intentionally generic/flexible: it walks an
  arbitrary, variable-shaped `ReportPayload` tree (any number of sections,
  each with free-form scalar fields and tabular blocks) with no fixed
  layout contract -- exactly right for a dashboard-style analytics export
  where the *set of sections itself* varies by report type.
* An invoice is the opposite: a rigid, legally/commercially defined
  document with a **fixed** set of required elements in a **fixed** order
  (seller/buyer header, dated line-item table, a tax breakdown that must
  show CGST/SGST/IGST as separate, clearly labeled lines -- never a lumped
  generic "tax" row -- then totals, then a footer). Coercing that fixed
  shape through `ReportPayload`/`ReportSection`'s generic convention would
  fight the very rigidity a real invoice needs, and would still require
  post-processing/relabeling those generic blocks to get GST-compliant
  labeling anyway -- at which point nothing would actually be saved.

What *is* reused, directly, without modification: the same installed
`reportlab` package (no new dependency), the same `platypus` primitives
(`SimpleDocTemplate`/`Paragraph`/`Table`/`TableStyle`/`Spacer`), the same
`A4`/`cm` page-geometry constants, and the same `getSampleStyleSheet()`
base styles `export.py` already uses. `invoice_pdf.render_invoice_pdf`
is verified for real in `test_billing_invoices_tax.py`'s
`TestInvoicePdfGeneration` -- the `%PDF` magic header, the `%%EOF`
trailer, a real non-trivial byte length, and (best-effort) that CGST/SGST
text actually appears in the rendered stream -- the identical rigor
BE-012 Part 5's own PDF export tests already establish.

## §44. RBAC permission-key reuse (Part 4)

No new `PermissionModule` for tax rates or the billing profile --
`/billing/tax-rates` and `/billing/profile` reuse `billing.*` exactly like
Plans/Coupons/Payments before them: tax rates are a platform-wide pricing/
tax catalog concern, so writes are pinned to `scope=ScopeType.GLOBAL`
(mirrors Plans/Coupons); the billing profile is a real, tenant-owned
resource, so ordinary inferred scope applies (mirrors Payments/
PaymentMethods), with `billing.update` for the upsert and `billing.read`
for both `GET /billing/profile/me` and `GET /billing/profile/{organization_id}`.
`/invoices` reuses `PermissionModule.INVOICES` -- seeded since BE-004 with
exactly the seven actions this part needs (`create`/`read`/`update`/
`delete`/`export`/`approve`/`manage`): `invoices.read` for every read
(including the PDF download, which is fundamentally an export of an
already-generated invoice, mapped onto the seeded `invoices.export`
action precisely); `invoices.manage` for every consequential financial
write (void, credit note, debit note) -- the same "reuse the closest
seeded action for a consequential write" precedent Payments' own refund/
retry already established via `billing.manage`. None of the mutating
`/invoices` endpoints enforce tenant-organization matching against the
caller's own scope context (mirrors `POST /payments/{id}/refund`/
`retry`'s identical "an admin action operating directly on the entity by
id" precedent) -- only the read-side `GET /invoices`/`GET /invoices/{id}`
enforce real tenant isolation, via `RequireOrganization` + the service
layer's own `organization_id` filter (`TestTenantIsolation`).

## §45. Invoice overdue sweep: real, working, but not yet Beat-registered

`OVERDUE` is a real, first-class `InvoiceStatus` member, and
`InvoiceService.mark_overdue_invoices` (backing the Celery task
`tasks.run_invoice_overdue_sweep`) is a real, fully working, independently
callable implementation -- every `ISSUED` invoice whose `due_date` has
passed transitions to `OVERDUE`, with real per-invoice failure isolation
mirroring `RenewalService.process_due_renewals`'s identical resilience
pattern. What this part deliberately does **not** do is register that
task in `app.core.celery_app`'s `beat_schedule` -- doing so requires
editing `app/core/celery_app.py`, a file outside this Part's own
directory-rule boundary (only `app/domains/billing/`, `app/core/config.py`,
`alembic/versions/`, `tests/unit/`, `docs/billing/`, and a few other
explicitly-named files are in scope). This mirrors Part 1's own explicit
"`expire_license` is fully built, tested, and ready for a future part's
Beat schedule to call" deferral -- the real, working code exists and is
tested; only the one-line Beat registration (an addition to
`beat_schedule`, at `Settings.invoice_overdue_sweep_interval_seconds`) is
left to that dedicated, narrow follow-up edit.

## §46. Invoice status transition graph + credit/debit note modeling

`constants.InvoiceStatus`'s full lifecycle -- `DRAFT` (created but never
sent; reachable via a future manual-invoice flow, not yet built) ->
`ISSUED` (this part's own `generate_invoice_for_subscription` issues
directly, skipping `DRAFT` -- it is the real trigger tied to an actual
renewal/charge event) -> `PAID` (terminal from this service's own
perspective -- correcting a paid invoice is done via a `CreditDebitNote`,
never a direct status change) or `OVERDUE` (reversible back to `PAID`) ->
`VOID` (an already-sent invoice formally voided; terminal) or, for a
never-sent `DRAFT`, `CANCELLED` (terminal). `void_invoice` picks the
correct terminal state automatically based on the invoice's current
status (`DRAFT` -> `CANCELLED`; `ISSUED`/`OVERDUE` -> `VOID`) and rejects
voiding an already-`PAID` invoice outright (a real accounting distinction
-- once money has changed hands, the correction path is a credit note,
never a silent void).

`CreditDebitNote` is one table with a `note_type` discriminator
(`constants.NoteType.CREDIT`/`DEBIT`), not two near-duplicate tables --
every other column (`invoice_id`/`amount`/`reason`/`issued_at`/
`note_number`) is identical between a credit note and a debit note; they
differ only in commercial direction (reduces vs. increases what the
customer owes) and in which independent number sequence generates their
own `note_number` (see §37). A credit note's `amount` is additionally
validated against the invoice's own `total_amount` (a credit note can
never credit more than was ever charged) -- a debit note has no such
ceiling (it represents a genuine additional charge). Both are legal only
against an invoice that was actually sent (`ISSUED`/`OVERDUE`/`PAID`) --
never against a `DRAFT`/`CANCELLED`/`VOID` invoice.
