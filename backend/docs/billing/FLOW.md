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
