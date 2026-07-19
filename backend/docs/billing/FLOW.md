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
