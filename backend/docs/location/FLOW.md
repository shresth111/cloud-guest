# Smart Location Provisioning -- Design Write-Up (Module 006 extension)

This document is the full design write-up for Smart Location Provisioning,
referenced throughout `app/domains/location/provisioning_service.py`'s own
module docstring. It extends the existing Location domain (Module 006) --
an earlier attempt built this as a separate `app/domains/onboarding/`
module and was explicitly rejected by the project owner: "Do NOT create a
separate onboarding module. Extend the existing Location module." Every
file this feature added or touched lives inside `app/domains/location/` (or
one of the narrow, explicitly-permitted exceptions below), and its two new
endpoints are registered on the exact same `app.domains.location.router`
`APIRouter` every other Location endpoint uses.

## 1. What this is

A single orchestration entry point,
`LocationProvisioningService.provision_location`, that composes nine
already-built domains into one "Create Location" flow for a CloudGuest
Super Admin onboarding a brand-new (or existing) customer:

1. Create Organization (conditionally -- see §4)
2. Create Location (with `property_type`/auto-generated `location_code`)
3. Create Location Owner (`UserService.create_user`, one call)
4. Register Router (`RouterService.create_router`)
5. Generate WireGuard Peer (`WireGuardService.create_tunnel`)
6. Apply default router configuration (`RouterProvisioningService
   .assign_profile`, see §7 for the template-resolution gap)
7. Apply Subscription Plan (`SubscriptionService.create_subscription`,
   which itself creates+activates the `License`)
8. Apply Feature Flags + Plan Limits (see §5)
9. Create Default Settings (see §8)
10. Configure Captive Portal / Guest WiFi (`CaptivePortalService
    .create_config`, reusing the resolved feature flags for login methods)
11. Audit logging (one additional `location_provisioned` entry; every
    composed step already writes its own)
12. Send Welcome Email (+ optional SMS)
13. Activate Customer/Tenant (only if the reused organization was not
    already `ACTIVE` -- License/Subscription are already activated by step 7)

No `try`/`except` appears anywhere in `provision_location` -- see §2 for
why that is exactly what makes the transactional guarantee real.

## 2. The real single-transaction guarantee

`app/database/session.py::get_db_session` is the entire mechanism:

```python
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
```

It yields exactly one request-scoped `AsyncSession`, commits **once**, at
the very end, only if nothing raised, and rolls back (then re-raises) if
anything did. Every domain service this orchestration composes
(`OrganizationService`, `LocationService`, `UserService`, `RouterService`,
`RouterProvisioningService`, `WireGuardService`, `PlanService`/
`SubscriptionService`, `CaptivePortalService`, RBAC's repository) is built
on `GenericRepository`, whose `create`/`update`/`soft_delete` call only
`session.flush()` -- confirmed by reading `app/database/repositories
/generic.py` -- never `session.commit()`. `GenericRepository` *does*
expose an explicit `commit()`/`rollback()` method, but neither
`PlanService` nor `SubscriptionService` (nor any other composed service)
calls it -- confirmed by reading the whole of `app/domains/billing
/service.py` before composing it here.

`get_location_provisioning_service` (`app/domains/location
/provisioning_dependencies.py`) builds every one of the above services
through FastAPI's own dependency graph. FastAPI resolves any given
dependency callable **at most once per request** (its documented default
caching behavior) -- so `Depends(get_db_session)`, transitively required
by every one of those provider functions, resolves to the exact same
`AsyncSession` instance for the whole request, and every repository
instantiated anywhere in this call tree shares one connection/transaction.

Because `provision_location` never catches an exception from any composed
step, a failure at, say, step 7 (Billing) propagates all the way up
through the FastAPI route handler to `get_db_session`'s own
`except Exception: await session.rollback(); raise` -- which genuinely
rolls back every flushed-but-uncommitted write from steps 1-6 too.

`tests/unit/test_location_provisioning.py::TestTransactionalRollback`
proves this directly: a `FakeSharedSession` double (with its own
`flush`/`commit`/`rollback`, mirroring `AsyncSession`'s exact shape) is
threaded through every fake repository/service, a `run_within_transaction`
helper mirrors `get_db_session`'s own try/yield/commit/except/rollback body
verbatim, and a forced mid-flow failure is asserted to (a) leave every
step after the failure point un-executed, (b) call `rollback()`, and (c)
never call `commit()` -- both for an early failure (step 5, WireGuard) and
a late one (step 10, Captive Portal), plus a control case proving a
successful run commits exactly once and never rolls back.

## 3. Why a second file, not a bigger `service.py`

`provisioning_service.py` is a new file inside `app/domains/location/`,
not new lines added to the existing `service.py`. This is a readability
choice, not an architectural one -- `service.py` stays focused on plain
Location CRUD/lifecycle (its existing, stable, independently reviewable
job); the orchestration composes nine other domains and would have
roughly doubled that file's size for no benefit. `provisioning_schemas.py`
mirrors the same reasoning for the ~40-field request/response schemas
(kept separate from `schemas.py`'s plain Location CRUD DTOs).

`provisioning_dependencies.py` is a *second*, separate wiring module from
`dependencies.py` for a real, non-stylistic reason: `dependencies.py`
(this domain's plain CRUD wiring, specifically `get_location_service`) is
imported at module level by `app.domains.captive_portal.dependencies`,
`app.domains.router.dependencies`, and
`app.domains.router_provisioning.dependencies` (each composes
`get_location_service` for its own hierarchy validation). If the new
provisioning-specific wiring lived inside `dependencies.py` itself, its
need to import *those same* modules back would create a genuine circular
import (`location.dependencies` -> `captive_portal.dependencies` ->
`location.dependencies`). A separate module (which none of those other
domains' `dependencies.py` files import) breaks the cycle with zero change
to any of them.

## 4. Existing-vs-new-organization conditional

`ProvisionLocationInput` carries `existing_organization_id` **or**
`new_organization` (validated as mutually-exclusive/required by
`ProvisionLocationRequest._validate_organization_selection` at the API
layer). `_resolve_organization` implements the real conditional:
`existing_organization_id` given -> `OrganizationService.get_organization`
(raising `OrganizationArchivedError` if it is archived -- a location
cannot be provisioned under a dead tenant); neither given -> raises
`NewOrganizationRequiredError`; `new_organization` given -> a real
`OrganizationService.create_organization` call, with a minimal, honest
`settings` default (`{"onboarded_via": "smart_location_provisioning",
"onboarding_completed": True}`).

## 5. Billing feature-flag/plan-limit override design

BE-013 Part 1's `PlanFeature` is inherently *plan-level* -- every
organization on the same `Plan` shares identical entitlements. There is no
per-organization override table anywhere in `app.domains.billing`
(confirmed by reading the domain's full model/constants surface before
deciding). Two designs were weighed for the spec's "Feature Access" step
(a Super-Admin override, at provisioning time, on top of whatever the
selected Plan's own defaults already are):

1. A new, `location`-owned override table keyed by `organization_id` +
   `feature_key`.
2. Reuse Billing's own existing, documented precedent:
   `PlanType.CUSTOM` + `Plan.is_public=False` -- "Super-Admin-created,
   negotiated, typically-private... one-off plans that don't fit any
   standard tier" (`app.domains.billing.constants.PlanType`'s own
   docstring; `docs/billing/DATABASE.md`'s `is_public` write-up).

**Design 2 was chosen.** Billing already owns "this specific customer's
entitlements diverge from the stock catalog"; a parallel override table in
`location` would split "what can this org do" across two places and
require every future entitlement check to learn about a second table --
exactly the duplication this codebase's own composition-not-duplication
convention argues against. The project owner's own instructions list
"Subscription" among the domains this feature may extend, which is exactly
what this does.

Concretely: zero overrides -> the organization subscribes directly to the
selected public `Plan`. One or more overrides ->
`_create_overridden_plan` clones the base plan's own `PlanFeature` rows
(`PlanService.list_features`), applies the overrides on top, and creates a
brand-new `is_public=False`, `plan_type=CUSTOM` `Plan` (via
`PlanService.create_plan` -- the only creation path that exists; there is
no dedicated "clone" method) that the organization subscribes to instead.

`PlanFeatureKey` (`app.domains.billing.constants`) was additively extended
with the "Feature Access"/"Plan Limits" keys the spec names that Part 1
had not yet needed:

* Plan limits (`LIMIT`-typed): `MAX_CONCURRENT_SESSIONS`,
  `MAX_STAFF_USERS`, `MAX_API_KEYS`.
* Feature access (`BOOLEAN`-typed): `DASHBOARD`, `GUEST_WIFI`,
  `CAPTIVE_PORTAL`, `FREERADIUS`, `WIREGUARD`, `REPORTS`, `ALERTS`,
  `BILLING`, `VOUCHER_LOGIN`, `QR_LOGIN`, `SOCIAL_LOGIN`, `MOBILE_OTP`,
  `NOTIFICATION_CENTER`, `AUDIT_LOGS`, `MULTI_ROUTER`, `MULTI_LOCATION`.

A plain, additive `StrEnum` member never requires a migration -- the
column (`PlanFeature.feature_key`) is a plain `String`, not a native
Postgres enum type, per that module's own documented convention.

## 6. RBAC role choice: "Organization Owner"

The spec's flowchart says "Location Owner / Organization Admin" as if
interchangeable. The real, seeded system role
(`app.domains.rbac.seed.SYSTEM_ROLES`) that best fits "the person who
should be able to administer this entire new customer account" is
**"Organization Owner"** (slug `organization-owner`), not "Organization
Admin": its own seed description is "Full control over a single
organization's configuration and operations", strictly broader than
"Organization Admin"'s "Day-to-day administration of a single
organization". There is no seeded "Location Owner" role at all -- the
narrowest location-scoped role that exists, "Location Manager", is a
day-to-day operational role (guest WiFi/staff operations), not an
account-administration one.

## 7. Default router config template gap

No system (`is_system_template=True`) `ConfigTemplate` is seeded anywhere
in this codebase's fixture/seed data (confirmed by grepping the whole
tree). `_resolve_default_template_id` calls
`RouterProvisioningService.list_templates(requesting_organization_id=None,
...)` (an already-existing public method that returns every template,
system and tenant-owned alike, when called with no organization scope),
filters client-side for `is_system_template and is_active`, and picks the
most recently created one. If none exists and the caller did not supply an
explicit `router_config_template_id`,
`DefaultConfigTemplateNotFoundError` is raised -- an honest, real
operational gap, not a fabricated fallback template. A real deployment
must seed at least one system config template
(`POST /router-provisioning/templates` with no `X-Organization-Id` header)
before this step can succeed without an explicit override.

## 8. Default settings

`Location.settings` gains (merged over whatever the caller supplied):
`owner_user_id` (the provisioned owner's user id -- enables
`resend_welcome_email` to find them later without a new column),
`provisioning_source: "smart_location_provisioning"`, and
`provisioned_at` (ISO timestamp). `Organization.settings` (only for a
brand-new organization) gains `onboarded_via`/`onboarding_completed`. Both
are minimal, real, non-fabricated defaults -- never the temporary
password or any other secret.

## 9. `must_change_password` (auth extension) -- necessity and scope

This flow hands a freshly-generated, high-entropy random password to a
brand-new account owner via email. This codebase's auth flow (BE-002) has
never before needed to force a password change before first ordinary use
-- confirmed by reading `app.domains.auth.models`/`service.py` in full
before adding anything.

**The diff, in full:**

* One additive column: `User.must_change_password: bool` (default
  `False` -- every pre-existing/self-registered account is unaffected).
* One check in `AuthService.login`, placed immediately alongside the
  existing, identically-shaped `EmailNotVerifiedError` check, before any
  token pair is created:
  ```python
  if user.must_change_password:
      ...
      raise PasswordChangeRequiredError()
  ```
* `PasswordChangeRequiredError` (a new `AuthServiceError` subclass, 403,
  mirroring `EmailNotVerifiedError`'s exact shape).
* The flag is cleared (`must_change_password=False`) by both
  `AuthService.change_password` and `AuthService.reset_password` -- the
  two existing, legitimate ways a user can set a new password. Since a
  flagged user's login is blocked *before* a session/token is ever
  issued, `change_password` (which requires an existing bearer token) is
  not reachable for them yet -- the intended recovery path is the
  existing, unauthenticated `forgot-password`/`reset-password` flow
  (`AuthService.initiate_password_reset` + `reset_password`), which
  *is* reachable and does clear the flag.

No rewriting of the surrounding login logic -- this is the entire,
narrow, additive diff to a domain this task may otherwise not touch.

## 10. `location_code` generator mechanism

`Location.location_code` (e.g. `"LOC-2026-000001"`) is generated by
`app.domains.location.number_generator.generate_location_code`, a direct
structural mirror of `app.domains.billing.number_generator
.generate_invoice_number`: a dedicated `LocationCodeCounter` table
(`counter_key` unique, `last_value`), incremented via **one** atomic
Postgres statement --
`INSERT ... ON CONFLICT (counter_key) DO UPDATE SET last_value =
last_value + 1 ... RETURNING last_value` (SQLAlchemy's
`postgresql.insert(...).on_conflict_do_update(...)`) -- never a racy
`SELECT MAX(...) + 1`. `counter_key` is `"location:<year>"`, so the
sequence resets to 1 at the start of each calendar year, the same
convention `InvoiceNumberCounter` already uses. Generation is not confined
to the provisioning flow -- `LocationService.create_location` itself was
extended to always generate one, for *every* newly-created location
(provisioned or plain-CRUD-created), so there is exactly one code path
that ever assigns a `location_code`.

`Location.location_code` is nullable at the *column* level (so this
migration never has to backfill a value for any pre-existing row), with a
**partial** unique index (`WHERE location_code IS NOT NULL`) enforcing
uniqueness only among rows that do have one -- mirrors
`organization_members`'s own partial-unique-index precedent (migration
`0003`).

`tests/unit/test_location_provisioning.py::TestLocationCodeGenerator`
verifies both the exact format/year-reset behavior and (mirroring
billing's own concurrency-test rigor for the identical mechanism) that 50
concurrent `asyncio.gather` callers against the same in-memory fake
counter never produce a duplicate code.

## 11. Username / temporary-password generation

No reusable "username generator" exists anywhere in this codebase. A
reusable *secure-random-token* pattern does
(`app.domains.router.service`'s zero-touch-provisioning token:
`secrets.token_urlsafe(32)`), but it is not directly reusable for a
human-typed, complexity-constrained temporary password.
`_generate_temporary_password` reuses the same `secrets` stdlib module
(never `random`) but composes a 16-character password guaranteed to
contain at least one uppercase, lowercase, digit, and special character,
matching `RegisterRequest.password`'s own documented complexity
expectation (`app.domains.auth.schemas`). `_generate_username` derives a
candidate from the owner's email local-part plus a short random suffix
(also via `secrets`).

## 12. Response payload -- shown-once temporary password discipline

`ProvisionLocationResponse.owner_temporary_password` is populated exactly
once, in this one response, and nowhere else: it is never written to
`Location.settings`/`Organization.settings` (§8's defaults deliberately
never include it), never logged (the welcome email composition builds the
message body directly, and only `LoggingEmailProvider`'s own `send()`
logs *metadata* -- recipient/subject/body length -- never the body
content itself, mirroring the OTP domain's own honest-logging posture),
and `resend_welcome_email` never re-sends it (that endpoint's email body
explicitly omits it and instead points the owner at "Forgot password").
This mirrors this codebase's existing "shown once" precedent for
provisioning tokens (`app.domains.router.service
.generate_provisioning_token`) and webhook secrets.

## 13. Login URL

`app/core/config.py` is outside this domain's directory-rule boundary (not
one of the explicitly-permitted narrow exceptions), so no `Settings` field
was added for a real frontend base URL.
`LocationProvisioningService.login_url_base` is a plain constructor
argument instead (documented placeholder default:
`https://app.cloudguest.example`) -- a real deployment should pass its
actual frontend origin when wiring `get_location_provisioning_service`.

## 14. Super-Admin / GLOBAL-scope-only gating

Both new endpoints are gated with
`RequirePermission("locations.manage", scope=ScopeType.GLOBAL)` -- the
identical factory call `app.domains.billing.router` already uses to
restrict Plan-catalog writes to Super-Admin-class roles. Per
`app.domains.rbac.seed.SYSTEM_ROLES`, only `Super Admin` and
`Platform Admin` hold `locations.manage` at `GLOBAL` scope (every other
role is either scoped narrower or has no `locations.manage` grant at
all) -- verified directly by
`tests/unit/test_location_provisioning.py
::TestSuperAdminGating::test_only_super_admin_and_platform_admin_hold_locations_manage_at_global`.

## 15. Captive Portal / Guest WiFi login-method reuse

The spec's "Feature Access" list overlaps with `CaptivePortalConfig`'s own
login-method booleans. Rather than tracking auth-method-enablement twice,
`_resolve_login_methods` derives `otp_sms_enabled`/`otp_email_enabled`
from the resolved `MOBILE_OTP` feature, `voucher_enabled` from
`VOUCHER_LOGIN`, and `social_login_enabled` from `SOCIAL_LOGIN`. `QR_LOGIN`
has no corresponding `CaptivePortalConfig` field to map onto today -- a
real, documented gap (not fabricated), left for a future Captive Portal
addition. `username_password_enabled` has no corresponding
`PlanFeatureKey` in the spec's list either, so it defaults to always-on
(the baseline login method). The config is created location-scoped
(`is_default=False`, `location_id=<the new location>`), not as the
organization's org-wide default, since it is provisioned for this one
specific location.
