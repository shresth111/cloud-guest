# Captive Portal: Flows and Design Decisions

This document records every design decision this module made where the
brief left room for judgment, plus the end-to-end config-lifecycle/
resolution flow. Read this before modifying `app/domains/captive_portal/`.

## 1. `organization_id`/`location_id`: real FKs, one non-nullable, both immutable

**Decision: `CaptivePortalConfig.organization_id` is a real, non-nullable
FK; `location_id` is a real, nullable FK. Neither is exposed on the update
schema -- both are immutable after creation.**

Mirrors `app.domains.voucher.models.VoucherBatch.organization_id`'s
identical choice (see that module's `FLOW.md` §10): a captive portal
config always belongs to a tenant, there is no "platform-wide, no
organization" config the way OTP's nullable scope columns allow.
`location_id` is nullable because a config may legitimately be an
organization-wide default (`NULL`) or a specific location's override
(non-null). Both are validated for real at creation time -- composing with
the real `OrganizationService`/`LocationService` (via narrow
`OrganizationLookupProtocol`/`LocationLookupProtocol` shapes, the identical
composition-over-duplication precedent `app.domains.voucher.service
.VoucherService` and `app.domains.router_provisioning.service
.RouterProvisioningService` already establish) to confirm the organization
exists and that a supplied location actually belongs to it
(`CrossOrganizationLocationAccessError` otherwise, reused, not
duplicated). `CaptivePortalService.get_config`/every other config-scoped
method additionally enforces `CrossOrganizationCaptivePortalConfigAccessError`
when a caller's resolved `requesting_organization_id` (from
`X-Organization-Id`) doesn't match the config's own `organization_id` --
mirroring `app.domains.voucher.exceptions
.CrossOrganizationVoucherBatchAccessError`'s identical tenant-boundary
check.

Neither field is settable via `PUT /captive-portal-configs/{id}` --
`CaptivePortalConfigUpdateRequest` never declares them, and
`CaptivePortalService.update_config` additionally, defensively strips them
from any hand-constructed `data` dict, mirroring
`app.domains.location.service.LocationService.update_location`'s identical
"organization_id is immutable" convention. A config "moving" between
organizations or locations is not a real operation -- the closest
equivalent is creating a new config in the right place and deleting the
old one.

## 2. Resolution: location override, else organization default, else raise

**Decision: `CaptivePortalService.resolve_portal_config` implements a
two-tier most-specific-wins lookup -- an active config scoped to the exact
`location_id`, else the organization's active default
(`location_id IS NULL`, `is_default=True`, `is_active=True`), else
`CaptivePortalConfigNotConfiguredError`. There is no third, hardcoded
platform-wide fallback tier.**

This is the same resolution *shape* `app.domains.router_provisioning
.service.RouterProvisioningService.resolve_variables` already establishes
(`ROUTER > LOCATION > ORGANIZATION > GLOBAL`, most-specific wins), narrowed
to this module's own two tiers: `LOCATION > ORGANIZATION`, with **no**
`GLOBAL` tier. This narrowing is deliberate, not an oversight: a config
*variable* (a RouterOS template placeholder value) can sensibly have a
platform-wide default -- e.g. a DNS server address every deployment might
share -- but a captive portal's branding is inherently tenant-specific
content: a business's own logo, brand colors, and legal text. CloudGuest
has no principled platform-wide "default logo" to fall back to that would
mean anything to a real guest looking at a real business's WiFi login
page. Every organization must therefore configure at least one active
default portal before its guest WiFi can be presented to a guest --
`resolve_portal_config` raises rather than silently serving some
placeholder/CloudGuest-branded page in its stead.

```python
async def resolve_portal_config(*, organization_id, location_id):
    if organization_id is None and location_id is None:
        raise MissingPortalResolutionParamsError()

    resolved_organization_id = organization_id
    if location_id is not None:
        location = await location_lookup.get_location(
            location_id, requesting_organization_id=organization_id
        )
        resolved_organization_id = location.organization_id
        location_config = await repository.find_active_for_location(...)
        if location_config is not None:
            return location_config  # tier 1: location override
    else:
        await organization_lookup.get_organization(resolved_organization_id)

    org_default = await repository.find_active_org_default(...)
    if org_default is not None:
        return org_default  # tier 2: organization default
    raise CaptivePortalConfigNotConfiguredError(resolved_organization_id)
```

### Deriving `organization_id` from `location_id`

**Decision: `GET /captive-portal/resolve` accepts `location_id` alone (no
`organization_id` required) -- the organization is derived from the
location's own row via `LocationLookupProtocol.get_location`.**

A real captive-portal deployment is tied to a specific location/router,
not necessarily aware of its own organization id up front (the device
knows where it physically is, not an abstract tenant identifier) -- this
mirrors how a location-scoped OTP/voucher redemption already only needs a
`location_id`-shaped context. When both `organization_id` and
`location_id` are supplied, the location is confirmed to actually belong
to that organization (`CrossOrganizationLocationAccessError` otherwise,
reused from `app.domains.location`) -- a real cross-tenant boundary check,
not a silently-trusted pair. When only `organization_id` is supplied (no
location context at all), resolution skips straight to the organization
default tier.

### The "neither exists" error case

`CaptivePortalConfigNotConfiguredError` is a `404` -- from the guest's
device's perspective, this reads the same as "nothing is here yet",
which is accurate: the tenant has simply not finished onboarding its
guest WiFi captive portal. It is distinct from
`CaptivePortalConfigNotFoundError` (raised by the admin-facing
`get_config`/`update_config`/etc. for a specific, named-by-id config that
doesn't exist) -- the resolve path never names a specific config id, so a
distinct exception class keeps the two "not found" reasons from being
conflated in logs/monitoring.

## 3. Single-default-per-organization enforcement

**Decision: "at most one `is_default=True` organization-level
(`location_id IS NULL`) config per organization" is enforced two ways: a
service-layer step that actually runs on every write, plus a database
partial unique index as a backstop.**

1. **Service layer (the one that actually maintains the invariant):**
   `CaptivePortalService._clear_existing_default` looks up the
   organization's current default (`CaptivePortalRepository
   .find_default_for_organization`, an explicit `location_id IS NULL`
   `select` -- `GenericRepository`'s filters dict cannot express `IS NULL`,
   see `repository.py`'s module docstring) and flips it to
   `is_default=False`, in the same call, *before* the new/updated row is
   persisted as the default. This runs from both `create_config` (when
   `is_default=True` is requested) and `update_config` (when a config is
   being *promoted* to default, i.e. `is_default` flips from `False` to
   `True` -- flipping an already-default config's other fields, or
   explicitly setting `is_default=False`, never triggers this).
2. **Database partial unique index (the backstop):** a partial unique
   index on `organization_id` where `location_id IS NULL AND
   is_default = true` (see the migration and
   `models.CaptivePortalConfig.__table_args__`) makes it structurally
   impossible for two org-level default rows to coexist even if the
   service-layer step were ever bypassed (a direct script, a bug, a
   concurrent write race) -- a real `IntegrityError` at the database
   layer, not just an application-level promise. This mirrors
   `app.domains.organization.models.OrganizationMember`'s identical
   belt-and-suspenders convention for its own "at most one active
   membership per (organization, user)" invariant.

**`is_default=True` is rejected outright when `location_id` is non-null**
(`InvalidDefaultConfigScopeError`, raised by
`validators.validate_default_scope`) -- `is_default` only has meaning for
an organization-level config; a location override's "is this the one
used" question is already fully answered by `is_active` (see §2's
resolution lookup: a location override participates in resolution purely
by being active, it never needs a separate "default" flag among other
location overrides for the same location).

## 4. Content fields: inline text *or* external URL, "at most one", not "exactly one"

**Decision: `terms_and_conditions_text`/`terms_and_conditions_url` (and
the identical `privacy_policy_text`/`privacy_policy_url` pair) are two
nullable columns each. `validators.validate_single_content_source` rejects
only the case where **both** are populated at once -- it does not require
*exactly* one to always be set.**

The module brief's own phrasing ("two nullable fields where exactly one is
expected to be set") was taken as guidance, not a hard requirement, and
this module deliberately implements the slightly looser "at most one, never
both" rule instead, for a concrete reason: a config is frequently created
*before* its legal text/URL is finalized (an admin iterating on branding,
colors, and login methods first, then adding a real terms-and-conditions
page once legal has approved copy) -- and `is_active` already exists as
the mechanism that gates whether a config should actually be served to a
real guest at all. Requiring *exactly* one non-null value from creation
onward would force every draft config to invent a placeholder value just
to pass validation, which is worse than simply allowing "not configured
yet" to mean exactly that. What must never happen, and is rejected
unconditionally, is **both** being set at once: a captive-portal frontend
rendering the resolved config would have no principled way to choose which
one to show, and persisting both invites them silently drifting out of
sync with each other over time.

This rule is enforced against the **merged, final state**, not just the
fields present in a given request -- `update_config` computes what the
final `terms_and_conditions_text`/`terms_and_conditions_url` pair would be
*after* applying the patch (falling back to the existing row's value for
any field the patch doesn't touch) before validating, so a `PUT` that only
sets `terms_and_conditions_url` on a config whose
`terms_and_conditions_text` is already populated is correctly rejected,
not silently allowed to produce an invalid combined row.

## 5. Authentication method flags, and the social-login/username-password boundary

**Decision: which guest login methods a portal enables is modeled as five
explicit booleans (`otp_sms_enabled`, `otp_email_enabled`,
`voucher_enabled`, `username_password_enabled`, `social_login_enabled`),
not a JSONB bag -- and `social_login_enabled`/`username_password_enabled`
are schema-only readiness flags, not working features.**

Explicit columns over JSONB: this is a small, fixed, individually
meaningful set the guest-facing resolve response needs to expose directly
(a real captive-portal frontend renders "Login with OTP" / "Enter your
voucher code" buttons conditionally on exactly these flags) -- the same
"explicit columns when the shape is known and small" judgment call
`app.domains.router_provisioning.models.ConfigTemplate.is_system_template`
already documents.

**`social_login_enabled` changes only what the resolve response reports as
enabled. Nothing in this module (or any other) actually performs a social
login.** There is no real OAuth/social-login integration anywhere in this
codebase, and building one was explicitly out of scope for this module --
the same honest-boundary posture `app.domains.otp`'s logging-only SMS/
email "providers" already establish for their own not-really-integrated
delivery channel. `social_login_providers` (JSONB, default `[]`) is a
forward-compatible extension point for a future integration to list
configured provider slugs (e.g. `["google", "facebook"]`) -- today it is
stored and returned verbatim, with **no validation against a real provider
registry**, because no such registry exists to validate against (see
`tests/unit/test_captive_portal.py::TestSocialLoginPlaceholder
.test_no_provider_registry_validation_is_performed`, which confirms an
obviously-fake provider slug is accepted without error).

`username_password_enabled` is the identical kind of placeholder: no
`Guest` model exists yet in this codebase (a later module in this same
BE-010 sequence) to authenticate a username/password against, so this flag
too is a forward-compatible extension point for the future `guest` module
to act on, not a working login path today.

## 6. Guest-facing resolve endpoint: no RBAC, but still enveloped

**Decision: `GET /captive-portal/resolve` carries no `RequirePermission`/
`CurrentUser` dependency at all, but still uses the standard
`ApiResponse`/`build_response` envelope.**

Mirrors `app.domains.otp.router`/`app.domains.voucher.router`'s identical
justification: the caller is a guest's device/captive-portal frontend,
resolving *before* the guest has authenticated by any method -- there is
no platform-user identity RBAC could ever grant a permission to. Unlike
OTP's/Voucher's guest-facing *mutating* endpoints (which need Redis-backed
rate limiting to guard against abuse), this endpoint is pure, read-only
configuration lookup with no state to protect against brute-forcing --
there is no secret being validated, only "what does this location's portal
look like", so no rate limiter was added here (an unauthenticated read of
non-sensitive branding data is a fundamentally different risk profile from
guessing an OTP code or voucher). It still uses the standard `ApiResponse`
envelope (consistent with OTP's/Voucher's own guest-facing-but-still-
enveloped precedent) since its real caller is the captive-portal
*frontend*, a real client that benefits from the same structured contract
every other user-facing endpoint returns.

## 7. Audit-volume judgment call: full coverage, unlike OTP/Voucher's tiering

**Decision: every `create_config`/`update_config`/`activate_config`/
`deactivate_config`/`delete_config` call writes one `audit_log_entries`
row. There is no tiering of which mutating actions get audited, unlike
OTP's/Voucher's own careful volume-based tiering.**

OTP and Voucher both deliberately do *not* audit every occurrence of their
own most-frequent actions (an OTP code request, a routine redemption
failure) because those are high-volume, guest-facing, often-
unauthenticated actions -- auditing every single one would flood a
moderate-volume, admin-reviewable table for limited benefit, and a guest
hammering "request OTP" carries no individually distinguishable value once
logged structurally. This module's mutating actions have the opposite
profile: they are **low-volume, always-authenticated, always
admin-initiated configuration changes** to how a tenant's guest WiFi login
page looks and behaves. An admin changing a captive portal's terms-and-
conditions URL, disabling a login method, or promoting a new default
config happens rarely (compared to guest traffic) and is exactly the kind
of change a compliance/support review would specifically want a complete
trail of ("who changed the terms and conditions URL, and when, and what
did it used to say"). There is no volume problem to tier against here --
this module's write path simply never sees the request-per-second profile
OTP's/Voucher's guest-facing endpoints do -- so full coverage is the
correct call for this module specifically, not merely the default/lazy
choice. The one read path this module exposes,
`resolve_portal_config`, is never audited, for the same reason no domain
audits its own read endpoints: no state changes, nothing to have a trail
of.

## End-to-End Flow

1. **Create.** `POST /captive-portal-configs` (requires
   `captive_portal.create`). `CaptivePortalService.create_config`:
   a. Validates `primary_color`/`secondary_color` (hex format, §-- see
      `validators.validate_hex_color`), the terms-and-conditions/
      privacy-policy pairs (§4), and `is_default`'s scope (§3).
   b. Confirms the organization exists and (if a location was given) that
      it belongs to that organization -- raises
      `CrossOrganizationCaptivePortalConfigAccessError`/
      `CrossOrganizationLocationAccessError` otherwise.
   c. If `is_default=True`, un-defaults any prior organization default
      (§3).
   d. Inserts the `CaptivePortalConfig` row, audits
      `CAPTIVE_PORTAL_CONFIG_CREATED`.
2. **Read.** `GET /captive-portal-configs`/`GET .../{id}` (both
   `captive_portal.read`) -- scoped to the caller's organization when
   `X-Organization-Id` is present; a platform-level caller
   (`requesting_organization_id=None`) may read any config.
3. **Update.** `PUT /captive-portal-configs/{id}` (`captive_portal.update`)
   -- re-validates colors/content-source pairs/default-scope against the
   *merged* final state (§4), un-defaults a prior default if this config
   is newly being promoted (§3), audits
   `CAPTIVE_PORTAL_CONFIG_UPDATED`.
4. **Activate/Deactivate.** `POST .../activate`/`POST .../deactivate`
   (both `captive_portal.update`, not `.manage`/`.delete` -- a lifecycle
   status toggle, not a destructive or platform-admin-only action,
   mirroring `app.domains.voucher.router`'s identical "revoke ->
   voucher.update" precedent) -- flips `is_active`, audits
   `CAPTIVE_PORTAL_CONFIG_ACTIVATED`/`CAPTIVE_PORTAL_CONFIG_DEACTIVATED`.
5. **Delete.** `DELETE /captive-portal-configs/{id}`
   (`captive_portal.delete`) -- deactivates (`is_active=False`) then
   soft-deletes (`GenericRepository.soft_delete`), audits
   `CAPTIVE_PORTAL_CONFIG_DELETED`.
6. **Resolve.** `GET /captive-portal/resolve` (guest-facing, no RBAC, §6)
   -- the most-specific-wins lookup (§2): a location-specific active
   config, else the organization's active default, else
   `CaptivePortalConfigNotConfiguredError`. Never audited (read-only).
