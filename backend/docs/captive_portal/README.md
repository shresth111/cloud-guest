# Module 010 Part 3: Captive Portal

The Captive Portal domain (`app.domains.captive_portal`) manages the
**branding and configuration** of the guest WiFi login page (the "captive
portal") a guest's device is redirected to before getting internet access
-- logo, colors, terms and conditions, splash content, and which guest
login methods (OTP SMS/email, voucher, username/password, social login)
are enabled. This is BE-010's third part, built after `app.domains.otp`
(Part 1) and `app.domains.voucher` (Part 2), before the final `guest`
module.

**This module does not implement guest authentication itself.** It is pure
configuration/branding data plus one guest-facing "give me the portal
config to render" read endpoint (`GET /api/v1/captive-portal/resolve`).
The future `app.domains.guest` module composes with `otp`/`voucher`/this
module to actually authenticate and admit a guest.

See `FLOW.md` for the full resolution-order/single-default-enforcement/
social-login-boundary write-up, and `DATABASE.md` for the one new table.

## Captive Portal, In One Paragraph

An organization configures at least one **organization-level default**
config (`location_id IS NULL`, `is_default=True`) via
`POST /captive-portal-configs`. Any of its locations may additionally get
its own **location-specific override** (`location_id` set to that
location's id). Before a guest authenticates, the captive-portal
frontend calls `GET /captive-portal/resolve?location_id=...` (or
`?organization_id=...` for a pure org-level lookup with no location
context), which implements a most-specific-wins lookup: the location's own
active config if one exists, else the organization's active default, else
a `404 CaptivePortalConfigNotConfiguredError` -- there is no hardcoded
platform-wide fallback branding. Admins may create/list/get/update/delete
configs and toggle `is_active` via dedicated `activate`/`deactivate`
endpoints.

## What This Module Does NOT Do

* **It does not authenticate guests.** No OTP delivery, no voucher
  redemption -- that is `app.domains.otp`/`app.domains.voucher`, already
  built. This module only stores/serves the branding and which methods a
  portal *enables*.
* **It does not implement social login.** `social_login_enabled` is a
  schema-only readiness flag and `social_login_providers` is an empty,
  forward-compatible JSONB extension point -- there is no real OAuth/
  social-login integration anywhere in this codebase, and none is
  attempted here. The same honest-boundary posture `app.domains.otp`'s
  logging-only SMS/email providers already establish. See `FLOW.md` §5.
* **It does not implement guest username/password authentication.**
  `username_password_enabled` is the same kind of placeholder -- no
  `Guest` model exists yet (a later module in this same BE-010 sequence)
  to authenticate against.
* **It does not invent a platform-wide default branding.** If neither a
  location override nor an active organization default exists,
  `resolve_portal_config` raises rather than falling back to some
  hardcoded CloudGuest-branded page -- every organization must configure
  at least a default portal before going live. See `FLOW.md` §2.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0014_create_captive_portal_tables.py
  app/
    domains/
      captive_portal/
        __init__.py
        constants.py       # PortalTheme, hex color pattern, defaults
        models.py           # CaptivePortalConfig (see DATABASE.md)
        exceptions.py         # CaptivePortalError subclasses (CloudGuestError)
        events.py              # Plain dataclasses, logged synchronously by service.py
        validators.py            # Pure hex-color/content-source/default-scope checks (no I/O)
        repository.py             # CaptivePortalRepositoryProtocol + repo
        service.py                 # CaptivePortalService: CRUD, default enforcement, resolution
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI dependency wiring
        router.py                     # FastAPI routes
      rbac/
        enums.py                     # AuditAction gained 5 additive CAPTIVE_PORTAL_CONFIG_* values
    api/
      v1/
        router.py                    # captive_portal_router registered
  docs/
    captive_portal/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_captive_portal.py
```

## API Surface

Admin-facing endpoints (registered under `/api/v1`), gated by RBAC's
already-seeded `captive_portal.*` permission keys:

```text
POST   /api/v1/captive-portal-configs                    captive_portal.create
GET    /api/v1/captive-portal-configs                    captive_portal.read
GET    /api/v1/captive-portal-configs/{id}               captive_portal.read
PUT    /api/v1/captive-portal-configs/{id}               captive_portal.update
DELETE /api/v1/captive-portal-configs/{id}               captive_portal.delete
POST   /api/v1/captive-portal-configs/{id}/activate      captive_portal.update
POST   /api/v1/captive-portal-configs/{id}/deactivate    captive_portal.update
```

Guest-facing endpoint -- no `RequirePermission`/`CurrentUser`, see
`FLOW.md` §6:

```text
GET /api/v1/captive-portal/resolve?location_id=...
GET /api/v1/captive-portal/resolve?organization_id=...
```

## Reused, Not Duplicated

* `GenericRepository` (Module 002) -- `CaptivePortalRepository` adds only
  the few hand-written `select` statements `GenericRepository`'s filters
  dict genuinely can't express (an explicit `location_id IS NULL`
  predicate -- see `repository.py`'s module docstring).
* `ApiResponse`/`build_response` (Module 001) for every endpoint,
  including the guest-facing resolve endpoint (consistent with OTP's/
  Voucher's own guest-facing-but-still-enveloped precedent).
* RBAC's `audit_log_entries` (via the same narrow `AuditLogWriter`
  protocol shape every other domain's service uses) with 5 additive
  `AuditAction` values, and RBAC's already-seeded `captive_portal.*`
  permission keys.
* `app.domains.organization.service.OrganizationService`/
  `app.domains.location.service.LocationService` (via narrow
  `OrganizationLookupProtocol`/`LocationLookupProtocol` shapes) for
  tenant/hierarchy validation -- mirrors `app.domains.voucher`'s own
  composition-not-duplication precedent.
* `CloudGuestError` (Module 001).

## New, Not Reused (Genuine Additions)

* `CaptivePortalConfig` -- a genuinely new table; nothing elsewhere models
  a captive portal's branding/content/enabled-login-methods.
* The most-specific-wins location-override-then-organization-default
  resolution lookup, narrowed from `app.domains.router_provisioning
  .ConfigVariable`'s four-tier precedent (`ROUTER > LOCATION >
  ORGANIZATION > GLOBAL`) to this module's own two tiers (`LOCATION >
  ORGANIZATION`, no `GLOBAL` fallback -- see `FLOW.md` §2 for why).
* The single-default-per-organization enforcement (service-layer
  un-defaulting plus a database partial unique index backstop).

## Testing

`tests/unit/test_captive_portal.py` exercises `CaptivePortalService`
against small, hand-rolled in-memory fakes for its repository, audit
writer, and organization/location lookups (there is no live Postgres in
this environment). Coverage: CRUD (create/get/list/update/delete,
activate/deactivate), full audit coverage of every mutating action,
single-default-per-organization enforcement (a second default un-defaults
the first, both on create and on update; `is_default` rejected alongside a
non-null `location_id`), resolution (location override wins, falls back to
the organization default, an inactive override/default is ignored, neither
existing raises, missing both query params raises, deriving the
organization from the location, rejecting a mismatched
organization/location pair), hex color validation (valid/invalid formats,
both at create and update time), terms-and-conditions/privacy-policy
mutual-exclusivity validation (neither set is legal, only one set is
legal, both set raises -- including when a patch would combine with an
existing value to produce an invalid merged state), cross-tenant isolation
(cross-organization get/create, a location that doesn't belong to the
stated organization), and the social-login/username-password flags being
schema-only placeholders with no real authentication ever attempted. All
383 previously-passing tests continue to pass unmodified, plus 49 new
tests here (432 total).
