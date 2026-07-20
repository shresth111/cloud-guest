# Module 010 Part 4: Guest

> **Guest Session Engine (Phase 1 roadmap item) addendum:** a gap analysis
> against the roadmap's "Guest Session Engine" requirements found this
> module already implemented live sessions, session history, accounting
> (including RADIUS interim-update), idle/session timeout detection,
> disconnect, and force logout (`terminate_session`) -- see the Architecture
> Design Document for the full analysis. Only two real gaps existed and were
> closed here, with **no new tables and no migration** (a deliberate
> finding, not an oversight):
>
> 1. **Concurrent session limit** -- previously unenforced; see FLOW.md §6a.
> 2. **The timeout sweep was dead code** -- `enforce_timeouts` existed and
>    was tested but nothing ever scheduled it; it now runs every 5 minutes
>    via Celery Beat. See FLOW.md §6's addendum and `tasks.py`.
>
> "Live Sessions" and "Session History" needed no new code at all -- both
> are already `GET /guest-sessions` (`?status=active` for the former, any/no
> filter for the latter).
>
> **Guest Access Control addendum:** `GuestService` gained a second
> optional hook, `access_control_hook` (mirrors `monitoring_hook`'s
> additive pattern), composing with the new `app.domains.guest_access`
> module. See `docs/guest_access/README.md` for the full write-up. Unlike
> `monitoring_hook`, this hook can change a login's outcome -- a resolved
> `BLOCKLIST` decision raises `GuestAccessDeniedError` and blocks the
> login, checked immediately after the existing `Guest.is_blocked` check.
>
> **NAS extension addendum:** `RadiusNasClient` (previously a bare
> `router_id`/`nas_identifier`/`shared_secret_encrypted`/`is_active` row)
> gained a real status lifecycle (`constants.NasStatus`), a human-readable
> `nas_code`, denormalized `organization_id`/`location_id`, and full admin
> CRUD/lifecycle endpoints (list/get/update/delete/activate/disable/
> regenerate-secret). See `NAS_EXTENSION.md` for the full write-up --
> including why this extends the existing NAS row rather than building a
> second, parallel one.

The Guest domain (`app.domains.guest`) is BE-010's **final** module -- the
one that actually ties `app.domains.otp` (Part 1), `app.domains.voucher`
(Part 2), `app.domains.captive_portal` (Part 3), and `app.domains.router`
(BE-008) together into a real guest WiFi login. It never reimplements OTP
verification, voucher redemption, or captive-portal resolution -- it
composes with all three through narrow, duck-typed protocols, adding only
what none of them model: a returning-guest identity, a device, a session,
session lifecycle management, a FreeRADIUS integration, and guest
analytics.

See `FLOW.md` for the full guest login journey write-up (portal resolve ->
otp/voucher auth -> session creation -> usage/accounting -> disconnect/
timeout), the FreeRADIUS `rlm_rest` integration choice, and the MAC-address-
uniqueness decision. See `DATABASE.md` for the six new tables.

## Guest WiFi Login, In One Paragraph

A guest's device is redirected to a captive portal (Part 3), which resolves
branding and enabled login methods. The guest submits an OTP code
(`POST /guest/login/otp`) or a voucher code (`POST /guest/login/voucher`).
This module first confirms (via `CaptivePortalService.resolve_portal_config`)
that the requested method is enabled for that location, then calls
`OtpService.verify_otp`/`VoucherService.redeem_voucher` to actually
authenticate. On success, it gets-or-creates a `Guest` row (recognized
across visits by `identifier`, unique per organization), gets-or-creates a
`GuestDevice` row (by MAC address), and creates a `GuestSession` -- one
continuous WiFi connection interval on one `Router` (the RADIUS NAS). A
guest's session usage/lifecycle is then driven by FreeRADIUS's own
Accounting packets, translated into this module's own HTTP endpoints
(`POST /radius/accounting`) via the `rlm_rest` integration pattern.

## What This Module Does NOT Do

* **It does not verify OTP codes or redeem vouchers itself.** Every code/
  voucher check goes through `OtpService.verify_otp`/
  `VoucherService.redeem_voucher` -- this module only orchestrates what
  happens before and after those calls.
* **It does not run a real FreeRADIUS server or speak the RADIUS-UDP wire
  protocol.** See `FLOW.md` §5 for the full `rlm_rest` HTTP-integration
  architectural choice and why.
* **It does not live-disconnect a device at the network level.**
  `enforce_timeouts`/quota detection are status-transition/reporting
  mechanisms only -- see `FLOW.md` §6.
* **It does not implement guest username/password authentication.**
  `GuestAuthMethod.USERNAME_PASSWORD` exists for schema parity with
  `CaptivePortalConfig.username_password_enabled` but no login path in this
  module implements it (mirrors that flag's own placeholder status).

## Folder Structure

```text
backend/
  alembic/
    versions/
      0015_create_guest_tables.py
      0030_extend_radius_nas_clients.py
  app/
    domains/
      guest/
        __init__.py
        constants.py       # GuestAuthMethod, GuestSessionStatus, NasStatus, defaults, RADIUS headers
        models.py           # Guest, GuestDevice, GuestSession, GuestLoginHistory,
                             # GuestConsent, RadiusNasClient, RadiusNasCodeCounter (see DATABASE.md)
        exceptions.py         # GuestError subclasses (CloudGuestError)
        events.py              # Plain dataclasses, logged synchronously by service.py
        validators.py            # Pure MAC/identifier normalization, transition/date checks
        repository.py             # GuestRepositoryProtocol + repo (incl. analytics SQL)
        nas_number_generator.py    # nas_code generation, shared-secret generation
        service.py                  # GuestService, RadiusService, GuestAnalyticsService
        schemas.py                   # Pydantic request/response DTOs
        dependencies.py                # FastAPI dependency wiring, CurrentNas
        router.py                      # guest_router/admin_router/radius_router/
                                        # nas_router/nas_cross_reference_router/analytics_router
      rbac/
        enums.py                     # AuditAction gained additive GUEST_*/RADIUS_* values;
                                      # PermissionModule.RADIUS gained the EXECUTE action
    api/
      v1/
        router.py                    # all six guest routers registered
  docs/
    guest/
      README.md
      FLOW.md
      DATABASE.md
      NAS_EXTENSION.md
  tests/
    unit/
      test_guest.py
```

## API Surface

Guest-facing (no RBAC -- abuse protection inherited from OTP's/Voucher's
own rate limiting):

```text
POST /api/v1/guest/login/otp
POST /api/v1/guest/login/voucher
POST /api/v1/guest/consent
```

Admin-facing (RBAC `guest_users.*`/`guest_sessions.*`):

```text
GET  /api/v1/guests                            guest_users.read
GET  /api/v1/guests/{id}                       guest_users.read
POST /api/v1/guests/{id}/block                 guest_users.update
POST /api/v1/guests/{id}/unblock               guest_users.update
POST /api/v1/guests/{id}/reconnect             guest_sessions.execute
GET  /api/v1/guest-sessions                    guest_sessions.read
GET  /api/v1/guest-sessions/{id}                guest_sessions.read
POST /api/v1/guest-sessions/{id}/disconnect    guest_sessions.execute
POST /api/v1/guest-sessions/{id}/terminate     guest_sessions.execute
```

RADIUS-facing (NAS shared-secret authenticated):

```text
POST /api/v1/radius/authorize    NAS shared secret
POST /api/v1/radius/accounting   NAS shared secret
```

NAS admin management (RBAC-gated -- see `NAS_EXTENSION.md`):

```text
POST   /api/v1/radius/nas                            radius.create
GET    /api/v1/radius/nas                             radius.read
GET    /api/v1/radius/nas/{id}                         radius.read
PUT    /api/v1/radius/nas/{id}                          radius.update
DELETE /api/v1/radius/nas/{id}                           radius.delete
POST   /api/v1/radius/nas/{id}/activate                  radius.execute
POST   /api/v1/radius/nas/{id}/disable                   radius.execute
POST   /api/v1/radius/nas/{id}/regenerate-secret         radius.execute
GET    /api/v1/locations/{location_id}/nas              radius.read
GET    /api/v1/routers/{router_id}/nas                 radius.read
```

Analytics (RBAC `analytics.read`):

```text
GET /api/v1/guest-analytics/summary
GET /api/v1/guest-analytics/top-locations
GET /api/v1/guest-analytics/top-devices
GET /api/v1/guest-analytics/otp-success-rate
GET /api/v1/guest-analytics/voucher-usage
```

## Reused, Not Duplicated

* `OtpService.verify_otp` (Part 1) -- OTP verification.
* `VoucherService.redeem_voucher` (Part 2) -- voucher redemption; its own
  `VOUCHER_REDEEMED`/`VOUCHER_REDEMPTION_FAILED` audit entries are relied
  on directly, never duplicated.
* `CaptivePortalService.resolve_portal_config` (Part 3) -- enabled-method
  resolution.
* `RouterService.get_router`/`RouterStatus` (BE-008) -- NAS eligibility.
* `app.domains.router.crypto.encrypt_secret`/`decrypt_secret` (BE-008) --
  RADIUS shared-secret storage, reused verbatim, not reimplemented.
* `GenericRepository` (Module 002), `ApiResponse`/`build_response`
  (Module 001), `CloudGuestError` (Module 001), RBAC's `audit_log_entries`
  via the same narrow `AuditLogWriter` protocol shape every other domain
  uses, and RBAC's already-seeded `guest_wifi.*`/`guest_users.*`/
  `guest_sessions.*`/`radius.*`/`analytics.*` permission keys.

## New, Not Reused (Genuine Additions)

* `Guest`/`GuestDevice`/`GuestSession`/`GuestLoginHistory`/`GuestConsent`/
  `RadiusNasClient` -- genuinely new tables; nothing elsewhere models a
  returning-guest identity, device, or WiFi session.
* The FreeRADIUS `rlm_rest` HTTP integration pattern (`/radius/authorize`,
  `/radius/accounting`) -- BE-010's first (and only) RADIUS-facing surface.
* `GuestAnalyticsService`'s real SQL aggregate queries.
* NAS extension: `RadiusNasCodeCounter` (new table), `NasStatus`'s real
  status lifecycle, `nas_number_generator`'s `nas_code`/shared-secret
  generation, and every NAS admin CRUD/lifecycle endpoint -- see
  `NAS_EXTENSION.md`.

## Testing

`tests/unit/test_guest.py` exercises `GuestService`/`RadiusService`/
`GuestAnalyticsService` against small, hand-rolled in-memory fakes for the
repository and every composed cross-domain service (there is no live
Postgres/Redis in this environment). Coverage: OTP login (happy path,
disabled-method rejection, blocked-guest rejection, wrong-code failure
recording, router-ineligibility rejection), voucher login (happy path,
quota/timeout copied-not-referenced verification, disabled-method
rejection, invalid-code failure recording), device MAC handling (global
uniqueness with guest reassignment, normalization, sessions without a
device), session lifecycle (disconnect audited only when admin-initiated,
double-disconnect rejected, terminate always audited and distinct from
disconnect, reconnect creates a new row and is idempotent when already
active, reconnect rejected outside the grace window / with no prior
session, termination cooldown blocking and then allowing reconnect),
timeout/quota pure-function checks plus `enforce_timeouts`/`record_usage`
integration, the full RADIUS `authenticate_nas`/`authorize`/
`accounting_start`/`accounting_interim_update`/`accounting_stop` flow
(including wrong-secret/unknown-NAS/inactive-NAS/cross-router rejection),
analytics aggregate correctness (visitors/unique/returning guests,
bandwidth, top locations/devices, OTP success rate, voucher usage, empty
range), and tenant isolation.

**NAS extension addendum:** further coverage for `nas_code` generation
(real `location_code` embedding, the location-id-prefix fallback,
per-location sequence increments, independent sequences per location),
shared-secret auto-generation/explicit-override, `ip_address` defaulting
from the router's own public IP, the full lifecycle (get/list-by-status/
update/activate/disable/regenerate-secret/delete, status-transition
rejection, a disabled NAS failing authentication, a regenerated secret
invalidating the old one, deletion setting both the terminal status and
the ordinary soft-delete fields, every lifecycle action being audited), and
tenant isolation/denormalization correctness -- all against the same
in-memory fakes, no live Postgres/Redis required.
