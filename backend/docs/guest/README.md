# Module 010 Part 4: Guest

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
  app/
    domains/
      guest/
        __init__.py
        constants.py       # GuestAuthMethod, GuestSessionStatus, defaults, RADIUS headers
        models.py           # Guest, GuestDevice, GuestSession, GuestLoginHistory,
                             # GuestConsent, RadiusNasClient (see DATABASE.md)
        exceptions.py         # GuestError subclasses (CloudGuestError)
        events.py              # Plain dataclasses, logged synchronously by service.py
        validators.py            # Pure MAC/identifier normalization, transition/date checks
        repository.py             # GuestRepositoryProtocol + repo (incl. analytics SQL)
        service.py                 # GuestService, RadiusService, GuestAnalyticsService
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI dependency wiring, CurrentNas
        router.py                     # guest_router/admin_router/radius_router/analytics_router
      rbac/
        enums.py                     # AuditAction gained 5 additive GUEST_*/RADIUS_* values
    api/
      v1/
        router.py                    # all four guest routers registered
  docs/
    guest/
      README.md
      FLOW.md
      DATABASE.md
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

RADIUS-facing (NAS shared-secret authenticated, except `/radius/nas` which
is RBAC-gated -- see `FLOW.md` §7):

```text
POST /api/v1/radius/nas          radius.create   (RBAC-gated, admin)
POST /api/v1/radius/authorize    NAS shared secret
POST /api/v1/radius/accounting   NAS shared secret
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
range), and tenant isolation. All 432 previously-passing tests continue to
pass unmodified, plus 50 new tests here (482 total).
