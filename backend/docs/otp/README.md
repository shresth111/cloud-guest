# Module 010 Part 1: OTP

The OTP domain (`app.domains.otp`) authenticates **guests** at a captive
WiFi portal via a one-time passcode delivered by SMS or email -- it is
**not** platform-user authentication (that is `app.domains.auth`, unchanged
by this module). A guest presents a phone number or email address, receives
a short numeric code, and proves control of that identifier by presenting
the code back within a short expiry window.

This is BE-010's first part. No `Guest` model exists yet (a later module in
this same sequence) -- this module is deliberately self-contained, keyed by
the raw identifier string the guest supplies, not a foreign key to a
not-yet-existing table.

See `FLOW.md` for the full request/verify/rate-limit/expiry lifecycle and
every non-obvious design decision, and `DATABASE.md` for the one new table.

## OTP, In One Paragraph

`POST /otp/request` validates the identifier's shape for the given channel,
enforces a per-identifier request-rate limit (Redis, protecting the
delivery channel itself from spam), generates a cryptographically random
numeric code, stores only its SHA-256 hash, and "sends" it through a
pluggable `SmsProviderProtocol`/`EmailProviderProtocol` (today, an honest
logging-only default -- no real SMS/email integration exists anywhere in
this codebase). `POST /otp/verify` looks up the latest matching
`OtpRequest` for that identifier/purpose and enforces, in order: it exists,
it has not already been consumed, it has not exceeded its own per-code
attempt cap, it has not expired, and the presented code hashes to the
stored value. A successful verification marks the row consumed -- it can
never be reused -- and returns it to the caller for a future `guest` module
to compose with.

## What This Module Does NOT Do

* **It does not send a real SMS or email.** There is no Twilio/SendGrid
  credential, no existing "send a message" infrastructure anywhere in this
  codebase. `LoggingSmsProvider`/`LoggingEmailProvider` log the would-be-sent
  message via the structured logger instead of calling a real gateway --
  the same honest "interim design" posture `app.domains.wireguard`'s
  simulated tunnel health and `app.domains.router_provisioning`/
  `app.domains.router_agent`'s simulated device dispatch already establish.
  A real provider is a pure drop-in behind `SmsProviderProtocol`/
  `EmailProviderProtocol` -- no change to `OtpService` itself.
* **It does not model a `Guest`.** There is no persistent guest account,
  session, or captive-portal grant here -- only the OTP code's own request/
  verify lifecycle. The future `guest` module composes with this one
  purely through `OtpService.verify_otp`'s return value (a verified
  `OtpRequest` for a known identifier), never a shared table or FK.
* **It does not hash the code with Argon2id.** See `FLOW.md` §1 for the
  full reasoning -- in short, a short-lived, expiry- and attempt-capped
  numeric code is a different threat model than a long-lived user
  password, and SHA-256 is the same choice this codebase already made
  twice for other short-lived bearer credentials
  (`RouterProvisioningToken.token_hash`, `RouterAgentCredential
  .credential_hash`).
* **It does not require an RBAC permission for the guest-facing
  endpoints.** `POST /otp/request`/`POST /otp/verify` carry no
  `RequirePermission`/`CurrentUser` dependency -- mirrors BE-008's own
  `POST /routers/provisioning/check-in`. See `FLOW.md` §5.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0012_create_otp_tables.py
  app/
    domains/
      otp/
        __init__.py
        constants.py       # OtpChannel, OtpPurpose, Redis key template
        models.py           # OtpRequest (see DATABASE.md)
        exceptions.py         # OtpError subclasses (CloudGuestError)
        events.py              # Plain dataclasses, logged synchronously by service.py
        validators.py            # Pure identifier-shape checks (no I/O)
        repository.py             # OtpRepositoryProtocol + repo
        service.py                 # OtpService: code gen/hash, request/verify, rate limit, providers
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI dependency wiring
        router.py                     # FastAPI routes
      rbac/
        enums.py                     # AuditAction gained 3 additive OTP_* values
    core/
      config.py                      # Settings gained 5 additive otp_* fields
    api/
      v1/
        router.py                    # otp_router registered
  docs/
    otp/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_otp.py
```

## API Surface

Guest-facing endpoints (registered under `/api/v1`, see
`app/api/v1/router.py`) use the standard `ApiResponse`/`build_response`
envelope but carry **no** `RequirePermission`/`CurrentUser` dependency --
see `FLOW.md` §5:

```text
POST /api/v1/otp/request
POST /api/v1/otp/verify
```

One additive admin-facing endpoint, gated by RBAC's already-seeded
`otp.read` permission key:

```text
GET  /api/v1/otp/requests   otp.read
```

## Reused, Not Duplicated

* `GenericRepository` (Module 002) -- `OtpRepository` adds no hand-written
  SQL.
* `ApiResponse`/`build_response` (Module 001) for both guest-facing
  endpoints.
* RBAC's `audit_log_entries` (via the same narrow `AuditLogWriter` protocol
  shape every other domain's service uses) with 3 additive `AuditAction`
  values, and RBAC's already-seeded `otp.*` permission keys
  (`app.domains.rbac.seed.MODULE_ACTIONS[PermissionModule.OTP]`) for the
  one admin-facing endpoint.
* `secrets` (stdlib) for both code generation and constant-time hash
  comparison -- the same "use `secrets` for anything security-relevant"
  posture `app.domains.router_agent`'s credential generation already
  establishes.
* `hashlib.sha256` (stdlib) -- no new hashing dependency.
* `redis.asyncio.Redis` (already a dependency, `app.database.redis`) for
  request-rate limiting -- the identical INCR+EXPIRE+TTL pattern
  `app.domains.auth.security.AuthSecurity.check_rate_limit` already uses.
* `CloudGuestError` (Module 001).

## New, Not Reused (Genuine Additions)

* `OtpRequest` -- a genuinely new table; nothing elsewhere models a guest
  OTP code's lifecycle.
* `OtpRateLimiter` -- a from-scratch, per-identifier Redis rate limiter
  scoped specifically to OTP delivery-channel spam protection (distinct in
  purpose, though similar in mechanism, from `AuthSecurity`'s own).
  `OtpRequest.attempt_count`/`max_attempts` -- a from-scratch, per-code
  brute-force lockout, distinct from the Redis-backed request limiter.
* `SmsProviderProtocol`/`EmailProviderProtocol` -- genuinely new provider
  interfaces; no SMS/email sending abstraction existed anywhere in this
  codebase before this module.
* `Settings.otp_code_length`/`otp_expiry_seconds`/
  `otp_max_verification_attempts`/`otp_max_requests_per_window`/
  `otp_request_window_minutes` -- new, additive config fields following the
  exact pattern of every other domain-specific `Settings` field already in
  `app/core/config.py`.

## Testing

`tests/unit/test_otp.py` exercises `OtpService` against small, hand-rolled
in-memory fakes for its repository, Redis client, and audit writer (there
is no live Postgres/Redis in this environment), plus a recording test
double standing in for the provider protocols. Coverage: request+verify
happy path for both channels, organization/location context carried through
to the row, expiry enforcement, per-code attempt lockout (including that a
subsequently-correct code is still rejected once locked out), per-identifier
request-rate-limit enforcement (and that it is scoped per-identifier, not
global), consumed-OTP rejection (no reuse), not-found handling for an
identifier that never requested a code, malformed-identifier rejection
before any side effect, provider-interface invocation (each channel invokes
only its own provider), the honest logging-provider default, and the
audit-volume judgment call (`otp_verified`/adversarially-relevant
`otp_verification_failed` reasons are audited; routine failures and every
`otp_requested` call are not). All 317 previously-passing tests continue to
pass unmodified, plus 26 new tests here (343 total).
