# OTP: Flows and Design Decisions

This document records every design decision this module made where the
brief left room for judgment, plus the end-to-end request/verify lifecycle.
Read this before modifying `app/domains/otp/`.

## 1. Hash choice: SHA-256, not Argon2id

**Decision: `service.hash_otp_code` uses a plain SHA-256 hex digest, not
`app.domains.auth.password.PasswordManager`'s Argon2id.**

`PasswordManager` hashes *user passwords* with a deliberately slow,
memory-hard KDF because a password is a long-lived secret an attacker who
steals the hash can attack offline, forever, at their own pace. An OTP code
is a fundamentally different kind of secret: it is a randomly-generated,
short numeric value (`Settings.otp_code_length`, default 6 digits) that is
already useless within minutes (`Settings.otp_expiry_seconds`, default
300) and can be guessed at most `max_attempts`
(`Settings.otp_max_verification_attempts`, default 5) times before that
specific row locks itself out. Argon2id's slow-hashing property defends
against an offline dictionary/brute-force attack against the *hash itself*
-- that is not the threat model here. The actual defense against guessing a
short numeric code is expiry plus the attempt cap, not hash cost; using
Argon2id would only add real per-request latency (a guest verifying a code
expects a fast response) for no additional security those two controls
don't already provide.

This is exactly the same judgment call this codebase already made twice:
`app.domains.router.models.RouterProvisioningToken.token_hash` and
`app.domains.router_agent.models.RouterAgentCredential.credential_hash`
both hash a short-lived, randomly-generated bearer credential with plain
SHA-256 (`app.domains.router_agent.service.hash_credential`) for the
identical reason.

Verification compares hashes with `secrets.compare_digest`, not `==` --
constant-time comparison, so response timing cannot leak how many leading
digits of a guess were correct.

## 2. The two distinct rate-limit dimensions

**Decision: request-rate limiting (Redis) and verification-attempt lockout
(a DB column) are two separate mechanisms, never conflated.**

1. **Request rate limiting** (`OtpRateLimiter`, Redis-backed,
   `Settings.otp_max_requests_per_window`/`otp_request_window_minutes`) --
   how many *new* codes a given identifier may request in a rolling
   window. This protects the delivery channel itself (a real phone
   number/email inbox, and this platform's SMS/email sending budget) from
   being spammed with codes nobody asked to receive. Enforced in
   `request_otp`, *before* any `OtpRequest` row is even created -- a
   rate-limited request never touches the database or a provider.
2. **Verification attempt lockout** (`OtpRequest.attempt_count` vs.
   `max_attempts`, `Settings.otp_max_verification_attempts`) -- how many
   times *one already-issued* code may be guessed before that specific
   code locks itself out. This protects against brute-forcing a live
   6-digit code. Enforced in `verify_otp`.

These mirror `app.domains.auth`'s own two distinct mechanisms
(`AuthSecurity.check_rate_limit`/`record_login_attempt` -- Redis-backed,
per email+IP request throttling -- versus `User.failed_login_attempts`/
`locked_until` -- a persisted, per-account lockout), applied to an
identifier string instead of a persistent `User` row, since no such row
exists for a guest yet. The naming mirrors that precedent too:
`otp_max_verification_attempts` parallels `max_login_attempts`;
`otp_request_window_minutes` parallels `account_lockout_minutes`.

`OtpRateLimiter` is scoped by identifier alone, not identifier+purpose or
+channel: the point is to protect the contact channel from spam, and that
risk exists regardless of which purpose a future caller passes. Scoping
per-purpose would let a caller reset an identifier's window just by
varying purpose, with no stronger justification for the extra
fragmentation.

## 3. Provider interfaces: `Protocol`, honest logging default

**Decision: `SmsProviderProtocol`/`EmailProviderProtocol` are structural
(`Protocol`) types; `LoggingSmsProvider`/`LoggingEmailProvider` are the only
implementations, and they only log.**

There is no real SMS/email provider anywhere in this codebase -- no
Twilio/SendGrid credentials, no existing "send a message" infrastructure at
all. Building a fake integration against a nonexistent gateway would be
worse than being honest about the gap: `LoggingSmsProvider`/
`LoggingEmailProvider` log the would-be-sent message
(`otp_sms_would_send`/`otp_email_would_send`) via the structured logger,
never pretending to call a real API. `dependencies.get_otp_service` wires
`sms_provider`/`email_provider` to `None`, which `OtpService.__init__`
interprets as "use the logging default" -- a real provider is a pure
substitution behind the same `Protocol` (e.g. overriding the FastAPI
dependency in a later module), with zero change to `OtpService` itself.
This is the identical "honestly documented interim boundary" posture
`app.domains.wireguard` uses for simulated tunnel health and
`app.domains.router_provisioning`/`app.domains.router_agent` use for
simulated device dispatch.

## 4. Audit-volume judgment call

**Decision: `otp_requested` is logged for every call but never written to
`audit_log_entries`; `otp_verified` and the two adversarially-relevant
`otp_verification_failed` reasons are both logged and audited.**

Three additive `AuditAction` values exist: `OTP_REQUESTED`, `OTP_VERIFIED`,
`OTP_VERIFICATION_FAILED`. Requesting a code is a high-volume,
guest-facing, entirely unauthenticated action (any caller can trigger it
for any identifier, bounded only by rate limiting) -- writing one row per
request to RBAC's `audit_log_entries` would flood a table this codebase's
own convention documents as scoped to "moderate-volume, human-attributable,
admin-reviewable" events, not general telemetry (the same reasoning
`app.domains.router_provisioning.models`'s module docstring gives for
keeping `RouterEvent`/`RouterHealthSnapshot` separate from
`audit_log_entries`). `OTP_REQUESTED` still exists as an `AuditAction`
value for forward-compatibility -- a future decision to start auditing it
needs no migration -- and every request is still logged via the structured
logger, just not written to the audit table.

`OTP_VERIFIED` (success) and `OTP_VERIFICATION_FAILED` (only for
`code_mismatch` and `attempts_exceeded` -- see `_AUDITED_FAILURE_REASONS`
in `service.py`) **are** written to the audit table: these are the
moderate-volume, security-relevant signal an admin/auditor would actually
want visibility into (was this identifier's guest-login flow being
brute-forced?). Routine, non-adversarial failures (`not_found`, `expired`,
`already_consumed`) are logged but not audited -- normal guest-side churn
(a guest waited too long, or double-submitted a form), not an attack
signal.

## 5. Guest-facing endpoints carry no RBAC permission

**Decision: `POST /otp/request`/`POST /otp/verify` have no
`RequirePermission`/`CurrentUser` dependency at all.**

The caller is a guest at a captive portal who by definition has no
platform-user identity or JWT to present -- there is no RBAC permission a
guest could ever be granted, since RBAC's whole model is platform-user
roles/permissions scoped to organizations/locations/routers. This mirrors
`app.domains.router.router.provisioning_check_in`'s exact justification
(see `docs/router/ROUTER_ARCHITECTURE.md` §5): abuse protection here comes
entirely from this module's own rate limiting (`OtpRateLimiter`,
per-identifier request throttling) and per-code attempt lockout
(`OtpRequest.max_attempts`), not from an authorization check that has no
meaningful subject to authorize.

The one admin-facing endpoint this module adds, `GET /otp/requests`, *is*
gated -- by RBAC's already-seeded `otp.read` permission
(`PermissionModule.OTP` in `app.domains.rbac.seed.MODULE_ACTIONS`) -- since
its caller is a platform user (support/audit staff), not a guest.

## 6. Error specificity vs. information leakage

**Decision: `verify_otp` raises a distinct exception per failure reason
(not-found, expired, already-consumed, attempts-exceeded, code-mismatch),
never a single collapsed "verification failed" error.**

`app.domains.auth.service.InvalidCredentialsError` intentionally collapses
"no such user" and "wrong password" into one message, to prevent username
enumeration against a *persistent* account an attacker does not otherwise
know exists. An OTP `identifier` is different: it is a phone number or
email address the guest themselves supplied moments earlier, in the very
same flow, via `POST /otp/request` -- there is no persistent account being
enumerated, and nothing a distinct `/otp/verify` error teaches an attacker
that they did not already know by virtue of being the party who (claims to
have) requested a code for that exact identifier. Clear, distinct errors
are therefore better guest-facing UX ("your code expired, request a new
one" vs. "wrong code, try again") with no meaningful security cost.

What must never leak, and never does: the code's own value, or anything
that narrows the brute-force search space below what
`OtpRequest.max_attempts` already bounds. `OtpCodeMismatchError` never
echoes the presented or expected code -- only an `attempts_remaining`
count, which the guest can already infer by counting their own tries.

## 7. Identifier validation: a loose regex, no new dependency

**Decision: `validators.validate_identifier` uses a hand-rolled,
deliberately loose regex for both phone numbers and email addresses -- no
`phonenumbers`/`email-validator` dependency added.**

Neither a carrier-grade phone-number library nor a full RFC 5322 email
parser exists anywhere else in this codebase. This module only needs to
catch obviously-malformed input (empty, letters where digits are expected,
wildly wrong length) before generating and "sending" a code -- not perform
exhaustive validation a determined guest could trivially route around
anyway (a real phone/email is only actually confirmed by the guest
successfully receiving and returning the code). Adding a new dependency for
marginal extra strictness was judged not to earn its keep.

## 8. Response envelope: the standard `ApiResponse`

**Decision: both guest-facing endpoints use the project's standard
`ApiResponse`/`build_response` envelope, unlike `app.domains.wireguard`/
`app.domains.router_agent`'s device-facing endpoints.**

Those device-facing endpoints are called by an embedded RouterOS agent
that has no reason to parse a rich, structured API contract. `/otp/request`
and `/otp/verify`, by contrast, are called by the guest-facing captive
-portal *frontend* -- a real web/app client that benefits from the same
consistent, structured success/message/data/request_id shape every other
user-facing endpoint in this codebase already returns.

## 9. `organization_id`/`location_id`: real, nullable FKs

**Decision: unlike `identifier` (a plain string, no FK target exists yet),
`organization_id`/`location_id` are real, nullable foreign keys to the
already-existing `organizations`/`locations` tables.**

A captive portal is always scoped to a specific organization/location's
guest WiFi, so carrying that context on the `OtpRequest` row itself (rather
than only on whatever downstream entity eventually consumes it) lets rate
limiting, audit filtering, and admin visibility (`GET /otp/requests`) all
be scoped by tenant without a join through a table (`Guest`) that does not
exist yet. Both are nullable because this module does not itself validate
that a caller-supplied id resolves to a real row -- an invalid id is caught
by the database's own FK constraint at insert time, not a cross-domain
lookup this genuinely self-contained module deliberately does not perform
(it has no `OrganizationService`/`LocationService` dependency at all).

## End-to-End Flow

1. **Request.** `POST /otp/request` with `identifier`, `channel`,
   optional `purpose` (defaults to `guest_login`), optional
   `organization_id`/`location_id`. `OtpService.request_otp`:
   a. Strips and validates the identifier's shape for the given channel
      (`validators.validate_identifier`) -- raises
      `InvalidOtpIdentifierError` (400) before any side effect.
   b. Checks and increments the Redis request-rate counter
      (`OtpRateLimiter.check_and_increment`) -- raises
      `OtpRequestRateLimitExceededError` (429, with `retry_after_seconds`)
      if the identifier has already hit `otp_max_requests_per_window`
      within the current `otp_request_window_minutes` window.
   c. Generates a cryptographically random numeric code
      (`generate_numeric_code`, `secrets.choice`), hashes it
      (`hash_otp_code`, SHA-256), and creates an `OtpRequest` row with
      `expires_at = now + otp_expiry_seconds` and
      `max_attempts = otp_max_verification_attempts`.
   d. Dispatches the plaintext code through the appropriate provider
      (`SmsProviderProtocol`/`EmailProviderProtocol`) -- today, the
      logging-only default.
   e. Logs `otp_requested`; does **not** write to `audit_log_entries`
      (see §4).
2. **Verify.** `POST /otp/verify` with `identifier`, `code`, optional
   `purpose`. `OtpService.verify_otp` looks up the latest `OtpRequest` for
   that identifier/purpose and checks, in order:
   a. **Exists?** No matching row at all -> `OtpNotFoundError` (404).
   b. **Already consumed?** `is_consumed` is one-way -> once `True`, a row
      can never be presented successfully again ->
      `OtpAlreadyConsumedError` (409).
   c. **Locked out?** `attempt_count >= max_attempts` ->
      `OtpAttemptsExceededError` (429) -- checked *before* expiry, so a
      locked-out code is reported as locked-out even if it also happens
      to be expired.
   d. **Expired?** `now > expires_at` -> `OtpExpiredError` (410).
   e. **Hash mismatch?** `secrets.compare_digest(hash_otp_code(code),
      code_hash)` fails -> increments `attempt_count`, raises
      `OtpCodeMismatchError` (400, with `attempts_remaining`).
   f. **Success.** Sets `is_consumed = True`, `verified_at = now`; logs
      `otp_verified`; writes one `audit_log_entries` row
      (`AuditAction.OTP_VERIFIED`).
   Steps (a)-(e) each log a warning (`otp_verification_failed`) with a
   `reason`; only `code_mismatch` and `attempts_exceeded` additionally
   write an audit row (see §4).
