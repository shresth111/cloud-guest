# Module 010 Part 2: Voucher

The Voucher domain (`app.domains.voucher`) manages pre-generated, printable
access codes an admin/location-manager hands out (printed, or given
verbally) to guests, who redeem them at the captive portal to get guest
WiFi access -- no username/password, no OTP round-trip. This is BE-010's
second part, built self-contained and independent of `app.domains.otp`
(BE-010 Part 1), before `captive_portal` and `guest`.

No `Guest` model exists yet (a later module in this same BE-010 sequence)
-- this module is deliberately self-contained, like OTP, recording a
redeeming guest's self-reported identifier (phone/email/device-MAC) as a
plain string, not a foreign key. The future `guest` module composes with
this one purely through `VoucherService.validate_voucher`/`redeem_voucher`'s
return values.

See `FLOW.md` for the full batch-lifecycle/redemption flow and every
non-obvious design decision, and `DATABASE.md` for the two new tables.

## Voucher, In One Paragraph

An admin creates a `VoucherBatch` (`POST /voucher-batches`) naming a
quantity, code shape (`code_length`/`code_prefix`), post-redemption
validity (`validity_minutes`), an optional batch-level shelf-life
(`batch_expires_at`), and how many times each voucher may be used
(`max_uses_per_voucher`). The batch starts `DRAFT`, is auto-submitted to
`PENDING_APPROVAL` in the same call, and -- unless the creator holds
`voucher.manage` (in which case it is auto-approved-and-activated) --
awaits a `voucher.approve` holder's decision (`POST .../approve`, which
performs both `-> APPROVED` and `APPROVED -> ACTIVE` in one call). Once
`ACTIVE`, its vouchers (bulk-generated with `secrets.choice` over a
print-friendly alphabet -- see `FLOW.md` §3) are redeemable: a guest
presents a code to `POST /vouchers/validate` (read-only check) or
`POST /vouchers/redeem` (mutating). The first redemption sets the
voucher's own `expires_at` (`redeemed_at + validity_minutes`) and
transitions it `UNUSED -> ACTIVE` (or straight to `EXHAUSTED` for a
single-use voucher); subsequent redemptions (up to `max_uses_per_voucher`)
just increment `use_count`.

## What This Module Does NOT Do

* **It does not hash the voucher code.** Unlike OTP codes/provisioning
  tokens, a voucher code is a physical/verbally-communicated artifact the
  platform must be able to display, print, and export in plaintext -- see
  `FLOW.md` §1 for the full reasoning. It is still uniquely indexed and
  looked up via parameterized queries.
* **It does not enforce `data_limit_mb`.** Stored as a bandwidth/data cap
  *hint* for a future `guest`/session-management module to enforce -- this
  module has no session/bandwidth-metering concept of its own yet.
* **It does not model a `Guest`.** `Voucher.redeemed_identifier` is a plain
  string, not a FK -- the identical "self-contained, no FK to a
  not-yet-existing table" posture `app.domains.otp.models.OtpRequest
  .identifier` already established.
* **It does not expose a separate "submit" or "activate" endpoint.** See
  `FLOW.md` §2 -- `create_batch` auto-submits, and `approve_batch`
  auto-activates, both in the same HTTP call.
* **It does not require an RBAC permission for the guest-facing
  endpoints.** `POST /vouchers/validate`/`POST /vouchers/redeem` carry no
  `RequirePermission`/`CurrentUser` dependency -- mirrors
  `app.domains.otp`'s identical `POST /otp/request`/`POST /otp/verify`
  precedent. See `FLOW.md` §7.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0013_create_voucher_tables.py
  app/
    domains/
      voucher/
        __init__.py
        constants.py       # VoucherBatchStatus/VoucherStatus, transition graph, code alphabet, rate-limit constants
        models.py           # VoucherBatch, Voucher (see DATABASE.md)
        exceptions.py         # VoucherError subclasses (CloudGuestError)
        events.py              # Plain dataclasses, logged synchronously by service.py
        validators.py            # Pure quantity/code-length/transition checks (no I/O)
        repository.py             # VoucherRepositoryProtocol + repo
        service.py                 # VoucherService: lifecycle, code gen, validate/redeem, export/import, stats
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI dependency wiring (incl. the voucher.manage bypass check)
        router.py                     # FastAPI routes
      rbac/
        enums.py                     # AuditAction gained 8 additive VOUCHER_* values
    api/
      v1/
        router.py                    # voucher_router registered
  docs/
    voucher/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_voucher.py
```

## API Surface

Admin-facing endpoints (registered under `/api/v1`), gated by RBAC's
existing `voucher.*` permission keys:

```text
POST /api/v1/voucher-batches                    voucher.create
GET  /api/v1/voucher-batches                    voucher.read
GET  /api/v1/voucher-batches/{id}                voucher.read
POST /api/v1/voucher-batches/{id}/approve        voucher.approve
POST /api/v1/voucher-batches/{id}/revoke         voucher.update
GET  /api/v1/voucher-batches/{id}/vouchers       voucher.read
GET  /api/v1/voucher-batches/{id}/export         voucher.export
GET  /api/v1/voucher-batches/{id}/stats          voucher.read
POST /api/v1/vouchers/import                     voucher.import
```

Guest-facing endpoints -- no `RequirePermission`/`CurrentUser`, see
`FLOW.md` §7:

```text
POST /api/v1/vouchers/validate
POST /api/v1/vouchers/redeem
```

## Reused, Not Duplicated

* `GenericRepository` (Module 002) -- `VoucherRepository` adds only the
  few hand-written statements `GenericRepository` genuinely can't express
  (a grouped per-status count, a bulk cascade-revoke `UPDATE`).
* `ApiResponse`/`build_response` (Module 001) for every endpoint except
  `GET .../export` (a deliberate, documented deviation -- see `FLOW.md` §6).
* RBAC's `audit_log_entries` (via the same narrow `AuditLogWriter`
  protocol shape every other domain's service uses) with 8 additive
  `AuditAction` values, and RBAC's already-seeded `voucher.*` permission
  keys.
* RBAC's `AccessValidator.has_permission` (a non-raising check) for the
  `voucher.manage` fast-path bypass -- composition with RBAC's public API,
  not a reimplementation of any part of it.
* `app.domains.organization.service.OrganizationService`/
  `app.domains.location.service.LocationService` (via narrow
  `OrganizationLookupProtocol`/`LocationLookupProtocol` shapes) for tenant/
  hierarchy validation -- mirrors `app.domains.router_provisioning`'s own
  composition-not-duplication precedent.
* `secrets` (stdlib) for code generation -- the same "use `secrets` for
  anything security-relevant" posture `app.domains.otp`/
  `app.domains.router_agent` already establish.
* `csv`/`io` (stdlib) for CSV export -- no new dependency.
* `redis.asyncio.Redis` (already a dependency) for redemption rate
  limiting -- the identical INCR+EXPIRE+TTL pattern
  `app.domains.otp.service.OtpRateLimiter` already uses.
* `CloudGuestError` (Module 001).

## New, Not Reused (Genuine Additions)

* `VoucherBatch`/`Voucher` -- genuinely new tables; nothing elsewhere
  models a voucher's generation/approval/redemption lifecycle.
* `VOUCHER_CODE_ALPHABET` -- a from-scratch, print-friendly alphabet
  (uppercase letters + digits, excluding `0`/`O`/`1`/`I`), independently
  derived for this module (not imported from any existing code-generation
  helper elsewhere in this codebase).
* `VoucherRedemptionRateLimiter` -- a from-scratch, per-source Redis rate
  limiter scoped specifically to voucher redemption/validation brute-force
  protection (distinct in purpose, though similar in mechanism, from
  `OtpRateLimiter`'s own).
* CSV export/pre-printed-code import -- genuinely new functionality; no
  export/import surface exists elsewhere in this codebase for a
  code-based, printable artifact.

## Testing

`tests/unit/test_voucher.py` exercises `VoucherService` against small,
hand-rolled in-memory fakes for its repository, Redis client, audit writer,
and organization/location lookups (there is no live Postgres/Redis in this
environment). Coverage: batch lifecycle (auto-submit, approve-and-activate,
the `voucher.manage` fast path, revoke-with-cascade, invalid transitions),
tenant isolation (cross-organization batch/location access), code
generation (uniqueness, print-friendly alphabet, prefix application,
bulk-size rejection, code-length bounds), validate-vs-redeem semantics
(validate never mutates), single-use vs. multi-use redemption (including
that `expires_at` is set once, at first redemption, and never recomputed),
expiry (both batch-level, which lazily flips a batch to `EXPIRED` on read,
and per-voucher post-redemption), CSV export correctness, pre-printed code
import (new codes, duplicate-within-request, duplicate-in-database,
import-into-a-dead-batch rejection), and redemption rate limiting
(exceeding the limit, and that it is scoped per-source). All 343
previously-passing tests continue to pass unmodified, plus 40 new tests
here (383 total).
