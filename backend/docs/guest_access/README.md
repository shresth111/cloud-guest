# Guest Access Control (Phase 1)

The Guest Access Control domain (`app.domains.guest_access`) is a new
module implementing the roadmap's "Guest Access Control" sub-item of the
Guest Session Engine phase: guest whitelist/blocklist, device
whitelist/blocklist, temporary access, and VIP access.

## Why a new module, not an extension

A gap analysis (see `docs/ARCHITECTURE_DESIGN.md`) found
`Guest.is_blocked`/`blocked_reason` plus `GuestService.block_guest`/
`unblock_guest` already implement a basic, permanent-only, guest-level
blocklist -- but nothing else this roadmap item asks for existed: no
whitelist concept, no device-level rules, no temporary/bounded-window
access, no VIP tier, and the existing mechanism only works *after* a
`Guest` row has already been created on first login. This module is a
genuine new build.

## Two rule tables, identifier/MAC-keyed, not FK-keyed

* `GuestAccessRule` -- keyed by a guest login `identifier` (phone/email/
  etc.), not `guest_id`. A rule must be able to exist and take effect
  *before* a `Guest` row is ever created.
* `DeviceAccessRule` -- keyed by `mac_address`, the identical reasoning.

Both share one `rule_type` column (`whitelist`/`blocklist`/`temporary`/
`vip`) rather than one table per type. See `models.py`'s module docstring
for the full reasoning.

## Default-allow, not deny-by-default

This module does **not** turn the platform into a whitelist-only system. A
guest with zero matching rules is allowed, exactly as before this module
existed. `WHITELIST` rules exist to guarantee precedence over some other
rule, not to gate access by themselves. True deny-by-default is explicitly
deferred to the Phase 2 Policy Engine's `AccessPolicy` type -- see
`docs/ARCHITECTURE_DESIGN.md` §13.

## Precedence

`AccessDecisionResolver.resolve` (in `service.py`) resolves, highest
first: `VIP` > `TEMPORARY` > `BLOCKLIST` > `WHITELIST` > default-allow.
Guest-level and device-level rules are resolved together as one combined
candidate set -- a VIP-tagged device overrides a blocklisted guest
identity, and vice versa.

## Composition with `app.domains.guest`, not duplication

This module has **zero import-time dependency on `app.domains.guest`**.
The dependency runs the other direction: `GuestService` (in
`app.domains.guest.service`) gained a new, optional, `None`-by-default
`access_control_hook` constructor parameter -- the identical additive-hook
pattern its existing `monitoring_hook` already established -- duck-typed
against this module's `GuestAccessService` via `AccessDecisionProtocol`.
When wired (see `app.domains.guest.dependencies.get_guest_service`), it is
called from `login_via_otp`/`login_via_voucher` immediately after the
existing `Guest.is_blocked` check, before any concurrent-session check or
OTP/voucher verification -- a denied guest never spends a real OTP attempt
or a voucher. **Unlike** `monitoring_hook`, this hook is not wrapped in a
blanket try/except: a resolved `BLOCKLIST` decision is a real authorization
gate and must propagate as `GuestAccessDeniedError`, not fail open.

## API

All endpoints under `/api/v1/guest-access/*`, RBAC-gated by the new
`guest_access.*` permission keys (`PermissionModule.GUEST_ACCESS`):

* `POST/GET /guest-access/rules`, `GET/DELETE /guest-access/rules/{id}`,
  `POST /guest-access/rules/{id}/deactivate` -- guest (identifier-keyed)
  rule CRUD.
* The identical five endpoints under `/guest-access/device-rules` for
  device (MAC-keyed) rules.
* `POST /guest-access/check` -- admin-facing "would this identifier/MAC be
  allowed to connect right now" preview, running the exact same
  `AccessDecisionResolver.resolve` real login-time enforcement uses.

## Database

Two new tables (migration `0027_create_guest_access_tables`):
`guest_access_rules`, `device_access_rules`. Neither has a foreign key to
`guests`/`guest_devices` -- see `models.py`'s module docstring. No RBAC FK
follow-up migration is needed.

## Testing

`tests/unit/test_guest_access.py` -- pure `AccessDecisionResolver`
precedence tests, rule CRUD/tenant-scoping, and the `check_access` decision
path against both rule tables. `tests/unit/test_guest.py`'s
`TestAccessControlHookIntegration` class covers the `GuestService`
enforcement hook itself, including that a denied login never reaches OTP
verification or voucher redemption, and that the default
(`access_control_hook=None`) behaves exactly as before this module existed.
