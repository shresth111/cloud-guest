# CloudGuest API Documentation

## Response Envelope

All API responses use the CloudGuest response envelope:

```json
{
  "success": true,
  "message": "",
  "data": {},
  "request_id": ""
}
```

`request_id` is generated per request unless the caller provides `X-Request-ID`.

## Versioning

Module 001 exposes API version 1 under:

```text
/api/v1
```

## Health Endpoints

### Liveness

```http
GET /api/v1/health/live
```

Returns service name, environment and uptime. This endpoint does not require
PostgreSQL or Redis to be reachable.

### Readiness

```http
GET /api/v1/health/ready
```

Checks PostgreSQL with `SELECT 1` and Redis with `PING`.

Status codes:

- `200` when all required dependencies are available.
- `503` when PostgreSQL or Redis is unavailable.

## Security Headers

Every response includes:

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Strict-Transport-Security`

## RBAC Endpoints (Module 004)

Roles, permissions, and user-role assignment. See
`backend/docs/rbac/README.md` and `backend/docs/rbac/RBAC_ARCHITECTURE.md`
for the full design.

```text
GET    /api/v1/roles
POST   /api/v1/roles
PUT    /api/v1/roles/{role_id}
DELETE /api/v1/roles/{role_id}
POST   /api/v1/roles/{role_id}/clone
POST   /api/v1/roles/{role_id}/activate
POST   /api/v1/roles/{role_id}/deactivate
GET    /api/v1/permissions
GET    /api/v1/permission-groups
POST   /api/v1/users/{user_id}/roles
DELETE /api/v1/users/{user_id}/roles/{role_assignment_id}
GET    /api/v1/users/{user_id}/permissions
GET    /api/v1/me/permissions
```

Mutating/protected endpoints require the appropriate `roles.*`/`permissions.*`
permission at the resolved scope (`X-Organization-Id`/`X-Location-Id`/
`X-Router-Id` headers supply scope context; see `RBAC_ARCHITECTURE.md` §7).

## Organization Endpoints (Module 005)

Tenant CRUD, MSP hierarchy, and membership management. See
`backend/docs/organization/README.md` and
`backend/docs/organization/ORGANIZATION_ARCHITECTURE.md` for the full
design.

```text
GET    /api/v1/organizations
POST   /api/v1/organizations
GET    /api/v1/organizations/{organization_id}
PUT    /api/v1/organizations/{organization_id}
DELETE /api/v1/organizations/{organization_id}
POST   /api/v1/organizations/{organization_id}/suspend
POST   /api/v1/organizations/{organization_id}/activate
GET    /api/v1/organizations/{organization_id}/children
GET    /api/v1/organizations/{organization_id}/members
POST   /api/v1/organizations/{organization_id}/members
DELETE /api/v1/organizations/{organization_id}/members/{member_id}
POST   /api/v1/organizations/{organization_id}/members/{member_id}/accept
GET    /api/v1/me/organizations
```

Mutating/protected endpoints require the appropriate `organizations.*`
permission (`create`/`read`/`update`/`delete`/`manage`) at the resolved
scope. `DELETE /organizations/{id}` archives (soft-deletes); it never hard-
deletes. `X-Organization-Id` is now validated against real membership data
(RBAC's `CurrentOrganization`, updated in this module) rather than trusted
at face value -- see `ORGANIZATION_ARCHITECTURE.md` §5.
`/organizations/{id}/members/{member_id}/accept` requires only that the
caller is the invited user, not any `organizations.*` permission (an
invited member holds none yet).

## Location Endpoints (Module 006)

Physical sites (Organization -> Location -> Router -> Guest) belonging to
exactly one organization. See `backend/docs/location/README.md` and
`backend/docs/location/LOCATION_ARCHITECTURE.md` for the full design.

```text
GET    /api/v1/organizations/{organization_id}/locations
POST   /api/v1/organizations/{organization_id}/locations
GET    /api/v1/locations/{location_id}
PUT    /api/v1/locations/{location_id}
DELETE /api/v1/locations/{location_id}
POST   /api/v1/locations/{location_id}/suspend
POST   /api/v1/locations/{location_id}/activate
```

Mutating/protected endpoints require the appropriate `locations.*`
permission (`create`/`read`/`update`/`delete`/`manage`) at the resolved
scope. `DELETE /locations/{id}` archives (soft-deletes); it never hard-
deletes. `organization_id` is immutable after creation (not present on the
update schema) -- see `LOCATION_ARCHITECTURE.md` §5. Every endpoint enforces
organization-tenant scoping via `requesting_organization_id`
(`X-Organization-Id`), the same as the Organization domain's own endpoints
-- see `LOCATION_ARCHITECTURE.md` §6. `X-Location-Id` (RBAC's
`CurrentLocation`, updated in this module) is now validated against a real,
non-archived location whose `organization_id` matches the resolved
`X-Organization-Id` context, rather than trusted at face value -- see
`LOCATION_ARCHITECTURE.md` §8.

## User Management Endpoints (Module 007)

An aggregation/management layer over the existing `auth.User`,
`OrganizationMember`, and RBAC domains -- not a second user table. See
`backend/docs/user/README.md` and `backend/docs/user/USER_ARCHITECTURE.md`
for the full design.

```text
GET    /api/v1/users
POST   /api/v1/users
GET    /api/v1/users/{user_id}
PUT    /api/v1/users/{user_id}
POST   /api/v1/users/{user_id}/deactivate
POST   /api/v1/users/{user_id}/activate
GET    /api/v1/me
PUT    /api/v1/me
```

Admin endpoints require the appropriate `users.*` permission
(`create`/`read`/`update`/`manage`) at the resolved scope; `/me` endpoints
require only an authenticated caller. `GET /users/{id}` and `GET /me`
return an aggregated view (identity + organization memberships + active
roles) assembled by `UserService`, not a persisted model. `PUT /me` exposes
a narrower, self-editable field set than admin's `PUT /users/{id}` -- see
`USER_ARCHITECTURE.md` §8 for the exact table (in particular: `email`/
`username`/`is_active`/`status` are never editable via either `PUT`, and
`designation`/`department`/`employee_id`/`is_verified` are admin-only).
`POST /users` optionally creates an active organization membership and an
initial `ORGANIZATION`-scoped role assignment in the same call -- see
`USER_ARCHITECTURE.md` §5 and §10. This module does not duplicate RBAC's
own `POST/DELETE /users/{id}/roles`, `GET /users/{id}/permissions`, or
`GET /me/permissions` endpoints, all of which remain unchanged.

## Router Endpoints (Module 008)

MikroTik RouterOS device records: registration, lifecycle, health, and
zero-touch provisioning (Organization -> Location -> Router -> Guest) --
not the guest-facing captive portal/hotspot/network-service configuration
layered on top of a router (separate future modules). See
`backend/docs/router/README.md` and
`backend/docs/router/ROUTER_ARCHITECTURE.md` for the full design.

```text
GET    /api/v1/locations/{location_id}/routers
POST   /api/v1/locations/{location_id}/routers
GET    /api/v1/routers/{router_id}
PUT    /api/v1/routers/{router_id}
DELETE /api/v1/routers/{router_id}
POST   /api/v1/routers/{router_id}/suspend
POST   /api/v1/routers/{router_id}/reinstate
POST   /api/v1/routers/{router_id}/provisioning-token
POST   /api/v1/routers/{router_id}/heartbeat
POST   /api/v1/routers/provisioning/check-in
```

Mutating/protected endpoints require the appropriate `routers.*` permission
(`create`/`read`/`update`/`delete`/`manage`) at the resolved scope; `DELETE
/routers/{id}` decommissions (soft-deletes), it never hard-deletes.
`location_id`/`organization_id` are immutable after creation (not present
on the update schema) -- see `ROUTER_ARCHITECTURE.md` §1. Every user-facing
endpoint enforces organization-tenant scoping via
`requesting_organization_id` (`X-Organization-Id`), the same as
Organization/Location/User's own endpoints. `POST
/routers/{id}/provisioning-token` additionally requires
`router_provisioning.approve` alongside `router_provisioning.create` --
see `ROUTER_ARCHITECTURE.md` §5. `POST /routers/provisioning/check-in` is
the one endpoint in this API that is **not** authenticated as a platform
user at all: it is presented by the physical device itself, using a
single-use provisioning token (issued by the token-generation endpoint) as
its sole credential, submitted in the request body rather than as a bearer
header, and its response is a minimal, non-`ApiResponse`-envelope shape --
see `ROUTER_ARCHITECTURE.md` §5 for the full auth-scheme reasoning. Router
API connection credentials (RouterOS username/password or API key) are
Fernet-encrypted at rest (`app.domains.router.crypto`) -- an interim design
pending a real secrets-manager/KMS integration, documented in
`ROUTER_ARCHITECTURE.md` §3; no response ever returns the ciphertext or a
decrypted secret, only a `has_api_credentials` boolean flag.

## Router Provisioning Endpoints (Module 009 Part 1)

Configuration templates/variables/profiles/versions, a durable provisioning
queue, device-initiated enrollment + admin approval, backup/restore,
factory reset, router secret rotation, and health/event history -- extends
Module 008's router registration/zero-touch-provisioning/heartbeat flows
without duplicating any of them. See
`backend/docs/router_provisioning/README.md`,
`backend/docs/router_provisioning/FLOW.md`, and
`backend/docs/router_provisioning/DATABASE.md` for the full design.

```text
GET    /api/v1/router-templates
POST   /api/v1/router-templates
GET    /api/v1/router-templates/{template_id}
PUT    /api/v1/router-templates/{template_id}
DELETE /api/v1/router-templates/{template_id}

GET    /api/v1/router-templates/variables
POST   /api/v1/router-templates/variables
PUT    /api/v1/router-templates/variables/{variable_id}
DELETE /api/v1/router-templates/variables/{variable_id}

POST   /api/v1/routers/{router_id}/config-profile

GET    /api/v1/routers/{router_id}/config-versions
GET    /api/v1/routers/{router_id}/config-versions/{version_id}
GET    /api/v1/routers/{router_id}/config-versions/{version_id}/diff/{other_version_id}
POST   /api/v1/routers/{router_id}/config-versions/{version_id}/rollback
POST   /api/v1/routers/{router_id}/config-versions/{version_id}/apply

POST   /api/v1/router-enrollment
GET    /api/v1/router-enrollment
POST   /api/v1/router-enrollment/{enrollment_id}/approve
POST   /api/v1/router-enrollment/{enrollment_id}/reject

GET    /api/v1/routers/{router_id}/provisioning-status
POST   /api/v1/routers/{router_id}/backup
POST   /api/v1/routers/{router_id}/restore/{backup_id}
POST   /api/v1/routers/{router_id}/factory-reset
POST   /api/v1/routers/{router_id}/rotate-secret

POST   /api/v1/routers/{router_id}/health-snapshot
GET    /api/v1/routers/{router_id}/health-history
GET    /api/v1/routers/{router_id}/events
```

Every endpoint except `POST /router-enrollment` requires the appropriate
`router_provisioning.*`/`templates.*` permission (see
`app/domains/rbac/seed.py::MODULE_ACTIONS`) and enforces organization-tenant
scoping via `requesting_organization_id` (`X-Organization-Id`), inherited
almost entirely from BE-008's own `RouterService.get_router` tenant checks
(composed through a narrow `RouterLookupProtocol`, never duplicated).
`POST /router-enrollment` is device-facing and carries no
`RequirePermission`/`CurrentUser` dependency at all -- mirroring BE-008's
own `POST /routers/provisioning/check-in`, see `FLOW.md` §3 for the
minimal-trust-boundary reasoning. `POST /routers/{id}/health-snapshot`
supplements (never replaces) `POST /routers/{id}/heartbeat` -- it calls
BE-008's own heartbeat method first, then additionally records a
`RouterHealthSnapshot` history row (see `FLOW.md` §5). Config version
diffs use Python's stdlib `difflib` (no new dependency). Router secret
rotation generates a new credential and stores it via BE-008's existing
`RouterService.update_router` (which itself calls
`app.domains.router.crypto.encrypt_secret` internally) -- this module never
touches encryption directly; the new plaintext secret is returned exactly
once, mirroring `ProvisioningTokenResponse.token`'s "shown once" convention.
`complete_provisioning_job` (the seam that realizes a queued job's
real-world side effects -- a version becoming `applied`, a restore
producing a new version, a factory reset resetting the router's BE-008
status) is intentionally **not** exposed over HTTP: this module manages the
workflow/queue side only, actually executing a job against a live device is
`app.domains.router_agent`'s job.

## Router Agent Endpoints (Module 009 Part 2)

The device-facing protocol a real MikroTik RouterOS agent uses for its
entire ongoing lifecycle after BE-008's zero-touch provisioning has
completed: a persistent device credential, heartbeat, current-configuration
pull, status push, and provisioning-action-queue poll/complete -- the
module `app.domains.router_provisioning.service`'s own docstring names as
the intended caller of `complete_provisioning_job`. See
`backend/docs/router_agent/README.md`, `backend/docs/router_agent/FLOW.md`,
and `backend/docs/router_agent/DATABASE.md` for the full design.

```text
POST   /api/v1/agent/heartbeat
GET    /api/v1/agent/config
POST   /api/v1/agent/status
GET    /api/v1/agent/actions
POST   /api/v1/agent/actions/{job_id}/complete
```

**Every endpoint above is device-facing** -- none carry
`RequirePermission`/`CurrentUser`, and none use the standard `ApiResponse`
envelope (mirroring `ProvisioningCheckInResponse`'s own minimal, "the
calling device is not expected to parse a rich, user-facing API contract"
shape). Authentication is this module's own `CurrentAgent` dependency: a
persistent credential presented via the `X-Agent-Credential` header
(deliberately not `Authorization: Bearer`, which is already RBAC's
platform-user JWT scheme, and deliberately a header rather than
BE-008/BE-009's request-body-token precedent, since two of these five
endpoints are `GET`s -- see `FLOW.md` §3). `CurrentAgent` rejects a
missing/invalid/expired/revoked credential and a `decommissioned`/
`suspended` router -- this check *is* the module's identity verification,
there is no separate "verify identity" endpoint (`FLOW.md` §4).

The persistent credential itself is **not** issued by any endpoint above --
it is issued additively inside BE-008's own
`POST /api/v1/routers/provisioning/check-in` response
(`ProvisioningCheckInResponse` gained two new, optional fields:
`agent_credential`, `agent_credential_expires_at`), since that check-in call
is the device's last opportunity to authenticate itself with a credential
this platform already trusts before the one-time provisioning token is
consumed (`FLOW.md` §2). `GET /agent/config` returns Module 009 Part 1's
current, latest-*applied* `ConfigVersion` (never a draft/pending/failed
one). `GET /agent/actions` composes with
`RouterProvisioningRepository.list_active_jobs_for_router`, claiming
(transitioning to `running`) every still-`queued` job via
`RouterProvisioningService.start_provisioning_job`; `POST
/agent/actions/{job_id}/complete` calls
`RouterProvisioningService.complete_provisioning_job` directly -- the exact
seam that service's own docstring names this module as the caller of.
`POST /agent/status` updates BE-008's existing `Router.routeros_version`
(via `RouterService.update_router`, only when it actually changed) and
records genuinely new facts (agent software version, capabilities, license
state) on this module's own `RouterAgentCredential` row, never a duplicate
of any existing field.

## WireGuard Endpoints (Module 009 Part 3)

Cloud-managed WireGuard tunnels between the platform's hub and each
router-peer, so the platform can always reach a router's management
interface even when it sits behind carrier-grade NAT with no public IP.
The platform generates both sides' keypairs (the hub's and each
router-peer's) -- see `backend/docs/wireguard/README.md`,
`backend/docs/wireguard/FLOW.md`, and `backend/docs/wireguard/DATABASE.md`
for the full design.

Admin-facing endpoints use the standard `ApiResponse` envelope and are
gated by RBAC's `RequirePermission` against the already-seeded
`wireguard.*` permission keys:

```text
GET    /api/v1/routers/{router_id}/wireguard-peer          wireguard.read
POST   /api/v1/routers/{router_id}/wireguard-peer          wireguard.create
DELETE /api/v1/routers/{router_id}/wireguard-peer          wireguard.delete
POST   /api/v1/routers/{router_id}/wireguard-peer/rotate   wireguard.execute
```

`GET` returns the peer's current status, tunnel IP, and a computed
`health_status` (`healthy`/`stale`/`unknown`/`revoked`, derived from
`last_handshake_at` against `Settings.wireguard_handshake_stale_after_minutes`
-- a DB-tracked, device-reported signal, not a live `wg show` integration).
`POST` creates a fresh tunnel (rejecting the call if the router already has
one -- revoke it first) and returns the peer's own private key once, for
manual configuration, alongside the hub's public connection details.
`DELETE` revokes the tunnel (its IP becomes available for reuse). `POST
.../rotate` generates a new keypair for the same peer, keeping its existing
tunnel IP unchanged (see `FLOW.md` §6 for why tunnel rotation and key
rotation are the same operation here).

Device-facing endpoints are authenticated by
`app.domains.router_agent`'s own `CurrentAgent` dependency (the
`X-Agent-Credential` header) -- reused as-is, not reimplemented -- and,
mirroring that module's own device-facing endpoints, do not use the
`ApiResponse` envelope:

```text
GET  /api/v1/agent/wireguard-config
POST /api/v1/agent/wireguard-config/handshake
```

`GET /agent/wireguard-config` returns the device's own (decrypted) private
key plus the hub's public key/endpoint/tunnel CIDR needed to configure a
local WireGuard interface -- unlike a one-time provisioning token, this is
repeatable: the device may re-pull it any number of times, since the
platform is its permanent custodian (see `FLOW.md` §9). The hub's private
key is never included in any device-facing response.
`POST /agent/wireguard-config/handshake` is an additive endpoint (beyond
this module's literal five admin/device endpoints) recording a device
-reported handshake, updating `last_handshake_at` for the health-status
computation above -- see `FLOW.md` §8 for why this is a small, dedicated
endpoint rather than composing through `router_agent`'s own
`POST /agent/status`.

## OTP Endpoints (Module 010 Part 1)

Guest-facing one-time-passcode request/verification for guest WiFi
captive-portal logins via SMS or email -- **not** platform-user
authentication (that remains `app.domains.auth`, unchanged). No `Guest`
model exists yet (a later module in this same BE-010 sequence); this
module is self-contained, keyed by the raw phone/email identifier the
guest supplies. See `backend/docs/otp/README.md`,
`backend/docs/otp/FLOW.md`, and `backend/docs/otp/DATABASE.md` for the full
design.

```text
POST /api/v1/otp/request
POST /api/v1/otp/verify

GET  /api/v1/otp/requests   otp.read
```

`POST /otp/request`/`POST /otp/verify` carry no `RequirePermission`/
`CurrentUser` dependency at all -- the caller is an unauthenticated guest
at a captive portal, with no platform-user identity RBAC could ever grant
a permission to (mirrors BE-008's own
`POST /routers/provisioning/check-in`; see `FLOW.md` §5). Abuse protection
comes entirely from this module's own two distinct rate-limit mechanisms:
a Redis-backed, per-identifier request throttle
(`Settings.otp_max_requests_per_window`/`otp_request_window_minutes`)
protecting the delivery channel from spam, and a persisted, per-code
verification-attempt lockout
(`Settings.otp_max_verification_attempts`) protecting against brute-forcing
a live code -- see `FLOW.md` §2. Both guest-facing endpoints use the
standard `ApiResponse` envelope (unlike the device-facing endpoints
elsewhere in this API), since their caller is the captive-portal
*frontend*, a real client that benefits from the same structured contract
every other user-facing endpoint returns. OTP codes are stored only as a
SHA-256 hash (`OtpRequest.code_hash`) -- never Argon2id, since a short
-lived, expiry- and attempt-capped numeric code is a different threat model
than a long-lived user password (`FLOW.md` §1); no response ever returns
the code's plaintext value or its hash. `GET /otp/requests` is an
additive, admin-facing endpoint gated by RBAC's already-seeded `otp.read`
permission, giving platform support/audit visibility into a captive
portal's OTP traffic without exposing any code value.

## Voucher Endpoints (Module 010 Part 2)

Pre-generated, printable access codes an admin/location-manager hands out
to guests, who redeem them at the captive portal for guest WiFi access --
no username/password, no OTP round-trip. Self-contained like OTP: no
`Guest` model exists yet (a later module in this same BE-010 sequence). See
`backend/docs/voucher/README.md`, `backend/docs/voucher/FLOW.md`, and
`backend/docs/voucher/DATABASE.md` for the full design.

Admin-facing endpoints use the standard `ApiResponse` envelope (except
`GET .../export`, see below) and are gated by RBAC's already-seeded
`voucher.*` permission keys:

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

A batch starts `DRAFT`, is auto-submitted to `PENDING_APPROVAL` in the same
`POST /voucher-batches` call, and -- unless the creator holds
`voucher.manage` (in which case the batch is auto-approved-and-activated,
skipping the queue) -- awaits a `voucher.approve` holder's decision.
`POST .../approve` performs both `-> APPROVED` and `APPROVED -> ACTIVE` in
one call; this module has no separate activation endpoint (see `FLOW.md`
§2). `POST .../revoke` (`voucher.update`, not `voucher.delete`/`.manage` --
revoking is a lifecycle status change, not a destructive or platform-
admin-only action) cascades to every non-terminal voucher in the batch.
`GET .../export` deliberately returns raw `text/csv`, not
`ApiResponse`-wrapped JSON -- a downloadable file a print vendor opens
directly cannot usefully be JSON-wrapped (`FLOW.md` §8). `POST
/vouchers/import` bulk-registers pre-printed codes from an external
system/print vendor into an existing batch, with partial-success reporting
(valid codes inserted, duplicates/invalid codes reported individually).

Guest-facing endpoints carry no `RequirePermission`/`CurrentUser`
dependency at all -- the caller is an unauthenticated guest at a captive
portal, with no platform-user identity RBAC could ever grant a permission
to (mirrors OTP's identical precedent; see `FLOW.md` §7). Abuse protection
comes entirely from a Redis-backed, per-source (IP address) redemption
rate limiter, distinct from OTP's own per-identifier request throttle.
Both still use the standard `ApiResponse` envelope, since their real caller
is the captive-portal frontend:

```text
POST /api/v1/vouchers/validate
POST /api/v1/vouchers/redeem
```

`POST /vouchers/validate` is a read-only check (never mutates a voucher's
state) returning whether a code is currently redeemable, its remaining
uses, and its post-redemption expiry if already set. `POST
/vouchers/redeem` performs the actual redemption: the first redemption sets
the voucher's own `expires_at` (`redeemed_at + validity_minutes` -- computed
at first use, not at generation time, since `validity_minutes` is a
post-redemption duration, see `FLOW.md` §4) and transitions
`UNUSED -> ACTIVE` (or straight to `EXHAUSTED` for a single-use voucher, the
default); subsequent redemptions of a multi-use voucher just increment
`use_count`/`last_used_at`. Voucher codes are stored in plaintext, never
hashed (`Voucher.code`) -- unlike OTP codes/provisioning tokens, a voucher
is a physical/verbally-communicated artifact the platform must be able to
display/print/export (`FLOW.md` §1). Every successful redemption is written
to RBAC's audit log (`AuditAction.VOUCHER_REDEEMED`) -- a deliberate
departure from OTP's own "don't audit the routine event" call, since a
voucher redemption is itself the moment real network access is granted
(`FLOW.md` §9).

## Captive Portal Endpoints (Module 010 Part 3)

Branding/content/enabled-login-methods configuration for the guest WiFi
login page a guest's device is redirected to before getting internet
access -- logo, colors, terms and conditions, splash content, and which
login methods (OTP SMS/email, voucher, username/password, social login)
are enabled. This module does **not** implement guest authentication
itself (that is `app.domains.otp`/`app.domains.voucher`, already built);
it is pure configuration/branding data plus one guest-facing resolve
endpoint. See `backend/docs/captive_portal/README.md`,
`backend/docs/captive_portal/FLOW.md`, and
`backend/docs/captive_portal/DATABASE.md` for the full design.

Admin-facing endpoints use the standard `ApiResponse` envelope and are
gated by RBAC's already-seeded `captive_portal.*` permission keys:

```text
POST   /api/v1/captive-portal-configs                    captive_portal.create
GET    /api/v1/captive-portal-configs                    captive_portal.read
GET    /api/v1/captive-portal-configs/{id}               captive_portal.read
PUT    /api/v1/captive-portal-configs/{id}               captive_portal.update
DELETE /api/v1/captive-portal-configs/{id}               captive_portal.delete
POST   /api/v1/captive-portal-configs/{id}/activate      captive_portal.update
POST   /api/v1/captive-portal-configs/{id}/deactivate    captive_portal.update
```

A config is either an organization-level default (`location_id` null,
`is_default=true`) or a location-specific override (`location_id` set).
Creating/updating a config as `is_default=true` un-defaults any prior
default for the same organization -- at most one org-level default may
exist per organization at a time, enforced both by the service layer and
by a database partial unique index backstop (`FLOW.md` §3).
`terms_and_conditions_text`/`terms_and_conditions_url` (and the identical
`privacy_policy_text`/`privacy_policy_url` pair) accept at most one
populated at a time, never both (`FLOW.md` §4). `activate`/`deactivate`
map to `captive_portal.update`, not `.manage`/`.delete` -- a lifecycle
status toggle, not a destructive or platform-admin-only action, mirroring
Voucher's identical "revoke -> voucher.update" precedent.

Guest-facing endpoint carries no `RequirePermission`/`CurrentUser`
dependency at all -- the caller is a guest's device/captive-portal
frontend, resolving *before* the guest has authenticated by any method
(mirrors OTP's/Voucher's identical precedent; see `FLOW.md` §6). It still
uses the standard `ApiResponse` envelope, since its real caller is the
captive-portal frontend:

```text
GET /api/v1/captive-portal/resolve?location_id={location_id}
GET /api/v1/captive-portal/resolve?organization_id={organization_id}
```

Implements a most-specific-wins lookup: an active config scoped to the
exact `location_id` (organization derived from the location itself if not
separately supplied), else the organization's active default, else a
`404` (`CaptivePortalConfigNotConfiguredError`) -- there is no hardcoded
platform-wide fallback branding; every organization must configure at
least one active default portal before going live (`FLOW.md` §2).
`social_login_enabled`/`social_login_providers` and
`username_password_enabled` are schema-only readiness flags -- no real
OAuth/social-login integration or guest username/password authentication
exists anywhere in this codebase; setting them only changes what this
resolve response reports as enabled (`FLOW.md` §5).

## Guest Endpoints (Module 010 Part 4, the final BE-010 module)

The Guest domain (`app.domains.guest`) is the module that actually ties
`app.domains.otp`/`app.domains.voucher`/`app.domains.captive_portal`/
`app.domains.router` together into a real guest WiFi login -- a
returning-guest identity, a device, a session, session lifecycle
management, a FreeRADIUS `rlm_rest` HTTP integration, and guest analytics.
See `backend/docs/guest/README.md`, `backend/docs/guest/FLOW.md`, and
`backend/docs/guest/DATABASE.md` for the full design.

Guest-facing endpoints carry no `RequirePermission`/`CurrentUser`
dependency at all -- the caller is an unauthenticated guest at a captive
portal (mirrors OTP's/Voucher's identical precedent). Abuse protection is
inherited entirely from `OtpService`'s/`VoucherService`'s own rate
limiting, never reimplemented here. All three still use the standard
`ApiResponse` envelope:

```text
POST /api/v1/guest/login/otp
POST /api/v1/guest/login/voucher
POST /api/v1/guest/consent
```

`POST /guest/login/otp`/`POST /guest/login/voucher` first confirm (via
`CaptivePortalService.resolve_portal_config`) that the requested method is
enabled for the given `location_id`, reject a request against a
decommissioned/suspended `router_id`
(`RouterNotEligibleForGuestSessionError`), reject a blocked guest
(`GuestBlockedError`) before ever calling
`OtpService.verify_otp`/`VoucherService.redeem_voucher`, then get-or-create
the `Guest`/`GuestDevice` rows and create a new, `ACTIVE` `GuestSession`.
For a voucher login, the session's `data_limit_mb`/`session_timeout_minutes`
are copied from the redeemed voucher's batch at creation time -- a later
edit to the batch never retroactively changes an in-progress guest's quota
(`FLOW.md` §7).

Admin-facing endpoints use the standard `ApiResponse` envelope and are
gated by RBAC's already-seeded `guest_users.*`/`guest_sessions.*`
permission keys:

```text
GET  /api/v1/guests                          guest_users.read
GET  /api/v1/guests/{id}                     guest_users.read
POST /api/v1/guests/{id}/block               guest_users.update
POST /api/v1/guests/{id}/unblock             guest_users.update
POST /api/v1/guests/{id}/reconnect           guest_sessions.execute
GET  /api/v1/guest-sessions                  guest_sessions.read
GET  /api/v1/guest-sessions/{id}             guest_sessions.read
POST /api/v1/guest-sessions/{id}/disconnect  guest_sessions.execute
POST /api/v1/guest-sessions/{id}/terminate   guest_sessions.execute
```

`disconnect` (normal, non-punitive end of use) and `terminate` (punitive,
admin-driven, blocks reconnection for
`constants.TERMINATION_RECONNECT_COOLDOWN_MINUTES`) are deliberately
distinct -- see `FLOW.md` §4. `reconnect` always creates a **new**
`GuestSession` row rather than resurrecting the guest's most recent one --
sessions are append-only history (`FLOW.md` §3).

RADIUS-facing endpoints implement the FreeRADIUS `rlm_rest` HTTP
integration pattern (`FLOW.md` §5) -- there is no real FreeRADIUS server or
RADIUS-UDP wire protocol anywhere in this sandbox, so this module
implements the realistic, actually-deployed HTTP contract `rlm_rest` would
be configured to call instead. Authenticated via a registered NAS's own
shared secret (`X-RADIUS-NAS-Identifier`/`X-RADIUS-Shared-Secret` headers),
**not** RBAC -- FreeRADIUS has no platform-user identity:

```text
POST /api/v1/radius/authorize     NAS shared secret
POST /api/v1/radius/accounting    NAS shared secret
POST /api/v1/radius/nas           radius.create (RBAC-gated, admin registers a NAS)
```

`POST /radius/nas` is the one RADIUS-prefixed endpoint that *is*
RBAC-gated -- an admin registering a router's NAS identity, not FreeRADIUS
calling in. `POST /radius/authorize` returns whether a given `username`
(the guest's identifier) has a currently-`ACTIVE` session on a router bound
to the authenticating NAS, plus reply attributes (`session_timeout_seconds`,
`data_limit_mb`) a real deployment would forward as RADIUS reply
attributes. `POST /radius/accounting` covers all three Acct-Status-Type
values (`start`/`interim-update`/`stop`) in one schema
(`RadiusAccountingRequest.status_type`): `start` confirms an existing
session (never fabricates one -- `FLOW.md` §5), `interim-update` calls
`record_usage` (immediately expiring the session if the running total now
exceeds `data_limit_mb`), `stop` records the final byte counts and calls
`disconnect_session`.

Analytics endpoints are tenant-scoped (`organization_id` via
`X-Organization-Id`, required), optional `location_id`, and a required
date range, gated by RBAC's already-seeded `analytics.read` permission key,
implemented as real SQL aggregate queries
(`func.count`/`func.sum`/`func.avg`, `GROUP BY`) -- never a Python-side
loop over fetched rows:

```text
GET /api/v1/guest-analytics/summary            analytics.read
GET /api/v1/guest-analytics/top-locations      analytics.read
GET /api/v1/guest-analytics/top-devices        analytics.read
GET /api/v1/guest-analytics/otp-success-rate   analytics.read
GET /api/v1/guest-analytics/voucher-usage      analytics.read
```

`otp-success-rate`/`voucher-usage` are derived entirely from this module's
own `GuestLoginHistory`/`GuestSession` tables -- no new method was added to
`app.domains.otp`/`app.domains.voucher` (`FLOW.md` §11).

## Monitoring Endpoints (Module 011 Part 1: Health Engine + Event Engine)

Distinct from the liveness/readiness probes under "Health Endpoints" above
(`/api/v1/health/live`, `/api/v1/health/ready`, unauthenticated, meant for
an orchestrator's own probe) -- these are RBAC-gated, richer,
persisted-history endpoints meant for an authenticated operator/dashboard.
All use the standard `ApiResponse` envelope and are gated by RBAC's
already-seeded `monitoring.*` permission keys, reused for events too (no
dedicated "events" permission module exists -- see
`docs/monitoring/FLOW.md` §6):

```text
GET  /api/v1/monitoring/health              monitoring.read    dashboard summary + per-component current status
GET  /api/v1/monitoring/health/{component}  monitoring.read    one component's health-check history (paginated)
POST /api/v1/monitoring/health/run          monitoring.manage  on-demand health-check run (admin-gated)
GET  /api/v1/events                         monitoring.read    unified, cross-domain event timeline
```

`{component}` is one of `database`/`redis`/`api`/`auth`/`storage`/`celery`/
`websocket`/`freeradius`/`wireguard` (`constants.HealthComponent`). The
dashboard summary's `overall_status` is `unhealthy` if any component is
`unhealthy`, `degraded` if any (remaining) component is `degraded`, and
`healthy` only when every component with a *known* status is `healthy` --
`celery`/`websocket` are honestly `unknown` forever in this environment (no
such infrastructure exists yet) and are deliberately excluded from that
"must all be healthy" rule so the aggregate stays a useful signal (see
`docs/monitoring/FLOW.md` §8).

`database`/`redis`/`auth`/`storage` are real checks (a real `SELECT 1`, a
real `PING`, a real narrow `AuthRepository` call, a real
`shutil.disk_usage` against the configured log directory); `api` is the
process's own trivial-but-uniform liveness; `celery`/`websocket` are
honest `unknown` placeholders (no such infrastructure exists in this
codebase yet -- never a fabricated `healthy`); `freeradius`/`wireguard` are
documented, DB-tracked proxy signals composing with
`app.domains.guest`/`app.domains.wireguard`'s own existing data, not a live
daemon ping (`docs/monitoring/FLOW.md` §4/§5).

`GET /events` accepts optional `organization_id`, repeatable `category`
(`constants.EventCategory` -- `system`/`security`/`network`/
`authentication`/`provisioning`/`guest`/`audit`) and `severity`
(`constants.EventSeverity` -- `info`/`warning`/`error`/`critical`) filters,
an optional `start_date`/`end_date` range, and `limit` (default 100, max
500). The returned timeline is a **read-side aggregation** across this
module's own narrowly-scoped `platform_events` table plus RBAC's
`audit_log_entries` and `router_provisioning`'s `router_events` (read
directly, never copied) -- see `docs/monitoring/FLOW.md` §3 for the full
composition-vs-new-storage decision.

## Alert / Notification / Incident / SLA Endpoints (Module 011 Part 2)

Extends the same Monitoring domain (no new top-level domain). Every
endpoint uses the standard `ApiResponse` envelope. See
`docs/monitoring/FLOW.md` §16 for the complete RBAC permission-key-reuse
reasoning (there is no dedicated "incidents"/"sla" permission module in the
seeded 36, and neither `alerts` nor `notifications` has a seeded `create`
action):

```text
POST   /api/v1/alerts/rules                     alerts.manage    create an alert rule
GET    /api/v1/alerts/rules                     alerts.read      list alert rules (organization_id/is_active filters, paginated)
GET    /api/v1/alerts/rules/{rule_id}           alerts.read      get one alert rule
PUT    /api/v1/alerts/rules/{rule_id}           alerts.update    update an alert rule (+ its notification channels)
DELETE /api/v1/alerts/rules/{rule_id}           alerts.delete    soft-delete an alert rule
GET    /api/v1/alerts                           alerts.read      list triggered alerts (organization_id/router_id/status/severity filters, paginated)
GET    /api/v1/alerts/{alert_id}                alerts.read      get one alert
POST   /api/v1/alerts/{alert_id}/acknowledge    alerts.update    TRIGGERED -> ACKNOWLEDGED
POST   /api/v1/alerts/{alert_id}/resolve        alerts.update    TRIGGERED/ACKNOWLEDGED -> RESOLVED

POST   /api/v1/notifications/channels                  notifications.manage  create a notification channel
GET    /api/v1/notifications/channels                   notifications.read    list channels (organization_id/is_active filters, paginated)
GET    /api/v1/notifications/channels/{channel_id}      notifications.read    get one channel (config never returned decrypted)
PUT    /api/v1/notifications/channels/{channel_id}      notifications.update  update a channel (name/config/is_active)
DELETE /api/v1/notifications/channels/{channel_id}      notifications.delete  soft-delete a channel
GET    /api/v1/notifications/logs                       notifications.read    list delivery logs (channel_id/alert_id/status filters, paginated)

POST   /api/v1/incidents                        alerts.manage    create an incident (OPEN)
GET    /api/v1/incidents                        alerts.read      list incidents (organization_id/status/severity filters, paginated)
GET    /api/v1/incidents/{incident_id}          alerts.read      get one incident
PUT    /api/v1/incidents/{incident_id}          alerts.update    update title/description/assignee/status (transition-graph-validated)
POST   /api/v1/incidents/{incident_id}/alerts   alerts.update    attach an alert to an incident (idempotent)

GET    /api/v1/sla                               reports.read     list SLA targets + each one's latest report
POST   /api/v1/sla/targets                       reports.manage   create an SLA target
GET    /api/v1/sla/{target_id}/reports           reports.read     list an SLA target's historical reports (paginated)
POST   /api/v1/sla/{target_id}/generate-report   reports.manage   on-demand report computation (optional period_days override)
```

**Alert rules** (`AlertRuleCreateRequest`): `trigger_type`
(`health_status_change`/`threshold`/`event_occurred`), `target_component`
(a `HealthComponent` value, `"router"`, or `null` -- see
`docs/monitoring/FLOW.md` §11/§12), `condition_config` (shape depends on
`trigger_type`), `severity` (`info`/`warning`/`critical`),
`notification_channel_ids` (which channels a triggered alert notifies --
a real join table, `alert_rule_notification_channels`, not a JSONB list).

**Notification channels** (`NotificationChannelCreateRequest`):
`channel_type` (`email`/`sms`/`whatsapp`/`slack`/`teams`/`discord`/
`webhook`) plus a `config` object whose required keys depend on
`channel_type` -- see `docs/monitoring/DATABASE.md`'s per-type schema
table. `config` is Fernet-encrypted before storage and never returned by
any `GET`.

**Incidents** (`IncidentCreateRequest`/`IncidentUpdateRequest`): status
transition graph is `OPEN -> {INVESTIGATING, RESOLVED, CLOSED}`,
`INVESTIGATING -> {OPEN, RESOLVED, CLOSED}`, `RESOLVED -> {INVESTIGATING,
CLOSED}`, `CLOSED` terminal. Grouping alerts into an incident is fully
manual (`POST /incidents/{id}/alerts`) -- no auto-correlation heuristic
(see `docs/monitoring/FLOW.md` §14).

**SLA** (`SlaTargetCreateRequest`/`SlaReportGenerateRequest`):
`achieved_percentage = healthy_checks / total_checks * 100` over the
target's `measurement_window_days` (or an explicit `period_days`
override), computed from Part 1's own `health_checks` history -- see
`docs/monitoring/FLOW.md` §15 for why this simple ratio, not a
downtime-duration-weighted formula, is the honest choice in this
environment. Raises a `422` if zero `HealthCheck` rows exist for the
window (never fabricates a result from no data).

