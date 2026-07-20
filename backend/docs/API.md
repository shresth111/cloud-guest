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

### Smart Location Provisioning (Module 006 extension)

Extends this same Location domain (explicitly *not* a new
`app/domains/onboarding/` module) with a single orchestrated "Create
Location" flow that composes Organization/User/RBAC/Router/Router
Provisioning/WireGuard/Billing/Captive Portal/OTP's provider protocols in
one real database transaction. See `backend/docs/location/FLOW.md` for the
full design write-up (the transactional mechanism, the billing feature-
override design, the RBAC role choice, the `must_change_password` auth
extension, the `location_code` generator, the default-router-config-
template gap) and `backend/docs/location/DATABASE.md` for the schema
changes.

```text
POST /api/v1/locations/provision
POST /api/v1/locations/{location_id}/resend-welcome-email
```

Both endpoints require `locations.manage` pinned at `ScopeType.GLOBAL`
(`RequirePermission("locations.manage", scope=ScopeType.GLOBAL)`) -- the
identical Super-Admin-only gating pattern `app.domains.billing.router`
already uses for Plan-catalog writes. Per the seeded `SYSTEM_ROLES` data,
only `Super Admin`/`Platform Admin` hold that grant, matching the spec's
"CloudGuest Super Admin" actor.

`POST /locations/provision` request body: `existing_organization_id`
**or** `new_organization` (exactly one), `location` (name/slug/
`property_type`/address/timezone/lat-long/contact/settings), `owner`
(name/email/optional username/phone/designation/etc., `send_welcome_sms`),
`router` (name/serial/MAC/model/management+public IP/API credentials),
`plan_id`, an optional `feature_overrides` list (each a
`{feature_key, limit_value | is_enabled | tier_value}`), an optional
`router_config_template_id`, and an optional `coupon_code`.

Response: `organization_id`/`name`, `location_id`/`name`/`location_code`/
`property_type`, `plan_id`/`name`, a resolved `feature_summary` (every
`PlanFeatureKey` currently in effect for the org, after overrides),
`router_id`/`name`, `tunnel_ip_address`, `owner_user_id`/`name`/`username`/
`email`, an `owner_temporary_password` (returned **exactly once**, in this
response only -- never logged, never persisted, never retrievable again),
a `login_url`, and `provisioned_at`.

`POST /locations/{id}/resend-welcome-email` re-sends the owner's welcome
email (login URL + username) **without** the original temporary password
(it is not retrievable) -- the email instead points the owner at the
"Forgot password" flow if they no longer have it. 404s
(`OwnerNotProvisionedError`) if the location was never provisioned through
this flow.

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

## Real-Time + ZTP Monitoring Dashboard + Analytics Endpoints (Module 011 Part 3)

Extends the same Monitoring domain (no new top-level domain, no new
persisted tables -- see `docs/monitoring/DATABASE.md`'s Part 3 section).
See `docs/monitoring/FLOW.md` §18-28 for every design decision in detail.

```text
WS   /api/v1/monitoring/ws/dashboard   monitoring.read        live health-transition/alert-triggered/alert-resolved feed
WS   /api/v1/monitoring/ws/sessions    guest_sessions.read     live guest-session-started/ended feed
GET  /api/v1/monitoring/dashboard      monitoring.read        platform "at a glance" statistics
GET  /api/v1/monitoring/devices        monitoring.read        device statistics + per-router lifecycle-stage listing
GET  /api/v1/ztp/dashboard             monitoring.read        provisioning dashboard/status/progress
GET  /api/v1/ztp/analytics             analytics.read          success rate / failure reports / retry dashboard / activation timing
```

### WebSocket endpoints

Both `WS /monitoring/ws/dashboard` and `WS /monitoring/ws/sessions` accept
a required `?token=<JWT access token>` query parameter (the same access
token issued by `POST /api/v1/auth/login`) -- a browser's native
`WebSocket` API cannot set an `Authorization` header, so the token travels
as a query parameter instead, validated with the identical JWT-decode logic
the HTTP `Authorization: Bearer` flow uses. **Known tradeoff:** a token in
a URL can be recorded in server access logs/browser history/proxy
logs/`Referer` headers -- see `docs/monitoring/FLOW.md` §20 for the full
write-up and the first-message-handshake alternative considered. The
connection is closed with code `4401` (missing/invalid/expired token, or
inactive user) or `4403` (authenticated but lacking the required
permission) before ever being accepted on any auth failure.

Every relayed message has the shape:

```json
{
  "type": "health_transition | alert_triggered | alert_resolved | guest_session_started | guest_session_ended",
  "payload": { "...": "message-type-specific fields" },
  "occurred_at": "2026-01-01T00:00:00+00:00"
}
```

`WS /monitoring/ws/dashboard` only ever relays
`health_transition`/`alert_triggered`/`alert_resolved`;
`WS /monitoring/ws/sessions` only ever relays
`guest_session_started`/`guest_session_ended` (`guest_session_ended` is
defined but has no current writer -- see `docs/monitoring/FLOW.md` §19).
Both share one underlying Redis channel and filter server-side, per
`docs/monitoring/FLOW.md` §19's "one channel, two purpose-filtered
endpoints" design.

### `GET /monitoring/dashboard`

Accepts optional `organization_id`, `start_date`, `end_date` (defaults to
the trailing 24 hours). Returns overall health status + every component's
current status, alert counts by severity/status, device counts by
`RouterStatus`, ZTP lifecycle-stage counts, pending-enrollment count,
average health-check response time, platform availability percentage
(same formula as SLA's `achieved_percentage`, computed live rather than
requiring a pre-configured `SlaTarget`), and -- only when `organization_id`
is supplied -- guest visitor/unique-guest counts (`app.domains.guest
.GuestAnalyticsService`, composed read-only).

### `GET /monitoring/devices` / `GET /ztp/dashboard`

Both call the identical underlying aggregation (see
`docs/monitoring/FLOW.md` §26) -- accept optional `organization_id`,
`page`, `page_size`. Returns a full stage-count tally
(`RouterLifecycleStage` -- `pending`/`claimed`/`approved`/`provisioning`/
`provisioned`/`online`/`offline`/`warning`/`failed`) over every matching
router/enrollment, a `pending_enrollment_count`, and a paginated listing of
individual rows (`router_id`/`enrollment_id` -- one or the other is
`null`, never both -- plus `lifecycle_stage`, `router_status`,
`enrollment_status`, `last_seen_at`, and the latest `ProvisioningJob`'s
type/status/attempts). See `docs/monitoring/FLOW.md` §22 for the complete
9-state derivation table.

### `GET /ztp/analytics`

Accepts optional `organization_id`, `start_date`/`end_date` (defaults to
the trailing 30 days), `retry_page`/`retry_page_size`,
`failure_sample_limit`. Returns:

* `success_rate_percentage` (`succeeded ProvisioningJobs / (succeeded +
  failed) ProvisioningJobs` in the window, `null` if none -- see
  `docs/monitoring/FLOW.md` §23 for the denominator-choice write-up),
  `succeeded_job_count`, `terminal_job_count`.
* `failure_breakdown` (counts grouped by `ProvisioningJobType`) and
  `failure_samples` (a small, most-recent-first list of individual failed
  jobs with their real `error_message`).
* `retry_jobs` (every job with `attempts > 0`, nearest-to-exhaustion
  first, paginated).
* `average_activation_seconds`/`activation_sample_size` -- an honest
  approximation (enrollment-approval-to-initial-config-job-completion, NOT
  a literal time-to-first-`ONLINE` measurement -- see
  `docs/monitoring/FLOW.md` §24).

## Observability (Module 011 Part 4)

Cross-cutting infrastructure, not a new domain -- no new persisted tables,
no new top-level router under `Settings.api_v1_prefix`. See
`docs/monitoring/OBSERVABILITY.md` for the full write-up (metric
inline-vs-on-scrape architecture, OpenTelemetry's honest default-vs-
configured exporter behavior, and how to wire Grafana/Loki against this
app).

```text
GET  /metrics    (no auth)    Prometheus scrape endpoint
```

`GET /metrics` is registered directly on the app
(`app.main.create_app`) -- **deliberately not** under
`Settings.api_v1_prefix` and **not** behind any RBAC dependency, since
Prometheus scrapers never carry a platform-user JWT (see
`docs/monitoring/OBSERVABILITY.md` for the full reasoning). **A production
deployment must restrict this path at the network/ingress layer** (a
scrape-only security group, a Kubernetes `NetworkPolicy`, or a reverse-
proxy allowlist) -- there is no application-layer gate on it by design.

Returns the standard Prometheus exposition text format
(`prometheus_client.generate_latest`), containing:

* `cloudguest_http_requests_total` / `cloudguest_http_request_duration_seconds`
  -- inline, per-request HTTP metrics (`app.core.metrics.PrometheusMiddleware`).
* `cloudguest_health_check_status` -- on-scrape `Gauge`, from
  `app.domains.monitoring`'s `ServiceHealth` rollup, labeled by `component`.
* `cloudguest_alerts_triggered_total` -- on-scrape `Gauge`, from
  `app.domains.monitoring`'s `Alert` table, labeled by `severity`.
* `cloudguest_guest_sessions_active` -- on-scrape `Gauge`, from
  `app.domains.guest`'s `GuestSession` table.
* `cloudguest_provisioning_jobs_total` -- on-scrape `Gauge`, from
  `app.domains.router_provisioning`'s `ProvisioningJob` table, labeled by
  `status`.

Every business metric above is refreshed from current database state on
each scrape, not incremented inline from within any other domain's own
business logic -- see `docs/monitoring/OBSERVABILITY.md` for the full
architecture write-up and why. OpenTelemetry tracing
(`app.core.tracing.configure_tracing`) is wired into the same app factory,
exporting spans to the console by default or to a real OTLP collector once
`Settings.otel_exporter_otlp_endpoint` is configured -- it has no HTTP
endpoint of its own to document here.

## Analytics Endpoints (Module 012 Part 1: Analytics Core Infrastructure)

See `docs/analytics/README.md`/`FLOW.md`/`DATABASE.md` for the full
architecture write-up (the real Celery + Beat deployment, the
async-in-a-sync-worker bridge, the Redis-vs-new-table cache decision, and
exactly what changed in `check_celery_health`). A deliberately minimal HTTP
surface for this infra-focused part -- full dashboard/per-domain-analytics/
forecasting/reporting endpoints are later BE-012 parts' job.

### `GET /analytics/snapshots`

Requires `analytics.read`. Query params: `location_id`, `snapshot_type`
(`org_daily_summary` / `location_daily_summary` / `platform_daily_summary`),
`start_date`/`end_date`, `page`/`page_size`. `organization_id` is **not** a
raw query parameter -- it is resolved via RBAC's `CurrentOrganization`
dependency off the `X-Organization-Id` header (tenant-validated: the
caller must hold active membership in that organization, or omit the
header entirely for a `GLOBAL`-scoped platform-wide query -- see
`docs/analytics/FLOW.md` §12). Returns a paginated list of
`AnalyticsSnapshot` rows (`organization_id`, `location_id`, `snapshot_type`,
`period_start`/`period_end`, `granularity`, `metrics` (the computed numbers
-- shape documented per `snapshot_type` in `docs/analytics/DATABASE.md`),
`computed_at`, `computation_duration_ms`).

### `POST /analytics/snapshots/trigger`

Requires `reports.manage` (see `docs/analytics/FLOW.md` §11 for why this
endpoint reuses `reports.manage` rather than a nonexistent
`analytics.manage`). Body: `organization_id` (required), `target_date_iso`
(optional `YYYY-MM-DD` to backfill a specific past day; omitted means
today's still-partial window). Synchronously (in the same request/response
cycle, not via Celery) computes and persists that organization's
`ORG_DAILY_SUMMARY` snapshot plus one `LOCATION_DAILY_SUMMARY` snapshot per
active location, returning every snapshot just created. 404s
(`AnalyticsOrganizationNotFoundError`) if `organization_id` does not
correspond to a real, non-deleted organization.

### Beat-scheduled background aggregation (no HTTP surface)

`app.core.celery_app`'s Beat schedule runs
`app.domains.analytics.tasks.run_daily_aggregation_for_all_organizations`
every 15 minutes (a rolling "today so far" snapshot for every active
organization/location/the platform) and once daily at 00:10 UTC (a final
"yesterday, in full" snapshot) -- see `docs/analytics/FLOW.md` §4. This has
no HTTP endpoint of its own; it requires a real `celery worker`
+ `celery beat` process running against the same `Settings.redis_url`
broker (see `docs/analytics/README.md`'s "Running a Worker + Beat Locally"
section) -- neither is started by `app.main.create_app()` or by the test
suite.

## Dashboard Endpoints (Module 012 Part 2: Super Admin + Organization + Location Dashboards)

See `docs/analytics/FLOW.md` §§13-22 for the full design write-up (the
peak-concurrent-sessions sweep-line algorithm, the Organization Health
Score formula and exact weights, the `DashboardScope` resolution and its
MSP-child rollup, the device/browser/OS real-capture-and-classify decision,
and the dashboard-view audit-throttling decision). All three endpoints
require `analytics.read`, each at an explicit, non-inferred RBAC scope
(`scope=` on `RequirePermission`), plus a second, independent
`DashboardScope` check inside `DashboardService` itself (see
`app.domains.analytics.dashboard_scope`'s module docstring for why both
layers exist).

### `GET /dashboard/super-admin`

Requires `analytics.read` at `GLOBAL` scope -- only a caller holding a
platform-wide (`GLOBAL`-scoped) RBAC role assignment (Super Admin, Platform
Admin, Platform Support, Billing Manager) can ever satisfy this; every
other caller is rejected by `app.domains.rbac.authorization.ScopeResolver`
itself (a `GLOBAL` check can only be satisfied by a `GLOBAL` grant), and
`DashboardScope.require_global()` re-asserts the same thing independently.
No query parameters. Returns: total organizations/locations/routers,
routers online/offline, total/today's/monthly guests, total/active
sessions, peak concurrent sessions (see FLOW.md §13) plus the exact window
it was computed over, five growth-trend series (organization/location/
router/guest/network, each a day-over-(`DEFAULT_GROWTH_LOOKBACK_DAYS`,
default 7)-days-ago delta computed from `PLATFORM_DAILY_SUMMARY` snapshot
history), trial/paid customer counts (see FLOW.md §17 for exactly how these
are approximated and why), and a `revenue` object that is **always**
`available: false` with every numeric field `null` (see FLOW.md §17 -- no
billing/subscription/payment domain exists anywhere in this codebase).

### `GET /dashboard/organization`

Requires `analytics.read` at `ORGANIZATION` scope. `organization_id` is
resolved via RBAC's `RequireOrganization` (`X-Organization-Id` header,
membership-validated) -- never a raw query parameter. If that organization
is an MSP (`OrganizationType.MSP`), the response additionally rolls up
every one of its child organizations' latest `ORG_DAILY_SUMMARY` snapshot
into the same totals (see FLOW.md §18 for the exact MSP-rollup composition
with `OrganizationService.list_children`, and which sub-sections stay
scoped to the primary organization only). Returns: per-organization summary
items (own org + any children) plus rolled-up totals (guest/session/router/
location counts), Captive Portal Usage (see FLOW.md §16 for the exact
data-source decision), Authentication Summary (real
`GuestLoginHistory.auth_method`/success breakdown), OTP Statistics (real
aggregate over `OtpRequest`), Voucher Statistics (real aggregate over
`Voucher`/`VoucherBatch`), bandwidth consumption + average session
duration, peak hour/day (UTC), a 7-day bandwidth traffic trend (from
`ORG_DAILY_SUMMARY` snapshot history), and the Organization Health Score
(see FLOW.md §15 for the exact formula and weights).

### `GET /dashboard/location`

Requires `analytics.read` at `LOCATION` scope. `location_id` is resolved
via RBAC's `RequireLocation` (`X-Location-Id` header, existence + org-
consistency validated). Returns: daily/weekly/monthly visitor counts (daily
is a live "today so far" aggregate; weekly/monthly sum already-closed
`LOCATION_DAILY_SUMMARY` daily snapshots plus today's own live count -- see
FLOW.md §19), unique/returning guests (reusing
`app.domains.guest.service.GuestAnalyticsService`'s own existing
"returning" definition, never redefined here), average stay time, peak
hours/days (UTC, real `EXTRACT(HOUR/DOW FROM started_at)` `GROUP BY`),
bandwidth usage + average session bandwidth/duration, a `devices` object
(Top Devices/Browsers/Operating Systems -- see FLOW.md §14 for the real
capture-and-classify mechanism, including honest `sessions_with_data`/
`sessions_total` coverage reporting), Authentication Methods (same real
`GuestLoginHistory` composition as the Organization Dashboard, scoped to
this one location), and a `country_statistics` object that is **always**
`available: false` (see FLOW.md §17 -- no GeoIP/IP-geolocation data source
exists in this environment).

## Domain Analytics Endpoints (Module 012 Part 3: Router + Network + Guest + Authentication Analytics)

See `docs/analytics/FLOW.md` §§23-34 for the full design write-up
(bandwidth-from-`GuestSession` reasoning, the hotspot-sessions equivalence,
the Internet Availability proxy signal, RADIUS success/failure scoping, the
Guest Retention and Peak Bandwidth formulas, composing with BE-010's own
Guest Analytics, the Voucher Failure honest-partial-signal gap, every
honest placeholder, and the Accept-Language capture decision). All four
endpoints require `analytics.read` at `ORGANIZATION` scope, plus a second,
independent `DashboardScope.require_organization` check inside
`DomainAnalyticsService` itself -- the same two-layer pattern Part 2's own
dashboards already establish. `organization_id` is resolved via RBAC's
`RequireOrganization` (`X-Organization-Id` header, membership-validated).
Every endpoint accepts an optional `location_id` query parameter (narrows
to one location within the organization) and optional `start_date`/
`end_date` query parameters (ISO 8601 datetimes; default to a trailing
30-day window ending now when omitted).

### `GET /analytics/routers`

Returns, per router in scope: CPU/RAM usage (current reading plus a trend
direction against a trailing 7-day average -- real, from
`RouterHealthSnapshot`), uptime and connected-clients count (real), total
bandwidth uploaded/downloaded (real, aggregated from `GuestSession` -- see
FLOW.md §23 for why this is not, and cannot be, read off
`RouterHealthSnapshot`), Internet Availability (a documented proxy signal --
see FLOW.md §25), WireGuard tunnel status (composed with
`app.domains.wireguard.service.WireGuardService.compute_health_status`),
Hotspot Sessions (real -- see FLOW.md §24 for the exact "guest sessions
are hotspot sessions" equivalence), and Authentication Requests/RADIUS
Success/RADIUS Failure (real per-router success count; a documented
location-level proxy for failure -- see FLOW.md §26).
`disk_usage`/`temperature`/`packet_loss`/`latency` are each **always**
`available: false` -- no MikroTik device has ever reported any of the four
in this sandbox.

### `GET /analytics/network`

Also accepts an optional `limit` query parameter (top-N size, default 10,
max 50). Returns: real download/upload/total bandwidth usage for the
scope, Peak Bandwidth (the highest-bandwidth bucket among recent
`ORG_DAILY_SUMMARY` snapshot history -- see FLOW.md §28 for the exact
formula and why it is a bucket total, not an instantaneous rate), Average
Speed (real, `total_bytes / window_duration_seconds`), Network
Availability (a platform/org-wide rollup of the same router-level Internet
Availability proxy signal), Top Consumers/Locations/Routers (real,
bandwidth-ranked), and a Traffic Trend (day-over-day, from the same
snapshot history Peak Bandwidth reads). `top_applications` is **always**
`available: false` -- no deep packet inspection exists.

### `GET /analytics/guests`

Also accepts an optional `limit` query parameter (top-N size, default 10,
max 50). Composes directly with
`app.domains.guest.service.GuestAnalyticsService` (`get_summary`/
`get_top_devices`/`get_top_locations`) rather than re-deriving any of its
numbers -- see FLOW.md §30. Returns: New/Returning/Unique Guests (New
Guests reuses the exact same `max(unique - returning, 0)` formula Part 1's
own snapshot aggregation established), Repeat Visits (a distinct, real
metric -- sessions beyond each guest's first visit *within this window*),
Guest Retention (a real formula -- see FLOW.md §27 for the exact
"% of previous-period guests retained into the current period"
definition), Average Data Usage and Average Session Duration (real), Top
Devices (real, composed from `GuestAnalyticsService`), device/OS/browser
statistics (reusing Part 2's exact User-Agent classification SQL), a
`languages` object (real -- the primary language tag extracted from the
new `Accept-Language` capture, see FLOW.md §34), and a `country_statistics`
object that is **always** `available: false` (Part 2's exact placeholder,
reused verbatim -- see FLOW.md §17/§32).

### `GET /analytics/authentication`

Returns: OTP Statistics (real, from `OtpRequest`), Voucher Statistics
(`redeemed_count` real and complete; `failed_attempts_recorded` real but
**partial** -- see FLOW.md §31 for exactly which failure reasons are
durably tracked and which are not), overall Authentication Success/Failure
totals and day-over-day trend (real, from `GuestLoginHistory`), Failed
Login Reasons (real `GROUP BY failure_reason`), and per-auth-method
success/failure breakdown (the same real composition Part 2's Organization
Dashboard already uses). `pms_login`/`social_login` are each **always**
`available: false` -- no PMS integration exists anywhere in this codebase,
and `CaptivePortalConfig.social_login_enabled` is a schema-only readiness
flag with no working social-login flow behind it.

## Business Analytics + Forecast/Insight Engines (Module 012 Part 4)

See `docs/analytics/FLOW.md` §§35-46 for the full design write-up (the two
honesty investigations this part opens with, the Trend Engine's
de-duplication of Part 2/3's own near-identical trend code, the exact OLS
linear-regression method, forecast endpoint consolidation, the Router
Failure Risk heuristic's exact signal set, the Capacity Prediction
threshold-crossing formula, every Insight Engine rule + threshold + its
home in `Settings`, Business Analytics' honest-placeholder shape, the
GLOBAL-vs-ORGANIZATION scope design, and why no migration was needed). No
new dependency was added anywhere in this part -- every forecast is
ordinary least-squares linear regression implemented directly in pure
stdlib Python (`app.domains.analytics.forecast.fit_linear_trend`), and
every insight is a plain, deterministic rule function
(`app.domains.analytics.insights`) -- **neither is, nor calls, an AI/LLM
provider**, since none exists anywhere in this codebase and this part's own
brief explicitly forbids implementing one.

### `GET /analytics/business`

Requires `analytics.read` at `GLOBAL` scope, plus a second, independent
`DashboardScope.require_global()` check inside `BusinessAnalyticsService`
itself -- the same two-layer pattern every other analytics endpoint in this
domain already establishes. No query parameters (this is an inherently
platform-wide, cross-tenant view: organizations themselves are CloudGuest's
customers, so there is no meaningful "one organization's" customer growth).
Returns: Customer Growth (real -- `organization_count_total` from
`PLATFORM_DAILY_SUMMARY` snapshot history, `DEFAULT_GROWTH_LOOKBACK_DAYS`
comparison, via the shared Trend Engine), Plan Distribution (real -- a
`GROUP BY Organization.subscription_tier`, reporting the true distribution
including a real, unmasked "unset" count -- see FLOW.md §43 for why this is
never skipped just because the field is known to be sparsely populated),
and Revenue Trends/Subscription Trends/Churn Rate/Renewal Rate/License
Utilization, each **always** `available: false` (mirroring
`dashboard_schemas.RevenueMetricsResponse`'s exact honesty posture -- see
FLOW.md §43 for the exact schema shape of each) -- no billing/subscription/
payment domain exists anywhere in this codebase to derive any of the five
from.

### `GET /analytics/forecast/bandwidth` / `/guest-growth` / `/network-load`

Each requires `analytics.read` at `ORGANIZATION` scope, plus a second,
independent `DashboardScope.require_organization` check inside
`ForecastService` itself. `organization_id` is resolved via RBAC's
`RequireOrganization` (`X-Organization-Id` header, membership-validated).
Each accepts an optional `location_id` query parameter (narrows to one
location's own `LOCATION_DAILY_SUMMARY` history instead of the
organization's `ORG_DAILY_SUMMARY` history) and an optional `forecast_days`
query parameter (`1`-`90`, defaults to `Settings.analytics_forecast_
default_days`, 7). Each projects one real metric
(`total_bandwidth_bytes`/`guest_count_unique`/`session_count_total`
respectively) forward via a real ordinary-least-squares linear-regression
fit over `Settings.analytics_forecast_history_days` (default 30) trailing
days of snapshot history -- see FLOW.md §38 for the exact formula. Returns
`available: false` (never a fabricated projection) when fewer than
`Settings.analytics_forecast_min_history_points` (default 3) real data
points exist. Every response carries the real historical points, the
projected points, and the fit's own real slope/intercept/R^2 (the ONLY
"confidence"-shaped number ever reported -- never an invented percentage),
plus a stated limitation: this is a linear projection assuming the recent
trend continues unchanged, not a guarantee. **Traffic Forecast and
Bandwidth Forecast are the same endpoint** -- see FLOW.md §39 for why a
second, identically-computed endpoint under a different name would be pure
duplication (this codebase has exactly one real per-day network-volume
metric).

### `GET /analytics/forecast/capacity`

Same RBAC/scope gating as the three endpoints above. Projects an
organization's own `router_count_total` history forward via the identical
linear-regression fit, then answers "when will this cross the configured
capacity ceiling" (`Settings.analytics_forecast_capacity_router_count_
threshold`, default 50) -- see FLOW.md §41 for the exact threshold-crossing
formula (already-crossed -> 0 days; flat/declining trend -> `available:
false`, never a fabricated future date; otherwise the real fitted line
solved for the crossing point). `threshold_crossing.threshold_note` states
on every response that this threshold is an operator-set planning
assumption, not data derived from any real infrastructure-capacity record --
no such record exists anywhere in this codebase.

### `GET /analytics/forecast/router-failure-risk`

Same RBAC/scope gating as the other Forecast Engine endpoints; `location_id`
narrows which routers are assessed (via `list_routers_for_scope`) rather
than narrowing snapshot history. For every router in scope, evaluates the
Router Failure Risk heuristic (`forecast.assess_router_failure_risk`) --
**explicitly a heuristic risk FLAG, never a machine-learning prediction or a
fabricated failure-probability number** -- flagging `at_risk: true` only
when at least one of three real, cited signals fires: a rising CPU/memory
usage trend (the same OLS fit, against `RouterHealthSnapshot` history), a
high ratio of recent `health_status="unhealthy"` readings, or repeated real
`app.domains.monitoring.models.Alert` rows against that router. See FLOW.md
§40 for the exact thresholds (all in `Settings`) and why each signal is
real. `heuristic_note` states this posture on every response.

### `GET /analytics/insights/business` / `GET /analytics/insights/operational`

Both require `analytics.read` at `GLOBAL` scope, plus a second, independent
`DashboardScope.require_global()` check inside `InsightService` itself --
both are, by design, platform-wide sweeps (mirroring Business Analytics'
own scope reasoning). No query parameters. Both run a real, deterministic
RULE ENGINE (`app.domains.analytics.insights`) -- **explicitly not an
AI/LLM system**; every insight fires only when a real, already-aggregated
number crosses a real, configured threshold in `Settings`, and every
response's own `rule_engine_note` states this explicitly. See FLOW.md §42
for the exact seven rules and their threshold's home in `Settings`.
Business Insights evaluates `customer_growth`/`guest_growth`/
`plan_distribution_coverage` (each platform-wide, at most one insight per
rule). Operational Recommendations evaluates `offline_routers` (per
organization), `location_guest_volume_drop` (per location),
`rising_router_cpu` (per router), and `persistent_critical_alerts` (per
organization) -- each producing one insight per qualifying entity, never a
single rolled-up sentence (see FLOW.md §42's own write-up of this
consistency choice).

## Report Engine + Export Engine (Module 012 Part 5, completes BE-012)

See `docs/analytics/FLOW.md` §§47-56 for the full design write-up (the
exact `ReportType` -> composed-service mapping, the manual-vs-scheduled
modeling decision, the CSV/Excel flattening convention, the `reportlab`
PDF library choice, the hourly Beat-scheduled task's per-schedule
failure-isolation pattern, the full-vs-throttled audit reasoning, the RBAC
scope-inference design, the export-routing design, and the honest
email-attachment limitation). This part adds **no new metric
computation** -- every figure in a generated report comes from an
already-existing Module 012 Part 2/3/4 endpoint's own response, composed
verbatim.

Two new dependencies: `openpyxl==3.1.5` (real `.xlsx` generation) and
`reportlab==4.4.4` (real PDF generation, chosen over `fpdf2`/`weasyprint` --
see FLOW.md §50).

### `POST /reports/templates`

Requires `reports.manage`. Creates a `ReportTemplate`
(`name`/`description`/`report_type`/`config`/`is_active`). `organization_id`
is resolved from the `X-Organization-Id` header (via `CurrentOrganization`,
optional) -- omitted for a platform-wide system template (requires a
GLOBAL-scoped `reports.manage` grant), present to scope it to that
organization (requires an ORGANIZATION-scoped grant covering it).
`report_type` is one of `dashboard`/`organization`/`location`/`router`/
`guest`/`network`/`revenue`/`health`.

### `GET /reports/templates` / `GET /reports/templates/{template_id}`

Requires `reports.read`. Lists (paginated) or fetches one template --
platform-wide system templates are always visible; organization-scoped
ones only to a caller whose resolved `DashboardScope` covers that
organization (a GLOBAL-scoped caller sees every template). A template
outside the caller's scope reads as `404`, identical to one that does not
exist.

### `PUT /reports/templates/{template_id}` / `DELETE /reports/templates/{template_id}`

Requires `reports.manage`. Partial update / soft delete, same visibility
rule as the `GET` endpoints above. Every mutation writes its own
`audit_log_entries` row (`report_template_created`/`_updated`/`_deleted`).

### `POST /reports` (generate a report, manual or on-demand)

Requires `reports.export` (see FLOW.md §53 for why `export`, not `read`).
Either `template_id` (loads a persisted `ReportTemplate`'s `report_type`/
`config`) or an ad-hoc `report_type` must be supplied.
`organization_id`/`location_id` are resolved from the `X-Organization-Id`/
`X-Location-Id` headers (never a request body field -- see FLOW.md §53),
so the required RBAC scope is inferred from whichever of those headers is
present (GLOBAL if neither, ORGANIZATION if `X-Organization-Id`, LOCATION
if `X-Location-Id`). `start_date`/`end_date` narrow the window for
`ROUTER`/`GUEST`/`NETWORK` report types (defaults to a trailing window
otherwise). `export_format` (`json`/`csv`/`excel`/`pdf`, default `json`)
selects the rendered output -- see FLOW.md §54 for why format selection is
folded into this one endpoint rather than a separate
`GET .../export`. Response: for `json`, the standard `ApiResponse`
envelope wrapping the assembled report payload; for `csv`/`excel`/`pdf`,
the real rendered file bytes with the correct `Content-Type` and a
`Content-Disposition: attachment` header naming the file. Every call --
regardless of format -- writes one unconditional `audit_log_entries` row
(`report_generated`, see FLOW.md §52 for why this is never throttled).

### `POST /reports/schedule`

Requires `reports.manage` at `ORGANIZATION` scope (the one endpoint in
this part with a fixed, explicit scope -- a `ScheduledReport` is never
platform-wide). `organization_id` is resolved from the mandatory
`X-Organization-Id` header via `RequireOrganization`. Body:
`template_id` (must reference a template visible to the caller),
`frequency` (`daily`/`weekly`/`monthly`), `recipient_emails` (non-empty
list), `export_format` (default `pdf`). `next_run_at` is always computed
server-side from `frequency` (never trusted from the request).

### `GET /reports/schedule` / `GET /reports/schedule/{schedule_id}`

Requires `reports.read`. Lists (paginated, GLOBAL-scoped callers see every
organization's schedules) or fetches one schedule -- an out-of-scope
schedule reads as `404`.

### `PUT /reports/schedule/{schedule_id}` / `DELETE /reports/schedule/{schedule_id}`

Requires `reports.manage`. Partial update (changing `frequency`
recomputes `next_run_at` from "now" under the new cadence rather than
leaving it stale) / soft delete. Every mutation writes its own
`audit_log_entries` row.

### Beat-scheduled report delivery (no HTTP surface)

Every hour (`reports-run-scheduled` in `app.core.celery_app`'s
`beat_schedule`), `report_tasks.run_scheduled_reports` sweeps for every
active `ScheduledReport` whose `next_run_at` has arrived, and for each:
generates the report (the exact same `ReportGenerationService.generate`
`POST /reports` itself calls), renders it in the schedule's own
`export_format`, "sends" it via `app.domains.otp`'s existing
`EmailProviderProtocol`/`LoggingEmailProvider` (reused verbatim -- see
FLOW.md §55 for the resulting honest attachment limitation: the shared
protocol has no attachment parameter, so the notification email describes
the report rather than attaching its bytes) to every `recipient_emails`
address, and updates `last_run_at`/`last_run_status`/`next_run_at`. One
schedule failing never blocks the rest of the hourly batch -- see FLOW.md
§51 for the exact per-schedule failure-isolation contract (mirroring
Module 012 Part 1's own per-organization aggregation-batch isolation).

## Billing Endpoints (Module 013 Part 1: Plan + License + Usage Core)

See `docs/billing/README.md`/`FLOW.md`/`DATABASE.md` for the full design
write-up -- including the `Organization.subscription_tier` relationship
decision, the `PlanFeature` typed-column choice, the full `License` status
transition graph, the `LicenseChangeLog` history mechanism, the
license-expiry-sweep scope decision, and exactly which existing domains'
data backs every `UsageMetric`.

### Plans (`billing.*`, reused -- no new `PermissionModule`)

`POST /plans` -- create a plan (unlimited plans, per the spec). Requires
`billing.manage` at **`GLOBAL`** scope explicitly (the pricing catalog is
platform-wide; in this codebase's seed data that's `Super Admin`/
`Platform Admin`/`Billing Manager`). Body: name/slug/`plan_type`/
`billing_cycle`/`base_price` (a `Decimal`, never a float)/`currency`/
`is_active`/`is_public`/`sort_order`/`features` (a list of
`{feature_key, feature_type, limit_value|is_enabled|tier_value}`, exactly
one of the three value columns populated per `feature_type`).

`GET /plans` -- requires `billing.read`. `include_private=true` is only
honored for a caller who independently holds `billing.manage` at `GLOBAL`
scope (checked inline via `AccessValidator.has_permission`); every other
caller always sees `is_public=true` plans only. Filterable by
`is_active`/`plan_type`, paginated.

`GET /plans/{plan_id}` -- requires `billing.read`; no public/private
filtering (knowing the id is treated as sufficient).

`PUT /plans/{plan_id}` -- requires `billing.update` at `GLOBAL` scope.
Partial update; supplying `features` fully replaces the plan's feature
set.

`DELETE /plans/{plan_id}` -- requires `billing.manage` at `GLOBAL` scope.
Deactivates (`is_active=false` + soft delete), never a hard delete.

### Licenses (`subscriptions.*`, reused -- no new `PermissionModule`)

`POST /licenses` -- requires `subscriptions.create`. Body:
`organization_id`, `plan_id`, optional `expires_at`. One `License` row per
organization, ever (`organization_id` unique) -- a second call for the
same organization is a `409` (`DuplicateLicenseError`); use
upgrade/downgrade to change plans instead. Starts in
`pending_activation`.

`GET /licenses/me` -- requires `subscriptions.read` plus a resolved
`X-Organization-Id` (`RequireOrganization`) -- the caller's own
organization's license.

`GET /licenses/{organization_id}` -- requires `subscriptions.read` --
any organization's license (RBAC scope governs which organizations a
caller may query).

`GET /licenses/{license_id}/history` -- requires `subscriptions.read` --
the full, ordered `LicenseChangeLog` for this license (every
assign/upgrade/downgrade, `from_plan_id`/`to_plan_id`/`changed_at`/
`changed_by_user_id`/`reason`).

`POST /licenses/{license_id}/activate` -- requires `subscriptions.update`.
Legal from `pending_activation` or `suspended` only (see FLOW.md's full
transition graph).

`POST /licenses/{license_id}/suspend` -- requires `subscriptions.update`.
Body: `reason` (required). Legal from `active` only.

`POST /licenses/{license_id}/cancel` -- requires `subscriptions.update`.
One additive endpoint beyond the spec's explicit list -- `cancelled` is a
first-class, required terminal state in the transition graph and needs a
real route to reach it (see FLOW.md). Terminal; legal from any
non-terminal state.

`POST /licenses/{license_id}/upgrade` / `POST /licenses/{license_id}/downgrade`
-- requires `subscriptions.update`. Body: `new_plan_id`, optional `reason`.
Legal only when the license is currently `active`; rejects a no-op
same-plan call (`409`). A downgrade additionally recomputes the
organization's real current usage and rejects (`409`,
`DowngradeBelowUsageError`, naming every exceeded metric) a change that
would immediately violate the target plan's own `LIMIT` features. Both
record a real `LicenseChangeLog` row and re-sync
`Organization.subscription_tier` to the new plan's slug.

### Usage

`GET /usage/{organization_id}` -- requires `billing.read`. Returns this
organization's current-period `UsageMetric` values (computing them fresh
if nothing has been recorded yet this calendar month) plus, for every
metric with a corresponding `LIMIT`-typed `PlanFeature` on the
organization's active license's plan, whether it is currently exceeded.

`POST /usage/{organization_id}/refresh` -- requires `billing.update`.
Forces a real recomputation (never a cached/stale read) of every
`UsageMetric` for this organization, then returns the same
usage-vs-limit summary as the `GET` above.

## Billing Endpoints (Module 013 Part 2: Subscription + Renewal + Coupon Engines)

See `docs/billing/FLOW.md` §12-§20 for the full design write-up --
including the `Subscription` status transition graph, the
`PAUSED`-vs-`CANCELLED` distinction, the `PaymentGatewayProtocol` seam
(and exactly what BE-013 Part 3 needs to wire in), the
coupon-applies-once decision, the flat-discount clamp, the atomic
`current_uses` increment, and the grace-period-then-expire composition
with Part 1's `LicenseService.expire_license`.

### Subscriptions (`subscriptions.*`, reused -- no new `PermissionModule`)

`POST /subscriptions` -- requires `subscriptions.create`. Body:
`organization_id`, `plan_id`, optional `coupon_code`. One `Subscription`
row per organization, ever (mirrors `License`'s own cardinality) -- a
second call for the same organization is a `409`
(`DuplicateSubscriptionError`). Composes with Part 1's
`LicenseService.assign_license`/`activate_license` (never duplicates
license assignment). Starts `trialing` (a `FREE_TRIAL`-type plan) or
`active` otherwise. A valid `coupon_code` is redeemed (a real
`CouponUsage` row written, `current_uses` incremented) at this exact
moment -- see the "coupon applies once" decision below.

`GET /subscriptions/{organization_id}` -- requires `subscriptions.read`.

`POST /subscriptions/{id}/cancel` -- requires `subscriptions.update`.
Body: `immediate` (bool, default `false`). `immediate=true` transitions
to `cancelled` right now and suspends (reversible, not hard-expires) the
underlying license. `immediate=false` only sets `cancel_at_period_end`;
the actual transition + license suspension happens later, when
`current_period_end` is reached (`RenewalService.process_renewal`'s own
fast path).

`POST /subscriptions/{id}/reactivate` -- requires `subscriptions.update`.
Legal only from `cancelled`, and only while the underlying license has
not since been hard-expired by the grace-period sweep (`409`
`SubscriptionReactivationNotAllowedError` otherwise) -- reverses the
license suspension and starts a fresh billing period from now.

`POST /subscriptions/{id}/pause` -- requires `subscriptions.update`.
Legal only from `active`. Stops future renewal attempts; the underlying
license/entitlements are completely untouched (see the
`PAUSED`-vs-`CANCELLED` write-up).

`POST /subscriptions/{id}/resume` -- requires `subscriptions.update`.
Legal only from `paused`. If the current billing period already elapsed
while paused, starts a fresh one from now; otherwise leaves it unchanged.

### Coupons (`billing.*`, reused -- no new `PermissionModule`)

`POST /coupons` -- requires `billing.manage` at **`GLOBAL`** scope
(mirrors the Plan-catalog gate -- an uncontrolled coupon is a direct
revenue-impacting instrument). Body: `code` (uppercase-normalized),
`discount_type` (`percentage`|`flat`), `discount_value`, optional
`currency`/`organization_id` (null = GLOBAL coupon)/`max_uses`,
`valid_from`, optional `valid_until`, `is_active`,
`applicable_plan_ids` (empty = every plan).

`GET /coupons` -- requires `billing.read`. Filterable by
`organization_id`/`is_active`, paginated.

`GET /coupons/{coupon_id}` -- requires `billing.read`.

`PUT /coupons/{coupon_id}` -- requires `billing.update` at `GLOBAL`
scope. Partial update; supplying `applicable_plan_ids` fully replaces
the plan restriction set.

`DELETE /coupons/{coupon_id}` -- requires `billing.manage` at `GLOBAL`
scope. Deactivates (`is_active=false` + soft delete), never a hard
delete.

`POST /coupons/validate` -- requires `subscriptions.read` (a
checkout-time eligibility read, not a billing-catalog-admin action).
Body: `code`, `organization_id`, `plan_id`, optional `base_amount`.
**Real-time, no side effects** -- writes no `CouponUsage` row, never
increments `current_uses` (the mutating counterpart,
`CouponService.apply_coupon`, is only ever called from
`POST /subscriptions`). When `base_amount` is supplied, the response
includes the real computed `estimated_discount_amount`.

## Billing Endpoints (Module 013 Part 3: Payment Service + Real Stripe/Razorpay Integration + Webhooks)

See `docs/billing/FLOW.md` §22-§34 for the full design write-up --
including the real idempotency-key enforcement mechanism, the exact
Stripe/Razorpay webhook signature verification schemes, the Redis-backed
event-id dedup, the per-provider refund/retry idempotency-key strategy,
the provider-selection model, and the honest "no real credentials in this
sandbox, but real SDK code" framing.

### Payments (`billing.*`, reused -- no new `PermissionModule`)

`POST /payments` -- requires `billing.manage`. Body: `organization_id`,
optional `subscription_id` (set for a manual renewal retry against an
existing subscription), `amount` (`Decimal`, `> 0`), `currency`,
`provider` (`stripe`|`razorpay`), `idempotency_key` (caller-supplied, 8-255
chars). **The same `idempotency_key` presented twice always returns/
references the same `Payment` row** -- a real database unique constraint
is the actual enforcement mechanism (see FLOW.md §22), not merely an
application-level check. If the selected provider is not configured (no
real API key anywhere in this sandbox), returns `503`
(`PaymentGatewayNotConfiguredError`) -- the `Payment` row is still created
and recorded as `failed` with a clear reason, a real history entry, not a
silently-dropped attempt.

`GET /payments` -- requires `billing.read` plus a resolved
`X-Organization-Id` (`RequireOrganization`). Tenant-scoped payment history
(see FLOW.md §27 for why this is the entire "Payment History" surface, not
a second table) -- filterable by `status`, paginated.

`GET /payments/{payment_id}` -- requires `billing.read` plus
`X-Organization-Id`. A payment belonging to a different organization
reports `404`, never leaking its existence (real tenant isolation,
enforced in `PaymentService.get_payment`).

`POST /payments/{payment_id}/refund` -- requires `billing.manage`. Body:
optional `amount` (omit for a full refund of the remaining chargeable
amount). Rejects (`409`) a refund of a payment not currently
`succeeded`/`partially_refunded`, or a refund amount exceeding the
remaining refundable amount. Real SDK refund call
(`stripe.Refund.create`/`client.payment.refund`) through the same
not-configured-safe guard as `POST /payments`; updates `refunded_amount`
and transitions to `refunded`/`partially_refunded` accordingly.

`POST /payments/{payment_id}/retry` -- requires `billing.manage`.
Re-attempts a charge for a `failed` payment, reusing the **same** `Payment`
row (never a new one -- see FLOW.md §27). Rejects (`409`) a retry of a
payment not currently `failed`. Stripe retries with a **fresh, derived**
idempotency key (Stripe's own guidance -- reusing the original key would
return the cached original decline, never actually retrying); Razorpay's
installed SDK exposes no client-supplied idempotency parameter at all, so
its retry is unconditionally a fresh provider-side attempt regardless (see
FLOW.md §25 for the full per-provider write-up). The `Payment
.idempotency_key` **column** itself never changes across a retry -- only
the wire-level key Stripe receives does.

### Payment Methods (`billing.*`, reused -- no new `PermissionModule`)

`POST /payments/methods` -- requires `billing.manage`. Body:
`organization_id`, `provider`, `provider_payment_method_id` (the
provider's own opaque token -- e.g. a Stripe `pm_...` id -- **never** a
raw card number/CVV, this platform never handles or stores raw card
data), `method_type` (`card`|`bank_account`|`upi`|`other`), optional
`last4` (display-only), `is_default`. At most one payment method may be
`is_default=true` per organization -- setting a new default atomically
unsets every sibling (`PaymentMethodRepository.set_as_default`).

`GET /payments/methods` -- requires `billing.read` plus
`X-Organization-Id`. Lists this organization's active payment methods.

`DELETE /payments/methods/{payment_method_id}` -- requires
`billing.manage`. Deactivates (`is_active=false`, `is_default=false` +
soft delete), never a hard delete.

### Webhooks (provider-authenticated via real signature verification -- NOT RBAC)

`POST /webhooks/stripe` -- verifies the real `Stripe-Signature` header
(timestamped HMAC-SHA256, via the installed `stripe` SDK's own
`stripe.Webhook.construct_event`; rejects a signature older than
`Settings.stripe_webhook_tolerance_seconds`, default 300s) against the raw
request body. Handles `payment_intent.succeeded`/
`payment_intent.payment_failed` -- updates the matching `Payment` row (by
`provider_payment_id`) and, when that payment is tied to a subscription
renewal, calls `RenewalService.confirm_renewal_payment_succeeded`/
`confirm_renewal_payment_failed` (two small, additive Part 3 methods that
compose with -- never reimplement -- the existing `_mark_renewed`/
`_mark_past_due` transitions `process_renewal`'s own synchronous path
already uses). Every other event type is acknowledged and ignored. An
invalid signature is a real `400`
(`WebhookSignatureInvalidError`); an internal processing error is a real
`500` (both providers' own retry policies re-deliver on a `5xx`, which is
the correct behavior for a transient failure). Success response: a plain
`{"received": true}`, not the standard `ApiResponse` envelope (neither
provider parses the response body, only the status code).

`POST /webhooks/razorpay` -- verifies the real `X-Razorpay-Signature`
header (HMAC-SHA256 of the raw body, via the installed `razorpay` SDK's
own `razorpay.Utility.verify_webhook_signature`; Razorpay's real scheme
has no timestamp/replay-tolerance component at all). Handles
`payment.captured`/`payment.failed` with the identical
`Payment`-row-update + `RenewalService` composition as the Stripe handler
above. Same response/error-status conventions.

Both webhook endpoints track processed event ids in Redis
(`webhooks.RedisWebhookEventDedup`, `Settings
.payment_webhook_event_dedup_ttl_seconds`, default 7 days) -- the same
event id delivered twice (a real, documented behavior of both providers)
is only ever actually applied once (see FLOW.md §24).

## Billing Endpoints (Module 013 Part 4: Invoice Engine + Tax/GST)

See `docs/billing/FLOW.md` §35-§46 for the full design write-up --
including the `BillingProfile` storage-location decision, the invoice
number generator's exact DB-level-atomic concurrency mechanism, the real
CGST/SGST/IGST-vs-IGST GST rule + platform home-jurisdiction config, the
tax-breakdown storage shape, the frozen `billing_snapshot` "copy, not
reference" principle, the payment-webhook-to-invoice composition, and the
PDF reuse-vs-dedicated-renderer decision.

### Invoices (`invoices.*` -- `PermissionModule.INVOICES`, seeded since BE-004)

`GET /invoices` -- requires `invoices.read` plus a resolved
`X-Organization-Id` (`RequireOrganization`). Tenant-scoped invoice
history, optionally filtered by `status`
(`draft`|`issued`|`paid`|`overdue`|`cancelled`|`void`), paginated.

`GET /invoices/{invoice_id}` -- requires `invoices.read` plus
`X-Organization-Id`. An invoice belonging to a different organization
reports `404`, never leaking its existence (real tenant isolation,
enforced in `InvoiceService.get_invoice`). Response includes the
invoice's own line items, any credit/debit notes, and its frozen
`billing_snapshot`.

`GET /invoices/{invoice_id}/download` -- requires `invoices.export` plus
`X-Organization-Id`. Returns the real, `reportlab`-rendered invoice PDF
(`Content-Type: application/pdf`,
`Content-Disposition: attachment; filename="<invoice_number>.pdf"`) --
raw file bytes, not the standard `ApiResponse` envelope (the same
"raw bytes + Content-Type/Content-Disposition" shape
`GET /reports`'s own export-download path already establishes). Header
(invoice number, dates, seller/buyer address block), a real line-item
table, a tax breakdown showing CGST/SGST/IGST as separate lines whenever
non-zero (never a lumped generic "tax" line), totals, and a footer.

`POST /invoices/{invoice_id}/void` -- requires `invoices.manage`. A
never-issued `draft` invoice transitions to `cancelled`; an `issued`/
`overdue` invoice transitions to `void`. Rejects (`409`) voiding an
already-`paid` invoice -- correct a paid invoice via a credit note
instead (see FLOW.md §46).

`POST /invoices/{invoice_id}/credit-note` -- requires `invoices.manage`.
Body: `amount` (`Decimal`, `> 0`), `reason`. Legal only against an
`issued`/`overdue`/`paid` invoice; rejects (`400`) an amount exceeding
the invoice's own `total_amount`. Generates its own real, independent
`"CN-2026-00001"`-shaped sequential number (see FLOW.md §37) -- never the
invoice sequence.

`POST /invoices/{invoice_id}/debit-note` -- requires `invoices.manage`.
Same legal invoice statuses as a credit note, no upper-amount ceiling (a
debit note represents a genuine additional charge). Its own,
independent `"DN-2026-00001"`-shaped sequence -- never the invoice's,
never the credit note's.

Invoices are generated automatically by
`InvoiceService.generate_invoice_for_subscription` (composing --  never
recomputing -- the same real charge-amount computation
`RenewalService.process_renewal` itself uses) and marked paid
automatically the moment a real payment webhook confirms success for a
payment tied to that invoice's own subscription (see FLOW.md §42) --
there is no `POST /invoices` endpoint; invoice creation is a real system
event, not a direct API write.

### Tax Rates (`billing.*`, reused -- no new `PermissionModule`; Super Admin "Manage Taxes")

`POST /billing/tax-rates` -- requires `billing.manage` at
`scope=GLOBAL`. Body: `name`, `tax_type`
(`gst`|`vat`|`sales_tax`|`none`), `rate_percentage` (`Decimal`, `0`-`100`),
`country_code` (ISO 3166-1 alpha-2), `is_active`. Platform-wide pricing/
tax catalog -- pinned to `GLOBAL` scope exactly like `POST /plans`/
`POST /coupons`.

`GET /billing/tax-rates` -- requires `billing.read`. Lists tax rates,
filterable by `country_code`/`is_active`, paginated.

`PUT /billing/tax-rates/{tax_rate_id}` -- requires `billing.update` at
`scope=GLOBAL`. Partial update.

### Billing Profile (`billing.*`, reused -- no new `PermissionModule`)

`POST /billing/profile` -- requires `billing.update` plus
`X-Organization-Id`. Body: `billing_name`, `billing_address_line1`,
optional `billing_address_line2`, `billing_city`, `billing_state`,
`billing_country` (ISO 3166-1 alpha-2), `billing_postal_code`, optional
`gst_identifier`, `tax_exempt`. Creates the organization's one
`BillingProfile` row the first time, upserts it in place on every
subsequent call (one profile per organization, ever -- see FLOW.md §36).
Editing this profile never retroactively changes any already-issued
invoice's own frozen `billing_snapshot` (see FLOW.md §41).

`GET /billing/profile/me` -- requires `billing.read` plus
`X-Organization-Id`. The caller's own organization's billing profile.

`GET /billing/profile/{organization_id}` -- requires `billing.read`.

## Billing Endpoints (Module 013 Part 5: Super Admin + Customer Billing Dashboards -- completes BE-013)

See `docs/billing/FLOW.md` §47-§55 for the full design write-up --
including the exact MRR/ARR/churn-rate formulas, the honest multi-currency
caveat, why this domain's own new Revenue Dashboard is a **separate**
capability from `app.domains.analytics`'s still-untouched
`RevenueMetricsResponse` placeholder, the customer self-service upgrade/
downgrade finding + fix, and the dashboard-view audit-throttling decision.
No new tables, no new migration.

### Super Admin Billing Dashboard

`GET /billing/dashboard/super-admin` -- requires `billing.read` at
`scope=GLOBAL` (mirrors every other platform-wide dashboard in this
codebase; a non-GLOBAL-scoped caller is rejected with a real `403` before
any dashboard logic runs). Query params: `months` (`1`-`36`, default `12`
-- the Revenue trend window), `page`/`page_size` (applied to both the
Customer Billing rows and the Failed Payments listing),
`failed_payments_organization_id` (optional filter). Returns one composite
payload with four real, computed sections:

* `revenue` -- `total_revenue`/`total_refunded` (net of every "captured
  money" `Payment` status, not just `SUCCEEDED` -- see FLOW.md §48),
  `mrr`/`arr` (summed over currently-`ACTIVE` subscriptions, normalized by
  `billing_cycle`), `active_paying_subscription_count`, a month-by-month
  `trend`, and an honest `currency_note` (no FX-conversion exists anywhere
  in this codebase -- every sum is raw, un-converted).
* `subscriptions` -- `counts_by_status`, `counts_by_plan_type`, and
  `churn` (`period_start`/`period_end`, `active_at_period_start`,
  `cancelled_this_period`, `churn_rate` -- `null`, never a fabricated
  `0.0`, when there is no active base to measure against; see FLOW.md
  §49 for the exact formula).
* `customers` -- paginated per-organization summary rows (`organization_id`/
  `name`, current `plan_id`/`name`/`slug`, `subscription_status`,
  `lifetime_revenue`, `outstanding_invoice_count`).
* `failed_payments` -- a listing of `FAILED` payments (reusing Part 3's
  own `PaymentService.list_failed_payments` verbatim), each flagged with
  `retry_eligible` (reusing the exact rule
  `PaymentService.retry_failed_payment` itself enforces), plus
  `counts_by_provider`.

### Customer Billing Dashboard (tenant-scoped)

`GET /billing/dashboard/me` -- requires `billing.read` plus
`X-Organization-Id` (`RequireOrganization` -- real, active-membership-
checked tenant resolution, mirrors `GET /billing/profile/me`'s identical
twin-route shape). `GET /billing/dashboard/{organization_id}` -- requires
`billing.read` (ordinary inferred scope, mirrors `GET
/billing/profile/{organization_id}`). Both return a unified summary --
pure composition over six already-built Parts 1-4 service methods, nothing
recomputed (see FLOW.md §47): current `license`/`plan` status, active
`subscription` details (period, `auto_renew`, next renewal date), a real
`usage` vs-limit snapshot (`UsageService.validate_usage_against_license`),
`recent_invoices`/`recent_payments` (capped to a dashboard-summary limit --
the full history is already available at `GET /invoices`/`GET /payments`),
and registered `payment_methods`.

### Renewal Settings (`subscriptions.update`, reused)

`PATCH /subscriptions/{subscription_id}/renewal-settings` -- requires
`subscriptions.update` plus `X-Organization-Id`. Body: `auto_renew`
(`bool`). Confirmed genuinely missing from Parts 1-4 -- updates
`Subscription.auto_renew` in place (no new column; that field has existed
since Part 2). Unlike every other `/subscriptions/{id}/*` mutator in this
domain, this endpoint **does** enforce a real tenant check: a caller
supplying an `organization_id` that does not own the target subscription
gets an honest `404`, never a leak (see FLOW.md §52 for why this endpoint
specifically breaks from the "operate on the entity by id" precedent the
others establish).

### Customer self-service upgrade/downgrade (fix, no new endpoint)

`POST /licenses/{license_id}/upgrade`/`downgrade` (Part 1) now accept
**either** `subscriptions.update` **or** `billing.update` at whichever
scope the request's own `X-Organization-Id` header implies -- a real,
confirmed RBAC seed-data gap (`Organization Owner`/`Admin` hold only
`SUBSCRIPTIONS: READ`) meant neither role could previously self-serve a
plan change, despite the endpoint itself already being tenant-capable.
Fixed entirely inside `app.domains.billing` (no RBAC seed edit) by
accepting `billing.update` -- which `Organization Owner` already holds --
as an alternative. See FLOW.md §51 for the full write-up, including why
the underlying RBAC seed-data gap itself is left as an honest, documented
follow-up rather than fixed directly (out of this Part's own directory-rule
boundary).


## Guest Teams Endpoints

See `docs/guest_teams/FLOW.md` for the full design write-up -- team status
lifecycle, join/removal/revocation semantics, the RBAC permission-module
decision (`PermissionModule.GUEST_TEAMS`, a new additive module), and the
shared-quota check's real scope vs. enforcement. Guest Teams is an
extension of `app.domains.guest`, composing its real `GuestService` (guest
identity resolution, session termination) rather than duplicating any of
it.

### Guest-facing

`POST /guest-teams/join` -- no RBAC (mirrors OTP's/Voucher's/Guest's own
identical guest-facing precedent: the caller is a guest presenting a
team's join code, with no platform-user identity RBAC could ever grant a
permission to). Body: `team_code`, `identifier`, optional `device_mac`/
`device_name`. Idempotent if the identifier already resolves to an active
member of the team; rejects an over-capacity team (`max_members`), an
expired team (checked lazily on this same call), or a revoked team.
Rejoining after a prior removal is allowed and creates a new membership
row (see FLOW.md §4.3).

### Admin-facing (tenant-scoped via `X-Organization-Id`)

`POST /guest-teams` -- requires `guest_teams.create`. Body: `organization_id`,
optional `location_id` (omit for an org-wide team), `name`, optional
`max_members`/`shared_data_limit_mb`/`expires_at`. Generates a unique join
code (reusing the voucher domain's own print-friendly alphabet) and creates
the team `ACTIVE`.

`GET /guest-teams` -- requires `guest_teams.read`. Paginated, filterable by
`location_id`/`status`.

`GET /guest-teams/{team_id}` -- requires `guest_teams.read`. Returns the
team plus a real summary: member count, active-session count, cumulative
(all-time) bandwidth usage, and -- if `shared_data_limit_mb` is set --
remaining shared quota and whether it has been exceeded.

`DELETE /guest-teams/{team_id}/members/{guest_id}` -- requires
`guest_teams.execute` (not `.delete` -- mirrors `guest_sessions.execute`'s
own choice for disconnect/terminate, see FLOW.md §10). Removes one member
from the roster and also terminates that guest's currently-active
session(s) (a real, argued design decision -- see FLOW.md §5), with
session-termination failures logged but never blocking the removal itself.

`POST /guest-teams/{team_id}/revoke` -- requires `guest_teams.execute`.
Transitions the whole team to `revoked` and terminates every currently-
active member's active session(s) via the real
`GuestService.terminate_session`, with per-member failure isolation (one
member's termination failure never stops the rest -- see FLOW.md §6).
Response includes `terminated_session_ids` and `failed_member_ids`.


## Policy Endpoints

See `docs/policy/FLOW.md` for the full design write-up -- the leaf-module
dependency rule, versioning/rollback semantics, resolution precedence, the
RBAC permission-module decision (`PermissionModule.POLICY`, a new additive
module), and exactly which existing platform constants this module's
default ruleset mirrors. Policy is a brand-new, dependency-free leaf domain
(`app.domains.organization`/`app.domains.location`/`app.domains.rbac`
only) -- **every** route below is admin-facing; there is no guest-facing
route in this domain at all.

`GET /policies/resolve` -- requires `policy.read`. Query params:
`policy_type` (required), optional `organization_id`/`location_id`. Returns
the effective rule set for that scope: the winning assignment's rules if
one matches (location beats organization beats global, tie-broken by
`priority`), or `constants.PLATFORM_DEFAULT_RULES` with
`source="platform_default"` if none does. Registered before
`GET /policies/{policy_id}` -- load-bearing route ordering (see
`router.py`'s own module docstring).

`POST /policies` -- requires `policy.create`. Body: optional
`organization_id` (omit for a platform-wide policy -- only a platform-level
caller, one with no `X-Organization-Id`, may do this), `policy_type`,
`name`, optional `description`. Created with no version yet
(`current_version_id=null`).

`GET /policies` -- requires `policy.read`. Paginated, filterable by
`policy_type`, scoped to the caller's own organization (or platform-wide
policies, if the caller is a platform-level caller).

`GET /policies/{policy_id}` -- requires `policy.read`. Returns the policy
plus its full version history and assignment list. A platform-wide policy
(`organization_id=null`) is readable by any organization; an organization's
own custom policy is only readable by that organization (or a
platform-level caller).

`POST /policies/{policy_id}/deactivate` -- requires `policy.execute`.
Retires the policy definition (`is_active=false`) without deleting it or
its version history.

`POST /policies/{policy_id}/versions` -- requires `policy.update`. Body:
`rules` (a JSON object). Validated against `schemas.POLICY_RULE_SCHEMAS
[policy_type]` (a concrete schema for `session`/`authn`; any JSON object for
every other type -- see FLOW.md §3/§9) before being persisted as a new
`draft` version. Version numbers increment per policy (`1`, `2`, `3`, ...).

`POST /policies/{policy_id}/versions/{version_id}/publish` -- requires
`policy.execute`. Transitions a `draft` version to `published` and moves
`Policy.current_version_id` to it. Publishing an already-published version
is rejected, not a silent no-op.

`POST /policies/{policy_id}/rollback` -- requires `policy.execute`. Query
param: `target_version_id`. Re-points `current_version_id` at any earlier
*already-published* version of the same policy -- rejects a `draft` target
or a version belonging to a different policy. Never deletes or duplicates
any version row (see FLOW.md §2).

`POST /policies/{policy_id}/assignments` -- requires `policy.create`. Body:
`scope_type` (one of `app.domains.rbac.enums.ScopeType`'s values), `scope_id`
(required unless `scope_type` is `global`), optional `priority`. Requires
the policy to already have a published version.

`GET /policies/{policy_id}/assignments` -- requires `policy.read`. Lists
every assignment (active and inactive) for the policy.

`DELETE /policies/{policy_id}/assignments/{assignment_id}` -- requires
`policy.execute`. Deactivates the assignment (`is_active=false`) -- it is
immediately excluded from future resolution, but the row itself is kept for
history.


## RADIUS NAS Admin Endpoints

See `docs/guest/NAS_EXTENSION.md` for the full design write-up -- this
extends `app.domains.guest`'s pre-existing `RadiusNasClient` (a router's
registered FreeRADIUS NAS identity, already wired into a real
`rlm_rest` integration) rather than introducing a second, parallel NAS
concept. `POST/GET /radius/authorize`/`/radius/accounting` (the RADIUS
wire-protocol endpoints) are unchanged by this extension and remain
unauthenticated (NAS shared-secret via `CurrentNas`) -- everything below is
new, RBAC-gated (`radius.*`) admin management.

`POST /radius/nas` -- requires `radius.create`. Body: `router_id`,
`nas_identifier`, optional `shared_secret` (omit to auto-generate a
cryptographically-random one), optional `name`/`description`/`ip_address`
(defaults from the router's own public/management IP). Response includes
`shared_secret` in plaintext -- the only time it is ever exposed again
after this call.

`GET /radius/nas` -- requires `radius.read`. Paginated, filterable by
`location_id`/`router_id`/`status`.

`GET /radius/nas/{nas_id}` -- requires `radius.read`.

`PUT /radius/nas/{nas_id}` -- requires `radius.update`. Cosmetic-only:
`name`/`description`/`ip_address`. Status transitions go through the
dedicated endpoints below, never this one.

`DELETE /radius/nas/{nas_id}` -- requires `radius.delete`. Transitions to
the terminal `deleted` status and sets the row's ordinary soft-delete
fields -- it disappears from `GET /radius/nas` afterward, the same as
every other domain's own soft-deleted rows.

`POST /radius/nas/{nas_id}/activate` -- requires `radius.execute`.

`POST /radius/nas/{nas_id}/disable` -- requires `radius.execute`. Body:
optional `reason`. A disabled NAS fails `authenticate_nas` (RADIUS
Authorize/Accounting calls from it are rejected) until reactivated.

`POST /radius/nas/{nas_id}/regenerate-secret` -- requires `radius.execute`.
Immediately invalidates the old secret. Response includes the new
plaintext `shared_secret`, the same one-time-exposure contract as
registration. Does not require or change the NAS's own status.

`GET /locations/{location_id}/nas` -- requires `radius.read`. Every NAS
registered at that location, paginated.

`GET /routers/{router_id}/nas` -- requires `radius.read`. A router has at
most one NAS (`router_id` is unique on `radius_nas_clients`) -- returns
that single object, not a list, despite the route's own plural shape.


## Provisioning Engine: Vendor Capabilities Endpoint

See `docs/router_provisioning/PROVISIONING_ENGINE.md` for the full design
write-up -- a bounded Strategy/Adapter extension on top of the already-real
`router_provisioning`/`router_agent` workflow/queue infrastructure, not a
rebuild of it. `POST /locations/{id}/routers` and `POST /router-templates`
both gained an optional `vendor` field (default `"mikrotik"`); no other
existing endpoint's request/response shape changed.

`GET /router-provisioning/vendors` -- requires `router_provisioning.read`.
Returns every registered `ProvisioningAdapterProtocol` implementation's
real, static capability description (supported job types, config format,
diff/rollback/health-snapshot support). No live device connection or
command execution -- see `PROVISIONING_ENGINE.md` §2 for what this
introspection endpoint is (and is not).


## Provisioning Engine Orchestrator Endpoints

See `docs/provisioning_engine/FLOW.md` for the full design write-up -- the
end-to-end automation orchestrator (Discover -> Validate -> Generate
Config -> Push Config -> Verify Config -> Health Check -> Register
Monitoring), a brand-new domain (`app.domains.provisioning_engine`)
composing `router`/`router_provisioning`/`policy`/`guest` rather than
duplicating any of them. Distinct from the "Vendor Capabilities" endpoint
above, which belongs to `router_provisioning`'s own, earlier, narrower
adapter extension. Every route below requires `provisioning_engine.*` and
is registered under `/provision`.

`POST /provision` -- requires `provisioning_engine.create`. Body:
`router_id`, optional `provision_template_id`, optional `max_retries`
(default 3). Freezes the router's effective session `Policy` at creation
time (`policy_snapshot`) -- a later `Policy` edit never silently changes an
already-created job.

`GET /provision/jobs` -- requires `provisioning_engine.read`. Paginated,
filterable by `router_id`/`status`. Registered before
`GET /provision/{job_id}` -- load-bearing route ordering (see `router.py`'s
own module docstring).

`GET /provision/history` -- requires `provisioning_engine.read`. Query
param: `router_id` (required). Every past job (original, retries,
rollbacks) for one router, chronological -- a read-model, not a separate
table.

`POST /provision/discover` -- requires `provisioning_engine.execute`. Body:
`router_id`. Connects to the router via its real device adapter and
returns vendor/model/serial/firmware/CPU/memory/uptime/interfaces/MAC --
usable independently of a job, e.g. a dashboard's "test connection" button.

`POST /provision/validate` -- requires `provisioning_engine.execute`.
Body: `router_id`, optional `provision_template_id`. Raises on any real
validation failure (missing device credentials, unsupported vendor, a
template/router vendor mismatch); returns a plain success message
otherwise.

`POST /provision/configuration` -- requires `provisioning_engine.execute`.
Body: `router_id`, `provision_template_id`. Seeds the template's `settings`
as real `ConfigVariable` rows (idempotent), registers a NAS for the router
if none exists yet, and returns a rendered configuration preview. Never
creates a `ConfigVersion` itself -- that is `PUSH_CONFIG`'s job, within a
real job run.

`POST /provision/{job_id}/start` -- requires `provisioning_engine.execute`.
Transitions a `pending` job to `queued` and enqueues it for
`tasks.drain_provision_queue` to actually run.

`POST /provision/{job_id}/retry` -- requires `provisioning_engine.execute`.
Only a `failed` job may be retried, and only up to `max_retries`. Creates
and starts a **new** job (`retry_of_job_id` set) -- the original row is
never mutated.

`POST /provision/{job_id}/rollback` -- requires
`provisioning_engine.execute`. Only a `success`, not-yet-rolled-back job
may be rolled back. Creates and starts a **new** job (`is_rollback=true`,
`rollback_of_job_id` + `rollback_target_version_id` set) targeting the
`ConfigVersion` immediately before the one the original job applied;
rejects if there is no prior version.

`POST /provision/{job_id}/cancel` -- requires
`provisioning_engine.execute`. Body: optional `reason`. Cancellable from
any non-terminal status; marks every not-yet-started step `skipped` rather
than leaving them `pending` forever.

`GET /provision/{job_id}/timeline` -- requires `provisioning_engine.read`.
A read-model aggregating the job's own step transitions and log entries
into one chronological list -- no separate timeline table.

`GET /provision/{job_id}` -- requires `provisioning_engine.read`.
