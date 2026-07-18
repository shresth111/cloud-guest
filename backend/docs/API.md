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

