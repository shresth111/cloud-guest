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

