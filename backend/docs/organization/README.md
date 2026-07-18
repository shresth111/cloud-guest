# Module 005: Organization Domain

The Organization domain models CloudGuest's tenants: plain customer
organizations and MSP ("managed service provider") containers that own a
portfolio of other organizations, plus the membership records that say
which users belong to which organization. It builds on Module 002
(database core: `BaseModel`, `GenericRepository`, pagination/filter/sort
utilities), Module 003 (auth: identity, `get_current_user`), and Module 004
(RBAC: `organizations.*` permission keys, `audit_log_entries`) without
modifying auth and touching RBAC only at the one targeted seam described
below.

See `ORGANIZATION_ARCHITECTURE.md` for the full design (MSP modeling,
membership vs. RBAC role-assignment distinction, the `settings` JSONB
extension point and billing boundary, the `CurrentOrganization` validation
change, and every judgment call made where the brief left room for one).

## Folder Structure

```text
backend/
  alembic/
    versions/
      0003_create_organization_tables.py
      0004_add_organization_fk_to_rbac_tables.py
  app/
    domains/
      organization/
        __init__.py
        enums.py           # OrganizationType / OrganizationStatus / MembershipStatus
        models.py          # Organization, OrganizationMember (SQLAlchemy ORM)
        exceptions.py      # OrganizationError subclasses (CloudGuestError)
        repository.py      # OrganizationRepositoryProtocol + OrganizationRepository
        service.py          # OrganizationService: CRUD, MSP hierarchy, membership, audit
        schemas.py           # Pydantic request/response DTOs
        dependencies.py       # get_organization_repository / get_organization_service
        router.py              # FastAPI routes
      rbac/
        models.py            # organization_id columns now carry a real FK (see below)
        dependencies.py       # CurrentOrganization now validates real membership
        enums.py              # AuditAction gained organization_* values
  docs/
    organization/
      README.md
      ORGANIZATION_ARCHITECTURE.md
  tests/
    unit/
      test_organization.py
```

## API Surface

All endpoints are registered under `/api/v1` (see `app/api/v1/router.py`)
and protected by RBAC's existing `RequirePermission()` against the
already-seeded `organizations.*` permission keys (`organizations.create`,
`.read`, `.update`, `.delete`, `.manage` -- see
`app/domains/rbac/seed.py::MODULE_ACTIONS[PermissionModule.ORGANIZATIONS]`).
No new permission keys were invented.

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

`DELETE /organizations/{id}` archives (soft-deletes), it never hard-deletes.
`GET /organizations` scopes results: a platform-level caller (no
`X-Organization-Id` header -- a `GLOBAL`-scoped role) sees every
organization; an org-scoped caller sees only its own organization plus its
children (if it is an MSP).

## Reused, Not Duplicated

* `GenericRepository`, `PageParams`/`PaginationMeta`/`paginate` (Module 002).
* `get_current_user` / `AuthUser` (Module 003) -- no re-derivation of
  identity.
* `RequirePermission`, `CurrentOrganization`, `ApiResponse`/`build_response`,
  `CloudGuestError` (Module 004).
* RBAC's `audit_log_entries` table, written through a narrow `AuditLogWriter`
  protocol rather than a new audit mechanism (see `AuditAction`'s new
  `organization_*` values in `app/domains/rbac/enums.py`).

## Testing

`tests/unit/test_organization.py` follows `test_auth.py`/`test_rbac.py`'s
conventions: a `FakeOrganizationRepository` (in-memory, implements
`OrganizationRepositoryProtocol`) and a `FakeAuditLogWriter` stand in for
Postgres, since neither Postgres nor Redis is available in this
environment. Coverage: organization CRUD, slug/email normalization, tenant
scoping (platform vs. org-scoped list/read/write), MSP hierarchy (child
creation, non-MSP-cannot-have-children, circular-parent prevention at any
depth, MSP-downgrade-with-children prevention), membership lifecycle
(invite/accept/remove, duplicate-active/pending-invite prevention,
suspended-must-reactivate, removed-can-be-re-invited, last-active-member
protection), and a direct model-level check that the RBAC
`organization_id` FK follow-up is actually in place. The RBAC FK migration
itself is additionally verified by running the full pre-existing
`tests/unit/test_rbac.py` suite (38 tests, all still passing unmodified).
