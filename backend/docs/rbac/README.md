# Module 004: Enterprise RBAC

CloudGuest RBAC provides a full, data-driven Role-Based Access Control system
with multi-tenant scoping across the platform hierarchy: CloudGuest (platform)
-> MSP -> Organization -> Location -> Router -> Guest. It builds on Module 002
(database core: `BaseModel`, `GenericRepository`, pagination/filter/sort
utilities) and Module 003 (auth: identity, `get_current_user`) without
modifying either.

See `RBAC_ARCHITECTURE.md` for the full design (scope model, resolver
design, inheritance/override semantics, cache invalidation, and every
judgment call made where the spec left room for one), and
`PERMISSION_MATRIX.md` for a table of default role -> permission-module
grants, mechanically generated from `app/domains/rbac/seed.py`.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0002_create_rbac_tables.py
  app/
    domains/
      rbac/
        __init__.py
        authorization.py   # PermissionResolver / RoleResolver / ScopeResolver / AccessValidator
        cache.py            # Redis-backed effective-permission cache
        context.py           # ScopeContext / GrantScope value objects
        dependencies.py      # CurrentUser/CurrentOrganization/RequirePermission/...
        enums.py             # ScopeType / PermissionAction / PermissionModule / ...
        exceptions.py        # RBAC-specific CloudGuestError subclasses
        models.py             # SQLAlchemy ORM models (11 tables)
        repository.py         # RBACRepositoryProtocol + RBACRepository
        router.py              # FastAPI routes
        schemas.py              # Pydantic request/response DTOs
        seed.py                  # Data-driven seed data + idempotent seed_rbac()
        service.py               # RBACService: CRUD, cloning, assignment, validation, audit
  docs/
    rbac/
      README.md
      RBAC_ARCHITECTURE.md
      PERMISSION_MATRIX.md
  tests/
    unit/
      test_rbac.py
```

## Database Tables

`permission_groups`, `permissions`, `permission_scopes`, `roles`,
`role_scopes`, `role_permissions`, `user_roles`, `permission_overrides`,
`organization_roles`, `location_roles`, `audit_log_entries` -- all extend
`app.database.base.BaseModel`. See `RBAC_ARCHITECTURE.md` for what each
table is for and why.

## Seeding

```bash
cd backend
python -m app.domains.rbac.seed
```

Idempotent: safe to run repeatedly (every insert is preceded by an
existence check). Seeds 36 permission groups (one per `PermissionModule`),
their applicable permissions (module x action, see `MODULE_ACTIONS` in
`seed.py`), permission-scope constraints (`MODULE_NARROWEST_SCOPE`), and the
15 default system roles with their permissions (`SYSTEM_ROLES`).

To regenerate `PERMISSION_MATRIX.md` after changing `seed.py`:

```bash
cd backend
python -c "from app.domains.rbac.seed import generate_permission_matrix_markdown as g; print(g())" > docs/rbac/PERMISSION_MATRIX.md
```

## API Endpoints

All registered under `/api/v1` (see `app/api/v1/router.py`), tagged `RBAC`,
each protected by `RequirePermission`/`RequireRole`:

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

## Alembic

```bash
cd backend
alembic upgrade head       # applies 0001 (auth) then 0002 (rbac)
alembic downgrade -1       # rolls back rbac only
```

## Testing

```bash
cd backend
pytest tests/unit/test_rbac.py
pytest   # full suite
```

See `RBAC_ARCHITECTURE.md`'s "Testing strategy" section for the fake
repository/cache pattern used (mirrors `tests/unit/test_auth.py`).

## Git Commit Message

```text
feat(module-004): add enterprise RBAC with multi-tenant scoping
```
