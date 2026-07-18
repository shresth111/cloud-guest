# Module 007: User Management/Aggregation Domain

The User domain is a management/aggregation **layer**, not a second
identity table. Every identity/profile column (`first_name`, `last_name`,
`email`, `username`, `phone`, `password_hash`, `profile_photo`,
`designation`, `department`, `employee_id`, `timezone`, `language`,
`status`, `is_active`, `is_verified`, etc.) already lives on
`app.domains.auth.models.User` (Module 003). This module composes that
table with Module 005's `OrganizationMember` (does this user belong to an
organization) and Module 004's RBAC (what can this user do) to cover
administrative user-management use cases none of those domains own alone:
admin-driven account creation, profile update, deactivation/reactivation,
tenant-scoped listing/search, and an aggregated "user detail" view.

See `USER_ARCHITECTURE.md` for the full design (what was added to `auth`
and why, the invited-vs-active admin-membership decision, admin-vs-self
editable fields, the aggregated-view design, and every other judgment call
made where the brief left room for one).

## Folder Structure

```text
backend/
  app/
    domains/
      user/
        __init__.py
        enums.py           # UserAccountStatus (typed view over User.status)
        exceptions.py       # UserError subclasses + re-exported auth errors
        service.py          # UserService: orchestration/read-composition, no owned model
        schemas.py          # Pydantic request/response DTOs
        dependencies.py     # get_user_service wiring
        router.py           # FastAPI routes
      auth/
        repository.py       # AuthRepositoryProtocol gained list_users (additive)
      rbac/
        enums.py            # AuditAction gained user_* values
  docs/
    user/
      README.md
      USER_ARCHITECTURE.md
  tests/
    unit/
      test_user.py
```

Note there is **no `models.py` or `repository.py`** in this domain -- see
`USER_ARCHITECTURE.md` §1 for why: it owns no persisted table of its own, so
there is nothing for a repository to wrap.

## API Surface

All endpoints are registered under `/api/v1` (see `app/api/v1/router.py`).
Admin endpoints are protected by RBAC's existing `RequirePermission()`
against the already-seeded `users.*` permission keys (`users.create`,
`.read`, `.update`, `.manage` -- see
`app/domains/rbac/seed.py::MODULE_ACTIONS[PermissionModule.USERS]`). No new
permission keys were invented. `/me` endpoints require only an
authenticated caller.

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

`GET /api/v1/users/{id}` and `GET /api/v1/me` return the **aggregated**
view: identity + organization memberships + active roles, assembled by
`UserService`, not a second persisted model.

Every admin endpoint resolves `CurrentOrganization` (`X-Organization-Id`)
and passes it to `UserService` as `requesting_organization_id`, enforcing
tenant scoping the same way `OrganizationService`/`LocationService` enforce
it: a platform-level caller (no header -- a `GLOBAL`-scoped role) may
touch any user; an org-scoped caller may only list/view/manage users who
are active members of its own organization, or (if it is an MSP) of one of
its child organizations.

## Reused, Not Duplicated

* `GenericRepository`, `PageParams`/`PaginationMeta`/`paginate` (Module 002)
  -- via the new `AuthRepository.list_users` hand-written query, for the
  same reason `OrganizationRepository.list_organizations`/
  `LocationRepository.list_locations` are hand-written (an OR-across-columns
  `ilike` search can't be expressed via `GenericRepository`'s equality/IN-
  only filter convention).
* `auth.models.User`, `AuthRepositoryProtocol.get_user_by_id/by_email/
  by_username/create_user/update_user` (Module 003) -- identity CRUD is
  never reimplemented, only composed through a narrow
  `IdentityRepositoryProtocol`.
* `auth.service.EmailAlreadyExistsError`/`UsernameAlreadyExistsError`
  (Module 003) -- duplicate-email/username rejection reuses these directly
  rather than a parallel `user`-domain error type.
* `auth.dependencies.get_current_user`'s existing `is_active` check (Module
  003) -- deactivation needs no separate session-revocation step; a
  deactivated user's bearer token already fails on its very next
  authenticated request.
* `OrganizationService.invite_member`/`accept_invite`/`list_members`/
  `list_user_organizations`/`get_organization`/`list_children` (Module 005),
  composed through a narrow `OrganizationLookupProtocol` -- membership
  creation/reads and MSP-hierarchy tenant scoping are never re-implemented
  against `organization_members`/`organizations` directly.
* `RBACService.assign_role_to_user` (Module 004), composed through a narrow
  `RoleAssignmentProtocol`, for the *optional* initial-role-assignment
  convenience at creation time only -- this domain never reimplements
  RBAC's own `POST/DELETE /users/{id}/roles` endpoints.
* `RoleResolver.get_active_roles` (Module 004), composed through a narrow
  `RoleResolverProtocol`, for the aggregated detail view's "active roles"
  section -- role lookup, never role assignment.
* RBAC's `audit_log_entries` table, written through a narrow
  `AuditLogWriter` protocol (see `AuditAction`'s new `user_*` values in
  `app/domains/rbac/enums.py`).
* `ApiResponse`/`build_response`, `CloudGuestError` (Module 001/004).

## Testing

`tests/unit/test_user.py` follows `test_organization.py`/`test_location
.py`'s conventions: small, independent in-memory fakes for each of the
narrow protocols `UserService` composes (`FakeIdentityRepository`,
`FakeOrganizationLookup`, `FakeRoleAssigner`, `FakeRoleResolver`,
`FakeAuditLogWriter`), since neither Postgres nor Redis is available in
this environment. Coverage: admin user creation (with and without an
organization + initial role), duplicate-email/username rejection,
tenant-scoped listing/search (platform vs. org-scoped vs. MSP-child
members), aggregated-detail assembly (identity + memberships + roles) and
its own tenant scoping, admin-vs-self profile-update field restrictions,
deactivate/reactivate (including a direct integration check that a
deactivated user's access token is rejected by the real, unmodified
`auth.dependencies.get_current_user`), and the self-deactivation guard. The
full pre-existing `tests/unit/test_auth.py` (Module 003),
`tests/unit/test_rbac.py` (Module 004), `tests/unit/test_organization.py`
(Module 005), and `tests/unit/test_location.py` (Module 006) suites all
still pass unmodified.
