# Module 006: Location Domain

The Location domain models CloudGuest's physical sites: offices, retail
branches, campus buildings -- each belonging to exactly one Organization,
where Routers are deployed and Guest WiFi is offered (hierarchy:
Organization -> Location -> Router -> Guest). It builds on Module 002
(database core: `BaseModel`, `GenericRepository`, pagination/filter/sort
utilities), Module 003 (auth: identity, `get_current_user`), Module 004
(RBAC: `locations.*` permission keys, `audit_log_entries`), and Module 005
(Organization: hierarchy validation composed via `OrganizationService`)
without modifying auth/organization internals and touching RBAC only at the
targeted seams described below (the `location_id` FK follow-up and
`CurrentLocation` hardening).

See `LOCATION_ARCHITECTURE.md` for the full design (the `LocationStatus`
semantics, why no `LocationMember` table, the RBAC `location_id` FK
`ondelete` policy choices, the immutable-`organization_id` decision, the
`CurrentLocation` org-consistency check, and every judgment call made where
the brief left room for one).

**Smart Location Provisioning** (a later extension of this same domain --
see `FLOW.md` for the full design write-up and `DATABASE.md` for the schema
additions) adds `property_type`/`location_code` to `Location`, and a single
orchestration entry point (`LocationProvisioningService.provision_location`)
that composes Organization/User/RBAC/Router/Router Provisioning/WireGuard/
Billing/Captive Portal/OTP into one real-transaction "Create Location" flow
for a CloudGuest Super Admin. Explicitly *not* a separate
`app/domains/onboarding/` module -- an earlier attempt built it that way and
was rejected by the project owner.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0005_create_location_tables.py
      0006_add_location_fk_to_rbac_tables.py
      0026_add_location_provisioning.py
  app/
    domains/
      location/
        __init__.py
        enums.py                       # LocationStatus, PropertyType
        models.py                      # Location, LocationCodeCounter (SQLAlchemy ORM)
        exceptions.py                  # LocationError subclasses (CloudGuestError)
        repository.py                  # LocationRepositoryProtocol/LocationRepository,
                                        #   LocationCodeCounterRepository
        number_generator.py            # generate_location_code (atomic counter, mirrors billing)
        service.py                     # LocationService: CRUD, hierarchy validation, lifecycle, audit
        provisioning_service.py        # LocationProvisioningService: Smart Location Provisioning
        schemas.py                     # Pydantic request/response DTOs (plain CRUD)
        provisioning_schemas.py        # Pydantic request/response DTOs (provisioning)
        dependencies.py                # get_location_repository / get_location_service
        provisioning_dependencies.py   # get_location_provisioning_service (separate module -- see FLOW.md §3)
        router.py                     # FastAPI routes (CRUD + provisioning)
      billing/
        constants.py       # PlanFeatureKey additively extended (see FLOW.md §5)
      auth/
        models.py           # User.must_change_password (see FLOW.md §9)
        service.py          # AuthService.login/change_password/reset_password additions
      rbac/
        models.py          # location_id columns now carry a real FK (see below)
        dependencies.py    # CurrentLocation now validates real location + org-consistency
        enums.py           # AuditAction gained location_*/provisioning-specific values
  docs/
    location/
      README.md
      LOCATION_ARCHITECTURE.md
      FLOW.md              # Smart Location Provisioning design write-up
      DATABASE.md          # Smart Location Provisioning schema additions
  tests/
    unit/
      test_location.py
      test_location_provisioning.py
```

## API Surface

All endpoints are registered under `/api/v1` (see `app/api/v1/router.py`)
and protected by RBAC's existing `RequirePermission()` against the
already-seeded `locations.*` permission keys (`locations.create`, `.read`,
`.update`, `.delete`, `.manage` -- see
`app/domains/rbac/seed.py::MODULE_ACTIONS[PermissionModule.LOCATIONS]`). No
new permission keys were invented.

```text
GET    /api/v1/organizations/{organization_id}/locations
POST   /api/v1/organizations/{organization_id}/locations
GET    /api/v1/locations/{location_id}
PUT    /api/v1/locations/{location_id}
DELETE /api/v1/locations/{location_id}
POST   /api/v1/locations/{location_id}/suspend
POST   /api/v1/locations/{location_id}/activate
POST   /api/v1/locations/provision                            # Smart Location Provisioning
POST   /api/v1/locations/{location_id}/resend-welcome-email    # Smart Location Provisioning
```

The last two are gated with `locations.manage` pinned at
`ScopeType.GLOBAL` (Super-Admin-class roles only -- see `FLOW.md` §14),
unlike every other endpoint above (which use the ordinary,
scope-inferred-from-headers `RequirePermission` call).

`DELETE /locations/{id}` archives (soft-deletes), it never hard-deletes.
Every endpoint resolves `CurrentOrganization` (`X-Organization-Id`) and
passes it to `LocationService` as `requesting_organization_id`, enforcing
tenant scoping the same way `OrganizationService` enforces it for
organizations themselves: a platform-level caller (no header -- a
`GLOBAL`-scoped role) may touch any location; an org-scoped caller may only
touch locations belonging to its own organization, or (if it is an MSP) to
one of its child organizations.

## Reused, Not Duplicated

* `GenericRepository`, `PageParams`/`PaginationMeta`/`paginate` (Module 002).
* `get_current_user` / `AuthUser` (Module 003) -- no re-derivation of
  identity.
* `RequirePermission`, `CurrentOrganization`, `ApiResponse`/`build_response`,
  `CloudGuestError` (Module 004).
* `OrganizationService.get_organization` (Module 005), composed through a
  narrow `OrganizationLookupProtocol` -- the parent-organization
  existence/archived check is never re-implemented with a raw query against
  `organizations`.
* RBAC's `audit_log_entries` table, written through a narrow `AuditLogWriter`
  protocol rather than a new audit mechanism (see `AuditAction`'s new
  `location_*` values in `app/domains/rbac/enums.py`).

## Testing

`tests/unit/test_location.py` follows `test_organization.py`/`test_rbac.py`'s
conventions: a `FakeLocationRepository`, a `FakeOrganizationLookup` (a small,
independent stand-in for `OrganizationService`'s duck-typed contract, so this
test file has no hard dependency on the organization test module), and a
`FakeAuditLogWriter` stand in for Postgres, since neither Postgres nor Redis
is available in this environment. Coverage: location CRUD, slug uniqueness
within an organization (and slug reuse allowed across different
organizations), organization-must-exist-and-not-be-archived validation,
`organization_id` immutability after creation, lifecycle
(suspend/activate/archive), tenant scoping (platform vs. org-scoped vs.
MSP-child access on read/list/create), and a direct model-level check that
the RBAC `location_id` FK follow-up is actually in place (plus that
`router_id` correctly remains FK-less). The RBAC FK migration itself is
additionally verified by running the full pre-existing `tests/unit/test_rbac.py`
suite (38 tests, all still passing unmodified) and `tests/unit/test_organization.py`
(36 tests, all still passing unmodified).

`tests/unit/test_location_provisioning.py` covers Smart Location
Provisioning: the full happy-path flow (every composed step verified via
protocol-conforming spy fakes, `LocationService` itself exercised as the
real class), the existing-vs-new-organization conditional, the real
single-transaction rollback proof (`TestTransactionalRollback`, see
`FLOW.md` §2), `location_code` format/year-reset/concurrent-collision
safety, the default-config-template resolution and honest gap, the
billing feature-override/custom-plan-cloning behavior, username/temporary-
password generation, the shown-once temporary-password discipline,
`resend_welcome_email`'s owner lookup and password-omission behavior, the
Super-Admin/GLOBAL-scope-only gating (a direct, seed-data-driven regression
test, not fragile route introspection), and `must_change_password`
enforcement (reusing `test_auth.py`'s own fakes).
