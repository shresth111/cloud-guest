# Module 008: Router Domain

> **Provisioning Engine addendum:** `Router` gained one additive column,
> `vendor` (default `"mikrotik"`, real and true -- every device deployed
> today is one), the extension point
> `app.domains.router_provisioning.adapters.get_provisioning_adapter`
> resolves against. See `docs/router_provisioning/PROVISIONING_ENGINE.md`
> for the full write-up.

The Router domain models CloudGuest's MikroTik RouterOS device records:
device registration, connection-credential storage, lifecycle/health
tracking, and zero-touch provisioning (hierarchy: Organization -> Location
-> Router -> Guest). It builds on Module 002 (database core: `BaseModel`,
`GenericRepository`, pagination/filter/sort utilities), Module 003 (auth:
identity, `get_current_user`), Module 004 (RBAC: `routers.*`/
`router_provisioning.*` permission keys, `audit_log_entries`), and Module
006 (Location: hierarchy validation composed via `LocationService`) without
modifying auth/organization/location internals and touching RBAC only at
the targeted seam described below (the `router_id` FK follow-up).

This module is specifically about the Router *device record* and its
provisioning lifecycle -- **not** the guest-facing captive portal/hotspot/
network-service configuration layered on top of a router. Captive Portal,
Guest WiFi, Guest Users, Guest Sessions, Radius, WireGuard, Firewall, DHCP,
DNS, Hotspot, Bandwidth, Monitoring, and Alerts are all separate,
already-seeded permission modules reserved for future domains.

See `ROUTER_ARCHITECTURE.md` for the full design (the `RouterStatus` state
machine and transition graph, the credential-encryption interim design, the
zero-touch provisioning flow and device-auth scheme, the
`organization_id` denormalization decision, and why no `RouterRole` table
was added).

## Folder Structure

```text
backend/
  alembic/
    versions/
      0007_create_router_tables.py
      0008_add_router_fk_to_rbac_tables.py
  app/
    domains/
      router/
        __init__.py
        enums.py           # RouterStatus, ROUTER_STATUS_TRANSITIONS, RouterHealthStatus
        models.py           # Router, RouterProvisioningToken (SQLAlchemy ORM)
        exceptions.py       # RouterError subclasses (CloudGuestError)
        crypto.py           # Fernet encrypt/decrypt helpers for API credentials
        repository.py       # RouterRepositoryProtocol + RouterRepository
        service.py          # RouterService: CRUD, hierarchy validation, lifecycle, provisioning, audit
        schemas.py          # Pydantic request/response DTOs
        dependencies.py     # get_router_repository / get_router_service
        router.py            # FastAPI routes
      rbac/
        models.py           # router_id columns now carry a real FK (see below)
        enums.py             # AuditAction gained router_* values
      core/
        config.py            # router_encryption_key, router_provisioning_token_expire_hours
  docs/
    router/
      README.md
      ROUTER_ARCHITECTURE.md
  tests/
    unit/
      test_router.py
```

## API Surface

All endpoints are registered under `/api/v1` (see `app/api/v1/router.py`)
and protected by RBAC's existing `RequirePermission()` against the
already-seeded `routers.*`/`router_provisioning.*` permission keys (see
`app/domains/rbac/seed.py::MODULE_ACTIONS[PermissionModule.ROUTERS]`/
`[PermissionModule.ROUTER_PROVISIONING]`). No new permission keys were
invented.

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

`DELETE /routers/{id}` decommissions (soft-deletes), it never hard-deletes.
Every user-facing endpoint resolves `CurrentOrganization`
(`X-Organization-Id`) and passes it to `RouterService` as
`requesting_organization_id`, enforcing tenant scoping the same way
`OrganizationService`/`LocationService` enforce it: a platform-level caller
(no header -- a `GLOBAL`-scoped role) may touch any router; an org-scoped
caller may only touch routers belonging to its own organization, or (if it
is an MSP) to one of its child organizations.

`POST /routers/{id}/provisioning-token` is approval-gated: it requires
*both* `router_provisioning.create` and `router_provisioning.approve` (see
`ROUTER_ARCHITECTURE.md` §5). `POST /routers/provisioning/check-in` is the
one endpoint in this codebase that is **not** authenticated as a platform
user at all -- it is presented by the physical device itself, using the
provisioning token as its sole credential (see `ROUTER_ARCHITECTURE.md` §5).

## Reused, Not Duplicated

* `GenericRepository`, `PageParams`/`PaginationMeta`/`paginate` (Module 002).
* `get_current_user` / `AuthUser` (Module 003) -- no re-derivation of
  identity.
* `RequirePermission`, `CurrentOrganization`, `ApiResponse`/`build_response`,
  `CloudGuestError` (Module 004).
* `LocationService.get_location` (Module 006), composed through a narrow
  `LocationLookupProtocol` -- the parent-location existence/archived check
  is never re-implemented with a raw query against `locations`.
* `OrganizationService.get_organization` (Module 005), composed through the
  identical narrow `OrganizationLookupProtocol` `LocationService` itself
  defines -- used for MSP-child tenant scoping (see
  `ROUTER_ARCHITECTURE.md` §1).
* RBAC's `audit_log_entries` table, written through a narrow `AuditLogWriter`
  protocol rather than a new audit mechanism (see `AuditAction`'s new
  `router_*` values in `app/domains/rbac/enums.py`).

## New, Not Reused (Genuine Additions)

* `cryptography` (Fernet symmetric encryption) -- a genuinely new
  dependency; no encryption utility (only one-way password hashing) existed
  anywhere in this codebase before this module. See
  `ROUTER_ARCHITECTURE.md` §3.
* `Settings.router_encryption_key` / `Settings
  .router_provisioning_token_expire_hours` -- new, documented config fields
  following `jwt_secret_key`'s existing pattern (required-override-in-
  production, sensible local-dev default).

## Testing

`tests/unit/test_router.py` follows `test_location.py`'s conventions: a
`FakeRouterRepository`, a `FakeLocationLookup` and `FakeOrganizationLookup`
(small, independent stand-ins for `LocationService`'s/`OrganizationService`'s
duck-typed contracts, so this test file has no hard dependency on either
domain's own test module), and a `FakeAuditLogWriter`, since neither
Postgres nor Redis is available in this environment. Coverage: router CRUD,
serial-number/MAC-address uniqueness, location-must-exist-and-not-be-
archived validation, the full status-transition graph (every legal edge
plus a representative illegal jump for each state), zero-touch provisioning
(token generation, single-use consumption, expiry, wrong-router-state
rejection), credential encryption round-trip, tenant scoping (platform vs.
org-scoped vs. MSP-child access), and a direct model-level check that the
RBAC `router_id` FK follow-up is actually in place (plus that `msp_id`
correctly remains FK-less and that `audit_log_entries` has no `router_id`
column at all). The RBAC FK migration itself is additionally verified by
running the full pre-existing `tests/unit/test_rbac.py` suite, all still
passing unmodified, and the one Module 006 test that encoded "`router_id`
is still FK-less" (`test_location.py
::TestRbacLocationFkFollowUp::test_router_id_columns_remain_fk_less`) was
updated in place -- see that test's new docstring -- to assert the current,
post-Module-008 state instead, since Module 008 landing is exactly the
anticipated event that test's own comment predicted would supersede it.
