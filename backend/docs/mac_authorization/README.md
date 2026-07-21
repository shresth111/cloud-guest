# MAC Authorization Domain

The MAC Authorization domain is CloudGuest's organization/location-scoped
MAC address whitelist: Dashboard -> MAC Authorization ->
`mac_authorization_entries`. Unlike most domains in this batch, it
composes no router/device concept at all -- entries are purely
organization-scoped (optionally further filtered by location).

It tracks each whitelisted MAC address's authorization type (permanent or
temporary with a real expiry), an admin-facing comment, and an
enable/disable toggle, plus bulk import (JSON body) and export (CSV
download).

See `FLOW.md` for the full design write-up (including its explicit
relationship to `app.domains.guest_access`) and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0041_create_mac_authorization_tables.py
  app/
    domains/
      mac_authorization/
        __init__.py
        constants.py        # MacAuthorizationType, MAC_ADDRESS_PATTERN, MAX_IMPORT_BATCH_SIZE
        models.py            # MacAuthorizationEntry
        exceptions.py         # MacAuthorizationError subclasses (CloudGuestError)
        events.py              # MacAuthorizationEntryCreated/Updated/Deleted
        validators.py            # pure MAC normalization + expiry validation
        repository.py             # MacAuthorizationRepositoryProtocol/Repository
        service.py                 # MacAuthorizationService: CRUD + import/export + is_mac_authorized
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI DI wiring (no cross-domain composition needed)
        router.py                      # FastAPI routes (7 endpoints, all admin-facing, RBAC-gated)
      rbac/
        enums.py             # PermissionModule.MAC_AUTHORIZATION (new) + AuditAction gained mac_authorization_entry_* values
        seed.py              # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE + 5 system-role grants
  docs/
    mac_authorization/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_mac_authorization.py   # models/repository/service/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/mac-authorization` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("mac_authorization.*")` against a brand-new, additive
`PermissionModule.MAC_AUTHORIZATION` key.

```text
POST   /api/v1/mac-authorization/entries                # mac_authorization.create
GET    /api/v1/mac-authorization/entries                # mac_authorization.read
POST   /api/v1/mac-authorization/entries/import         # mac_authorization.import
GET    /api/v1/mac-authorization/entries/export          # mac_authorization.export
GET    /api/v1/mac-authorization/entries/{entry_id}      # mac_authorization.read
PUT    /api/v1/mac-authorization/entries/{entry_id}      # mac_authorization.update
DELETE /api/v1/mac-authorization/entries/{entry_id}      # mac_authorization.delete
```

`/entries/import`/`/entries/export` are registered *before*
`/entries/{entry_id}` -- load-bearing route ordering (see `router.py`'s
own module docstring): without it, `GET /entries/export` would be
swallowed by the `{entry_id}` path parameter and fail UUID parsing.

Import accepts a plain JSON body (`{"entries": [...]}`, bounded to 1000
rows), mirroring `app.domains.voucher.router.import_vouchers`'s identical
shape. Export returns a raw `text/csv` `Response` (not the standard
`ApiResponse` envelope), mirroring
`app.domains.voucher.router.export_voucher_batch`'s identical "a file
someone opens directly cannot usefully be JSON-wrapped" reasoning.

## Composition

Reused, never re-implemented: `GenericRepository`, `PageParams`/
`PaginationMeta`, `ApiResponse`/`build_response`, `CloudGuestError`,
RBAC's `RequirePermission`/`CurrentOrganization`/`audit_log_entries`.
Unlike every router-scoped domain in this batch, there is **no**
`app.domains.router` composition here at all -- see `FLOW.md` §1.

## Validation

* `mac_address` is normalized (via Python's own `re` module, not a
  third-party MAC-parsing library) to the canonical uppercase
  colon-separated form, accepting either colon or dash separators on
  input -- `validators.normalize_mac_address`.
* `expires_at` must be set and in the future for a `temporary` entry, and
  must be absent for a `permanent` one -- `validators.validate_expiry`.
* An organization may not hold two non-deleted entries for the same MAC
  address -- enforced at both the service layer and a partial unique
  database index.

## Honest Scope: Not Yet Wired Into Guest Login

`MacAuthorizationService.is_mac_authorized` is the real seam a future
pass integrating this domain with `app.domains.guest.service
.GuestService`'s own login flow would call, to actually implement
"Authentication Bypass" (skipping OTP/voucher verification for a trusted
device). This build deliberately does not wire that integration -- see
`FLOW.md` §1 for the full reasoning, including this domain's explicit,
deliberate relationship to (and independence from)
`app.domains.guest_access.models.DeviceAccessRule`.

## Testing

`tests/unit/test_mac_authorization.py` exercises `MacAuthorizationService`
against a small, hand-rolled in-memory fake for its own repository (no
cross-domain protocol to fake at all in this domain). Coverage: entry CRUD
(tenant isolation), MAC normalization/validation, expiry validation per
authorization type, uniqueness per organization (including "same MAC
across different orgs is fine" and "reusable after soft-delete"), the
required-organization-context guard on create/import/export, bulk import
(partial success), CSV export, the `is_mac_authorized` read-model query
(valid/expired/disabled/missing/malformed), and a structural check that
every route carries a `RequirePermission` dependency.
