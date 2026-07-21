# Hotspot Settings Domain

The Hotspot Settings domain is CloudGuest's per-router hotspot
user-profile inventory: Dashboard -> Hotspot Settings -> Router Service ->
`hotspot_profiles` (real device push composed via `app.domains
.network_config` -- see below).

It tracks every hotspot user-profile a router serves: name,
session-timeout, idle-timeout, upload/download rate limits, a
walled-garden allowed-hosts list, and an enable/disable toggle.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0044_create_hotspot_tables.py
  app/
    domains/
      hotspot/
        __init__.py
        constants.py        # MAX_WALLED_GARDEN_HOSTS
        models.py            # HotspotProfile
        exceptions.py         # HotspotError subclasses (CloudGuestError)
        events.py              # HotspotProfileCreated/Updated/Deleted
        validators.py            # pure walled-garden-host validation
        repository.py             # HotspotRepositoryProtocol/Repository
        service.py                 # HotspotService: CRUD + validation
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI DI wiring (composes router's own DI)
        router.py                      # FastAPI routes (5 endpoints, all admin-facing, RBAC-gated)
      network_config/         # composes list_profiles_for_router, renders /ip hotspot config
      router/                 # composed (get_router), never modified
      rbac/
        enums.py             # PermissionModule.HOTSPOT already existed (seeded ahead of any real domain) -- reused as-is
        seed.py              # AuditAction gained hotspot_profile_* values; display name updated to "Hotspot Settings"
  docs/
    hotspot/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_hotspot.py       # models/repository/service/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/hotspot-profiles` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("hotspot.*")` against the already-seeded
`PermissionModule.HOTSPOT` key (seeded ahead of any real domain,
specifically for this concern -- see `FLOW.md` §3, the same reuse posture
`app.domains.dhcp`/`app.domains.port_forwarding` established for
`PermissionModule.DHCP`/`FIREWALL`).

```text
POST   /api/v1/hotspot-profiles                   # hotspot.create
GET    /api/v1/hotspot-profiles                   # hotspot.read
GET    /api/v1/hotspot-profiles/{profile_id}      # hotspot.read
PUT    /api/v1/hotspot-profiles/{profile_id}      # hotspot.update
DELETE /api/v1/hotspot-profiles/{profile_id}      # hotspot.delete
```

No `EXECUTE`/`MANAGE` action used by this router in this pass, even
though `PermissionModule.HOTSPOT` was pre-seeded with both -- this
domain has no device-facing action of its own; real device provisioning
is composed via `app.domains.network_config`'s own `EXECUTE`-gated push
endpoint instead (mirrors `app.domains.vlan`/`app.domains.dhcp`/
`app.domains.port_forwarding`'s identical scope).

`GET /hotspot-profiles` is registered *before*
`GET /hotspot-profiles/{profile_id}` -- load-bearing route ordering (see
`router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

`app.domains.network_config` composes this domain's own
`list_profiles_for_router` to render real RouterOS `/ip hotspot user
profile`/`/ip hotspot walled-garden` config -- see that domain's own
`FLOW.md` for the render/push details.

## Validation

* Walled-garden hosts: no blank entries, no entries containing
  whitespace, and at most `MAX_WALLED_GARDEN_HOSTS` (200) per profile --
  `validators.validate_walled_garden_hosts`. Deliberately permissive
  otherwise (RouterOS's own `dst-host` matcher accepts plain hostnames,
  IPs, and `*`-prefixed wildcard domains).

## Honest Scope: No Live Device Push in This Pass, Composed via NCM

Mirrors `app.domains.dhcp`/`app.domains.vlan`/`app.domains
.port_forwarding`'s own "config resource + enable/disable, realized onto
a device later" precedent -- no `device_adapters.py`, no Celery task of
its own. Unlike those three domains (built before Network Configuration
Management existed), this domain's real device provisioning is composed
into that pipeline in the *same* pass -- see `FLOW.md` §2 for why only
the `/ip hotspot user profile` + walled-garden slice is modeled, not a
full `/ip hotspot` server bind.

## Testing

`tests/unit/test_hotspot.py` exercises `HotspotService` against small,
hand-rolled in-memory fakes for its own repository and the composed
`RouterLookupProtocol` (mirrors `test_dhcp.py`'s own "fake the narrow
Protocol boundary" precedent). Coverage: profile CRUD (tenant isolation),
walled-garden validation (blank/whitespace entries rejected, too-many-hosts
bound enforced, re-validated on update), the unpaginated
`list_profiles_for_router` read path, and a structural check that every
route carries a `RequirePermission` dependency.
