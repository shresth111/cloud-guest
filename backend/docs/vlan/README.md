# VLAN Management Domain

The VLAN Management domain is CloudGuest's per-router VLAN inventory:
Dashboard -> VLAN Management -> Router Service -> `vlans` (real device
push deferred -- see below).

It tracks every VLAN a router carries: VLAN ID (the real IEEE 802.1Q tag,
1-4094), name, gateway IP, CIDR block, parent interface, description, and
an enable/disable toggle. A router may not hold two non-deleted VLANs
with the same `vlan_id` -- enforced by a partial unique database index.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0038_create_vlan_tables.py
  app/
    domains/
      vlan/
        __init__.py
        constants.py        # MIN_VLAN_ID/MAX_VLAN_ID
        models.py            # Vlan
        exceptions.py         # VlanError subclasses (CloudGuestError)
        events.py              # VlanCreated/Updated/Deleted
        validators.py            # pure vlan_id/CIDR/gateway-IP validation
        repository.py             # VlanRepositoryProtocol/Repository
        service.py                 # VlanService: CRUD + validation
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI DI wiring (composes router's own DI)
        router.py                      # FastAPI routes (5 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (get_router), never modified
      rbac/
        enums.py             # PermissionModule.VLAN (new) + AuditAction gained vlan_* values
        seed.py              # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE[PermissionModule.VLAN]
  docs/
    vlan/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_vlan.py          # models/repository/service/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/vlans` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("vlan.*")` against a brand-new, additive
`PermissionModule.VLAN` key.

```text
POST   /api/v1/vlans                  # vlan.create
GET    /api/v1/vlans                  # vlan.read
GET    /api/v1/vlans/{vlan_pk}        # vlan.read
PUT    /api/v1/vlans/{vlan_pk}        # vlan.update
DELETE /api/v1/vlans/{vlan_pk}        # vlan.delete
```

No `EXECUTE` action -- this domain has no device-facing action in this
pass (mirrors `app.domains.isp_routing`'s identical scope).

`GET /vlans` is registered *before* `GET /vlans/{vlan_pk}` -- load-bearing
route ordering (see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

## Validation

* `vlan_id` must fall within IEEE 802.1Q's real 1-4094 usable range
  (VLAN 0 and 4095 are reserved) -- `validators.validate_vlan_id`.
* `vlan_id` must be unique per router among non-deleted rows -- checked at
  the service layer on both create and update, and enforced at the
  database level by a partial unique index (`uq_vlans_router_id_vlan_id`).
* `cidr`/`gateway_ip_address`, when supplied, must be real, parseable
  values (validated via Python's own `ipaddress` module) --
  `validators.validate_cidr`/`validate_gateway_ip_address`.

## Honest Scope: No Live Device Push in This Pass

Mirrors `app.domains.isp_routing`/`app.domains.policy`'s own "priority/
config + enable/disable, realized onto a device later" precedent exactly
-- no `device_adapters.py`, no Celery task. Real RouterOS VLAN interface +
IP address provisioning belongs to the not-yet-built Network
Configuration Management domain's own provisioning-integration layer. See
`FLOW.md` §2 for the full reasoning.

## Testing

`tests/unit/test_vlan.py` exercises `VlanService` against small,
hand-rolled in-memory fakes for its own repository and the composed
`RouterLookupProtocol` (mirrors `test_isp_routing.py`'s own "fake the
narrow Protocol boundary" precedent). Coverage: VLAN CRUD (tenant
isolation), `vlan_id` range validation, `vlan_id` uniqueness per router
(on both create and update, including that the same `vlan_id` is allowed
across *different* routers, and reusable again after a soft-delete),
CIDR/gateway IP validation, and a structural check that every route
carries a `RequirePermission` dependency.
