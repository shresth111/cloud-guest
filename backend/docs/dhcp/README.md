# DHCP Pool Management Domain

The DHCP Pool Management domain is CloudGuest's per-router DHCP pool
inventory: Dashboard -> DHCP Pool Management -> Router Service ->
`dhcp_pools` (real device push deferred -- see below).

It tracks every DHCP address pool a router serves: name, the interface it
serves, address range (start/end), gateway, primary/secondary DNS, lease
time, and an enable/disable toggle. Overlapping ranges on the same
router+interface are rejected at create/update time.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0039_create_dhcp_pool_tables.py
  app/
    domains/
      dhcp/
        __init__.py
        constants.py        # DEFAULT_LEASE_TIME_SECONDS
        models.py            # DhcpPool
        exceptions.py         # DhcpError subclasses (CloudGuestError)
        events.py              # DhcpPoolCreated/Updated/Deleted
        validators.py            # pure IP/range validation + overlap check
        repository.py             # DhcpRepositoryProtocol/Repository
        service.py                 # DhcpService: CRUD + validation + conflict detection
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI DI wiring (composes router's own DI)
        router.py                      # FastAPI routes (5 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (get_router), never modified
      rbac/
        enums.py             # PermissionModule.DHCP already existed (seeded ahead of any real domain, like BANDWIDTH) -- reused as-is
        seed.py              # AuditAction gained dhcp_pool_* values; display name updated to "DHCP Pool Management"
  docs/
    dhcp/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_dhcp.py          # models/repository/service/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/dhcp-pools` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("dhcp.*")` against the already-seeded
`PermissionModule.DHCP` key (seeded ahead of any real domain, specifically
for this concern -- see `FLOW.md` §4, the same reuse posture
`app.domains.queue_management` established for `PermissionModule.BANDWIDTH`).

```text
POST   /api/v1/dhcp-pools                 # dhcp.create
GET    /api/v1/dhcp-pools                 # dhcp.read
GET    /api/v1/dhcp-pools/{pool_id}       # dhcp.read
PUT    /api/v1/dhcp-pools/{pool_id}       # dhcp.update
DELETE /api/v1/dhcp-pools/{pool_id}       # dhcp.delete
```

No `EXECUTE` action -- this domain has no device-facing action in this
pass (mirrors `app.domains.vlan`/`app.domains.isp_routing`'s identical
scope).

`GET /dhcp-pools` is registered *before* `GET /dhcp-pools/{pool_id}` --
load-bearing route ordering (see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

## Validation and Conflict Detection

* `address_range_start`/`address_range_end` must both be real, parseable
  IP addresses of the same family with start <= end --
  `validators.validate_address_range`.
* `gateway_ip_address`/`dns_primary`/`dns_secondary`, when supplied, must
  be real, parseable IP addresses -- `validators.validate_ip_address`.
* A pool's range is checked against every other non-deleted pool on the
  *same router and interface* -- two different interfaces are different
  L2 domains and may legitimately reuse the same private range. This is a
  service-layer check only, not a database constraint (see `models.py`'s
  own module docstring for why: range overlap isn't expressible as a
  simple equality index).

## Honest Scope: No Live Device Push in This Pass

Mirrors `app.domains.vlan`/`app.domains.isp_routing`/`app.domains.policy`'s
own "config resource + enable/disable, realized onto a device later"
precedent exactly -- no `device_adapters.py`, no Celery task. Real
RouterOS DHCP server/pool provisioning belongs to the not-yet-built
Network Configuration Management domain's own provisioning-integration
layer. See `FLOW.md` §2 for the full reasoning.

## Testing

`tests/unit/test_dhcp.py` exercises `DhcpService` against small,
hand-rolled in-memory fakes for its own repository and the composed
`RouterLookupProtocol` (mirrors `test_vlan.py`'s own "fake the narrow
Protocol boundary" precedent). Coverage: pool CRUD (tenant isolation),
address-range validation (ordering, IP parseability), gateway/DNS IP
validation, range-conflict detection (overlap rejected on the same
router+interface, allowed across different interfaces or different
routers, re-checked on update excluding the pool itself), and a
structural check that every route carries a `RequirePermission`
dependency.
