# ISP Management Domain

The ISP Management domain is CloudGuest's per-router WAN/ISP uplink
inventory: Dashboard -> ISP Management -> Router Service (device
connection/credentials) -> ISP Health Adapter -> {MikroTik ISP Health
Adapter (real RouterOS `/tool/ping`), Cisco/Aruba/UniFi (future)}.

It tracks every WAN uplink a router carries (`IspLink`: provider name,
type, static `role` priority, bandwidth, gateway/DNS, interface), runs
real periodic health checks against each link's own gateway (latency,
packet loss), keeps an append-only history of every check
(`IspHealthCheck`), and automatically fails traffic over to the best
available backup link once a primary crosses a real, threshold-gated
unhealthy streak -- never on a single blip.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0036_create_isp_management_tables.py
  app/
    domains/
      isp/
        __init__.py
        constants.py        # IspLinkType/IspLinkRole/HealthStatus + health-check thresholds
        models.py            # IspLink (current state), IspHealthCheck (history)
        exceptions.py         # IspError subclasses (CloudGuestError)
        events.py              # IspLinkCreated/Updated/Deleted/HealthCheckRecorded/Failover/FailbackTriggered
        validators.py            # pure health-status classification / threshold checks
        device_adapters.py        # BaseIspHealthAdapter Protocol + MikroTikIspHealthAdapter (real librouteros /tool/ping)
        repository.py               # IspRepositoryProtocol/Repository
        service.py                   # IspService: CRUD, health checks, failover/failback
        tasks.py                      # Celery: run_isp_health_check_sweep (platform-wide, every 60s)
        schemas.py                     # Pydantic request/response DTOs
        dependencies.py                  # FastAPI DI wiring (composes app.domains.router's own DI)
        router.py                         # FastAPI routes (9 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (device connection fields, decrypted API secret), never modified
      rbac/
        enums.py             # PermissionModule.ISP (new) + AuditAction gained isp_* values
        seed.py              # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE[PermissionModule.ISP]
  docs/
    isp/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_isp.py           # models/repository/service/sweep/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/isp` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("isp.*")` against a brand-new, additive
`PermissionModule.ISP` key.

```text
POST   /api/v1/isp/links                          # isp.create
GET    /api/v1/isp/links                          # isp.read
GET    /api/v1/isp/links/{link_id}                # isp.read
PUT    /api/v1/isp/links/{link_id}                # isp.update
DELETE /api/v1/isp/links/{link_id}                # isp.delete

POST   /api/v1/isp/links/{link_id}/check-health   # isp.execute -- manual, on-demand
GET    /api/v1/isp/links/{link_id}/health-checks  # isp.read -- history + computed availability %

POST   /api/v1/isp/routers/{router_id}/failover   # isp.execute -- manual trigger
POST   /api/v1/isp/routers/{router_id}/failback   # isp.execute -- manual trigger
```

`GET /links` is registered *before* `GET /links/{link_id}` -- load-bearing
route ordering (see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`/
  `get_decrypted_api_secret` -- this domain never opens a device connection
  or decrypts a credential itself.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

The per-router vendor adapter is resolved dynamically from `Router.vendor`
(`device_adapter_resolver`, default `device_adapters.get_isp_health_adapter`),
mirroring `app.domains.queue_management.service.QueueManagementService`'s
own "resolve per-router at the point of use, never fix one adapter at
construction time" convention -- never a fixed adapter injected at
construction/DI time.

## `role` vs. `is_active_uplink`

A router's static, admin-assigned priority (`role`: `PRIMARY`/`BACKUP`)
never changes during a failover. `is_active_uplink` is the dynamic flag
tracking which link is *currently* carrying traffic -- it flips during a
real failover/failback without ever touching `role`. See `FLOW.md` §2 for
the full reasoning and the partial-unique-index enforcement.

## Failover / Failback: Threshold-Gated, Never on a Single Blip

`IspLink.consecutive_unhealthy_count` must reach
`constants.DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER` (default 3)
*consecutive* `UNHEALTHY` readings before an automatic failover fires.
Failback (auto or manual) requires the primary to be genuinely `HEALTHY`
(not merely "not unhealthy") before restoring it. See `FLOW.md` §3.

## Honest Scope: Real Device I/O, Untested End-to-End Here

`MikroTikIspHealthAdapter` issues a genuine RouterOS `/tool/ping` command
via the same real, genuinely-installed `librouteros` dependency this
codebase's other MikroTik adapters already use -- but via the raw `Api`
callable form (`api("/tool/ping", ...)`), not `.path(...)`, since a ping is
a one-shot command invocation, not menu CRUD. This is the first call site
in the codebase to use that form. There is no live MikroTik device
anywhere in this sandbox -- if actually invoked, it raises a real
`IspDeviceConnectionError` the moment it tries to open a real socket,
never a fabricated ping result. See `device_adapters.py`'s own module
docstring for the full write-up.

## Testing

`tests/unit/test_isp.py` exercises `IspService` against small,
hand-rolled in-memory fakes for its own repository and the composed
`RouterLookupProtocol`/health adapter (mirrors
`test_queue_management.py`'s own "fake the narrow Protocol boundary"
precedent). Coverage: link CRUD (tenant isolation, primary-uniqueness),
health-check recording and classification, threshold-gated automatic
failover/failback, manual failover/failback triggers (lowest-priority
healthy backup selection, unhealthy-backup skipping), the computed
availability-percentage read-model, the platform-wide health-check
sweep's per-link failure isolation, and a structural check that every
route carries a `RequirePermission` dependency.
