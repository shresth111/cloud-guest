# Network Diagnostics Domain

The Network Diagnostics domain is CloudGuest's real, on-demand
network-tool execution engine: Dashboard -> Network Diagnostics ->
Router Service -> real `/tool/ping`/`/tool/traceroute` on the router
itself -> `diagnostic_runs` (an immutable history log).

This is the final domain of the original 13-item roadmap fragment. Unlike
DHCP/VLAN/Port Forwarding/Hotspot/QoS (static config-resource inventory
tables, realized onto a device later by `app.domains.network_config`),
this domain is a real-time **execution** domain -- closer in shape to
`app.domains.device_sync`. An admin asks for a `ping` or `traceroute`
right now and gets a real result in the same HTTP response; every
attempt, successful or failed, is recorded as an immutable
`DiagnosticRun` row.

See `FLOW.md` for the full design write-up (including why
`app.domains.router_agent`'s job queue was rejected as the execution
mechanism) and `DATABASE.md` for the schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0046_create_network_diagnostics_tables.py
  app/
    domains/
      network_diagnostics/
        __init__.py             # the domain's own honest-scope statement
        constants.py             # DiagnosticType/DiagnosticStatus, ping/traceroute defaults
        models.py                  # DiagnosticRun (immutable, append-only)
        exceptions.py                # NetworkDiagnosticsError subclasses (CloudGuestError)
        events.py                      # DiagnosticRunCompleted
        device_adapters.py               # real librouteros ping+traceroute (MikroTikDiagnosticsAdapter)
        repository.py                       # NetworkDiagnosticsRepositoryProtocol/Repository (create + read only)
        service.py                            # NetworkDiagnosticsService: run_ping/run_traceroute/get_run/list_runs
        schemas.py                              # Pydantic request/response DTOs
        dependencies.py                           # FastAPI DI wiring (composes router's own DI)
        router.py                                   # FastAPI routes (4 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (get_router/get_decrypted_api_secret), never modified
      isp/                    # NOT a runtime dependency -- ping logic mirrored, not imported (see FLOW.md)
      rbac/
        enums.py             # PermissionModule.NETWORK_DIAGNOSTICS (new) + AuditAction gained network_diagnostic_run_completed
        seed.py              # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE[PermissionModule.NETWORK_DIAGNOSTICS]
  docs/
    network_diagnostics/
      README.md (this file)
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_network_diagnostics.py   # parsing/service/API structural tests
```

Not composed into `app.domains.network_config`'s own render/push
pipeline -- this domain owns no config to render (see `FLOW.md`).

## API Surface

All endpoints are registered under `/api/v1/network-diagnostics` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("network_diagnostics.*")` against a brand-new,
additive `PermissionModule.NETWORK_DIAGNOSTICS` key.

```text
POST /api/v1/network-diagnostics/routers/{router_id}/ping         # network_diagnostics.execute
POST /api/v1/network-diagnostics/routers/{router_id}/traceroute   # network_diagnostics.execute
GET  /api/v1/network-diagnostics/runs                              # network_diagnostics.read -- diagnostic history
GET  /api/v1/network-diagnostics/runs/{run_id}                      # network_diagnostics.read
```

No `CREATE`/`UPDATE`/`DELETE` actions -- `DiagnosticRun` rows are
immutable and only ever created by running a diagnostic itself.

`GET /runs` (list) is registered before `GET /runs/{run_id}` --
load-bearing route ordering (see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`/
  `get_decrypted_api_secret`.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

`app.domains.isp.device_adapters.MikroTikIspHealthAdapter.ping`'s exact
RouterOS command/reply-parsing logic is **mirrored**, not imported at
runtime -- see `FLOW.md` for why a runtime dependency on the ISP domain
(which is WAN-uplink-specific) would be a real architectural mismatch
for a router-generic diagnostic tool.

## Honest Scope: Every Attempt Recorded, Never Discarded

`run_ping`/`run_traceroute` never let a real device-connection/operation
failure bubble to the caller as a bare HTTP error -- both catch
`DiagnosticsDeviceConnectionError`/`DiagnosticsDeviceOperationError` and
record a `FAILED` `DiagnosticRun` with the real error message instead,
returning it like any other run. `MissingDiagnosticsCredentialsError` (a
configuration problem, not a diagnostic outcome) is the one exception
that still raises directly.

## Testing

`tests/unit/test_network_diagnostics.py` exercises the pure RouterOS
reply-parsing helpers directly (`_parse_ping_rows`/
`_parse_traceroute_rows`/`_parse_routeros_duration_ms`) and
`NetworkDiagnosticsService` against small, hand-rolled in-memory fakes
for its own repository, the composed `RouterLookupProtocol`, and an
injectable diagnostics adapter (mirrors `test_isp.py`'s own "fake the
narrow Protocol boundary, inject a fake adapter" precedent). Coverage:
successful/failed ping and traceroute runs (always recorded), missing
credentials raising directly (never recorded), tenant-isolated history
reads, and a structural check that every route carries a
`RequirePermission` dependency.
