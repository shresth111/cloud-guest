# Device Synchronization Domain

The Device Synchronization domain is CloudGuest's honest orchestrator
over every *real* per-router sync mechanism this codebase already has:
Dashboard -> Device Synchronization -> {Router Service, Connected Device
Service, Queue Management Service, Provisioning Engine Service} ->
`device_sync_runs` (an immutable history log).

Triggering a sync for a router runs three real operations and records
one immutable row capturing every component's own outcome:

* **Connected Devices** -- a real DHCP-lease/ARP/wireless sync
  (`app.domains.connected_devices.service.ConnectedDeviceService
  .sync_router`).
* **Queue Management** -- a real per-assignment device re-push for every
  currently-active queue assignment on the router (a new bulk method,
  `reapply_assignments_for_router`, added to that domain specifically
  for this orchestrator).
* **Provisioning** -- a read-only check of the router's latest real
  `ProvisionJob` status (`app.domains.provisioning_engine.service
  .ProvisioningEngineService.list_jobs`).

**DHCP/VLAN/Port Forwarding are always reported `not_provisioned`** --
none of those domains has a real device push today (confirmed: no
`device_adapters.py` in any of them); that work is explicitly deferred to
the not-yet-built Network Configuration Management domain. This
orchestrator never fabricates a sync for them.

See `FLOW.md` for the full design write-up (including the explicit scope
boundary with Network Configuration Management) and `DATABASE.md` for
the schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0043_create_device_sync_tables.py
  app/
    domains/
      device_sync/
        __init__.py            # the domain's own honest-scope statement
        constants.py            # SyncComponent/SyncComponentStatus/SyncRunStatus, UNPROVISIONED_COMPONENTS
        models.py                 # DeviceSyncRun (immutable, append-only)
        exceptions.py               # DeviceSyncError subclasses (CloudGuestError)
        events.py                     # DeviceSyncRunCompleted
        validators.py                   # pure compute_overall_status
        repository.py                    # DeviceSyncRepositoryProtocol/Repository (create + read only)
        service.py                        # DeviceSyncService: orchestration + per-component isolation
        schemas.py                          # Pydantic response DTOs (no create/update request needed)
        dependencies.py                       # FastAPI DI wiring (composes 4 other domains' own DI)
        router.py                              # FastAPI routes (3 endpoints, all admin-facing, RBAC-gated)
      queue_management/
        service.py             # gained reapply_assignments_for_router + QueueReapplySummary (new bulk method)
      router/                # composed (get_router), never modified
      connected_devices/       # composed (sync_router), never modified
      provisioning_engine/      # composed (list_jobs), never modified
      rbac/
        enums.py             # PermissionModule.DEVICE_SYNC (new) + AuditAction gained device_sync_run_completed
        seed.py              # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE[PermissionModule.DEVICE_SYNC]
  docs/
    device_sync/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_device_sync.py          # orchestration/isolation/status/history/API structural tests
      test_queue_management.py     # gained TestReapplyAssignmentsForRouter
```

## API Surface

All endpoints are registered under `/api/v1/device-sync` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("device_sync.*")` against a brand-new, additive
`PermissionModule.DEVICE_SYNC` key.

```text
POST /api/v1/device-sync/routers/{router_id}/sync   # device_sync.execute -- trigger a sync
GET  /api/v1/device-sync/runs                        # device_sync.read -- sync history
GET  /api/v1/device-sync/runs/{run_id}                # device_sync.read
```

No `CREATE`/`UPDATE`/`DELETE` actions -- `DeviceSyncRun` rows are
immutable and only ever created by the sync trigger itself.

`GET /runs` (list) is registered before `GET /runs/{run_id}` --
load-bearing route ordering (see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`.
* `app.domains.connected_devices.service.ConnectedDeviceService
  .sync_router`.
* `app.domains.queue_management.service.QueueManagementService
  .reapply_assignments_for_router` (itself composing that domain's own
  pre-existing `reset_queue` per assignment -- no device I/O
  reimplemented here).
* `app.domains.provisioning_engine.service.ProvisioningEngineService
  .list_jobs`.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

## Testing

`tests/unit/test_device_sync.py` exercises `DeviceSyncService` against
small, hand-rolled in-memory fakes for its own repository and every
composed cross-domain protocol (mirrors `test_isp.py`'s own "fake the
narrow Protocol boundary" precedent). Coverage: orchestration across all
three real components, per-component failure isolation, overall-status
computation (`SUCCESS`/`PARTIAL`/`FAILED`), the honest
`not_provisioned` reporting for DHCP/VLAN/Port Forwarding, the
"no provisioning jobs yet is not a failure" distinction, immutable sync
history reads (tenant isolation), and a structural check that every
route carries a `RequirePermission` dependency.

`tests/unit/test_queue_management.py` gained
`TestReapplyAssignmentsForRouter`, covering the new bulk method this
domain composes: reapplying every active assignment on a router,
ignoring non-active ones, and per-assignment failure isolation.
