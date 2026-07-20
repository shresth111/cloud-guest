# Provisioning Engine Domain

The Provisioning Engine is CloudGuest's end-to-end automation orchestrator:
Dashboard -> Provisioning Engine -> {Policy Service, Router Service, NAS
Service, Router Provisioning Service} -> Device Adapter ->
{MikroTik Adapter, OPNsense/Cisco/Aruba/UniFi (future)}.

It is **not** a config-push helper -- it never talks to a device directly.
Every device action is delegated to a real, pluggable
`app.domains.provisioning_engine.device_adapters.BaseProvisionAdapter`
implementation (`MikroTikProvisionAdapter` today), and every other concern
(template rendering, variable resolution, config versioning, NAS
registration, policy resolution, health snapshots) is *composed* from the
existing, already-tested domains that already own it -- see `FLOW.md`'s
"Composition, not duplication" section for the full write-up. This module
is new: it did not exist before this build, and is distinct from (but
composes) `app.domains.router_provisioning`'s own, earlier, narrower
`ProvisioningAdapterProtocol` extension (documented in
`docs/router_provisioning/PROVISIONING_ENGINE.md`) -- that one only
validates template/vendor compatibility and shapes job payload metadata; it
never opens a device connection.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0032_create_provisioning_engine_tables.py
  app/
    domains/
      provisioning_engine/
        __init__.py
        constants.py        # ProvisionJobStatus/ProvisionStepType/site types + transition graphs
        models.py            # ProvisionJob, ProvisionStep, ProvisionLog, ProvisionTemplate
        exceptions.py         # ProvisioningEngineError subclasses (CloudGuestError)
        events.py              # ProvisionJobCreated/Started/Succeeded/Failed/Cancelled/Retried/RolledBack
        device_adapters.py       # BaseProvisionAdapter Protocol + MikroTikProvisionAdapter (real I/O)
        repository.py              # ProvisioningEngineRepositoryProtocol/Repository + Redis queue dispatcher
        service.py                  # ProvisioningEngineService: the orchestrator
        tasks.py                     # Celery: drain_provision_queue (real background executor)
        schemas.py                    # Pydantic request/response DTOs
        dependencies.py                 # FastAPI DI wiring (composes existing domains' own DI)
        router.py                        # FastAPI routes (12 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (device connection fields, heartbeat), never modified
      router_provisioning/   # composed (templates/variables/versions/rendering), never modified
      policy/                # composed (effective policy resolution), never modified
      guest/                 # composed (RadiusService.register_nas/list_nas_clients), never modified
      rbac/
        enums.py             # PermissionModule.PROVISIONING_ENGINE, AuditAction gained provision_job_* values
        seed.py              # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE/SYSTEM_ROLES additions
  docs/
    provisioning_engine/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_provisioning_engine.py           # models/repository/service/API structural tests
      test_provisioning_engine_adapters.py   # device_adapters.py via fake librouteros/asyncssh transports
```

## API Surface

All endpoints are registered under `/api/v1/provision` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("provisioning_engine.*")` -- there is no guest-facing
route in this domain.

```text
POST   /api/v1/provision                       # provisioning_engine.create -- create a job
GET    /api/v1/provision/jobs                  # provisioning_engine.read   -- list jobs (router_id/status filters)
GET    /api/v1/provision/history               # provisioning_engine.read  -- every past job for one router
POST   /api/v1/provision/discover              # provisioning_engine.execute -- ad-hoc device discovery
POST   /api/v1/provision/validate              # provisioning_engine.execute -- ad-hoc validation (no job)
POST   /api/v1/provision/configuration         # provisioning_engine.execute -- ad-hoc config generation preview
POST   /api/v1/provision/{job_id}/start        # provisioning_engine.execute -- queue a PENDING job
POST   /api/v1/provision/{job_id}/retry        # provisioning_engine.execute -- new job, retry_of_job_id set
POST   /api/v1/provision/{job_id}/rollback     # provisioning_engine.execute -- new job, is_rollback=true
POST   /api/v1/provision/{job_id}/cancel       # provisioning_engine.execute -- cancel a non-terminal job
GET    /api/v1/provision/{job_id}/timeline     # provisioning_engine.read   -- step+log read-model
GET    /api/v1/provision/{job_id}              # provisioning_engine.read   -- get one job
```

`GET /provision/jobs` and `GET /provision/history` are registered *before*
`GET /provision/{job_id}` in `router.py` -- load-bearing route ordering, see
that file's own module docstring.

`PermissionModule.PROVISIONING_ENGINE` is a new, additive RBAC module (`
create`/`read`/`execute`/`manage` actions, `ScopeType.ROUTER` narrowest
scope -- the same profile `router_provisioning`/`radius`/`wireguard`/
`firewall`/`dhcp`/`dns`/`hotspot`/`monitoring` already share). `Network
Administrator` is the one system role given an explicit `FULL` override
(alongside its existing `ROUTER_PROVISIONING: FULL`) -- every broader-scope
role (`Super Admin`/`Platform Admin`/MSP/Organization Owner-Admin) picks it
up automatically through its own `FULL`/`OPERATE` default level.

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router_provisioning.service.render_template`/
  `RouterProvisioningService.resolve_variables`/`assign_profile`/
  `apply_version`/`start_provisioning_job`/`complete_provisioning_job`/
  `list_versions`/`rollback_to_version`/`record_health_snapshot`/
  `create_variable` -- every one of these already exists, real and tested.
* `app.domains.router.service.RouterService.get_router`/`heartbeat`/
  `get_decrypted_api_secret`.
* `app.domains.policy.service.PolicyService.resolve_effective_policy`.
* `app.domains.guest.service.RadiusService.register_nas`/`list_nas_clients`.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

See `FLOW.md` §1 for the full write-up of exactly how each composed call is
used, and §2 for why only 4 tables exist despite the module brief naming 9
entities (`ProvisionHistory`/`ProvisionTimeline`/`ProvisionQueue`/
`ProvisionRetry`/`ProvisionRollback` are read-models or a new-row
composition pattern, not separate storage).

## Honest Scope: Real Device I/O, Untested End-to-End Here

`MikroTikProvisionAdapter` uses two real, genuinely-installed libraries
(`librouteros` for the RouterOS API, `asyncssh` for SSH/SFTP) -- real
command construction and response parsing, exercised in
`test_provisioning_engine_adapters.py` via a hand-rolled fake transport for
every method, plus one test that opens a real (always-failing) socket
against a guaranteed-unreachable TEST-NET-1 address to confirm a genuine
connection failure raises a real `ProvisionDeviceConnectionError`, never a
fabricated success. There is no live MikroTik device anywhere in this
sandbox -- see `device_adapters.py`'s own module docstring for the full
"honest placeholder" scope note, the same discipline this codebase already
applied to Celery health before a worker existed, FreeRADIUS before a live
daemon existed, and `router_agent`'s own dispatch before a real agent
process existed.

## Testing

`tests/unit/test_provisioning_engine.py` exercises `ProvisioningEngineService`
against small, hand-rolled in-memory fakes for its own repository and every
composed cross-domain protocol (mirrors `test_policy.py`'s own "fake the
narrow Protocol boundary" precedent). Coverage: job creation (policy
snapshot freezing, denormalized organization/location/router), the full
status transition graph (start/cancel/retry/rollback, including the "new
row, not mutate" convention and retry-limit/rollback-precondition
rejection), tenant isolation, history/timeline read-models, the three
ad-hoc actions (discover/validate/generate-configuration, including
idempotent variable seeding and conditional NAS registration), the full
seven-step `run_provision_job` orchestration (success path, a mid-sequence
device-push failure halting the job before verify/health-check/monitoring
ever run, a rollback job's `GENERATE_CONFIG` skip, and the "no template --
re-push the router's existing latest version" path plus its own "nothing to
push" failure mode), and a structural check that every route in this domain
carries a `RequirePermission` dependency.

`tests/unit/test_provisioning_engine_adapters.py` covers the real device
adapter layer -- see "Honest Scope" above.
