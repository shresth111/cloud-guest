# Module 009 Part 2: Router Agent

The Router Agent domain (`app.domains.router_agent`) is the device-facing
protocol a real MikroTik RouterOS agent uses for its entire ongoing
lifecycle *after* BE-008's zero-touch provisioning has completed: a
persistent device credential, heartbeat, current-configuration pull, status
push, and provisioning-action-queue poll/complete. It is explicitly the
module `app.domains.router_provisioning.service`'s own docstring names as
the intended caller of `complete_provisioning_job` -- "a future
`app.domains.router_agent` module is expected to call
`complete_provisioning_job` after actually performing the device-side
action."

See `FLOW.md` for the full device lifecycle and every non-obvious design
decision, and `DATABASE.md` for the one new table and its relationships.

## What This Module Does NOT Do

* It does not duplicate BE-008's router registration, provisioning-token
  check-in flow, or its admin-testing heartbeat endpoint
  (`POST /routers/{id}/heartbeat`, gated by `RequirePermission
  ("routers.manage")` -- unchanged, still for admin/manual use). This
  module's own heartbeat (`POST /agent/heartbeat`) composes with
  `RouterService.heartbeat` directly, it is the real device-authenticated
  counterpart.
* It does not store configuration a second time. `GET /agent/config` reads
  Module 009 Part 1's own `ConfigVersion`/`ConfigProfile` tables (composed
  through a narrow protocol satisfied directly by
  `RouterProvisioningRepository`), it never persists a config copy of its
  own.
* It does not build a second provisioning queue. `GET /agent/actions`/
  `POST /agent/actions/{job_id}/complete` are the **consumer** side of
  Module 009 Part 1's existing `provisioning_jobs` table + Redis dispatch
  signal (`RedisProvisioningQueueDispatcher`/`PROVISIONING_QUEUE_REDIS_KEY`)
  -- this module never enqueues a job itself, only picks one up and reports
  its outcome.
* It does not build RBAC authorization of its own. Every endpoint here is
  device-facing and carries no `RequirePermission`/`CurrentUser` dependency
  at all -- see `dependencies.CurrentAgent` for this module's entire
  authentication mechanism.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0010_create_router_agent_tables.py
  app/
    domains/
      router_agent/
        __init__.py
        constants.py      # AgentLicenseStatus, RouterAgentEventType, credential header/TTL constants
        models.py          # RouterAgentCredential (see DATABASE.md)
        exceptions.py       # RouterAgentError subclasses (CloudGuestError)
        events.py            # Plain dataclasses, logged synchronously by service.py
        validators.py          # Pure business-rule checks (no I/O)
        repository.py           # RouterAgentRepositoryProtocol + repo
        service.py               # RouterAgentService: the whole domain's business logic
        schemas.py                # Pydantic request/response DTOs (minimal, non-ApiResponse)
        dependencies.py            # FastAPI dependency wiring + CurrentAgent auth dependency
        router.py                   # FastAPI routes
      router/
        schemas.py                  # ProvisioningCheckInResponse gained 2 additive, optional fields
        router.py                    # provisioning_check_in additively issues the agent credential
  docs/
    router_agent/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_router_agent.py
```

## API Surface

All endpoints are registered under `/api/v1/agent` (see
`app/api/v1/router.py`) and are **device-facing**, authenticated via this
module's own `CurrentAgent` dependency (a persistent bearer credential
presented in the `X-Agent-Credential` header) -- not RBAC's
`RequirePermission`/`CurrentUser`, and not the `ApiResponse` envelope every
other domain's user-facing endpoints use.

```text
POST /api/v1/agent/heartbeat
GET  /api/v1/agent/config
POST /api/v1/agent/status
GET  /api/v1/agent/actions
POST /api/v1/agent/actions/{job_id}/complete
```

The credential itself is **not** issued by any endpoint in this file --
it is issued additively by BE-008's own
`POST /api/v1/routers/provisioning/check-in` (see `FLOW.md` §2 for why).

## Reused, Not Duplicated

* `GenericRepository` (Module 002).
* `RouterService.heartbeat`/`RouterService.update_router` (BE-008) --
  composed through a narrow `RouterLookupProtocol`, never re-implemented.
* `RouterProvisioningRepository.get_latest_applied_version`/
  `list_active_jobs_for_router` and `RouterProvisioningService
  .get_job`/`start_provisioning_job`/`complete_provisioning_job` (Module 009
  Part 1) -- composed through narrow protocols, never re-queried/
  re-implemented. **No new method was added to either** -- every read this
  module needs already existed.
* `RouterProvisioningRepository.create_event` (Module 009 Part 1's
  `router_events` table) -- composed via a narrow `RouterEventWriter`
  protocol for this module's own event types (`constants
  .RouterAgentEventType`, a separate `StrEnum` from that module's own, since
  `RouterEvent.event_type` is a plain string column with no enum-level
  coupling either way).
* `validate_job_belongs_to_router` (Module 009 Part 1's `validators.py`) --
  imported and reused directly, not duplicated.
* `CloudGuestError` (Module 001).

## New, Not Reused (Genuine Additions)

* `RouterAgentCredential` -- a genuinely new table; no existing model
  captures a persistent, ongoing device credential (BE-008's
  `RouterProvisioningToken` is single-use and already consumed by the time
  this credential is needed).
* Two additive, optional fields on BE-008's
  `ProvisioningCheckInResponse` (`agent_credential`/
  `agent_credential_expires_at`) and a matching, additive change to
  `provisioning_check_in` (calls `RouterAgentService
  .issue_credential_for_router` after `RouterService.check_in` succeeds) --
  see `FLOW.md` §2 for why this, and not a separate `/agent/activate`
  endpoint.
* `AgentLicenseStatus`/`agent_software_version`/`capabilities`/
  `license_key` -- genuinely new facts (no existing column anywhere
  captures a device agent's own software version, reported capabilities, or
  license state). `routeros_version` is deliberately **not** duplicated --
  `POST /agent/status` updates BE-008's existing `Router.routeros_version`
  via `RouterService.update_router`.
* A custom `X-Agent-Credential` header presentation scheme (as opposed to
  BE-008's check-in precedent of a request-body token) -- see `FLOW.md` §3.

## Testing

`tests/unit/test_router_agent.py` exercises `RouterAgentService`/
`CurrentAgent` against **real** `RouterService`/`RouterProvisioningService`
instances (themselves wired against small in-memory fakes, mirroring
`test_router_provisioning.py`'s own `make_services` setup) rather than a
hand-rolled fake for either. Coverage: credential issuance (hash-only
storage, rotation on reissue, the full check-in -> credential-issuance
seam), the `CurrentAgent` dependency's full rejection matrix (missing/
invalid/expired/revoked credential, decommissioned/suspended router),
device-authenticated heartbeat, config pull (with and without an applied
version), status push (credential fields updated every call,
`Router.routeros_version` refreshed only when it actually changed, a
`RouterEvent` recorded), and the action queue (poll claims queued jobs
without re-claiming already-running ones, complete calls back through
`complete_provisioning_job`, cross-router job-completion rejected). All 250
previously-passing tests continue to pass unmodified, plus 22 new tests here
(272 total).
