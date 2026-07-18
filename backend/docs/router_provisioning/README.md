# Module 009 Part 1: Router Provisioning

The Router Provisioning domain extends BE-008 (`app.domains.router`) with
everything that module explicitly left out: configuration template/profile/
variable management, a versioned config-apply/rollback engine, a durable
provisioning queue, device-initiated enrollment + admin approval (distinct
from BE-008's admin-first "create router, generate token" flow), backup/
restore, factory reset, router secret rotation, and health/event history.
It builds on Module 002 (database core: `BaseModel`, `GenericRepository`,
pagination/filter/sort utilities), Module 004 (RBAC: `router_provisioning.*`/
`templates.*` permission keys, `audit_log_entries`), Module 006 (Location:
composed via `LocationService` for one seam -- denormalizing a
`LOCATION`-scoped variable's `organization_id`), and Module 008 (Router: the
real `Router` device record, composed via `RouterService` for every
router-scoped operation) -- **without duplicating any of BE-008's own
router-registration, provisioning-token check-in, or heartbeat endpoints.**

See `FLOW.md` for the provisioning/config-apply/rollback flows and every
non-obvious design decision, and `DATABASE.md` for every new table and its
relationships.

## What This Module Does NOT Do

* It does not re-implement router registration, the provisioning-token
  check-in flow, or the basic heartbeat endpoint -- those already exist in
  `app.domains.router` (BE-008) and are reused as-is via a narrow
  `RouterLookupProtocol`.
* It does not build a live device-dispatch mechanism. Every action that
  would, in a real deployment, touch a physical device (config push,
  backup, restore, factory reset) only ever creates a durable
  `ProvisioningJob` row and pushes its id onto a Redis queue --
  **actually executing** that job against a live device is
  `app.domains.router_agent`'s job (a future module this module's queue is
  designed to be drained by).
* It does not build a message bus / event-sourcing framework -- `events.py`
  is a handful of plain, frozen dataclasses constructed and consumed
  synchronously, in-process, by `service.py` itself.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0009_create_router_provisioning_tables.py
  app/
    domains/
      router_provisioning/
        __init__.py
        constants.py      # StrEnums + state-transition graphs + template placeholder syntax
        models.py          # 8 SQLAlchemy ORM models (see DATABASE.md)
        exceptions.py       # RouterProvisioningError subclasses (CloudGuestError)
        events.py           # Plain dataclasses consumed synchronously by service.py
        repository.py       # RouterProvisioningRepositoryProtocol + repo + Redis queue dispatcher
        validators.py       # Pure business-rule checks (no I/O)
        service.py           # RouterProvisioningService: the whole domain's business logic
        schemas.py            # Pydantic request/response DTOs
        dependencies.py        # FastAPI dependency wiring
        router.py               # FastAPI routes
      router/
        enums.py                # ROUTER_STATUS_TRANSITIONS gained 2 additive edges (see FLOW.md)
        service.py               # Gained one additive method: reset_to_pending_provisioning
      rbac/
        enums.py                 # AuditAction gained 9 new router_provisioning_* values
  docs/
    router_provisioning/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_router_provisioning.py
```

## API Surface

All endpoints are registered under `/api/v1` (see `app/api/v1/router.py`)
and protected by RBAC's existing `RequirePermission()` against the
already-seeded `router_provisioning.*`/`templates.*` permission keys (see
`app/domains/rbac/seed.py::MODULE_ACTIONS`). No new permission keys were
invented.

```text
GET    /api/v1/router-templates
POST   /api/v1/router-templates
GET    /api/v1/router-templates/{template_id}
PUT    /api/v1/router-templates/{template_id}
DELETE /api/v1/router-templates/{template_id}

GET    /api/v1/router-templates/variables
POST   /api/v1/router-templates/variables
PUT    /api/v1/router-templates/variables/{variable_id}
DELETE /api/v1/router-templates/variables/{variable_id}

POST   /api/v1/routers/{router_id}/config-profile

GET    /api/v1/routers/{router_id}/config-versions
GET    /api/v1/routers/{router_id}/config-versions/{version_id}
GET    /api/v1/routers/{router_id}/config-versions/{version_id}/diff/{other_version_id}
POST   /api/v1/routers/{router_id}/config-versions/{version_id}/rollback
POST   /api/v1/routers/{router_id}/config-versions/{version_id}/apply

POST   /api/v1/router-enrollment                       (device-facing, unauthenticated)
GET    /api/v1/router-enrollment
POST   /api/v1/router-enrollment/{enrollment_id}/approve
POST   /api/v1/router-enrollment/{enrollment_id}/reject

GET    /api/v1/routers/{router_id}/provisioning-status
POST   /api/v1/routers/{router_id}/backup
POST   /api/v1/routers/{router_id}/restore/{backup_id}
POST   /api/v1/routers/{router_id}/factory-reset
POST   /api/v1/routers/{router_id}/rotate-secret

POST   /api/v1/routers/{router_id}/health-snapshot      (additive -- see FLOW.md §5)
GET    /api/v1/routers/{router_id}/health-history
GET    /api/v1/routers/{router_id}/events
```

Every endpoint except `POST /router-enrollment` is gated by
`RequirePermission()` and resolves `CurrentOrganization` (`X-Organization-Id`),
passed through to `RouterProvisioningService` as `requesting_organization_id`.
Tenant isolation is inherited for free almost everywhere: every router-scoped
method resolves the router via `RouterService.get_router`, which already
raises `CrossOrganizationRouterAccessError` for a cross-tenant access attempt
(the exact mechanism BE-008 itself uses).

`POST /router-enrollment` is the one device-facing, unauthenticated endpoint
-- see `FLOW.md` §3 for the minimal-trust-boundary reasoning (mirrors
BE-008's own `POST /routers/provisioning/check-in`).

## Reused, Not Duplicated

* `GenericRepository`, `PageParams`/`PaginationMeta`/`paginate` (Module 002).
* `RequirePermission`, `CurrentOrganization`, `CurrentUser`,
  `ApiResponse`/`build_response`, `CloudGuestError` (Module 004).
* `LocationService.get_location` (Module 006), composed through a narrow
  `LocationLookupProtocol` -- used only to denormalize a `LOCATION`-scoped
  variable's `organization_id`.
* `RouterService` in its entirety (Module 008) -- device lookup, creation
  (enrollment approval), credential update (secret rotation, which reuses
  BE-008's existing `encrypt_secret` call inside `update_router` rather than
  calling `app.domains.router.crypto` directly), and heartbeat (the
  health-snapshot endpoint calls it, then adds history on top) -- composed
  through a narrow `RouterLookupProtocol`, never re-queried directly.
* RBAC's `audit_log_entries` table, written through the same narrow
  `AuditLogWriter` protocol shape every other domain uses.
* `difflib` (Python stdlib) for config version diffs -- no new dependency.

## New, Not Reused (Genuine Additions)

* Two additive `ROUTER_STATUS_TRANSITIONS` edges in
  `app.domains.router.enums` (`ONLINE`/`OFFLINE` -> `PENDING_PROVISIONING`)
  and one additive method, `RouterService.reset_to_pending_provisioning`, in
  `app.domains.router.service` -- required for the factory-reset workflow to
  be internally consistent (a factory-reset router must be able to re-enter
  BE-008's own zero-touch-provisioning flow). See `FLOW.md` §6 for the full
  justification of why this was a genuinely necessary, narrowly-scoped,
  purely-additive extension rather than scope creep or duplication.
* Redis as a provisioning-job dispatch transport
  (`repository.RedisProvisioningQueueDispatcher`) -- no new dependency
  (`redis` is already a Module 001 dependency), but a new usage pattern
  (a plain dispatch list) alongside RBAC's existing cache usage.

## Testing

`tests/unit/test_router_provisioning.py` exercises `RouterProvisioningService`
against a **real** `RouterService` instance (itself wired against small
in-memory fakes, exactly mirroring `test_router.py`'s own `make_service`
setup) rather than a hand-rolled fake for BE-008's router lookups -- this
both avoids duplicating `RouterService`'s own business logic in a second
fake and directly exercises the real cross-domain composition this module
relies on, including the two new `RouterService` additions above. Coverage:
template/variable CRUD and the 4-tier resolution-order merge, config version
create/diff/rollback/apply state transitions, the provisioning queue's
queued/running/succeeded/failed job lifecycle (including the retry edge),
enrollment submit/approve/reject (including the serial/MAC collision race
check at approval time), backup/restore, factory reset (including the
`ROUTER_STATUS_TRANSITIONS` edge and the single, non-duplicated
`audit_log_entries` row it produces), secret rotation (asserting the new
secret decrypts via BE-008's own `RouterService.get_decrypted_api_secret`,
never a second encryption code path), and tenant isolation. All 197
previously-passing tests continue to pass unmodified, plus 53 new tests
here (250 total).
