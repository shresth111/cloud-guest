# Queue Management Engine Domain

The Queue Management Engine is CloudGuest's vendor-agnostic bandwidth/QoS
orchestrator: Dashboard -> Queue Management Engine -> {Policy Service,
Router Service, Guest Service, Voucher Service, Guest Teams Service} ->
Queue Adapter -> {MikroTik Queue Adapter, Cisco/Aruba/UniFi QoS Adapter
(future)}.

It controls bandwidth at every level the module brief names -- User
(`Guest`), Guest Group (`GuestTeam`), Voucher, Device (`GuestDevice`),
Session (`GuestSession`), Location, Organization, Router -- via a single,
polymorphic `QueueAssignment` (mirrors `app.domains.policy.models
.PolicyAssignment`'s own `scope_type`/`scope_id` shape) resolved against
real, reusable `QueueProfile` rate/burst/priority definitions. It never
talks to a device directly -- every device-side operation goes through
`app.domains.queue_management.device_adapters.BaseQueueAdapter`, real for
MikroTik today (`librouteros`-backed `/queue simple`/`/queue tree`/PCQ
commands), pluggable for Cisco/Aruba/UniFi later without touching this
module's own core engine.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0033_create_queue_management_tables.py
  app/
    domains/
      queue_management/
        __init__.py
        constants.py        # QueueStatus/QueueTargetType/QueueType/schedule+persona enums + transition graphs
        models.py            # QueueProfile, QueueSchedule, QueueTemplate, QueueAssignment
        exceptions.py         # QueueManagementError subclasses (CloudGuestError)
        events.py              # QueueProfileCreated/QueueAssignmentCreated/Applied/Removed/Moved/Expired
        validators.py            # pure target/status-transition validation
        device_adapters.py        # BaseQueueAdapter Protocol + MikroTikQueueAdapter (real librouteros queue I/O)
        repository.py               # QueueManagementRepositoryProtocol/Repository
        service.py                   # QueueManagementService: the orchestrator
        tasks.py                      # Celery: sweep_schedule_transitions (time-based auto suspend/resume)
        schemas.py                     # Pydantic request/response DTOs
        dependencies.py                  # FastAPI DI wiring (composes existing domains' own DI)
        router.py                         # FastAPI routes (18 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (device connection fields, decrypted API secret), never modified
      policy/                # composed (BandwidthPolicyRules/QoSPolicyRules resolution), gained 2 typed schemas
      guest/                 # composed via an additive, optional GuestService.queue_assignment_hook
      rbac/
        enums.py             # AuditAction gained queue_* values (PermissionModule.BANDWIDTH already existed)
        seed.py              # MODULE_ACTIONS[PermissionModule.BANDWIDTH] extended (CREATE/DELETE/EXECUTE added)
  docs/
    queue_management/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_queue_management.py           # models/repository/service/API structural tests
      test_queue_management_adapters.py   # device_adapters.py via fake librouteros transport
```

## API Surface

All endpoints are registered under `/api/v1/queue` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("bandwidth.*")` -- this domain reuses the pre-existing
`PermissionModule.BANDWIDTH` key (seeded ahead of any real domain,
specifically for this concern) rather than minting a new one.

```text
POST   /api/v1/queue/profiles                  # bandwidth.create
GET    /api/v1/queue/profiles                  # bandwidth.read
GET    /api/v1/queue/profiles/{profile_id}     # bandwidth.read
PUT    /api/v1/queue/profiles/{profile_id}     # bandwidth.update
DELETE /api/v1/queue/profiles/{profile_id}     # bandwidth.delete

POST   /api/v1/queue/assign                    # bandwidth.create
PUT    /api/v1/queue/assign/{assignment_id}    # bandwidth.execute -- Move Queue
DELETE /api/v1/queue/assign/{assignment_id}    # bandwidth.execute -- Expire

GET    /api/v1/queue/assignments               # bandwidth.read
GET    /api/v1/queue/assignments/{assignment_id} # bandwidth.read

POST   /api/v1/queue/apply                     # bandwidth.execute
POST   /api/v1/queue/remove                    # bandwidth.execute
POST   /api/v1/queue/reset                     # bandwidth.execute

GET    /api/v1/queue/history                   # bandwidth.read

GET    /api/v1/queue/templates                 # bandwidth.read
POST   /api/v1/queue/templates                 # bandwidth.create

GET    /api/v1/queue/schedules                 # bandwidth.read
POST   /api/v1/queue/schedules                 # bandwidth.create
```

`GET /queue/assignments` is registered *before*
`GET /queue/assignments/{assignment_id}` -- load-bearing route ordering
(see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`/
  `get_decrypted_api_secret`.
* `app.domains.policy.service.PolicyService.resolve_effective_policy` for
  `PolicyType.BANDWIDTH` -- see "Policy Integration" below.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

This domain deliberately does **not** compose `app.domains.guest`/
`app.domains.voucher`/`app.domains.guest_teams` directly:
`QueueAssignment.target_id` is polymorphic and not deep-validated against
those domains' own tables (mirrors `PolicyAssignment.scope_id`'s own "not a
real foreign key" stance) -- see `FLOW.md` §1 for the full reasoning.

## Policy Integration

`PolicyType.BANDWIDTH`/`QOS` were real, assignable policy types before this
module existed, but validated their `rules` JSONB only as generic JSON (no
typed schema, no seeded platform default). This build registered
`BandwidthPolicyRules`/`QoSPolicyRules` typed Pydantic schemas into
`app.domains.policy.schemas.POLICY_RULE_SCHEMAS` -- real rate-limit/
traffic-classification validation for those two types, still with no
platform default (no existing hardcoded bandwidth cap anywhere in this
codebase to honestly mirror one from). `QueueManagementService
.resolve_and_assign_queue` composes `resolve_effective_policy` and
find-or-creates a matching `QueueProfile` from the resolved rules --
falling back to a real, persisted "Unlimited" system profile when no
policy is configured at any scope, never a fabricated ephemeral rate.

## Dynamic Queue Assignment

Guest Login -> Policy Engine -> Queue Profile Resolution -> Queue
Assignment -> Queue Adapter -> Router, exactly as the module brief's own
flow diagram names. Wired via `app.domains.guest.service.GuestService`'s
new, additive, `None`-by-default `queue_assignment_hook` (mirrors that
class's own `monitoring_hook` precedent exactly -- best-effort, wrapped in
a blanket try/except, never blocks a real guest's login). Fires once per
login, targeting the newly-created `GuestSession` itself (not the guest) --
a real RouterOS `/queue simple` entry is tied to one concrete IP address,
and the session's own `ip_address` is the only one that is actually correct
*right now*.

## Honest Scope: Real Device I/O, Untested End-to-End Here

`MikroTikQueueAdapter` uses the same real, genuinely-installed
`librouteros` dependency `app.domains.provisioning_engine`'s own device
adapter already added -- real `/queue simple`/`/queue tree`/`/queue type`
(PCQ) command construction via `librouteros`'s own confirmed
`Path.add`/`.update`/`.remove` API (verified directly against the
installed package's source, not guessed from memory). No SSH is needed at
all: every queue operation is a native RouterOS API command, unlike
`provisioning_engine`'s own adapter, which also needs SFTP for config/
backup file transfer. Exercised in `test_queue_management_adapters.py` via
a hand-rolled fake transport for every method, plus one test that opens a
real (always-failing) socket against a guaranteed-unreachable TEST-NET-1
address to confirm a genuine connection failure raises a real
`QueueDeviceConnectionError`, never a fabricated success. There is no live
MikroTik device anywhere in this sandbox -- the same "honest placeholder"
discipline `app.domains.provisioning_engine.device_adapters` already
established.

## Testing

`tests/unit/test_queue_management.py` exercises `QueueManagementService`
against small, hand-rolled in-memory fakes for its own repository and every
composed cross-domain protocol (mirrors
`test_provisioning_engine.py`'s own "fake the narrow Protocol boundary"
precedent). Coverage: queue profile CRUD (tenant-scoped reads, system-vs-
org visibility), the pure `is_schedule_active_now` time-window logic
(office hours, overnight "night mode" wrap-around, weekend day-of-week
filtering, holiday specific dates), queue templates, the full assignment
lifecycle (create with polymorphic target validation, apply/remove --
including the schedule-suspended path that never opens a device
connection, reset, move as a new row superseding the old one, expire), the
dynamic "resolve and assign" pipeline, the schedule-transition sweep, and a
structural check that every route carries a `RequirePermission`
dependency.

`tests/unit/test_queue_management_adapters.py` covers the real device
adapter layer -- see "Honest Scope" above.
