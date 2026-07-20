# Queue Management Engine -- Design Write-Up

This document covers every non-obvious design decision made while building
the Queue Management Engine, and the reasoning behind each -- see
`README.md` for the folder/API surface overview and `DATABASE.md` for the
schema.

## 1. Composition, not duplication

`QueueManagementService` composes `app.domains.router.service.RouterService`
(via `RouterLookupProtocol` -- router existence/tenant-scoping, decrypted
API credentials) and `app.domains.policy.service.PolicyService` (via
`PolicyLookupProtocol` -- `resolve_effective_policy` for
`PolicyType.BANDWIDTH`). It deliberately does **not** compose
`app.domains.guest`/`app.domains.voucher`/`app.domains.guest_teams`
directly: a `QueueAssignment`'s `target_id` is polymorphic (its target
table depends on `target_type`) and is not deep-validated against those
domains' own tables, mirroring `app.domains.policy.models.PolicyAssignment
.scope_id`'s own identical "not a real foreign key" stance. The caller (an
admin via the REST API, or the guest-login hook in
`app.domains.guest.service.GuestService`) is responsible for supplying a
real, already-known `target_id` and `device_target` (the RouterOS `target`
string -- an IP/CIDR or interface), not this service. This keeps
`queue_management` from needing to depend on three additional domains just
to confirm a UUID it was already given by a caller that unquestionably
already has it.

## 2. Four tables, not six

The module brief named six entities: Queue Profile, Queue Assignment, Queue
History, Queue Template, Queue Audit, Queue Schedule. Only four are real
tables (`models.py`) -- mirrors this codebase's own established discipline
(most recently, `app.domains.provisioning_engine`'s own 9-to-4 reduction
for an identical reason):

* **History** = querying `QueueAssignment` rows for a target, ordered by
  `created_at` (`QueueManagementService.get_history`). No separate table --
  every past assignment already is a row here, since reassignment ("Move
  Queue") creates a **new** row rather than mutating the old one.
* **Audit** = the existing RBAC `audit_log_entries` table, written through
  the same narrow `AuditLogWriter` protocol every other domain uses --
  mirrors `app.domains.provisioning_engine`'s own identical posture.

## 3. `QueueAssignment.target_type`/`target_id`: a new polymorphic enum, not
## a reuse of `ScopeType`

`app.domains.rbac.enums.ScopeType` (global/organization/location/router/
device) is *not* reused here -- guest/voucher/device/session are not RBAC
scopes, and `ScopeType`'s own members don't cover "guest team" or
"session" at all. `constants.QueueTargetType` is a new, purpose-built
enum mirroring the *shape* of `PolicyAssignment.scope_type`/`scope_id`
(a discriminator plus a nullable, non-FK, polymorphic id) without reusing
its actual values. `GUEST_TEAM` is the brief's own "Guest Group" -- this
codebase already has a real, named "grouped guest access" concept
(`app.domains.guest_teams.models.GuestTeam`), so this reuses that domain's
own name rather than inventing a second one.

## 4. Apply / Remove *are* Enable / Disable

The module brief names four operations -- "Apply Queue", "Remove Queue",
"Enable Queue", "Disable Queue" -- as if they were four distinct actions.
They are two: `apply_queue` (push the profile's rates to the device,
`PENDING`/`DISABLED`/`SUSPENDED` -> `ACTIVE` -- "enabling" a queue *is*
applying it) and `remove_queue` (pull the live queue off the device,
`ACTIVE` -> `DISABLED` -- "disabling" a queue *is* removing it, keeping the
row for a later re-apply). Naming four separate methods that collapse into
the same two real device operations would be a fake distinction, not a
real one. "Reset Queue" is a third, real, distinct operation:
remove-then-reapply the *same* profile, which genuinely clears a RouterOS
queue's own accumulated byte/packet counters (a real device behavior, not
a platform convention) -- implemented as `reset_queue`.

## 5. Move Queue: a new row, not a mutation

Mirrors `app.domains.provisioning_engine`'s own `retry_job`/`rollback_job`
convention (itself mirroring `ConfigVersion`'s "new row, not mutate"):
reassigning a target to a different profile (`move_queue`) never edits an
`ACTIVE` row's own `queue_profile_id` in place. It creates a **new**
`QueueAssignment` row and marks the old one `EXPIRED` with
`superseded_by_assignment_id` set -- so "Queue History" is simply every
`QueueAssignment` row for a target, chronological, never a second table.

## 6. Time-based policies: `PENDING`/`ACTIVE` <-> `SUSPENDED`, and a real
## background sweep

A `QueueAssignment` scoped to a `QueueSchedule` is only ever pushed to the
device while that schedule's window is currently open.
`is_schedule_active_now` (a pure function, `service.py`) evaluates a
schedule's own real window fields -- `days_of_week`/`start_time`/
`end_time` for recurring windows (with correct overnight wrap-around, e.g.
"Night Mode" 22:00-06:00), `specific_dates` for `HOLIDAY`. `apply_queue`
checks this itself: if the window is currently closed, the assignment
transitions straight to `SUSPENDED` (a legal edge from both `PENDING` and
`ACTIVE` -- see `constants.QUEUE_STATUS_TRANSITIONS`) without ever
attempting a device connection. `tasks.sweep_schedule_transitions` is the
Beat-scheduled task (every 5 minutes -- see
`constants.SCHEDULE_SWEEP_INTERVAL_SECONDS`'s own docstring for the
cadence reasoning) that re-evaluates every `ACTIVE`/`SUSPENDED`
schedule-bound assignment and flips its device state the moment a window
opens or closes -- the real background executor behind "Automatically
change assigned queues based on time."

## 7. Real device I/O: `librouteros`, no SSH needed

`device_adapters.BaseQueueAdapter` is the Strategy/Adapter seam that keeps
this domain's own core engine completely vendor-agnostic.
`MikroTikQueueAdapter` uses `librouteros` (the same real dependency
`app.domains.provisioning_engine`'s own device adapter already added) to
speak RouterOS's real API protocol against `/queue/simple`, `/queue/tree`,
and `/queue/type` (PCQ). Confirmed directly against the installed
`librouteros` package's own source: `Api.path(*segments)` returns a `Path`
object with real `add(**kwargs)` (RouterOS `add`, returns the new row's
device-side `.id`), `update(**kwargs)` (RouterOS `set`, must include
`.id`), and `remove(*ids)` (RouterOS `remove`) methods -- not guessed from
memory. Unlike `provisioning_engine`'s own adapter, no SSH/SFTP transport
is needed at all: every queue operation (add/set/remove/print) is a native
RouterOS API command, never a file-system-level operation. `QueueProfile`
rates are stored in kbps; RouterOS's own `max-limit`/`burst-limit` fields
always receive a `k`-suffixed value (e.g. `"5000k"`), a real, valid
RouterOS unit, never converted to `M` for readability.

## 8. RBAC: extending an existing seeded module, not minting a new one

`PermissionModule.BANDWIDTH` already existed in `app.domains.rbac.enums`
before this domain was built -- seeded (display name, `ScopeType.ROUTER`
narrowest scope, one `Network Administrator` role grant) specifically for
this concern, but with a narrower action tuple (`READ`/`UPDATE`/`MANAGE`)
than a full-CRUD+execute domain needs. This build extends that tuple
(`CREATE`/`DELETE`/`EXECUTE` added, mirroring `ROUTER_PROVISIONING`'s/
`PROVISIONING_ENGINE`'s own identical "device-affecting action" use of
`EXECUTE`) rather than minting a second, redundant `PermissionModule` --
the same "reuse the existing seeded key" discipline this session already
applied when `app.domains.guest`'s NAS extension reused `PermissionModule
.RADIUS` rather than adding its own module.
