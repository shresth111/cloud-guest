# Router Provisioning: Flows and Design Decisions

This document records every design decision this module made where the
brief left room for judgment, plus the end-to-end flows (config apply,
rollback, enrollment, backup/restore, factory reset). Read this before
modifying `app/domains/router_provisioning/` or the two targeted seams it
touches in BE-008 (`app/domains/router/enums.py`/`service.py`).

## 1. Variable resolution order

`ConfigVariable` rows are scoped at `ORGANIZATION`, `LOCATION`, or `ROUTER`
level (`constants.ConfigVariableScope` -- a new, narrower enum than RBAC's
`ScopeType`, since `GLOBAL`/`DEVICE` make no sense for a template variable;
string values are kept identical to `ScopeType`'s for easy cross-reference).
A "global default" is not a fourth enum member -- it is simply an
`ORGANIZATION`-scope row with `organization_id IS NULL`, exactly mirroring
`ConfigTemplate`'s own `organization_id IS NULL` == "system template"
convention.

**Resolution order, most-specific wins:** `router` > `location` >
`organization` > `global`. `RouterProvisioningService.resolve_variables`
implements this as four ordered passes over the router's parent hierarchy,
lowest-precedence first, each overwriting any same-`key` entry the pass
before it wrote:

```text
1. global defaults        (scope=organization, organization_id IS NULL)
2. organization defaults   (scope=organization, organization_id = router.organization_id)
3. location overrides      (scope=location, location_id = router.location_id)
4. router overrides        (scope=router, router_id = router.id)
```

`ROUTER`/`LOCATION`-scoped rows carry **denormalized** `organization_id`/
`location_id` columns (populated at creation time by composing with
`RouterLookupProtocol`/`LocationLookupProtocol`, never a raw query) so every
resolution pass is a plain equality filter, no join required -- the same
precedent `Router.organization_id`'s own denormalization already set in
BE-008.

Secret variables (`is_secret=True`) store Fernet ciphertext (the *same*
`app.domains.router.crypto.encrypt_secret`/`decrypt_secret` helpers BE-008
established -- this module adds no second encryption mechanism) and are
decrypted during resolution, before being handed to the renderer; the
rendered config text a version stores is always the final plaintext RouterOS
script, ciphertext never leaks into `ConfigVersion.rendered_content`.

## 2. `ConfigVersion` state graph

```text
DRAFT ---------(apply_version)-------> PENDING_APPLY
PENDING_APPLY --(job succeeds)--------> APPLIED
PENDING_APPLY --(job fails)------------> FAILED
FAILED --------(apply_version again)---> PENDING_APPLY
APPLIED -------(a different version for
                the same router becomes
                APPLIED)----------------> ROLLED_BACK
ROLLED_BACK ---(terminal, no outgoing edges)
```

The exhaustive graph lives in `CONFIG_VERSION_STATUS_TRANSITIONS`
(`constants.py`), consulted by `validators.validate_config_version_transition`
-- the identical "one graph, one validator, every mutation consults it"
discipline `app.domains.router.enums.ROUTER_STATUS_TRANSITIONS` established.

**Why `apply_version` never jumps straight to `APPLIED`.** There is no live
device in this sandbox to confirm a config push actually landed. Applying,
in this module, literally means: create a `ProvisioningJob`
(`initial_config` if the router has no prior applied version, `config_push`
otherwise) and transition the version `DRAFT -> PENDING_APPLY`. The version
only becomes `APPLIED` when `complete_provisioning_job(job_id, success=True)`
is later called -- the seam a real `app.domains.router_agent` module would
call back through after actually performing the device-side push. This
module deliberately does not call that seam itself (see §7).

**Why `APPLIED -> ROLLED_BACK` fires the way it does.** Rollback
(`rollback_to_version`) does not mutate any existing row -- it creates a
brand-new `DRAFT` version whose content matches an earlier one, tagged via
`rollback_of_version_id`. That new version must still be applied like any
other draft (reusing the exact same `apply_version`/`complete_provisioning_job`
path -- no separate "apply a rollback" code path exists). When that
completion succeeds, whichever version was previously the router's current
applied config (excluding the one just applied) transitions to
`ROLLED_BACK` -- marking it "no longer this router's live configuration."
This is a deliberately broad reading of "rolled back": it fires whenever a
version created via `rollback_to_version` supersedes a prior applied
version, and also whenever a `restore` job completes (a restore is, in
effect, a rollback to a backup snapshot). An ordinary forward `config_push`
(no `rollback_of_version_id`) does **not** push the previous version into
`ROLLED_BACK` -- both are left `APPLIED`, since "which one is current" is
already unambiguous from `version_number` ordering
(`ConfigVersionRepository.get_latest_applied_version` always orders by
`version_number DESC`), and there was no rollback operation to describe.

## 3. Enrollment: device-first, not admin-first

BE-008's flow is admin-first: an admin creates a `Router` record, then
generates a provisioning token the device later presents. This module adds
the opposite direction: the device shows up first (`POST /router-enrollment`,
`{serial_number, mac_address, model}`), with **no** `Router` record and no
platform user identity, before any admin has ever heard of it.

**Minimal identity check.** Unlike BE-008's check-in endpoint (which at
least validates a bearer provisioning token), a first-contact enrollment
request has no credential to authenticate with at all -- it is presented
before any per-device secret could possibly exist. The "identity check"
this endpoint performs is entirely server-side and data-driven: reject if
the serial number or MAC address already belongs to an active `Router`
(composed via `RouterService.get_by_serial_number`/`get_by_mac_address`,
never a duplicated query), and reject a second pending request for the same
serial/MAC. Nothing changes the platform's authoritative state (no `Router`
row is created) until an authenticated, `router_provisioning.approve`-gated
admin actually approves it -- this is the accepted trust boundary: anyone
can *submit*, only a permissioned admin can make it *real*.

**Approval requires admin-supplied context the device could never know.**
`RouterEnrollmentRequest` has no `location_id` -- a location is an
administrative/tenant concept, not something a bare device announces.
`approve_enrollment` therefore requires the admin to supply `location_id`
(and a display `name`) at approval time, then calls
`RouterService.create_router` (reused verbatim, not reimplemented) to
produce the real BE-008 row, starting -- like every BE-008-created router --
in `pending_provisioning`.

**The race-condition re-check.** Between submission and approval, another
approval (or an unrelated direct BE-008 registration) could claim the same
serial/MAC. `approve_enrollment` re-runs the exact same collision check
submission did, immediately before calling `create_router` -- this is a
real, tested race condition
(`TestEnrollment::test_approve_enrollment_race_condition_conflict`), not a
theoretical one.

## 4. Provisioning queue: Redis transport, Postgres source of truth

Every device-affecting action (`apply_version`, `create_backup`,
`restore_backup`, `factory_reset`) funnels through one primitive,
`RouterProvisioningService._enqueue_job`:

1. Insert a `ProvisioningJob` row (`status=queued`) -- the durable record.
2. `LPUSH` the job id onto a single Redis list
   (`constants.PROVISIONING_QUEUE_REDIS_KEY`) via
   `repository.RedisProvisioningQueueDispatcher` -- purely a wake-up signal.
3. Record a `RouterEvent` (`provisioning_queued`).

If Redis is unreachable, evicts the key, or restarts, nothing is lost: every
piece of state that matters (status, attempts, error history) lives only in
`provisioning_jobs` (Postgres); Redis holds nothing that isn't trivially
reconstructible by re-scanning queued jobs. This is the identical posture
Module 004 (RBAC) already takes for `PermissionCache` -- Redis as a
disposable acceleration/signaling layer, Postgres as ground truth.

The job lifecycle (`constants.PROVISIONING_JOB_STATUS_TRANSITIONS`):

```text
QUEUED ---(start_provisioning_job)-------> RUNNING
RUNNING --(complete_provisioning_job, ok)--> SUCCEEDED
RUNNING --(complete_provisioning_job, !ok)-> FAILED
FAILED ---(retry, attempts < max_attempts)-> QUEUED
SUCCEEDED (terminal)
```

## 5. Health snapshots: composition, not a second heartbeat

BE-008's `POST /routers/{id}/heartbeat` already exists and already updates
`Router.last_seen_at`/`health_status`/`last_health_check_at` -- this module
does not touch it, replace it, or add a competing endpoint that also asserts
liveness. Instead, `POST /routers/{id}/health-snapshot` (additive, beyond
the module brief's literal endpoint list -- explicitly invited by the
brief's own composition guidance, "a new endpoint that supplements it")
**calls `RouterService.heartbeat` first** (reusing its exact liveness/
status-transition logic unchanged), then persists a `RouterHealthSnapshot`
row with the richer metrics (CPU/memory/uptime/connected-client-count)
BE-008's own single "current snapshot" fields were never designed to
retain. If a caller only wants the original heartbeat behavior, every metric
field is optional and a snapshot is still recorded with `health_status`
alone.

## 6. What was added to BE-008, and why it was necessary (not duplication)

Factory reset (`RouterProvisioningService.factory_reset` /
`complete_provisioning_job`'s `FACTORY_RESET` branch) must, on completion,
put the router back into a state where BE-008's own zero-touch-provisioning
flow can run again from scratch (a factory-reset device has had its config
wiped -- exactly the situation a brand-new, never-provisioned router is in).
The only status that means that is `PENDING_PROVISIONING`. But
`ROUTER_STATUS_TRANSITIONS` (BE-008, `app/domains/router/enums.py`) had
**no edge into `PENDING_PROVISIONING` from anywhere** -- it is reachable
only as the initial status a brand-new `Router` row starts in. Without an
edge, `RouterService.generate_provisioning_token` (which requires
`PENDING_PROVISIONING`) could never be called again for a factory-reset
router, making "factory reset, then re-provision" impossible to express
correctly.

This was a genuine, narrowly-scoped gap in BE-008 that this module's own
new requirement exposed -- not a preference for touching someone else's
code. The fix, kept as small and additive as it could possibly be:

* **Two new edges**, `ONLINE -> PENDING_PROVISIONING` and
  `OFFLINE -> PENDING_PROVISIONING`, added to the existing
  `ROUTER_STATUS_TRANSITIONS` dict in `app/domains/router/enums.py`. Every
  existing edge is untouched; nothing was renamed, removed, or reordered.
  `SUSPENDED`/`DECOMMISSIONED` deliberately gained no such edge -- reset
  eligibility (`ONLINE`/`OFFLINE` only) is independently enforced by
  `validators.validate_router_eligible_for_factory_reset` before this edge
  is ever consulted, so a suspended or decommissioned router is rejected
  before BE-008's transition graph even comes into play.
* **One new method**, `RouterService.reset_to_pending_provisioning`, added
  to `app/domains/router/service.py` immediately alongside the other
  status-changing methods, calling the exact same `_set_status` internal
  helper every other status transition (`suspend_router`,
  `reinstate_router`, ...) already uses -- so it is audited
  (`AuditAction.ROUTER_FACTORY_RESET`, itself an additive RBAC enum value)
  through BE-008's own, already-established `_audit` mechanism, with zero
  new audit-writing code in this module. `RouterProvisioningService` calls
  this method through its `RouterLookupProtocol` (composition, the same
  pattern used for every other BE-008 interaction) and does **not** write a
  second, duplicate `audit_log_entries` row for the same fact -- it only
  adds its own `RouterEvent` (`factory_reset_completed`) for device-history
  purposes. This is directly asserted by
  `TestFactoryReset::test_factory_reset_completion_resets_router_status`,
  which checks exactly one `router_factory_reset` audit entry exists.
* **No other change** to `app/domains/router/`. `RouterUpdateRequest`,
  `RouterCreateRequest`, every existing exception, every existing test in
  `tests/unit/test_router.py` -- all untouched and all still passing
  unmodified.

This is the *only* place this module reached into BE-008's own files (as
the module brief itself anticipated: "only if you add a genuinely-missing
method do you touch `app/domains/router/service.py`/`repository.py`,
additively" -- `enums.py` needed the same additive treatment for the
identical, inseparable reason: a new transition edge and the method that
exercises it are one indivisible unit of change, not two).

## 7. What this module deliberately does not do

* No live device dispatch -- `complete_provisioning_job` is never called by
  this module's own code; it exists for a future `app.domains.router_agent`
  module (or, today, for tests simulating that agent) to call after
  actually performing a device-side action. It is intentionally **not**
  exposed over HTTP.
* No `RouterSecretRotationLog` table -- a rotation is already fully captured
  by one `RouterEvent` row plus one `audit_log_entries` row; a third table
  with the same three facts (router, actor, timestamp) would duplicate data
  for no distinct query need. See `models.py`'s module docstring for the
  full reasoning, mirroring `docs/router/ROUTER_ARCHITECTURE.md` §7's
  identical "no gap found" discipline for why BE-008 added no `RouterRole`
  table either.
* No message bus / event-sourcing framework -- `events.py`'s dataclasses are
  constructed and consumed synchronously, in-process, by `service.py`
  itself.
* No MSP-child inheritance for `ConfigTemplate` tenant scoping (unlike
  `RouterService`'s own MSP-aware `_enforce_organization_scope`) -- a
  template is either a system template (usable by anyone) or scoped to
  exactly the calling organization; this is a deliberate simplification
  since the module brief did not call out MSP template sharing as a
  requirement, documented here rather than silently assumed.
