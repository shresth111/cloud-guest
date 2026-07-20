# Provisioning Engine -- Design Write-Up

This document covers every non-obvious design decision made while building
the Provisioning Engine, and the reasoning behind each -- see `README.md`
for the folder/API surface overview and `DATABASE.md` for the schema.

## 1. Composition, not duplication -- the whole point of this module

`ProvisioningEngineService` never reimplements template rendering, variable
resolution, config versioning/diffing, the device-action job queue, policy
resolution, NAS registration, or health-snapshot recording -- every one of
those already exists, real and tested, in `app.domains.router_provisioning`
(composed via `RouterProvisioningLookupProtocol`), `app.domains.router`
(via `RouterLookupProtocol`), `app.domains.policy` (via
`PolicyLookupProtocol`), and `app.domains.guest`'s `RadiusService` (via
`NasLookupProtocol`). What is genuinely new is the orchestration itself: a
real, ordered, tracked seven-step sequence over all of them, plus the one
piece none of them do -- actually calling a real device adapter
(`device_adapters.py`) to perform the push/verify/health-check, and closing
`router_provisioning`'s own long-anticipated `complete_provisioning_job`
seam. That module's own docstring has always said *"a future
app.domains.router_agent module is expected to call
complete_provisioning_job after actually performing the device-side
action"* -- `tasks.py`'s `drain_provision_queue`, via
`ProvisioningEngineService.run_provision_job`'s own `PUSH_CONFIG` step, is
that caller, now real.

## 2. Four tables, not nine

The module brief named nine entities: Provision Job, Provision Step,
Provision History, Provision Timeline, Provision Log, Provision Template,
Provision Queue, Provision Retry, Provision Rollback. Only four are real
tables (`models.py`) -- the rest are read-models or a composition pattern
over these four, mirroring this codebase's own established discipline
(e.g. `app.domains.router_provisioning`'s own module docstring rejecting a
dedicated `RouterSecretRotationLog` table for an analogous reason -- a
bespoke table duplicating facts an existing row shape already captures):

* **History** = querying `ProvisionJob` rows for a router, ordered by
  `created_at` (`ProvisioningEngineService.get_history`). No separate
  table -- every past run already is a row here.
* **Timeline** = a read-model aggregating one job's `ProvisionStep`
  transitions plus its `ProvisionLog` entries into one ordered list
  (`ProvisioningEngineService.get_timeline`).
* **Queue** = the same real "Postgres row + Redis wake-up signal" mechanism
  `router_provisioning`'s own `ProvisioningJob`/
  `RedisProvisioningQueueDispatcher` already establishes, reused via a
  structurally identical dispatcher (`RedisProvisionEngineQueueDispatcher`)
  and its own Redis key (`PROVISION_ENGINE_QUEUE_REDIS_KEY`).
* **Retry** = a **new** `ProvisionJob` row (`retry_of_job_id` set), never a
  mutation of the failed row back to a running status -- mirrors
  `ConfigVersion`'s/`PolicyVersion`'s own "new row, not mutate" convention.
* **Rollback** = a **new** `ProvisionJob` row (`is_rollback=True`,
  `rollback_of_job_id` + `rollback_target_version_id` set) whose own
  `PUSH_CONFIG` step composes `RouterProvisioningService
  .rollback_to_version`/`apply_version` -- never a duplicated mechanism.

## 3. The seven-step sequence

`constants.PROVISION_STEP_SEQUENCE`: Discover -> Validate -> Generate
Config -> Push Config -> Verify Config -> Health Check -> Register
Monitoring. "Provision Success" (the brief's own final flow-diagram node)
is not a step -- it is the job's own terminal `ProvisionJobStatus.SUCCESS`,
reached once every step above has succeeded. `run_provision_job` stops and
marks the job `FAILED` the moment any step fails -- it never continues past
a failure (unlike the per-item failure isolation this codebase's own
*batch* sweeps use elsewhere: a single router's own provisioning steps are
strictly sequential and dependent, so pushing a config to a router that
failed discovery would be a real, dangerous mistake, not a resilience win).
Per-**job** failure isolation belongs one layer up, in `tasks.py`'s own
queue-drain loop: one job raising must never stop the rest of a drained
batch.

## 4. `GENERATE_CONFIG`'s real trick: settings become variables

A naive design would have `ProvisionTemplate.settings` (DHCP/DNS/hotspot/
WireGuard/firewall/NTP/logging presets) generate a *second* block of config
text, appended after `router_provisioning`'s own rendered `ConfigTemplate`
content -- two rendering mechanisms for one config. Instead,
`GENERATE_CONFIG` flattens `settings` (e.g. `{"ntp": {"primary": "..."}}` ->
`ntp_primary`) and materializes each entry as a real, router-scoped
`ConfigVariable` (via `RouterProvisioningLookupProtocol.create_variable`,
tolerating `DuplicateConfigVariableError` as "already seeded, fine" --
idempotent across retries) *before* `PUSH_CONFIG` calls the existing
`assign_profile`/`apply_version`. The linked `ConfigTemplate` is expected to
reference these same variable names as `{{placeholders}}` -- authored once,
by whoever writes that site type's script -- so the *existing*, unmodified
`render_template`/`resolve_variables` pipeline picks them up naturally. One
rendering mechanism, one source of truth, zero changes to
`router_provisioning`'s own tested code.

## 5. `PUSH_CONFIG`'s three source-of-truth branches

* **Rollback job** (`is_rollback=True`) -- calls `rollback_to_version`
  against `rollback_target_version_id` (resolved once, at `rollback_job`
  creation time, to the `ConfigVersion` immediately before the one the
  original job applied).
* **Job with a `provision_template_id`** -- calls `assign_profile` against
  that template's own `config_template_id`, creating a fresh `ConfigVersion`.
* **Job with neither** -- the router already has a `ConfigProfile`/
  `ConfigVersion` assigned directly, outside this orchestrator (see
  `models.ProvisionJob.provision_template_id`'s own docstring). This branch
  re-pushes whatever is already the router's latest `ConfigVersion`
  (`list_versions(page=1, page_size=1)`); if none exists,
  `ProvisionNoConfigurationSourceError` fails the step honestly -- there is
  nothing this step could possibly push.

Every branch converges on the same `apply_version` ->
`start_provisioning_job` -> real `adapter.push_config` ->
`complete_provisioning_job(success=...)` sequence, and records
`applied_config_version_id` on the job only once the device push itself
succeeds.

## 6. Real device I/O, honestly scoped

`device_adapters.BaseProvisionAdapter` is the heavier, "actually connect to
and operate a device" Strategy/Adapter seam -- distinct from (and composed
alongside) `router_provisioning.adapters.ProvisioningAdapterProtocol` (that
one only validates template/vendor compatibility and shapes a job's payload
metadata; it never opens a connection, by design).
`MikroTikProvisionAdapter` uses `librouteros` (RouterOS API, a synchronous
library bridged into this codebase's async call sites via
`asyncio.to_thread`, the same pattern `app.core.celery_app`'s own worker
tasks already use for the sync/async boundary) for discovery/health-checks,
and `asyncssh` (SSH/SFTP) for file/script upload, `/import`, and
backup/restore -- RouterOS's own real, supported mechanism for both. Every
method's command-construction and response-parsing logic is exercised via a
hand-rolled fake transport in `test_provisioning_engine_adapters.py`; there
is no live device anywhere in this sandbox to prove an actual network round
trip, so every method, if genuinely invoked here, raises a real
`ProvisionDeviceConnectionError` -- confirmed empirically against a
guaranteed-unreachable TEST-NET-1 address, never a fabricated success. This
is this codebase's own "honest placeholder" discipline (already applied to
Celery health before a worker existed, FreeRADIUS before a live daemon
existed, `router_agent`'s own dispatch before a real agent process existed)
applied to a genuinely new class of gap: not a missing feature, but an
environment that cannot host what would prove the feature real end to end.

## 7. The Celery queue-drain task

`tasks.drain_provision_queue` is a Beat-scheduled task (every 15 seconds --
see `constants.PROVISION_QUEUE_DRAIN_INTERVAL_SECONDS`'s own docstring for
why this is much shorter than every other sweep in this codebase's Beat
schedule: a human is plausibly watching a dashboard's progress bar for a
user-triggered "start provisioning now" request to move). Each tick pops up
to `PROVISION_QUEUE_DRAIN_BATCH_SIZE` job IDs off
`PROVISION_ENGINE_QUEUE_REDIS_KEY` and runs each via `run_provision_job`,
opening a fresh `AsyncSession` and building the full, real repository/
service graph by hand (mirrors `app.domains.billing.tasks`'s identical
bridge pattern) -- including a real `GuestService`/`OtpService`/
`VoucherService`/`CaptivePortalService` graph, since `RadiusService`'s own
constructor requires a `GuestService` instance even though this task's own
calls into it (`register_nas`/`list_nas_clients`) never touch it. One job's
own failure never stops the rest of the batch draining.

## 8. RBAC: a new, additive `PermissionModule`

`PermissionModule.PROVISIONING_ENGINE` follows the exact precedent
`PermissionModule.POLICY` set at its own first Part: an additive block in
`MODULE_ACTIONS`/`MODULE_DISPLAY_NAMES`/`MODULE_NARROWEST_SCOPE`, never a
domain-local constants shadow of the shared enum. Action set (`CREATE`/
`READ`/`EXECUTE`/`MANAGE`) mirrors `PermissionModule.OTP`'s identical
shape -- jobs are created and driven through their lifecycle
(start/retry/rollback/cancel, all `EXECUTE`), never directly updated or
deleted by a user. Narrowest scope is `ScopeType.ROUTER`, the same
device-level profile `ROUTER_PROVISIONING`/`RADIUS`/`WIREGUARD`/
`FIREWALL`/`DHCP`/`DNS`/`HOTSPOT`/`MONITORING` already share.
`Network Administrator` (the one system role whose own default level is
`NONE`, requiring an explicit override to gain any module) is given
`PROVISIONING_ENGINE: FULL` right alongside its existing
`ROUTER_PROVISIONING: FULL` -- the identical persona.
