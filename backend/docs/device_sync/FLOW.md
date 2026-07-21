# Device Synchronization -- Design Write-Up

## 1. Why this is an orchestrator, not a new sync mechanism

Before building this domain, the real state of per-router sync across
this codebase was audited:

* **Connected Devices** already has a real, working `sync_router` (built
  earlier in this same effort).
* **Provisioning Engine** already has a real `ProvisionJob`/status
  history for a router's own config provisioning.
* **Queue Management** has real, working *per-assignment* device push
  (`apply_queue`/`remove_queue`/`reset_queue`), but no *bulk*, router-wide
  "sync everything" method -- a genuine, small gap this domain's own
  build closed by adding `reapply_assignments_for_router` directly to
  that domain (see §3).
* **DHCP/VLAN/Port Forwarding** have **no** real device push anywhere in
  this codebase -- confirmed via `grep` for `device_adapter` across all
  three domains (zero hits), and each domain's own `FLOW.md` already
  documents this as a deliberate, explicit deferral to the not-yet-built
  Network Configuration Management domain (roadmap item #11).

Given this, "Device Synchronization" cannot honestly be a domain that
invents six new device-push mechanisms. It is instead a thin
orchestration + history layer over what's *actually* real today, with
the rest reported accurately rather than faked.

## 2. Division of responsibility with Network Configuration Management

Network Configuration Management (not yet built) is explicitly scoped as
"Manage DHCP/VLAN/Port Forwarding/QoS/ISP Routing/Hotspot Settings;
Support Versioning/Backup/Restore/Rollback; Provisioning Integration" --
i.e., it will own *pushing new config* to those domains, with real
versioning/rollback semantics. Device Synchronization's own job is
narrower and different in kind: given a router, run whatever real sync
operations already exist, and report status -- never invent a competing
push mechanism for the domains NCM will eventually own. When NCM is
built, this domain's own `not_provisioned` placeholders for DHCP/VLAN/
Port Forwarding are the natural extension point (that domain will supply
this one a real `sync`/`status` composition, the same shape Connected
Devices and Provisioning Engine already have) -- not something this
build needs to anticipate further than documenting the seam.

## 3. `reapply_assignments_for_router`: reusing `reset_queue`, not reimplementing device push

Added directly to `app.domains.queue_management.service
.QueueManagementService` (not this domain) since it's genuinely that
domain's own concern -- a bulk operation over its own assignments,
authored the same way every other bulk-over-one-domain method in this
codebase is (i.e., inside that domain, not bolted on from outside).
It lists every currently-`ACTIVE` assignment for the router
(`list_assignments(router_id=..., status=ACTIVE, page_size=1000)`) and
calls that domain's own pre-existing `reset_queue` (remove then
re-apply -- the real "force a fresh device push" operation, already used
elsewhere for RouterOS counter resets) on each, one at a time, with
per-assignment failure isolation (one bad assignment never aborts the
rest of the router's own queues). No new device I/O, no new adapter --
this method is entirely a loop over already-real per-assignment
operations.

## 4. Per-component failure isolation and overall status

`DeviceSyncService.sync_router` wraps each of the three real components
in its own `try`/`except` -- a Connected Devices sync failure (e.g. the
router is unreachable) never prevents the Queue Management re-push from
still running, and vice versa. `validators.compute_overall_status`
computes `SUCCESS`/`PARTIAL`/`FAILED` from the *real* components only --
`NOT_PROVISIONED` components are excluded from the tally entirely (they
never had a real operation to succeed or fail at, so they can never drag
an otherwise-clean run down to `PARTIAL`). A `NO_JOBS` provisioning
result (no `ProvisionJob` has ever run for this router) is treated as a
successful *check*, not a failure -- the lookup itself worked; there
simply being no history yet is not an error.

## 5. Sync History: one immutable row per invocation, not a mutable status

Mirrors `app.domains.provisioning_engine.models.ProvisionJob`'s own "new
row, not mutate" convention exactly -- `DeviceSyncRun` has no `update`
method on its own repository at all. Each sync attempt (whether
triggered manually via the API, or in a future pass by a scheduled sweep)
gets its own permanent row; "Sync History" (the roadmap's own named
capability) is simply `list_runs`, ordered by `started_at` descending,
never a second table or a row that gets overwritten on the next attempt.

## 6. `component_results`: a real, structured JSONB blob, not a workaround

Each component's result is `{"status": ..., "summary": ...}` where
`summary`'s own shape varies by component (discovered/updated/
disconnected counts for Connected Devices; reapplied/failed counts for
Queue Management; job_id/job_status for Provisioning; `None` for the
unprovisioned three). A fixed relational schema would need a column per
component per possible summary field, mostly always empty -- JSONB here
mirrors `app.domains.policy.models.PolicyVersion.rules`'s own established
"real, structured, but variably-shaped result" precedent in this
codebase, not an escape hatch from real modeling.
