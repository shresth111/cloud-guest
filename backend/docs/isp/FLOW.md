# ISP Management -- Design Write-Up

## 1. Composition, not duplication

`IspService` never opens a device connection or decrypts a credential
itself. `RouterLookupProtocol` -- a narrow, duck-typed Protocol satisfied
structurally by the real `app.domains.router.service.RouterService`, the
identical composition-over-duplication pattern every prior domain in this
codebase establishes -- supplies both the router's own connection fields
and its already-decrypted API secret (`get_decrypted_api_secret`, reused
directly, never re-decrypted here).

Which vendor adapter actually issues the ping is resolved per-router from
`Router.vendor` via `device_adapter_resolver` (default
`device_adapters.get_isp_health_adapter`), mirroring
`app.domains.queue_management.service.QueueManagementService`'s own
"resolve per-router at the point of use, never fix one adapter at
construction time" convention exactly -- injectable purely for tests.

## 2. Two tables, not three -- current state + history

`app.domains.monitoring`'s own module docstring documents a deliberate
choice: a device's *current* health lives as columns on its own row
(`Router.health_status`/`last_seen_at`/`last_health_check_at`), while its
*history* lives in a separate, append-only time-series table
(`HealthCheck`) -- never a third, redundant "current status" table
layered on top. This domain follows the identical split:

* `IspLink` -- one row per WAN uplink a router carries, holding its
  *current* health snapshot (`health_status`/`latency_ms`/
  `packet_loss_percentage`/`last_checked_at`) directly as columns, updated
  in place by every health check.
* `IspHealthCheck` -- one row per health-check *execution*, an append-only
  log mirroring `monitoring.models.HealthCheck`'s identical shape. This is
  what "History" (the roadmap's own named capability) means concretely.

Failover *events* (a link flipping `is_active_uplink`) are **not** a third
table either -- they are written to RBAC's own `audit_log_entries` (a
real, admin-relevant, moderate-volume state change), while the frequent,
high-volume per-tick health readings above are not (mirrors
`app.domains.guest.service`'s own "high-volume, no per-call audit row"
judgment call for login attempts).

### `role` vs. `is_active_uplink`: static assignment vs. live state

`IspLink.role` (`PRIMARY`/`BACKUP`) is a static, admin-assigned priority
that never changes during a failover. `IspLink.is_active_uplink` is a
dynamic boolean flag tracking which link is *currently* carrying traffic,
which flips during a real failover/failback without ever touching `role`.
A partial unique index
(`uq_isp_links_router_id_active_uplink` on `(router_id)`,
`postgresql_where=text("is_active_uplink = true AND is_deleted = false")`)
enforces "at most one active uplink per router" at the database level,
mirroring `app.domains.guest_teams.models.GuestTeamMember`'s own identical
partial-unique-index precedent for "at most one active X per scope".

A router may carry more than one `BACKUP` link -- `priority` (lower value
tried first) picks which enabled, non-unhealthy backup `trigger_failover`
fails over to when several exist.

## 3. Failover: real, threshold-gated, never on a single blip

`trigger_failover`/the module-level `run_health_check_sweep` never act on
one bad ping -- `IspLink.consecutive_unhealthy_count` must reach
`constants.DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER` (default 3)
*consecutive* `UNHEALTHY` readings first. `DEGRADED` readings never count
toward this threshold at all (reset the counter to 0, same as `HEALTHY`).
A guest network's live WAN uplink flapping back and forth on transient
packet loss would be strictly worse than staying on a briefly-degraded
primary.

`trigger_failover` selects the lowest-`priority`, enabled backup link
whose own `health_status` is not currently `UNHEALTHY` (skipping the
currently-active link itself) -- raising `IspNoBackupLinkAvailableError`
if none qualifies. The primary's own outage is real, but there is nothing
safe to switch to.

`trigger_failback` requires the primary to currently be `HEALTHY` (not
merely "not unhealthy") before restoring it -- failing back onto a still-
degraded/unhealthy link would recreate the exact outage the failover just
fixed. Auto-failback (`IspLink.auto_failback`, default `True`) evaluates
this same condition after every health-check recording, so a primary that
recovers on its own hands traffic back without an admin needing to trigger
it manually.

## 4. Real health checks: RouterOS `/tool/ping` via the raw `Api` callable

Confirmed via exhaustive research that no ICMP/ping/latency mechanism
existed anywhere in this codebase before this domain. Every other adapter
in this codebase (`queue_management`, `provisioning_engine`) only ever
calls `.add`/`.update`/`.remove`/iterates a `Path` menu -- all CRUD
operations against a stable RouterOS *menu*. `/tool/ping` is not a menu
CRUD operation; it is a one-shot RouterOS *command* invocation. Confirmed
directly against the installed `librouteros` package's own source:
`Api.__call__(self, cmd: str, **kwargs)` is a generator that writes `cmd`
as a raw sentence and yields each reply row -- the correct, library-native
way to invoke a bare command word that isn't scoped under a menu's own
`add`/`set`/`remove`. This module is the first call site in this codebase
to use that raw form.

A RouterOS API `/tool/ping` call (given `count=N`) yields one reply
sentence per echo attempt, each carrying cumulative `sent`/`received`/
`packet-loss`/`avg-rtt` fields that update as probes complete --
`device_adapters._parse_ping_rows` reads the **last** yielded row (the
final, cumulative tally). `avg-rtt` is a RouterOS duration string (e.g.
`"1ms200us"`, `"850us"`, `"12ms"`) -- `_parse_routeros_duration_ms` is a
small, real parser for that specific format (RouterOS never emits plain
ISO-8601 durations here), not a generic duration library.

## 5. Availability: a computed read-model, never persisted

`IspService.compute_availability_percentage` mirrors
`app.domains.wireguard.constants.HealthStatus`'s own "computed at read
time from history, never stored" precedent -- the fraction of
non-`UNHEALTHY` checks in a link's own history, deliberately returning
`None` (not `100.0`) when there is no history at all yet, since "never
checked" must never be conflated with "always up."

## 6. Audit-volume judgment call

Mirrors `app.domains.guest.service`'s own tiering exactly: every
individual health-check reading (potentially one per link per minute,
platform-wide) is **not** audited -- it is recorded in the dedicated,
high-volume `IspHealthCheck` table and logged via the structured logger
only. Link create/update/delete, and especially a failover/failback (a
guest network's live uplink just changed), **are** always audited --
including when system-triggered by the health-check sweep, not just
admin-driven, since a guest network's live uplink changing is judged
always operationally significant regardless of trigger source (mirrors
`AuditAction.GUEST_SESSION_TERMINATED`'s own "always audited" profile
rather than `GUEST_SESSION_DISCONNECTED`'s system-vs-admin split).

## 7. Per-link failure isolation in the platform-wide sweep

`run_health_check_sweep` mirrors
`app.domains.billing.renewal_service.RenewalService.run_renewal_sweep`'s
own per-item isolation contract -- a single router that's unreachable/
misconfigured is caught, logged (`isp_health_check_sweep_link_failed`),
and skipped, never aborting the sweep for every other router's own links.
Tracked via a `HealthCheckSweepSummary` frozen dataclass (`checked`,
`failovers`, `failbacks`, `skipped`, `errors`). Pulled out to module scope
(not a method requiring a full pre-constructed service) for the identical
"Celery task + test suite share one real implementation, no live Postgres
needed for the latter" reason `app.domains.guest.service
.enforce_session_timeouts`/`run_fup_time_accrual` were.

## 8. RBAC: a brand-new, additive module

Unlike Queue Management (which reused the pre-existing
`PermissionModule.BANDWIDTH` key), ISP Management mints a new
`PermissionModule.ISP` -- full CRUD plus `EXECUTE` (manual health
check/failover/failback triggers) and `MANAGE`. `MODULE_NARROWEST_SCOPE`
is `ScopeType.ROUTER` (an ISP link is physically terminated at one
router), and the existing "Network Administrator" system role's own
`_M.BANDWIDTH: _L.FULL` override gained an identical `_M.ISP: _L.FULL`
entry. No migration is needed for any of this -- `permission_groups`/
`permissions`/`permission_scopes`/`role_permissions` rows are all seeded
idempotently at application/CLI startup by `seed_rbac`.
