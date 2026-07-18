# BE-011 Part 1: Monitoring -- Design Decisions

This document walks through every non-obvious architectural call made in
`app.domains.monitoring`, in the order the module spec raised them.

## 1. DeviceHealth: no new table, and not even a new composition method

The module brief invited a router-level health "rollup" (`DeviceHealth`)
here. After reading `app.domains.router.models.Router` and
`app.domains.router_provisioning.models.RouterHealthSnapshot`/`RouterEvent`
in full, the conclusion is that **nothing new is needed**:

* "What is this router's health *right now*" is already exactly three
  plain columns BE-008 already maintains on every heartbeat:
  `Router.health_status`/`last_seen_at`/`last_health_check_at`.
* "What was this router's health *over time*" is already exactly
  BE-009's `RouterHealthSnapshot` (a full time-series table --
  `cpu_usage_percent`/`memory_usage_percent`/`uptime_seconds`/
  `connected_clients_count`, paginated by
  `RouterProvisioningRepository.list_health_snapshots_for_router`) plus
  `RouterEvent` (reboot/config-applied/error/enrollment history).

A `DeviceHealth` table here would either (a) duplicate every one of those
columns for zero new information captured, or (b) be a thin read-only view
joining `Router`+`RouterHealthSnapshot` -- which is just as easily (and more
honestly) expressed as "call `RouterService.get_router` and
`RouterProvisioningRepository.list_health_snapshots_for_router` directly,"
something every caller (a future ZTP/analytics dashboard, BE-011 Part 3)
can already do today with zero code added here. This module's own dashboard
(`GET /monitoring/health`) is scoped entirely to platform-level components
-- a per-router breakdown is a different question `router_provisioning`'s
own existing endpoints already answer completely.

**Revisit only if** a genuine cross-router *aggregate* need emerges that
neither domain currently answers -- and even then, "how many routers are
unhealthy platform-wide" is a single `COUNT(...) WHERE health_status =
'unhealthy'` query against the existing `routers` table, not a reason for a
new persisted table.

## 2. HeartbeatLog: a platform-wide log, composing with (not replacing) `router_agent`'s existing heartbeat

`app.domains.router_agent`'s `POST /agent/heartbeat` endpoint already
updates BE-008's `Router.last_seen_at` (via `RouterAgentService.heartbeat`
-> `RouterService.heartbeat`) on every real device heartbeat, and that
remains the *only* mechanism that flips a router's liveness/online status --
`HeartbeatLog` changes none of that.

What `HeartbeatLog` adds is a **platform-wide, cross-component log** of the
same moment (plus, in the future, other component types), for a monitoring
dashboard's unified timeline that wants to show router heartbeats
side-by-side with WireGuard/future-service heartbeats without querying N
different domains' tables and merging them client-side.

**The decision made:** `app.domains.router_agent.router.agent_heartbeat`
gets one small, additive call -- after its existing
`RouterAgentService.heartbeat` call -- into
`MonitoringService.record_heartbeat` (`component_type=ROUTER`). This is
composition, not duplication: the endpoint's request/response contract and
its existing liveness-detection behavior are completely unchanged; the only
addition is one extra row in a separate, platform-wide table. This is the
**one** additive cross-domain hook this module's directory rule permitted,
and it was spent here because it reaches every provisioned router, far more
devices than WireGuard's still-optional tunnel.

`HeartbeatComponentType.WIREGUARD_PEER` is defined (so no migration is
needed once a writer exists) but has **no current writer**: the natural
seam (`WireGuardService.record_handshake`) lives inside
`app.domains.wireguard`, which this module's directory rule does not permit
editing in this iteration -- only one additive hook was budgeted, and it was
spent on the router-agent seam above. `HeartbeatComponentType.SERVICE` is
likewise defined but has no current writer: it is reserved for a future
platform self-heartbeat source (e.g. a Celery worker, once one exists), the
same honest "defined, not fabricated" posture as `HealthComponent.CELERY`.

`component_id` is a plain, **unconstrained** `UUID` column (no SQL foreign
key) because it polymorphically refers to a different table depending on
`component_type` -- a single FK cannot reference more than one table, and a
separate nullable FK column per component type would grow this table's
schema with every new type added. This mirrors `AuditLogEntry.entity_id`'s
identical, already-established "no referential integrity for a polymorphic
log" tradeoff in this same codebase.

## 3. PlatformEvent: composition, with one narrowly-scoped new table

Two tables already log domain events, each with its own well-justified,
already-documented scope: RBAC's `audit_log_entries` (accountable,
human-attributable, moderate-volume *admin actions*) and
`router_provisioning`'s `RouterEvent` (high-volume, often-no-human-actor
*device telemetry* for one router). Both are, individually, already the
right table for the events they carry.

**The architectural call:** `PlatformEvent` is a real, new table, but
scoped **only** to what genuinely has no home elsewhere -- in this Part 1,
that means exactly this module's own Health Engine's status-transition
detections (`_record_transition_event` in `service.py`), which nothing else
in this codebase currently records anywhere.
`MonitoringService.get_event_timeline` is the actual unified timeline the
module brief asked for: a **read-side aggregation** that queries
`PlatformEvent` *and* `audit_log_entries` *and* `RouterEvent` directly (via
read-only `SELECT`s against their already-defined models in
`repository.py` -- no code inside `rbac`/`router_provisioning` is touched to
make this work) and merges all three into one chronologically-sorted list
at request time.

This means: zero duplicate storage, zero cross-domain writes into another
domain's own table, and a genuinely new (if narrow) table that captures a
real gap no existing table filled. A future domain that wants its own
moments on this platform-wide timeline can call
`MonitoringService.record_platform_event` directly -- the same
"`ServiceX` composes with `ServiceY` through a narrow surface" pattern every
other domain in this codebase already uses -- but no such call was added to
any other domain's files in this iteration (out of this module's own
directory-rule scope), so today's only writer is this module itself.

Since `audit_log_entries`/`RouterEvent` carry no `category`/`severity` of
their own, the read-side merge classifies them with a documented,
best-effort mapping (`TimelineEntry.from_audit_log`/`from_router_event` in
`service.py`): every audit-log row becomes `category=AUDIT`,
`severity=INFO` (an accurate description of that table's own scope); every
router-event row becomes `category=PROVISIONING`, with `severity=WARNING`
only when its `event_type` reads as a failure (contains "error"/"failed"/
"reset"), `INFO` otherwise.

## 4. FreeRADIUS health: a proxy signal, not a live daemon ping

There is no real FreeRADIUS process anywhere in this sandbox -- as
`app.domains.guest.service`'s own module docstring already establishes,
this platform's RADIUS integration is an `rlm_rest`-style HTTP contract
FreeRADIUS would be configured to call *into*, not a daemon this process
could ever health-check by reaching out to it. `check_freeradius_health`
therefore composes with `app.domains.guest`'s existing data (read directly,
no code changes to `guest`): how many active `RadiusNasClient` rows are
registered, and how recently any RADIUS-accounting-driven session activity
(`GuestSession.last_activity_at`, updated by the accounting endpoints) was
recorded. Zero registered NAS clients reads as `UNKNOWN` (nothing to judge
yet); registered-but-never-any-activity or stale activity (beyond
`FREERADIUS_ACTIVITY_STALE_MINUTES`, a generous hour given guest WiFi's
naturally bursty traffic) reads as `DEGRADED`; recent activity reads as
`HEALTHY`.

## 5. WireGuard health: a proxy signal, reusing the real staleness method

Symmetrically, `check_wireguard_health` composes directly with
`app.domains.wireguard.service.WireGuardService.compute_health_status` --
called once per non-revoked `WireGuardPeer` row (read directly from the
`wireguard_peers` table, no code changes to `wireguard`) -- rather than
reimplementing that method's own handshake-staleness threshold logic. No
peers provisioned yet reads as `UNKNOWN`; every peer stale reads as
`UNHEALTHY`; some-but-not-all stale reads as `DEGRADED`; none stale reads as
`HEALTHY`. This mirrors `app.domains.wireguard`'s own documented posture: a
DB-tracked, device-*reported* signal, not a live `wg show` integration.

## 6. RBAC permission-key reuse: `monitoring.*` for events too

There is no dedicated "events" permission module in
`app.domains.rbac.enums.PermissionModule` -- only `MONITORING` (already
seeded with `read`/`view`/`manage` actions in `app.domains.rbac.seed`). This
module reuses `monitoring.read`/`monitoring.manage` for **both** the health
endpoints and `GET /events`, rather than inventing a parallel `events.*`
permission module for what is, conceptually, one "observability" surface an
operator is granted or denied as a unit. `POST /monitoring/health/run` (an
on-demand, real round-trip against every platform dependency) requires the
stricter `monitoring.manage`; every `GET` requires only `monitoring.read`.

## 7. The honest Celery/WebSocket treatment

No Celery worker/broker exists anywhere in this codebase (there is no
background task queue at all), and no WebSocket support exists anywhere
either. `check_celery_health`/`check_websocket_health` return
`HealthStatus.UNKNOWN` with a `details`/`error_message` explaining exactly
why, **never** a fabricated `HEALTHY`. The health-check *type*
(`HealthComponent.CELERY`/`WEBSOCKET`) is fully defined and wired into every
dashboard/history endpoint now, so no migration is needed the moment a real
Celery deployment or WebSocket endpoint exists -- only the check's
implementation needs to change, from "report why this can't be judged" to
"actually judge it."

## 8. Overall dashboard status: UNKNOWN components don't block HEALTHY

Read literally, "HEALTHY only if every component is HEALTHY" would mean
`GET /monitoring/health`'s aggregate status could *never* show `HEALTHY` in
this environment, since `CELERY`/`WEBSOCKET` are honestly `UNKNOWN` forever
until that infrastructure is actually deployed -- that would make the
aggregate status useless as a signal for operators. `MonitoringService
._aggregate_status` instead treats `UNKNOWN` as "not currently applicable"
rather than "not healthy": `UNHEALTHY` wins if any component is `UNHEALTHY`,
`DEGRADED` wins next, and the aggregate is computed from whichever
components have a *live* (non-`UNKNOWN`) status otherwise -- `UNKNOWN` only
when literally every component is (which only happens before the very
first health-check run has ever executed). This is a deliberate, documented
reading of the module spec, not a silent deviation.

## 9. Storage/auth checks: real, narrow, and honest about scope

`check_storage_health` is a real `shutil.disk_usage` (stdlib, no new
dependency) call against the actual configured `Settings.log_dir`,
classified by a pure, independently-testable function
(`validators.classify_storage_health`) against two thresholds (85%/95%
used) -- an unwritable directory is always `UNHEALTHY` regardless of free
space, since a full disk and a permissions problem both mean the same thing
in practice (structured logging can no longer be written).

`check_auth_health` makes one real, cheap call through the actual
`AuthRepository` (`list_users(page_size=1)`) to prove the auth domain's own
repository/DB wiring resolves and can be queried -- it deliberately does
**not** fabricate a "login success rate" metric, which would need real
authentication traffic this environment has no way to generate. This keeps
the check meaningful (a real query through a real cross-domain dependency)
while being honest about its narrow scope (wiring health, not a business
metric).
