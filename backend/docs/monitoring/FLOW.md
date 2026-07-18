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

---

# BE-011 Part 2: Alert Engine + Notification Engine + Incident Engine + SLA Monitoring

Everything below extends the same `app.domains.monitoring` bounded context
-- no new top-level domain, same directory. All four sub-engines compose
with Part 1's Health/Event Engine (`ServiceHealth`, `HealthCheck`,
`PlatformEvent`) and with other domains' already-existing data
(`app.domains.router`/`router_provisioning`'s `Router`/
`RouterHealthSnapshot`/`ProvisioningJob`, `app.domains.otp`'s provider
protocols, `app.domains.router.crypto`) rather than duplicating any of it.

## 10. Alert de-duplication key and the recovery design

**De-duplication key: `(rule_id, organization_id, location_id, router_id)`.**
`AlertService.evaluate_alert_rules` never creates a second open
(`TRIGGERED`/`ACKNOWLEDGED`) `Alert` for a condition that is already firing
-- before creating one, it calls
`MonitoringRepository.find_active_alert(rule_id=..., organization_id=...,
location_id=..., router_id=...)`, which is a real lookup for an existing,
not-yet-`RESOLVED` `Alert` row with that *exact* tuple. For a platform-wide
`HEALTH_STATUS_CHANGE` rule watching a `ServiceHealth` component,
`location_id`/`router_id` are always `NULL` (there is exactly one target: the
component itself). For a per-router `HEALTH_STATUS_CHANGE`/`THRESHOLD` rule,
the tuple is populated per-router, so N routers tripping the same rule
produce N independent alerts (each de-duplicated against *itself*, not
against each other) -- this is intentional: "router A is offline" and
"router B is offline" are different facts an operator needs to see and
acknowledge independently, not one merged alert that hides how many routers
are actually affected. `EVENT_OCCURRED` rules use a **different** key
entirely -- see below.

**Recovery design: no separate "Router Online"/paired recovery rule.** There
is exactly one `AlertRule` per condition (e.g. one "Router Offline" rule,
not a second "Router Online" rule alongside it). Every call to
`evaluate_alert_rules` re-evaluates each active rule's condition against
*current* state: the moment a condition that was true is no longer true
**and** an open `Alert` for that exact de-duplication key still exists, that
alert transitions straight from `TRIGGERED`/`ACKNOWLEDGED` to `RESOLVED`
(`_auto_resolve`), and a recovery notification is dispatched through the
same `NotificationChannel` rows the original trigger used (`_dispatch_for_alert`
is called for both newly-triggered *and* newly-resolved alerts every pass).
This was chosen over a paired-rule model for three reasons: (a) it is half
the configuration for an operator (one rule per condition, not two), (b) a
recovery rule can never drift out of sync with its trigger rule -- there is
only one rule, one condition, two possible truth values -- and (c) it
mirrors this same codebase's own Part 1 precedent:
`_record_transition_event` already detects a component *recovering* by
re-evaluating the same health check, not via a second "recovered" check
type. `EVENT_OCCURRED` alerts are the one exception: a past event has no
ongoing "condition" that can later become false, so those alerts never
auto-resolve -- they stay open until a human calls
`POST /alerts/{id}/resolve`. See `app.domains.monitoring.service.AlertService`'s
own class docstring for the complete write-up, including exactly why
`EVENT_OCCURRED` rules are only wired against this module's own
`PlatformEvent` table (not `RouterEvent`/`audit_log_entries`) -- `Alert
.related_event_id` is a single FK to `platform_events.id`, and a second,
differently-typed FK/dedup path for another table has no clear, currently-
demonstrated need (a future domain that wants its own event alertable can
call `MonitoringService.record_platform_event` directly, the same seam
Part 1's own docstring already invites).

## 11. Threshold rules: composing with `RouterHealthSnapshot`, not a new metrics system

A `THRESHOLD` rule's `condition_config` (`{"metric": ..., "operator": ...,
"value": ...}`) is validated against `constants.ThresholdMetric` -- exactly
the four columns `app.domains.router_provisioning.models
.RouterHealthSnapshot` already persists
(`cpu_usage_percent`/`memory_usage_percent`/`uptime_seconds`/
`connected_clients_count`). `AlertService._evaluate_threshold_rule` reads
each in-scope router's *latest* snapshot (`MonitoringRepository
.get_latest_router_health_snapshot`, a read-only query against
`router_health_snapshots`) and compares the named metric with
`validators.compare_threshold`. No new metrics table, no new metrics
collection mechanism -- if a router has no snapshot yet, the rule simply
has nothing to judge (and auto-resolves any stale alert whose snapshot
later disappears, rather than leaving it firing on data that no longer
exists).

## 12. Health-status-change rules can watch two different things

`target_component` on a `HEALTH_STATUS_CHANGE` rule is either (a) a
`HealthComponent` value (`"database"`, `"redis"`, ...) -- watches Part 1's
own `ServiceHealth` rollup for that platform component, or (b) the sentinel
string `"router"` (`constants.ALERT_TARGET_ROUTER`) -- watches every
in-scope `app.domains.router.models.Router.health_status` directly (a
read-only `SELECT`, the same "read another domain's table directly"
precedent `repository.py` already established in Part 1 for
`RadiusNasClient`/`WireGuardPeer`/`RouterEvent`). This is why the module
brief's own examples ("Router Offline" vs. "Database Down") are both
representable by the *same* trigger type with a different
`target_component`, rather than needing two trigger types.

## 13. Notification Engine: composition vs. real HTTP vs. honest placeholder

* **Email/SMS wrap `app.domains.otp`'s existing provider protocols.**
  `EmailNotifier`/`SmsNotifier` take an `EmailProviderProtocol`/
  `SmsProviderProtocol` (the *exact* protocols `app.domains.otp.service`
  already defines) and default to the same `LoggingEmailProvider`/
  `LoggingSmsProvider` OTP itself uses when no real provider is configured
  -- genuine composition, not a second provider abstraction. No file inside
  `app.domains.otp` is edited.
* **Slack/Teams/Discord/Webhook are REAL `httpx.AsyncClient` POSTs.** Each
  uses that platform's real, documented incoming-webhook payload
  convention: Slack (`{"text": ...}`), Teams (legacy `MessageCard`:
  `{"@type": "MessageCard", "@context": ..., "themeColor": ..., "title":
  ..., "text": ...}`), Discord (`{"content": ...}`). The generic `WEBHOOK`
  channel type has no third-party convention to match, so it POSTs this
  module's own structured JSON body (`event`/`alert_id`/`rule_id`/
  `severity`/`status`/`message`/`triggered_at`) plus an optional single
  custom auth header (`config.auth_header_name`/`auth_header_value`).
  Every real POST shares one bounded timeout
  (`HTTP_NOTIFICATION_TIMEOUT_SECONDS`, 10s) so one slow/unreachable
  third-party endpoint can never hang alert dispatch.
* **WhatsApp is an honest logging-only placeholder -- and here is exactly
  why it, and only it, gets this treatment.** A real WhatsApp notification
  requires a paid WhatsApp Business API account/SDK (Meta's Cloud API, or a
  BSP like Twilio/360dialog) with real per-account credentials, a verified
  sending number, and pre-approved message templates -- none of which exist
  or should be fabricated in this sandbox, per this codebase's explicit
  honesty mandate around Stripe/Razorpay/MSG91/SES/OpenAI/WhatsApp-Business-
  API integrations. This is categorically different from Slack/Teams/
  Discord/Webhook: each of those is *just* a plain outbound HTTP POST to an
  incoming-webhook URL that any operator can generate for free, with no
  paid account, in seconds -- there is no comparable "this genuinely can't
  be done without a paid vendor" boundary for any of the four, so all four
  get the real `httpx` treatment while WhatsApp gets `WhatsAppNotifier`, a
  logging-only class mirroring OTP's own `LoggingSmsProvider`/
  `LoggingEmailProvider` precedent exactly.
* **A delivery failure never raises.** `NotificationService
  .dispatch_notification` catches every exception a `Notifier.send` call
  can raise (`NotificationDeliveryError` for an expected failure -- a
  non-2xx response, a network error -- plus any other unexpected exception)
  and always returns a `NotificationLog` row (`SENT` or `FAILED`), never
  propagating. `AlertService.evaluate_alert_rules` may fan one trigger out
  to several channels; a single bad Slack webhook URL or a temporarily-down
  SMS gateway must never prevent the *other* configured channels from being
  notified, and must never crash the evaluation pass that is the actual
  mechanism protecting the platform. Every failure is still fully
  observable: logged via the structured logger and durably recorded with
  its `error_message` in `notification_logs`.
* **Channel config is always encrypted at rest.** `NotificationChannel
  .config_encrypted` is a JSON object (shape varies by `channel_type`, see
  `DATABASE.md`) serialized then encrypted with
  `app.domains.router.crypto.encrypt_secret` -- reused directly, not
  reimplemented. A Slack/Teams/Discord incoming-webhook URL (or a generic
  webhook's optional auth header value) is a bearer-equivalent secret
  exactly like a RouterOS API password, so it gets the identical
  Fernet-encrypted-at-rest treatment. The API never echoes a channel's
  decrypted config back (`NotificationChannelResponse` deliberately omits
  it entirely).

## 14. Incident Engine: fully manual, no auto-grouping heuristic

`Incident`/`IncidentAlert` model a human-managed grouping of related
`Alert` rows -- **fully manual by design**. The module brief invited an
auto-correlation heuristic (e.g. "N alerts for the same location within M
minutes auto-creates an incident"). None is implemented: every candidate
rule (what counts as "the same location", what time window, what alert
count threshold, whether severity should factor in) would be an arbitrary,
untested guess with no real incident data in this environment to validate
it against -- exactly the kind of unjustified complexity this codebase's
own conventions argue against (the same honesty posture behind Part 1's
Celery/WebSocket `UNKNOWN`s: don't fabricate precision/logic you can't
actually justify). An operator creates an `Incident`
(`POST /incidents`) and explicitly attaches the `Alert` rows they judge
related (`POST /incidents/{id}/alerts`, idempotent -- attaching the same
alert twice is a no-op, not an error). This is simpler, fully defensible,
and easy to extend later: a future auto-suggestion heuristic would only
ever *call* the same `IncidentService.attach_alert` this manual path
already uses -- nothing about this schema needs to change to add one.
`Incident.severity` reuses `constants.AlertSeverity` (info/warning/
critical) rather than a duplicate `IncidentSeverity` enum, since the two
concepts are the same three-level scale.

## 15. SLA formula: a simple check-count ratio, not downtime-duration-weighted

`SlaService.generate_report` computes `achieved_percentage = healthy_checks
/ total_checks * 100` over `[period_start, period_end]` (the target's own
`measurement_window_days`, or an explicit override), scanning Part 1's own
`health_checks` table (`MonitoringRepository.compute_health_check_stats`,
real SQL `COUNT`/`AVG` aggregates, never a Python-side loop over fetched
rows) for the target's `component` (or every component, if `NULL` -- a
platform-wide target). A duration-weighted formula (summing the wall-clock
time each non-healthy status was actually in effect) would, in principle,
more precisely measure "percentage of time healthy" -- it was deliberately
**not** chosen: this environment has no recurring scheduler (no Celery, see
`HealthComponent.CELERY`'s docstring), so `health_checks` rows are produced
whenever `POST /monitoring/health/run` happens to be invoked (an on-demand
admin action, or a test), not on any guaranteed fixed cadence. A
duration-weighted calculation would have to either assume a fixed polling
interval that does not exist, or infer one from the gaps between actual
rows -- both would silently fabricate precision this data does not honestly
support. A simple healthy/total ratio makes no such assumption: it is
exactly what the recorded data says, "what fraction of the checks we
actually ran came back healthy" -- and becomes numerically equivalent to a
duration-weighted formula the moment a real, fixed-interval scheduler
exists. If zero `HealthCheck` rows exist in the window,
`generate_report` raises `InsufficientSlaDataError` rather than fabricating
a 0%/100% result -- the identical honesty posture Part 1's Health Engine
already established for `UNKNOWN`. The same computation also returns
`average_response_time_ms` (a real `AVG(response_time_ms)` over the same
rows) for the spec's "Average Response Time" analytics bullet, and
`SlaService.get_average_provisioning_duration_seconds` composes read-only
with `app.domains.router_provisioning.models.ProvisioningJob`'s own
`started_at`/`completed_at` timestamps (`AVG(EXTRACT(EPOCH FROM
completed_at - started_at))`) for the "Average Router Response"/
provisioning-time analytics bullet -- no new provisioning-time tracking
mechanism, no code inside `router_provisioning` touched.

## 16. RBAC permission-key reuse (no "incidents"/"sla" module, no "create" action)

`app.domains.rbac.enums.PermissionModule.ALERTS` is seeded (see
`app.domains.rbac.seed.MODULE_ACTIONS`) with `read`/`update`/`delete`/
`view`/`manage` -- **no `create` action**. `PermissionModule.NOTIFICATIONS`
is seeded with `read`/`update`/`delete`/`manage` -- **no `create` action**
either. There is no dedicated "incidents" or "sla" `PermissionModule` among
the seeded 36 at all. This module makes three deliberate, documented
key-reuse decisions rather than inventing new `PermissionModule` enum
values (which would require editing `app.domains.rbac.enums`/`seed.py`,
outside this module's directory rule):

1. **Alert-rule and notification-channel *creation* use `.manage`.** Since
   neither seeded module has a `create` action, `POST /alerts/rules` uses
   `alerts.manage` and `POST /notifications/channels` uses
   `notifications.manage` -- the closest seeded action for an admin-gated
   write. Every other CRUD verb reuses its own precise seeded action
   (`alerts.update`/`alerts.delete`, `notifications.update`/
   `notifications.delete`); every `GET` uses `.read`.
2. **Incidents reuse `alerts.*` entirely.** An incident is, conceptually,
   just a human-managed grouping of `Alert` rows -- the same operators who
   are granted/denied alert visibility and management are the natural
   audience for incident visibility and management, so no new module is
   invented. `POST /incidents` (no seeded create action either) uses
   `alerts.manage`; `PUT /incidents/{id}`/`POST /incidents/{id}/alerts`
   (status transitions/attach) use `alerts.update`; every `GET` uses
   `alerts.read`.
3. **SLA reuses `reports.*` entirely.** SLA percentages are fundamentally a
   reporting/analytics concern (a computed measurement over historical
   data, presented to an operator), and `PermissionModule.REPORTS` is
   already seeded with exactly the shape this needs
   (`read`/`export`/`view`/`manage`, no `create`). `POST /sla/targets` and
   `POST /sla/{id}/generate-report` (an operational, on-demand computation,
   not a plain read) both use `reports.manage`; every `GET` uses
   `reports.read`.

See `docs/API.md`'s Monitoring section for the complete endpoint -> 
permission-key table, and `tests/unit/test_monitoring_alerts.py`'s
`test_endpoint_requires_expected_permission_key` for the test that verifies
every one of these keys is actually wired onto the registered route (not
just documented).

## 17. Resilience: alert evaluation never crashes on a notification failure

Restated from §13 for visibility: `AlertService._dispatch_for_alert` calls
`NotificationService.dispatch_notification` for every active channel a
triggered/resolved alert's rule is wired to, and that call is guaranteed to
never raise (see §13). This means a single misconfigured channel (a stale
Slack webhook URL, a down SMS gateway) degrades gracefully -- that one
channel's delivery is recorded as `FAILED` with a diagnosable
`error_message`, every *other* channel still gets notified, and the
alert's own `TRIGGERED`/`RESOLVED` state (the actual source of truth an
operator or automated poller relies on) is completely unaffected.

# BE-011 Part 3: Real-Time + ZTP Monitoring Dashboard + Analytics -- Design Decisions

Part 3 extends the same `app.domains.monitoring` domain (no new top-level
domain) with three things: (1) genuine, working WebSocket endpoints backed
by Redis pub/sub, composing with Part 1's Health Engine and Part 2's Alert
Engine plus one narrow, additive hook into `app.domains.guest`; (2) a
read-only ZTP (zero-touch-provisioning) monitoring dashboard/analytics
layer over `app.domains.router_provisioning`'s already-existing data; (3)
platform-wide dashboard statistics composing all of the above. Unlike the
Celery/WebSocket honesty note from Part 1 ("no such infrastructure exists
yet"), WebSocket support is something FastAPI provides natively, and this
part is specifically tasked with building it for real -- every endpoint
below is a genuinely working `@router.websocket(...)` route backed by a
real Redis `PUBLISH`/`SUBSCRIBE`, not a placeholder.

## 18. No new persisted state (migration decision)

**Conclusion: zero new tables, zero new columns.** Every one of Part 3's
three surfaces is either (a) a live relay of already-happening domain
events (Redis pub/sub is a transient, disposable transport -- nothing about
it needs Postgres durability, mirroring `ProvisioningJob`'s own "Redis is
the dispatch transport, Postgres is the durable source of truth" precedent
from `app.domains.router_provisioning`) or (b) a read-side computation over
data three other domains already persist (`RouterEnrollmentRequest.status`,
`Router.status`/`last_seen_at`, `ProvisioningJob.status`/`attempts`/
`max_attempts`/timestamps, `Alert`/`HealthCheck` rows Part 1/2 already
own). `RouterLifecycleStage` (§20) is the clearest instance of "don't
persist a value you can always recompute correctly from data you already
have" -- see that section for the full argument. No `alembic/versions/0018_...`
migration was written for this part; `backend/alembic/versions/` and
`alembic/env.py` are untouched.

## 19. Real-Time Engine: one Redis channel, message-type filtering, two endpoints

`constants.MONITORING_LIVE_CHANNEL` (`"monitoring:live"`) is the single
Redis pub/sub channel every real-time-producing write path publishes a
uniformly-shaped JSON message to: `{"type": <RealtimeMessageType>,
"payload": {...}, "occurred_at": <iso8601>}`. Three write paths publish,
each *after* its own real database write already succeeded (never instead
of, never before):

* `MonitoringService._persist_result` -- on a genuine `ServiceHealth`
  status *transition* (the same trigger condition Part 1's
  `_record_transition_event` already uses for `PlatformEvent`), publishes
  `RealtimeMessageType.HEALTH_TRANSITION`.
* `AlertService._create_alert`/`_auto_resolve`/`resolve_alert` -- publishes
  `ALERT_TRIGGERED` on every new `Alert` row, `ALERT_RESOLVED` on both
  auto-resolution and manual `POST /alerts/{id}/resolve`.
* `app.domains.guest.service.GuestService`'s `login_via_otp`/
  `login_via_voucher` (via the additive hook, §21) -- publishes
  `GUEST_SESSION_STARTED`.

`GUEST_SESSION_ENDED` is a defined `RealtimeMessageType` member with **no
current writer** -- the identical honest "defined, wired into every
consumer, not yet produced" posture Part 1 already established for
`HeartbeatComponentType.WIREGUARD_PEER`/`HealthComponent.CELERY`. Producing
it would need a hook into `GuestService`'s session-end methods
(disconnect/terminate/expire), which this part's directory rule does not
license (exactly one guest-domain hook was budgeted; see §21).

**Two WebSocket endpoints share the one channel, filtering by
`message["type"]`, rather than one Redis channel per message type:**
`WS /monitoring/ws/dashboard` relays `HEALTH_TRANSITION`/`ALERT_TRIGGERED`/
`ALERT_RESOLVED`; `WS /monitoring/ws/sessions` relays
`GUEST_SESSION_STARTED`/`GUEST_SESSION_ENDED`. This was chosen over a
per-type channel because every publisher already knows unambiguously what
kind of event it is producing (no channel-selection logic needed at
publish time), a single channel is a single operational
`PUBLISH`/`SUBSCRIBE` surface to reason about, and it cleanly separates the
*transport* concern (one channel) from the *client-facing* concern (which
message types a given widget wants) -- adding a third WebSocket endpoint
with a third filter set later needs zero publisher-side changes.

**Publish resilience.** `service._publish_live_message` never raises: a
Redis publish failure (Redis down, a transient blip) is caught and logged,
never propagated -- the same resilience posture
`NotificationService.dispatch_notification` already established in Part 2
for a notification-delivery failure. A missed live-stream update never
means lost data -- the underlying `HealthCheck`/`ServiceHealth`/`Alert`/
`GuestSession` row the message describes is already durably committed; only
the real-time *notice* of it can be missed, and the next state-changing
event (or a fresh `GET`) still reflects reality.

## 20. WebSocket authentication: JWT via `?token=` query parameter, and its tradeoff

A browser's native `WebSocket` constructor cannot set custom request
headers (unlike `fetch`/`XMLHttpRequest`), so the conventional pattern for
browser-originated WebSocket auth is a bearer token passed as a query
parameter. `router._authenticate_websocket` validates it with the exact
same `app.domains.auth.jwt.JWTManager.validate_token` the HTTP
`Authorization: Bearer` flow already uses (composed, never reimplemented),
then checks the resolved permission via the exact same
`app.domains.rbac.authorization.AccessValidator.has_permission` every
`RequirePermission`-gated HTTP route already uses -- closing the socket
with a private-use code (4401 unauthenticated, 4403 forbidden; RFC 6455
reserves 3000-4999 for this) *before* `websocket.accept()` on any failure,
never a silent drop.

**Known, documented tradeoff.** A token in a URL can end up recorded in
server access logs, browser history, proxy logs, and `Referer` headers of
any same-origin request a page embedding the socket URL later makes -- a
real exposure surface a header-based credential does not have. The
alternative considered was a **first-message auth handshake**: accept the
connection unauthenticated, require the client's first WebSocket *message*
to carry the token before subscribing to anything. That is genuinely more
secure against the log-leakage class of exposure, at the cost of a
two-step client protocol (connect, then send auth, then wait for an ack)
instead of a single `new WebSocket(url + "?token=...")` call, and a
connection that briefly exists unauthenticated. The query-param pattern was
chosen for this iteration as the simpler, more conventional approach (it is
how most production WebSocket APIs that must support plain browser clients
actually do this) -- a documented, revisitable choice, not an oversight. A
deployment with strict log-hygiene requirements should ensure access logs
are not persisted with query strings (or configure a reverse proxy to
redact the `token` param before logging); switching to the first-message
handshake later requires no change to `MONITORING_LIVE_CHANNEL`'s message
shape or to any publisher, only to `_authenticate_websocket`'s call site.

**Connection lifecycle.** Each endpoint subscribes via
`redis_client.pubsub()` and runs two concurrent `asyncio` tasks --
`_relay_redis_to_websocket` (forwards matching `pubsub.listen()` messages
via `websocket.send_json`) and `_watch_for_websocket_disconnect` (awaits
`websocket.receive()` purely to detect a client-initiated disconnect
promptly, since a pure server-push socket would otherwise never notice the
client left until its next send attempt failed). Whichever finishes first
wins (`asyncio.wait(..., return_when=FIRST_COMPLETED)`); the other is
cancelled, and the `finally` block always unsubscribes and closes the
`PubSub` -- no leaked Redis subscription, no leaked task, on either a clean
disconnect or an error. See
`tests/unit/test_monitoring_realtime.py::test_websocket_disconnect_unsubscribes_from_redis_channel`.

## 21. The `GuestService` broadcast hook: precisely what was added, and why it is additive

`app.domains.guest.service.GuestService.__init__` gained one new,
keyword-only, `None`-by-default constructor parameter: `monitoring_hook:
GuestSessionBroadcastProtocol | None = None` (duck-typed against
`MonitoringService.broadcast_guest_session_event`, the same narrow-protocol
composition style every other `GuestService` dependency -- `otp_service`/
`voucher_service`/`captive_portal_service`/`router_lookup`/`audit_writer` --
already uses). `login_via_otp`/`login_via_voucher` each gained exactly one
new call, `await self._broadcast_guest_session_started(...)`, placed
immediately after their existing `session = await self._create_session(...)`
line (i.e. strictly after the real session row already exists) and before
`_bump_guest_visit`. `_broadcast_guest_session_started` is a new private
helper that no-ops when `monitoring_hook is None` and otherwise wraps the
hook call in a `try`/`except` that only ever logs a warning, never raises.

**Why this is additive, not a behavior change:** (1) the parameter defaults
to `None`, so every existing caller -- including every test in
`tests/unit/test_guest.py`'s `make_fixture` -- behaves exactly as before,
with zero broadcast attempts; (2) no existing parameter, return type, or
exception contract of `login_via_otp`/`login_via_voucher` changed; (3) a
hook failure can never break a real guest's login (mirrors
`NotificationService.dispatch_notification`'s identical resilience
posture). `tests/unit/test_monitoring_realtime.py` verifies all three:
the hook fires with the right arguments, a raising hook does not break
login, and a fixture built without the hook keeps working unmodified.

`app.domains.guest.dependencies.get_guest_service` gained one line wiring
`MonitoringService` in as `monitoring_hook` -- necessary for the hook to
ever fire in the real running app (without it, `GuestService` would only
ever be constructed with `monitoring_hook=None`, and the broadcast would be
dead code no request path exercises). This mirrors
`app.domains.router_agent.router.agent_heartbeat`'s Part 1 precedent in
spirit (a small, additive, documented composition seam into a *different*
domain's existing lifecycle method) with one deliberate difference: that
heartbeat hook lives at the single `router_agent` *endpoint* call site,
while this hook lives inside `GuestService`'s own method bodies, since
guest login is reachable through more than one caller and every one of
them should broadcast, not just whichever endpoint happens to call it
first.

**A note on `app.domains.monitoring.dependencies`/`app.domains.guest.dependencies`
avoiding a circular import.** `guest.dependencies` now imports
`monitoring.dependencies.get_monitoring_service` for the hook above.
Because of this, `monitoring.dependencies.get_platform_dashboard_service`
(§23) deliberately does **not** import anything from `app.domains.guest` --
doing so would create `guest.dependencies -> monitoring.dependencies ->
guest.dependencies`, a cycle. Instead, `router.py`'s
`get_platform_dashboard` endpoint (which has no such cycle) imports
`app.domains.guest.dependencies.get_guest_analytics_service` directly and
passes the resolved service into
`PlatformDashboardService.get_dashboard_statistics` as a per-call argument.

## 22. ZTP Monitoring Dashboard: `RouterLifecycleStage` is computed, never persisted

The module brief names 9 idealized lifecycle labels -- `Pending`,
`Claimed`, `Approved`, `Provisioning`, `Provisioned`, `Online`, `Offline`,
`Warning`, `Failed` -- that map onto no single existing enum.
`validators.compute_lifecycle_stage(router, enrollment, latest_job, now=)`
is a pure, side-effect-free function (mirrors `classify_storage_health`'s
identical shape) that derives one of these 9 labels by combining
`EnrollmentStatus` + `RouterStatus` + `ProvisioningJobStatus`
(+`attempts`/`max_attempts`) + `Router.last_seen_at` heartbeat staleness.
**Full mapping table** (evaluated top-to-bottom, first match wins -- see
the function's own docstring for the identical, canonical copy):

| # | Condition | Stage |
|---|---|---|
| 1 | No `Router` row, no `RouterEnrollmentRequest` either | `PENDING` |
| 2 | No `Router` row, enrollment `status=PENDING` | `PENDING` |
| 3 | No `Router` row, enrollment `status=REJECTED` | `FAILED` |
| 4 | No `Router` row, enrollment `status=APPROVED` (data anomaly: approved but the linked router is unresolvable) | `WARNING` |
| 5 | `Router.status=SUSPENDED` | `WARNING` |
| 6 | `Router.status=PENDING_PROVISIONING`, no `ProvisioningJob` yet | `APPROVED` |
| 7 | `Router.status=PENDING_PROVISIONING`, latest job `QUEUED`/`RUNNING`/`SUCCEEDED` | `CLAIMED` |
| 8 | `Router.status=PENDING_PROVISIONING`, latest job `FAILED`, `attempts < max_attempts` | `WARNING` |
| 9 | `Router.status=PENDING_PROVISIONING`, latest job `FAILED`, `attempts >= max_attempts` | `FAILED` |
| 10 | `Router.status=PROVISIONING`, no job or latest job `QUEUED`/`RUNNING` | `PROVISIONING` |
| 11 | `Router.status=PROVISIONING`, latest job `SUCCEEDED` | `PROVISIONED` |
| 12 | `Router.status=PROVISIONING`, latest job `FAILED`, `attempts < max_attempts` | `WARNING` |
| 13 | `Router.status=PROVISIONING`, latest job `FAILED`, `attempts >= max_attempts` | `FAILED` |
| 14 | `Router.status=OFFLINE` | `OFFLINE` |
| 15 | `Router.status=ONLINE`, heartbeat fresh (< `ROUTER_HEARTBEAT_WARNING_STALE_MINUTES`, 5 min) | `ONLINE` |
| 16 | `Router.status=ONLINE`, heartbeat stale (>= 5 min, < 15 min) | `WARNING` |
| 17 | `Router.status=ONLINE`, heartbeat very stale (>= `ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES`, 15 min) or `last_seen_at IS NULL` | `OFFLINE` |
| 18 | `Router.status=DECOMMISSIONED` (excluded from the active dashboard listing by `ZtpMonitoringService.get_dashboard` -- reachable here only defensively) | `WARNING` |

`CLAIMED` (row 7) is the one genuinely new sub-phase this system's actual
data can distinguish within the `PENDING_PROVISIONING` window: "an
initial-config job has been queued/picked up for this router, but the
device has not yet checked in with its provisioning token" (`Router.status`
itself only flips to `PROVISIONING` once the device presents that token).

**Why this is computed on every read, never persisted as a tenth column
anywhere.** Every one of its four inputs (`RouterEnrollmentRequest.status`,
`Router.status`, `ProvisioningJob.status`/`attempts`, `Router.last_seen_at`)
already has its own authoritative, independently-owned column in its own
domain, updated by that domain's own service methods. A persisted
`lifecycle_stage` column would be a **derived, tenth copy** of information
already fully recoverable from the other four -- and would immediately risk
drifting out of sync the moment any one of those four changes without this
label being recomputed in lockstep (e.g. a router's heartbeat going stale
between health-check runs would leave a persisted `ONLINE` stage
technically "true" by the stale copy but false by the actual `last_seen_at`
data). Recomputing it fresh on every dashboard read costs one pure Python
function call per row and is correct-by-construction, always. This mirrors
this codebase's own established discipline (`RouterHealthStatus`'s "not
storing computed staleness" precedent in `app.domains.router`,
`AccessValidator`'s "recompute effective grants fresh, cache only as an
invalidatable accelerant" design in `app.domains.rbac`).

## 23. Provisioning Success Rate: denominator choice

`ZtpMonitoringService.get_analytics` computes success rate as `succeeded
ProvisioningJobs / (succeeded + failed) ProvisioningJobs` in the requested
window -- **not** "approved enrollments that reached `ONLINE` / total
approved enrollments" (the module brief's other suggested denominator).
`ProvisioningJob`-based was chosen because it is the actual execution unit
this codebase already tracks success/failure/retry
(`attempts`/`max_attempts`) for, per job type (`initial_config`/
`config_push`/`backup`/`restore`/`factory_reset`) -- exactly what "did this
provisioning *action* succeed" means operationally. `Router.status ==
ONLINE`, by contrast, is driven by **heartbeats**
(`app.domains.router_agent`'s check-in flow), a signal orthogonal to any
specific job's outcome: a router can reach `ONLINE` via heartbeat even
after its most recent `config_push` job failed, and a router whose
`initial_config` job succeeded can still show `OFFLINE`/stale for reasons
that have nothing to do with provisioning execution (a device unplugged
after setup). Using "reached `ONLINE`" as the success signal would conflate
provisioning-execution success with device-connectivity success -- two
genuinely different failure modes this dashboard should be able to tell
apart (the Retry Dashboard for the former, the lifecycle stage's
`OFFLINE`/`WARNING` heartbeat signal for the latter). Queued/running jobs
are excluded from both numerator and denominator (still in flight, not yet
a resolved outcome).

Failure Reports (`list_provisioning_failure_counts`) are a real SQL
`GROUP BY job_type` over `FAILED` jobs in the window, paired with a small,
most-recent-first sample of individual failures (with their real
`error_message` -- not itself aggregated, since there is no meaningful
`GROUP BY` over arbitrary free-form error text). The Retry Dashboard
(`list_retry_jobs`) lists every job with `attempts > 0`, ordered nearest-
to-exhaustion first (`max_attempts - attempts` ascending).

## 24. Router Activation analytics: an honest approximation, not a literal measurement

`ZtpMonitoringService.get_analytics`'s `average_activation_seconds`
composes `RouterEnrollmentRequest.reviewed_at` (the approval timestamp)
with the completion timestamp of that router's `initial_config`
`ProvisioningJob` (`repository.compute_activation_duration_stats`, a real
SQL `AVG`/`COUNT` over an `extract('epoch', ...)` expression, mirroring
`SlaService.get_average_provisioning_duration_seconds`'s identical
`started_at`/`completed_at` composition from Part 2). This is explicitly
**not** a literal "time to first `ONLINE`" measurement: no table anywhere
in this codebase records the timestamp of a router's first transition to
`RouterStatus.ONLINE` -- `Router.last_seen_at` is overwritten on every
single heartbeat (never "first seen"), and neither `RouterHealthSnapshot`
(periodic metrics, not status transitions) nor `RouterEvent` (no
`"router_online"` event type exists) capture that moment. "Approval ->
initial-config-job-completion" is the closest genuinely-recoverable proxy
this system's actual persisted data supports, reported honestly as such
(the response schema's field descriptions say so explicitly) rather than
mislabeled as more precise than it is -- the identical "don't fabricate
precision the data doesn't support" discipline
`SlaService.generate_report` already established in Part 2 for its
check-count-ratio-vs-duration-weighted formula choice.

## 25. Availability % / Average Response Time: composed, not reimplemented

The platform dashboard's `availability_percentage` calls the exact same
`repository.compute_health_check_stats` method Part 2's
`SlaService.generate_report` already uses (a real SQL `COUNT`/`AVG`
aggregate against `health_checks`), computed live for the "at a glance"
figure rather than requiring an admin to have first configured an
`SlaTarget` and generated a persisted `SlaReport` against it -- this
dashboard figure must be available with zero configuration.
`average_response_time_ms` is the same call's `AVG(response_time_ms)`
column, not a second query.

## 26. `GET /monitoring/devices` vs `GET /ztp/dashboard`: same data, two framings

Both endpoints call the identical `ZtpMonitoringService.get_dashboard` --
deliberately, per this module's "compose, don't duplicate" discipline. The
former is that data framed for the monitoring dashboard's device tab
(alongside health/alerts); the latter is the same data framed as the
ZTP-specific provisioning-progress view. No second implementation exists.

## 27. `GET /monitoring/services` was deliberately not added

The module brief invited a "service/component health listing" endpoint and
explicitly said to check whether Part 1 already exposed one under a
different path before adding a duplicate. It did: `GET /monitoring/health`
(Part 1) already returns exactly this -- the overall aggregate status plus
every `ServiceHealth` row. Adding `GET /monitoring/services` would be a
pure duplicate route serving identical data from the identical repository
method, which the brief's own "don't duplicate, extend if so" instruction
argues against. No such route exists in this part.

## 28. RBAC permission-key reuse (Part 3)

No new `PermissionModule` was added. `WS /monitoring/ws/dashboard`,
`GET /monitoring/dashboard`, `GET /monitoring/devices`, and
`GET /ztp/dashboard` all require `monitoring.read` -- the same
observability surface Part 1 already gates this way (live status/health
views). `WS /monitoring/ws/sessions` requires `guest_sessions.read` -- a
live guest-session feed is conceptually a `GUEST_SESSIONS` concern (already
seeded with a `read` action), not a platform `MONITORING` one.
`GET /ztp/analytics` requires `analytics.read` -- statistics/success-rates/
failure-reports/retry-projections are a reporting/analytics concern,
matching `PermissionModule.ANALYTICS`'s own seeded semantic, distinct from
the live-status `monitoring.read` surface the other three endpoints use.
