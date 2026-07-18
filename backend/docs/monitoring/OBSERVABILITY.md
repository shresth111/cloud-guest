# BE-011 Part 4: Observability

This is the final part of BE-011 (Enterprise Monitoring, Alerting & Health
Management). Parts 1-3 (`app.domains.monitoring`) built the platform's own
Health/Event/Alert/Notification/Incident/SLA engines, real-time WebSocket
dashboard, ZTP monitoring dashboard, and analytics. Part 4 is different in
kind from those: it is cross-cutting **infrastructure/tooling** --
Prometheus metrics, OpenTelemetry tracing, and the Grafana/Loki config
artifacts that consume them -- not a new business domain. It adds no new
database tables and edits no file inside `app.domains.monitoring`,
`app.domains.guest`, or `app.domains.router_provisioning`.

See `docs/monitoring/README.md`/`FLOW.md`/`DATABASE.md` (Part 1),
`ALERTS.md`-equivalent sections of `docs/API.md` (Part 2), and the
real-time/ZTP sections of `docs/API.md` (Part 3) for everything this part
builds on top of.

## 1. Prometheus Metrics (`app.core.metrics`)

`prometheus-client` (the core, minimal, widely-used Python client library)
is a new dependency. `GET /metrics` (registered directly on the app in
`app.main.create_app`, not under `Settings.api_v1_prefix`) returns the
standard Prometheus exposition text format via `prometheus_client
.generate_latest`.

### Two architectures, chosen per metric

**HTTP-level metrics are inline**, via `PrometheusMiddleware` -- a ~30-line
pure-ASGI middleware (stdlib `time.perf_counter`, no third-party
instrumentator package). There is no other honest way to measure
per-request latency/outcome: nothing in the database records "a request
happened", so this is the one metric family where an inline hook is
genuinely necessary, not just convenient.

* `cloudguest_http_requests_total` (`Counter`, labels `method`/`path`/
  `status_code`) -- incremented once per completed request.
* `cloudguest_http_request_duration_seconds` (`Histogram`, labels `method`/
  `path`) -- observed once per completed request.

`path` is the matched route's *template* (e.g.
`/api/v1/guest/sessions/{session_id}`), read from `scope["route"].path`
after the inner app call completes, not the raw request path -- this keeps
label cardinality bounded to the fixed set of registered routes instead of
growing one label value per distinct UUID ever requested.

**Business metrics are on-scrape collectors**, computed fresh from current
database state every time `GET /metrics` is hit, via
`refresh_business_metrics` -- never incremented inline from within
`app.domains.monitoring`/`app.domains.guest`/`app.domains.router_provisioning`'s
own business logic. This is the strongly-preferred architecture for
DB-backed metrics specifically because this part's directory rule permits
**zero edits** to any of those three domains' files: an on-scrape
`COUNT(*)`/`GROUP BY` query is exactly as accurate as an inline increment
(with no risk of drifting from the database if a scrape is ever missed or
the process restarts), and it reuses the exact same "read another domain's
table directly, read-only, compose instead of duplicate" precedent
`app.domains.monitoring.repository` already established for `Router`/
`ProvisioningJob`/`RadiusNasClient`/`WireGuardPeer` (see that module's own
docstring). **No inline-increment hook was needed anywhere** -- the one
permitted exception in this part's directory rule was considered for
`cloudguest_alerts_triggered_total` specifically (incrementing a `Counter`
from inside `AlertService`'s alert-creation method) and rejected as
unnecessary for exactly this reason.

* `cloudguest_health_check_status` (`Gauge`, label `component`) -- one
  value per row in `app.domains.monitoring`'s `ServiceHealth` rollup table.
  `1`=healthy, `0`=degraded, `-1`=unhealthy, `-2`=unknown (a distinct
  sentinel, not folded into `-1` -- `unknown` is an honestly-not-fabricated
  result, e.g. `celery`/`websocket` before any real infrastructure exists;
  see `app.domains.monitoring.constants.HealthStatus`'s own docstring).
* `cloudguest_alerts_triggered_total` (`Gauge`, label `severity`) -- an
  all-time `COUNT(*) ... GROUP BY severity` over `app.domains.monitoring`'s
  `Alert` table.
* `cloudguest_guest_sessions_active` (`Gauge`, no labels) -- a live
  `COUNT(*) WHERE status = 'active'` over `app.domains.guest`'s
  `GuestSession` table.
* `cloudguest_provisioning_jobs_total` (`Gauge`, label `status`) -- a live
  `COUNT(*) ... GROUP BY status` over `app.domains.router_provisioning`'s
  `ProvisioningJob` table.

**Why the last two are `Gauge`s, not `Counter`s, despite the `_total`
suffix on their names** (kept because the module brief named them, and the
Grafana dashboard below references them): `prometheus_client.Counter` only
exposes `.inc()`, with no public API to set an arbitrary absolute value on
every scrape. `cloudguest_provisioning_jobs_total` is unambiguously a
`Gauge` regardless of name -- a job moving `queued -> running` makes the
`queued` count go *down*. `cloudguest_alerts_triggered_total` is
effectively monotonic in practice (rows are soft-deleted, never hard-
deleted), but re-`set()`-ing a `Gauge` to a fresh `COUNT(*)` result on every
scrape is observably identical to a `Counter` for every real consumer
(`rate()`/`increase()` behave the same way over either; the dashboard's own
panels use plain `sum by (...)`, agnostic to the distinction). See
`app/core/metrics.py`'s module docstring for the full write-up.

### Why the on-scrape collector is testable without a live database

`refresh_business_metrics` takes an `ObservabilityRepositoryProtocol`, not
a raw `AsyncSession` -- the same narrow, duck-typed `Protocol` composition
pattern every domain in this codebase already uses for its own repository.
`ObservabilityMetricsRepository` is the real, SQLAlchemy-backed
implementation (composing with `app.domains.monitoring.repository
.MonitoringRepository` for the two monitoring-owned queries, and issuing
its own direct, read-only `SELECT`s against `GuestSession`/`ProvisioningJob`
for the other two). `tests/unit/test_observability.py` exercises
`refresh_business_metrics` against a small hand-rolled fake instead
(`FakeObservabilityRepository`), the identical style
`tests/unit/test_monitoring.py` already establishes -- there is no live
Postgres/Redis in this environment. The `GET /metrics` route itself is
tested the same way `tests/unit/test_monitoring_realtime.py` tests
WebSocket routes: `app.dependency_overrides[get_observability_repository]`
swapped for the fake, exercised through a real `fastapi.testclient
.TestClient` call, asserting the response is valid Prometheus exposition
text (parsed with `prometheus_client.parser.text_string_to_metric_families`,
never a raw substring guess).

### Why `GET /metrics` has no RBAC gate

Prometheus scrapers are not platform users -- they never carry a JWT.
Gating this route behind `app.domains.rbac` would mean either provisioning
a service-account JWT for every scrape config in existence (something no
real Prometheus deployment anywhere does) or silently exempting the route
from auth in a way that isn't visible from `app/main.py`. Leaving it
unauthenticated at the application layer is standard practice for
Prometheus exporters. **A production deployment MUST restrict `/metrics` at
the network/ingress layer instead** -- a scrape-only security group, a
Kubernetes `NetworkPolicy` limiting ingress to the Prometheus pod/service
account, or a reverse-proxy allowlist on that one path. This is a
deployment-topology concern, not something any application-layer check in
this codebase can substitute for.

### Wiring Grafana to this app

1. Add a Prometheus data source in Grafana pointed at a Prometheus server
   that scrapes this app's `GET /metrics` (e.g. a `scrape_configs` entry
   with `static_configs: [{ targets: ["<host>:<port>"] }]`, `metrics_path:
   /metrics`).
2. Import `docs/monitoring/grafana-dashboard.json` (**Dashboards -> Import
   -> Upload JSON file**), selecting that Prometheus data source for the
   `DS_PROMETHEUS` variable prompt.
3. Every panel's `expr` references only the six real metric names defined
   in `app/core/metrics.py` above -- HTTP request rate (by status code),
   HTTP request latency (p50/p95/p99, via `histogram_quantile`), health
   check status per component, active guest sessions, provisioning job
   status breakdown, and alerts triggered by severity.

## 2. OpenTelemetry Tracing (`app.core.tracing`)

`opentelemetry-sdk`, `opentelemetry-instrumentation-fastapi`, and
`opentelemetry-exporter-otlp-proto-http` are new dependencies. This is
genuinely-working tracing infrastructure -- a real `TracerProvider`, a real
`Resource` identifying the service, and `FastAPIInstrumentor.instrument_app`
(a real, standard call from `opentelemetry-instrumentation-fastapi`)
wrapping every request in a real span with real timing. Unlike this
codebase's honest WhatsApp-notifier placeholder
(`app.domains.monitoring`), there is no "no real SDK exists" problem here
to work around.

### Honest default vs. configured behavior

There is no real OpenTelemetry Collector/Jaeger/Tempo instance anywhere in
this sandbox. `Settings.otel_exporter_otlp_endpoint` (new, defaults to
`None`) decides which real exporter is used -- never a fabricated one:

* **Unset (every environment today)** -- spans export via the real
  `ConsoleSpanExporter` (part of the OpenTelemetry SDK itself, not a stub),
  wrapped in a `SimpleSpanProcessor` (synchronous, no background thread --
  the right choice for a console sink with no batching benefit to gain,
  and where seeing a span the instant it ends is more useful for local
  inspection than a batched flush).
* **Set to a real collector's OTLP/HTTP endpoint** (e.g.
  `CLOUDGUEST_OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318/v1/traces`)
  -- spans export via the real `OTLPSpanExporter`, wrapped in a
  `BatchSpanProcessor` (the standard production choice: batches + a
  background thread so span export never blocks the request that created
  them).

`app.core.tracing.resolve_span_exporter(settings)` makes this decision in
one place, exposed as its own pure function (separate from
`build_tracer_provider`/`configure_tracing`) specifically so it -- and
`build_tracer_provider` -- can be unit-tested in isolation without touching
any process-global OpenTelemetry state or needing a running app. See both
functions' docstrings in `app/core/tracing.py` for why: OpenTelemetry's own
global tracer provider may only genuinely be set once per process (later
`trace.set_tracer_provider` calls are harmless, logged no-ops), which
matters for a test suite that calls `create_app()` (and therefore
`configure_tracing`) hundreds of times in one process.

This is ready to point at a real observability backend (Jaeger, Tempo, an
OTel Collector, a SaaS APM) the moment `Settings
.otel_exporter_otlp_endpoint` is set, with zero code changes.

## 3. Loki / Structured Logging

`app.core.logging.JsonLogFormatter` already emits structured JSON logs on
every log record (`timestamp`, `level`, `logger`, `message`, `request_id`,
`user_id`, `organization_id`, plus every extra field a given call site
passes via `extra={...}`) to both a console handler and a rotating file
handler (`Settings.log_path`). **This needed no new Python code for this
part** -- it was already "Loki-ready" in substance; the only genuinely new
artifact is `docs/monitoring/promtail-config-example.yaml`, a real, minimal
Promtail scrape config showing how to ship that existing log output to a
Loki instance:

* A `json` pipeline stage extracts exactly the fields
  `JsonLogFormatter.format` actually emits (`timestamp`/`level`/`logger`/
  `message`/`request_id`/`user_id`/`organization_id`) -- verified against
  `app/core/logging.py` directly, not guessed.
* A `timestamp` stage uses the log record's own `timestamp` field (already
  UTC ISO-8601) as Loki's ingestion timestamp.
* A `labels` stage promotes only `level`/`logger` to real (indexed) Loki
  labels -- `request_id` is deliberately **not** a label (unique per
  request; an unbounded-cardinality label would blow up Loki's index), it
  stays queryable via `| json | request_id="..."` line filtering instead.
* No `output` stage is used, so the full original JSON line -- including
  every extra field beyond the ones extracted above -- ships to Loki
  unmodified and stays queryable via `| json` at query time.

To wire this up: run Promtail alongside the app
(`promtail -config.file=docs/monitoring/promtail-config-example.yaml`)
pointed at a real Loki instance via the example's `clients[0].url`, and
adjust its `__path__` glob to match wherever `Settings.log_dir`/
`Settings.log_file` actually write in a given deployment.

## 4. Verification Performed

* `prometheus-client==0.25.0`, `opentelemetry-sdk==1.44.0`,
  `opentelemetry-instrumentation-fastapi==0.65b0`,
  `opentelemetry-exporter-otlp-proto-http==1.44.0` (plus their transitive
  dependencies) installed cleanly into this backend's Python 3.13 venv with
  no version-compatibility issues, and every import used by
  `app/core/metrics.py`/`app/core/tracing.py` was confirmed to import
  successfully.
* `ruff check`/`ruff format --check` pass on every file created or
  modified for this part.
* The full test suite (633 pre-existing tests + 15 new tests in
  `tests/unit/test_observability.py` = 648) passes.
* `app.main.create_app()` boots with `GET /metrics` registered exactly
  once, not under `Settings.api_v1_prefix`, with no duplicate
  `(path, methods)` route registered anywhere in the app (asserted
  directly in `tests/unit/test_observability.py`).
* `GET /metrics`, called via `fastapi.testclient.TestClient`, returns
  real, parseable Prometheus exposition text (parsed with
  `prometheus_client.parser.text_string_to_metric_families`) containing
  every metric name documented above.

## 5. What This Part Does NOT Do

* It does not add any inline metric-increment hook to
  `app.domains.monitoring`/`app.domains.guest`/
  `app.domains.router_provisioning` -- every business metric is an
  on-scrape collector, per the architecture decision above. **No file
  inside those three domains is edited by this part.**
* It does not gate `GET /metrics` behind RBAC -- see the dedicated section
  above for why, and the explicit production-deployment note about
  restricting it at the network layer instead.
* It does not fabricate a live OTel collector connection where none
  exists -- the console-exporter default is real, working tracing
  infrastructure, not a stub.
* It does not add any new Grafana/Loki/Prometheus *server* to this
  sandbox -- `docs/monitoring/grafana-dashboard.json` and
  `docs/monitoring/promtail-config-example.yaml` are config artifacts for
  operators to import/run against their own real Grafana/Loki/Prometheus
  instances.
