"""Unit tests for BE-011 Part 4 (Observability): Prometheus metrics
(``app.core.metrics``) and OpenTelemetry tracing (``app.core.tracing``).

Follows this project's plain-``assert``/native-``async def``/hand-rolled-
fake style (see ``tests/unit/test_monitoring.py``) -- there is no live
Postgres/Redis in this environment, so the on-scrape business-metrics
collector is exercised against a small fake implementing
``ObservabilityRepositoryProtocol``, and the app-level ``GET /metrics``
test wires that same fake in via ``app.dependency_overrides``, the
identical pattern ``tests/unit/test_monitoring_realtime.py`` already
establishes for overriding ``get_redis_client``/``get_auth_repository``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from prometheus_client.parser import text_string_to_metric_families

from app.core.config import Settings
from app.core.metrics import (
    ALERTS_TRIGGERED_TOTAL,
    GUEST_SESSIONS_ACTIVE,
    HEALTH_CHECK_STATUS,
    PROVISIONING_JOBS_TOTAL,
    get_observability_repository,
    refresh_business_metrics,
)
from app.core.tracing import (
    build_tracer_provider,
    configure_tracing,
    resolve_span_exporter,
)
from app.domains.monitoring.models import ServiceHealth
from app.main import create_app

# ============================================================================
# Test double
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _service_health(component: str, status: str) -> ServiceHealth:
    return ServiceHealth(
        id=uuid.uuid4(),
        created_at=_now(),
        updated_at=_now(),
        deleted_at=None,
        is_deleted=False,
        created_by=None,
        updated_by=None,
        version=1,
        component=component,
        status=status,
        last_checked_at=_now(),
        consecutive_failure_count=0,
    )


@dataclass
class FakeObservabilityRepository:
    """Stand-in for ``ObservabilityRepositoryProtocol``."""

    service_health_rows: list[ServiceHealth] = field(default_factory=list)
    alert_severity_counts: list[tuple[str, int]] = field(default_factory=list)
    active_guest_session_count: int = 0
    provisioning_job_status_counts: list[tuple[str, int]] = field(default_factory=list)

    async def list_service_health(self) -> list[ServiceHealth]:
        return list(self.service_health_rows)

    async def compute_alert_counts_by_severity(self) -> list[tuple[str, int]]:
        return list(self.alert_severity_counts)

    async def count_active_guest_sessions(self) -> int:
        return self.active_guest_session_count

    async def count_provisioning_jobs_by_status(self) -> list[tuple[str, int]]:
        return list(self.provisioning_job_status_counts)


def _metric_value(
    text: str, name: str, labels: dict[str, str] | None = None
) -> float | None:
    """Look up one sample's value by its exact exposed metric name (e.g.
    ``cloudguest_http_requests_total``). Matches on ``sample.name``, not
    ``family.name`` -- for a real ``Counter``, the OpenMetrics *family* name
    has the ``_total`` suffix stripped (``cloudguest_http_requests``) even
    though every individual *sample* keeps it
    (``cloudguest_http_requests_total``), so matching on the family name
    would silently miss every Counter-backed metric."""
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            if sample.name != name:
                continue
            if labels is None or all(
                sample.labels.get(key) == value for key, value in labels.items()
            ):
                return sample.value
    return None


def _sample_names(text: str) -> set[str]:
    return {
        sample.name
        for family in text_string_to_metric_families(text)
        for sample in family.samples
    }


# ============================================================================
# refresh_business_metrics -- on-scrape collector reflects fake DB state
# ============================================================================


async def test_refresh_business_metrics_sets_health_check_status_gauge() -> None:
    repo = FakeObservabilityRepository(
        service_health_rows=[
            _service_health("database", "healthy"),
            _service_health("redis", "unhealthy"),
            _service_health("celery", "unknown"),
        ]
    )

    await refresh_business_metrics(repo)

    assert HEALTH_CHECK_STATUS.labels(component="database")._value.get() == 1.0
    assert HEALTH_CHECK_STATUS.labels(component="redis")._value.get() == -1.0
    assert HEALTH_CHECK_STATUS.labels(component="celery")._value.get() == -2.0


async def test_refresh_business_metrics_sets_alerts_triggered_gauge() -> None:
    repo = FakeObservabilityRepository(
        alert_severity_counts=[("critical", 3), ("warning", 1)],
    )

    await refresh_business_metrics(repo)

    assert ALERTS_TRIGGERED_TOTAL.labels(severity="critical")._value.get() == 3
    assert ALERTS_TRIGGERED_TOTAL.labels(severity="warning")._value.get() == 1
    assert ALERTS_TRIGGERED_TOTAL.labels(severity="info")._value.get() == 0


async def test_refresh_business_metrics_sets_active_guest_sessions_gauge() -> None:
    repo = FakeObservabilityRepository(active_guest_session_count=7)

    await refresh_business_metrics(repo)

    assert GUEST_SESSIONS_ACTIVE._value.get() == 7

    # A later scrape reflecting a changed DB state overwrites the prior
    # value -- this is the entire point of an on-scrape collector.
    repo.active_guest_session_count = 2
    await refresh_business_metrics(repo)
    assert GUEST_SESSIONS_ACTIVE._value.get() == 2


async def test_refresh_business_metrics_sets_provisioning_jobs_gauge() -> None:
    repo = FakeObservabilityRepository(
        provisioning_job_status_counts=[("queued", 2), ("succeeded", 10)],
    )

    await refresh_business_metrics(repo)

    assert PROVISIONING_JOBS_TOTAL.labels(status="queued")._value.get() == 2
    assert PROVISIONING_JOBS_TOTAL.labels(status="succeeded")._value.get() == 10
    assert PROVISIONING_JOBS_TOTAL.labels(status="running")._value.get() == 0
    assert PROVISIONING_JOBS_TOTAL.labels(status="failed")._value.get() == 0


# ============================================================================
# GET /metrics -- real Prometheus exposition format, via TestClient
# ============================================================================


def _client_with_fake_repository(
    repo: FakeObservabilityRepository,
) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_observability_repository] = lambda: repo
    return TestClient(app)


def test_metrics_endpoint_returns_valid_prometheus_exposition_format() -> None:
    repo = FakeObservabilityRepository(
        service_health_rows=[_service_health("database", "healthy")],
        alert_severity_counts=[("critical", 1)],
        active_guest_session_count=4,
        provisioning_job_status_counts=[("succeeded", 5)],
    )
    client = _client_with_fake_repository(repo)

    # The HTTP-level counter/histogram are updated by PrometheusMiddleware
    # only *after* a request finishes (see PrometheusMiddleware's
    # docstring) -- a request's own exposition body is generated before its
    # own completion is recorded, so it can never reflect itself. A warm-up
    # call first means the assertion below observes a prior, already-
    # recorded request instead of racing its own in-flight one.
    client.get("/metrics")
    response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")

    text = response.text
    names = _sample_names(text)
    assert "cloudguest_http_requests_total" in names
    assert "cloudguest_http_request_duration_seconds_bucket" in names
    assert "cloudguest_health_check_status" in names
    assert "cloudguest_alerts_triggered_total" in names
    assert "cloudguest_guest_sessions_active" in names
    assert "cloudguest_provisioning_jobs_total" in names

    assert (
        _metric_value(text, "cloudguest_health_check_status", {"component": "database"})
        == 1.0
    )
    assert (
        _metric_value(
            text, "cloudguest_alerts_triggered_total", {"severity": "critical"}
        )
        == 1.0
    )
    assert _metric_value(text, "cloudguest_guest_sessions_active") == 4.0
    assert (
        _metric_value(
            text, "cloudguest_provisioning_jobs_total", {"status": "succeeded"}
        )
        == 5.0
    )


def test_metrics_endpoint_reflects_updated_fake_db_state_on_next_scrape() -> None:
    repo = FakeObservabilityRepository(active_guest_session_count=1)
    client = _client_with_fake_repository(repo)

    first = client.get("/metrics")
    assert _metric_value(first.text, "cloudguest_guest_sessions_active") == 1.0

    repo.active_guest_session_count = 9
    second = client.get("/metrics")
    assert _metric_value(second.text, "cloudguest_guest_sessions_active") == 9.0


def test_metrics_endpoint_records_its_own_http_request_metric() -> None:
    repo = FakeObservabilityRepository()
    client = _client_with_fake_repository(repo)

    client.get("/metrics")
    response = client.get("/metrics")

    value = _metric_value(
        response.text,
        "cloudguest_http_requests_total",
        {"method": "GET", "path": "/metrics", "status_code": "200"},
    )
    assert value is not None
    assert value >= 2.0


# ============================================================================
# App boot / route wiring
# ============================================================================


def test_app_boots_with_metrics_route_registered_and_no_route_conflicts() -> None:
    app = create_app()

    metrics_routes = [
        route for route in app.routes if getattr(route, "path", None) == "/metrics"
    ]
    assert len(metrics_routes) == 1

    seen: set[tuple[str, frozenset[str]]] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or methods is None:
            continue
        key = (path, frozenset(methods))
        assert key not in seen, f"duplicate route registered: {key}"
        seen.add(key)


def test_metrics_route_not_under_api_v1_prefix() -> None:
    app = create_app()
    settings = app.state.settings
    metrics_routes = [
        route for route in app.routes if getattr(route, "path", None) == "/metrics"
    ]
    assert len(metrics_routes) == 1
    assert not metrics_routes[0].path.startswith(settings.api_v1_prefix)


# ============================================================================
# OpenTelemetry tracing -- console default vs. OTLP-configured
# ============================================================================


def test_resolve_span_exporter_defaults_to_console_when_unconfigured() -> None:
    exporter, processor_cls = resolve_span_exporter(Settings())

    assert isinstance(exporter, ConsoleSpanExporter)
    assert processor_cls is SimpleSpanProcessor


def test_resolve_span_exporter_uses_otlp_when_endpoint_configured() -> None:
    settings = Settings(
        otel_exporter_otlp_endpoint="http://otel-collector:4318/v1/traces"
    )

    exporter, processor_cls = resolve_span_exporter(settings)

    assert isinstance(exporter, OTLPSpanExporter)
    assert processor_cls is BatchSpanProcessor


def test_build_tracer_provider_initializes_without_error_in_console_mode() -> None:
    provider = build_tracer_provider(Settings())

    assert isinstance(provider, TracerProvider)
    resource_attributes = dict(provider.resource.attributes)
    assert resource_attributes["service.name"] == Settings().service_name


def test_build_tracer_provider_initializes_without_error_in_otlp_mode() -> None:
    settings = Settings(
        otel_exporter_otlp_endpoint="http://otel-collector:4318/v1/traces"
    )

    provider = build_tracer_provider(settings)

    assert isinstance(provider, TracerProvider)


def test_configure_tracing_instruments_a_fresh_app_without_error() -> None:
    app = FastAPI()
    settings = Settings()

    provider = configure_tracing(app, settings)

    assert isinstance(provider, TracerProvider)


def test_app_create_app_configures_tracing_without_error() -> None:
    # app.main.create_app() itself calls configure_tracing -- this just
    # confirms boot succeeds end-to-end with tracing wired in (already
    # exercised implicitly by every other TestClient(create_app()) test in
    # this suite, asserted explicitly here for this observability module).
    app = create_app()
    assert app is not None
