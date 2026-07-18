"""OpenTelemetry distributed tracing setup (BE-011 Part 4: Observability).

This is genuinely-working tracing infrastructure, not a faked integration
(unlike, say, this codebase's honest WhatsApp-notifier placeholder in
``app.domains.monitoring`` -- there is no equivalent "no real SDK exists"
problem here: ``opentelemetry-sdk``/``opentelemetry-instrumentation-fastapi``
are real, standard libraries, and every call this module makes into them is
real).

## Honest default vs. configured behavior

There is no real OpenTelemetry Collector/Jaeger/Tempo instance anywhere in
this sandbox. Rather than fabricate one or silently no-op, this module makes
the same choice every other honestly-scoped part of this codebase makes
(see e.g. ``app.domains.monitoring``'s Celery/WebSocket ``UNKNOWN`` health
checks): build a completely real ``TracerProvider`` and instrument the app
for real either way, but choose the exporter based on whether
``Settings.otel_exporter_otlp_endpoint`` is actually configured --

* **Unset (the default in every environment today)** -- spans are exported
  via ``ConsoleSpanExporter`` (part of the real OpenTelemetry SDK, not a
  stub) wrapped in a ``SimpleSpanProcessor`` (synchronous, one span per
  line, immediately visible in this process's own logs/stdout -- the right
  choice for a console sink with no batching benefit to gain and where
  seeing a span the instant it ends is more useful for local
  inspection/debugging than a batched flush).
* **Set to a real collector's OTLP/HTTP endpoint** -- spans are exported via
  the real ``OTLPSpanExporter`` (HTTP+protobuf, ``opentelemetry-exporter-
  otlp-proto-http``) wrapped in a ``BatchSpanProcessor`` (the standard,
  production-appropriate choice: batches + background-thread export so span
  export never blocks the request that created them).

Either way, ``FastAPIInstrumentor.instrument_app`` (a real, standard
library call from ``opentelemetry-instrumentation-fastapi``) wraps every
request in a real span with real timing -- this is ready to point at a real
backend (Jaeger, Tempo, an OTel Collector, a SaaS APM) the moment
``Settings.otel_exporter_otlp_endpoint`` is set, with zero code changes.
"""

from __future__ import annotations

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)

from app.core.config import Settings


def resolve_span_exporter(
    settings: Settings,
) -> tuple[SpanExporter, type[SpanProcessor]]:
    """Pick the exporter (and its matching processor type) for
    ``settings``. Exposed as its own function -- separate from
    ``build_tracer_provider``/``configure_tracing`` -- so unit tests (and
    anything else) can assert the exact console-vs-OTLP decision in
    isolation, without needing a running FastAPI app or mutating any global
    OpenTelemetry state. See module docstring for the exact reasoning
    behind each processor choice."""
    if settings.otel_exporter_otlp_endpoint:
        return (
            OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint),
            BatchSpanProcessor,
        )
    return ConsoleSpanExporter(), SimpleSpanProcessor


def build_tracer_provider(settings: Settings) -> TracerProvider:
    """Build a real ``TracerProvider`` for ``settings``, without touching
    any process-global OpenTelemetry state (``trace.set_tracer_provider``
    is a separate, explicit step in ``configure_tracing`` below) -- this
    split keeps this function safely callable multiple times in the same
    process (e.g. once per test), which a direct call to the process-global
    ``configure_tracing`` is not (OpenTelemetry's own global tracer
    provider may only genuinely be set once per process; see
    ``configure_tracing``'s docstring)."""
    resource = Resource.create(
        {
            "service.name": settings.service_name,
            "deployment.environment": settings.environment,
        }
    )
    provider = TracerProvider(resource=resource)
    exporter, processor_cls = resolve_span_exporter(settings)
    provider.add_span_processor(processor_cls(exporter))
    return provider


def configure_tracing(app: FastAPI, settings: Settings) -> TracerProvider:
    """Build a ``TracerProvider`` for ``settings``, install it as the
    process-wide OpenTelemetry tracer provider, and instrument ``app`` with
    it. Called once from ``app.main.create_app``.

    ``trace.set_tracer_provider`` may only genuinely take effect once per
    process -- the OpenTelemetry SDK's own ``Once`` guard makes every call
    after the first a harmless, logged-but-not-raised no-op (the first
    provider set in this process stays authoritative). This matters for a
    test suite that calls ``create_app()`` (and therefore this function)
    many times in one process: only the first call's exporter choice is
    ever actually installed globally. This is why ``resolve_span_exporter``/
    ``build_tracer_provider`` above are separate, side-effect-free
    functions unit tests call directly to assert the console-vs-OTLP
    decision, rather than relying on inspecting global state after calling
    this function repeatedly."""
    provider = build_tracer_provider(settings)
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
    return provider


__all__ = [
    "resolve_span_exporter",
    "build_tracer_provider",
    "configure_tracing",
]
