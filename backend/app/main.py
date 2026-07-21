from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_v1_router
from app.common.exceptions import register_exception_handlers
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
from app.core.metrics import PrometheusMiddleware
from app.core.metrics import router as metrics_router
from app.core.tracing import configure_tracing
from app.database.redis import redis_client
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_context import RequestContextMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or get_settings()
    configure_logging(app_settings)
    logger = get_logger(__name__)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.started_at = datetime.now(UTC)
        logger.info(
            "application_started",
            extra={"service": app_settings.service_name},
        )
        yield
        logger.info(
            "application_stopped",
            extra={"service": app_settings.service_name},
        )

    app = FastAPI(
        title="CloudGuest Backend",
        description=(
            "CloudGuest modular monolith API for managed MikroTik networking."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = app_settings
    app.state.started_at = datetime.now(UTC)

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    # Global, Redis-backed rate limit on auth/public/guest-facing routes
    # only -- see app.middleware.rate_limit's own module docstring for
    # exactly which paths and why.
    app.add_middleware(
        RateLimitMiddleware,
        redis=redis_client,
        max_requests=app_settings.rate_limit_max_requests,
        window_seconds=app_settings.rate_limit_window_seconds,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in app_settings.allowed_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )
    # Prometheus HTTP-level metrics (app.core.metrics) -- must wrap every
    # request, so it is added like every other cross-cutting middleware
    # above, not scoped to api_v1_router.
    app.add_middleware(PrometheusMiddleware)

    register_exception_handlers(app)
    app.include_router(api_v1_router, prefix=app_settings.api_v1_prefix)
    # GET /metrics -- the standard Prometheus scrape path, deliberately not
    # under app_settings.api_v1_prefix and not behind RBAC. See
    # app.core.metrics's module docstring and
    # docs/monitoring/OBSERVABILITY.md for why.
    app.include_router(metrics_router)

    # OpenTelemetry tracing (app.core.tracing) -- real SDK + FastAPI
    # instrumentation either way; exports to the console by default, or to
    # a real OTLP collector once app_settings.otel_exporter_otlp_endpoint
    # is configured. See app.core.tracing's module docstring.
    configure_tracing(app, app_settings)

    return app


app = create_app()
