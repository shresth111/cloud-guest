from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_v1_router
from app.common.exceptions import register_exception_handlers
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in app_settings.allowed_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    register_exception_handlers(app)
    app.include_router(api_v1_router, prefix=app_settings.api_v1_prefix)

    return app


app = create_app()

