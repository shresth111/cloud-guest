import asyncio
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1.health.schemas import DependencyStatus, LivenessData, ReadinessData
from app.common.responses import ApiResponse, build_response
from app.database.redis import redis_client
from app.database.session import SessionLocal

router = APIRouter()


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/live",
    response_model=ApiResponse[LivenessData],
    status_code=status.HTTP_200_OK,
)
async def live(request: Request) -> dict[str, object]:
    settings = request.app.state.settings
    started_at = request.app.state.started_at
    uptime_seconds = (datetime.now(UTC) - started_at).total_seconds()
    return build_response(
        success=True,
        message="Service is live",
        data=LivenessData(
            service=settings.service_name,
            environment=settings.environment,
            uptime_seconds=round(uptime_seconds, 3),
        ).model_dump(),
        request_id=_request_id(request),
    )


async def _database_status() -> DependencyStatus:
    started_at = time.perf_counter()
    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return DependencyStatus(
            status="ok",
            latency_ms=round((time.perf_counter() - started_at) * 1000, 3),
        )
    except Exception as exc:
        return DependencyStatus(
            status="unavailable",
            latency_ms=round((time.perf_counter() - started_at) * 1000, 3),
            error=type(exc).__name__,
        )


async def _redis_status(timeout_seconds: float) -> DependencyStatus:
    started_at = time.perf_counter()
    try:
        await asyncio.wait_for(redis_client.ping(), timeout=timeout_seconds)
        return DependencyStatus(
            status="ok",
            latency_ms=round((time.perf_counter() - started_at) * 1000, 3),
        )
    except Exception as exc:
        return DependencyStatus(
            status="unavailable",
            latency_ms=round((time.perf_counter() - started_at) * 1000, 3),
            error=type(exc).__name__,
        )


@router.get(
    "/ready",
    response_model=ApiResponse[ReadinessData],
)
async def ready(request: Request) -> JSONResponse:
    settings = request.app.state.settings
    database, redis = await asyncio.gather(
        _database_status(),
        _redis_status(settings.redis_health_timeout_seconds),
    )
    is_ready = database.status == "ok" and redis.status == "ok"
    response_status = (
        status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    return JSONResponse(
        status_code=response_status,
        content=build_response(
            success=is_ready,
            message="Service is ready" if is_ready else "Service dependencies unavailable",
            data=ReadinessData(
                service=settings.service_name,
                database=database,
                redis=redis,
            ).model_dump(),
            request_id=_request_id(request),
        ),
    )

