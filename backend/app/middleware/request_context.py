import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import (
    get_logger,
    organization_id_context,
    request_id_context,
    user_id_context,
)

logger = get_logger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        user_id = request.headers.get("X-User-ID")
        organization_id = request.headers.get("X-Organization-ID")
        started_at = time.perf_counter()

        request.state.request_id = request_id
        request_token = request_id_context.set(request_id)
        user_token = user_id_context.set(user_id)
        organization_token = organization_id_context.set(organization_id)

        try:
            response = await call_next(request)
        finally:
            elapsed_ms = round((time.perf_counter() - started_at) * 1000, 3)
            logger.info(
                "http_request_completed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "execution_time_ms": elapsed_ms,
                    "user_id": user_id,
                    "organization_id": organization_id,
                },
            )
            request_id_context.reset(request_token)
            user_id_context.reset(user_token)
            organization_id_context.reset(organization_token)

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Execution-Time-MS"] = str(elapsed_ms)
        return response

