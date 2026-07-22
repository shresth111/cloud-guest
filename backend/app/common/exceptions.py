from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.common.responses import build_response
from app.core.logging import get_logger

logger = get_logger(__name__)


def _jsonable_validation_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """``RequestValidationError.errors()`` embeds the raw exception instance
    in ``ctx["error"]`` whenever a Pydantic ``field_validator`` raises
    ``ValueError`` (rather than returning a plain error string) -- that raw
    exception object is not JSON-serializable, which crashes this handler
    into an unrelated 500 instead of the intended 422. Stringify anything
    inside ``ctx`` that isn't already JSON-safe."""
    sanitized: list[dict[str, Any]] = []
    for error in errors:
        clean = dict(error)
        ctx = clean.get("ctx")
        if isinstance(ctx, dict):
            clean["ctx"] = {
                key: str(value) if isinstance(value, BaseException) else value
                for key, value in ctx.items()
            }
        sanitized.append(clean)
    return sanitized


class CloudGuestError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        data: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.data = data or {}
        super().__init__(message)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(CloudGuestError)
    async def cloudguest_error_handler(
        request: Request,
        exc: CloudGuestError,
    ) -> JSONResponse:
        logger.warning(
            "application_error",
            extra={"status_code": exc.status_code, "path": request.url.path},
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=build_response(
                success=False,
                message=exc.message,
                data=exc.data,
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        message = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        return JSONResponse(
            status_code=exc.status_code,
            content=build_response(
                success=False,
                message=message,
                data={},
                request_id=_request_id(request),
            ),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=build_response(
                success=False,
                message="Request validation failed",
                data={"errors": _jsonable_validation_errors(exc.errors())},
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        logger.exception(
            "unhandled_exception",
            extra={"path": request.url.path, "exception_type": type(exc).__name__},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=build_response(
                success=False,
                message="Internal server error",
                data={},
                request_id=_request_id(request),
            ),
        )
