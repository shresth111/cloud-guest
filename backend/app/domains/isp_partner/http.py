"""Response helpers shared by the ``/isp`` routers."""

from __future__ import annotations

from typing import Any

from fastapi import Request

from app.common.responses import build_response


def request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID", "") or str(
        getattr(getattr(request, "state", None), "request_id", "")
    )


def ok(request: Request, data: Any, message: str = "OK") -> dict:
    return build_response(
        success=True, message=message, data=data, request_id=request_id(request)
    )
