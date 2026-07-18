from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    success: bool
    message: str
    data: T | None
    request_id: str


def build_response(
    *,
    success: bool,
    message: str,
    data: Any,
    request_id: str,
) -> dict[str, Any]:
    return {
        "success": success,
        "message": message,
        "data": data,
        "request_id": request_id,
    }

