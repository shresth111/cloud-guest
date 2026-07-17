from typing import Generic, TypeVar

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field

T = TypeVar("T")


class MetaResponse(PydanticBaseModel):
    model_config = ConfigDict(from_attributes=True)

    page: int | None = Field(default=None, ge=1)
    page_size: int | None = Field(default=None, ge=1)
    total_items: int | None = Field(default=None, ge=0)
    total_pages: int | None = Field(default=None, ge=0)
    has_next: bool | None = None
    has_previous: bool | None = None


class BaseResponse(PydanticBaseModel, Generic[T]):
    success: bool
    message: str
    data: T | None = None
    request_id: str
    meta: MetaResponse | None = None


class SuccessResponse(BaseResponse[T], Generic[T]):
    success: bool = True


class ErrorResponse(BaseResponse[dict[str, object]]):
    success: bool = False
    data: dict[str, object] = Field(default_factory=dict)


class PaginationResponse(BaseResponse[list[T]], Generic[T]):
    success: bool = True
    data: list[T]
    meta: MetaResponse

