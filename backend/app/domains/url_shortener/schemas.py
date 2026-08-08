"""Pydantic request/response schemas for the URL Shortener API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py`` -- except
``GET /s/{code}``, which deliberately returns a raw redirect, not JSON (see
``router.py``'s own module docstring for why).

``short_url`` on :class:`ShortLinkCreateResponse` is composed from
``Settings.public_app_base_url`` (the same "one place this codebase already
names its own public base URL" this module reuses rather than duplicates --
see ``app.domains.campaigns``/``app.domains.guest_teams``'s own
share-link-composition precedent) plus this module's own
``GET /s/{code}`` route.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ShortLinkPublicCreateRequest",
    "ShortLinkCreateRequest",
    "ShortLinkUpdateRequest",
    "ShortLinkCreateResponse",
    "ShortLinkResponse",
    "ShortLinkListResponse",
    "MasterShortLinkModerateRequest",
]


# ============================================================================
# Request schemas
# ============================================================================


class ShortLinkPublicCreateRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=8192)

    model_config = ConfigDict(
        json_schema_extra={"example": {"target_url": "https://example.com/pricing"}}
    )


class ShortLinkCreateRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=8192)
    expires_at: datetime | None = Field(default=None)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "target_url": "https://example.com/promo",
                "expires_at": None,
            }
        }
    )


class ShortLinkUpdateRequest(BaseModel):
    target_url: str | None = Field(default=None, min_length=1, max_length=8192)
    is_active: bool | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)


class MasterShortLinkModerateRequest(BaseModel):
    """``PATCH /api/v1/master/short-links/{id}`` -- platform-operator
    moderation of any organization's link. Deliberately narrower than
    :class:`ShortLinkUpdateRequest` -- a Master operator moderates
    (deactivates/reactivates) a link for abuse handling; it is not this
    surface's job to edit a tenant's own ``target_url``."""

    is_active: bool = Field(
        ..., description="Set to false to deactivate this link for abuse handling."
    )


# ============================================================================
# Response schemas
# ============================================================================


class ShortLinkCreateResponse(BaseModel):
    """Returned by both create endpoints -- the minimal "here is your new
    link" payload, distinct from :class:`ShortLinkResponse`'s fuller
    admin/detail shape (no ``click_count``/``organization_id``/etc., which
    a freshly-created link has nothing interesting to say about yet)."""

    code: str
    short_url: str
    target_url: str
    created_at: datetime
    expires_at: datetime | None


class ShortLinkResponse(BaseModel):
    id: str
    code: str
    short_url: str
    target_url: str
    organization_id: str | None
    created_by_user_id: str | None
    source: str
    click_count: int
    last_clicked_at: datetime | None
    is_active: bool
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ShortLinkListResponse(BaseModel):
    items: list[ShortLinkResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
