"""Pydantic request/response schemas for the Demo Request API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict(from_attributes=True)``, explicit ``Field`` descriptions,
``field_validator``-checked status values -- see
``app.domains.support_tickets.schemas``) and is wrapped in the project's
standard ``ApiResponse``/``build_response`` envelope by ``router.py``.

``DemoRequestCreateRequest`` (the public form submission) carries no
``status``/``internal_notes`` fields at all -- those are Master-console-only
and set exclusively by ``DemoRequestUpdateRequest``, mirroring
``TicketCreateRequest``'s own "the submitter's request body can never set
admin-only fields" posture.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .constants import DemoRequestStatus

__all__ = [
    "DemoRequestCreateRequest",
    "DemoRequestUpdateRequest",
    "DemoRequestResponse",
    "DemoRequestListResponse",
]

_ALLOWED_STATUSES = {s.value for s in DemoRequestStatus}


# ============================================================================
# Request schemas
# ============================================================================


class DemoRequestCreateRequest(BaseModel):
    """The public "Book a Demo" form submission -- no auth, no platform
    identity. ``email`` is validated as a real address by ``EmailStr``
    (requires the ``email-validator`` package, already a dependency via
    ``app.domains.auth.schemas``'s own identical use)."""

    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr = Field(..., description="Work email address")
    phone: str | None = Field(default=None, max_length=30)
    company_name: str = Field(..., min_length=1, max_length=255)
    message: str | None = Field(
        default=None,
        max_length=5_000,
        description="What the prospect is looking for -- optional free text.",
    )


class DemoRequestUpdateRequest(BaseModel):
    """Master-console-only fields -- status/internal notes. Both optional
    so a caller can update just one at a time, mirroring
    ``TicketUpdateRequest``'s identical partial-update shape."""

    status: str | None = Field(default=None)
    internal_notes: str | None = Field(default=None, max_length=5_000)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str | None) -> str | None:
        if value is not None and value not in _ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {sorted(_ALLOWED_STATUSES)}")
        return value


# ============================================================================
# Response schemas
# ============================================================================


class DemoRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    full_name: str
    email: str
    phone: str | None
    company_name: str
    message: str | None
    status: str
    internal_notes: str | None
    submitted_at: datetime
    updated_at: datetime


class DemoRequestListResponse(BaseModel):
    items: list[DemoRequestResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
