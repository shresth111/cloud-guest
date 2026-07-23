"""Pydantic request/response schemas for the Support Tickets API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict(from_attributes=True)``, explicit ``Field`` descriptions --
see ``app.domains.billing.schemas.TaxRateResponse``) and is wrapped in the
project's standard ``ApiResponse``/``build_response`` envelope by
``router.py``.

``priority``/``status`` are plain ``str`` fields (not the ``constants``
``StrEnum`` types directly), each ``field_validator``-checked against the
allowed value set -- mirrors this codebase's existing
``field_validator``-based validation style (see e.g.
``app.domains.location.schemas``'s ``validate_slug``/``validate_country``)
rather than relying on pydantic's own enum-coercion error messages.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .constants import TicketPriority, TicketStatus

__all__ = [
    "TicketCreateRequest",
    "TicketUpdateRequest",
    "TicketResponse",
    "TicketListResponse",
]

_ALLOWED_PRIORITIES = {p.value for p in TicketPriority}
_ALLOWED_STATUSES = {s.value for s in TicketStatus}


# ============================================================================
# Request schemas
# ============================================================================


class TicketCreateRequest(BaseModel):
    location_id: str | None = Field(
        default=None,
        description="Scopes the ticket to one location. Omit for an org-wide ticket.",
    )
    subject: str = Field(..., min_length=2, max_length=255)
    description: str = Field(..., min_length=5)
    category: str | None = Field(
        default=None,
        max_length=50,
        description=(
            "Free-form, application-level only -- suggested values: "
            "billing/technical/network/account/other."
        ),
    )
    priority: str = Field(default=TicketPriority.MEDIUM.value)

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, value: str) -> str:
        if value not in _ALLOWED_PRIORITIES:
            raise ValueError(f"priority must be one of {sorted(_ALLOWED_PRIORITIES)}")
        return value


class TicketUpdateRequest(BaseModel):
    """Admin-only fields -- status/priority/assignment/resolution. All
    optional so a caller can update just one field at a time (e.g. only
    reassigning, without touching status)."""

    status: str | None = Field(default=None)
    priority: str | None = Field(default=None)
    assigned_to_user_id: str | None = Field(default=None)
    resolution_notes: str | None = Field(default=None)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str | None) -> str | None:
        if value is not None and value not in _ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {sorted(_ALLOWED_STATUSES)}")
        return value

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, value: str | None) -> str | None:
        if value is not None and value not in _ALLOWED_PRIORITIES:
            raise ValueError(f"priority must be one of {sorted(_ALLOWED_PRIORITIES)}")
        return value


# ============================================================================
# Response schemas
# ============================================================================


class TicketResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    created_by_user_id: uuid.UUID
    created_by_name: str
    created_by_email: str
    assigned_to_user_id: uuid.UUID | None
    assigned_to_name: str | None
    subject: str
    description: str
    category: str | None
    priority: str
    status: str
    resolution_notes: str | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime


class TicketListResponse(BaseModel):
    items: list[TicketResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
