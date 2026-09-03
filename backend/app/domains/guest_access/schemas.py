"""Pydantic request/response schemas for the Guest Access Control API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict``, ``from_attributes``, explicit ``Field`` descriptions) and
is wrapped in the project's standard ``ApiResponse``/``build_response``
envelope by ``router.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .constants import AccessRuleType

__all__ = [
    "GuestAccessRuleCreate",
    "DeviceAccessRuleCreate",
    "AccessCheckRequest",
    "GuestAccessRuleResponse",
    "DeviceAccessRuleResponse",
    "GuestAccessRuleListResponse",
    "DeviceAccessRuleListResponse",
    "AccessCheckResponse",
]


def _assume_utc_if_naive(v: datetime | None) -> datetime | None:
    """HTML's ``<input type="datetime-local">`` -- what the customer
    dashboard's Whitelist "End Date" field (``WhiteList.tsx``) submits --
    produces a value with no UTC offset, e.g. ``"2026-08-01T06:49"``.
    Pydantic parses that into a *naive* ``datetime``. ``validate_rule_expiry``/
    ``is_rule_expired`` then compare it against ``datetime.now(UTC)`` (aware),
    which raises ``TypeError: can't compare offset-naive and offset-aware
    datetimes`` -- an unhandled 500 that (since it escapes CORSMiddleware)
    the browser reports as a CORS failure, masking the real error. Treat a
    naive value as already-UTC, the same interpretation every other stored
    ``expires_at`` in this table uses, rather than crashing the request."""
    if v is not None and v.tzinfo is None:
        return v.replace(tzinfo=UTC)
    return v


# ============================================================================
# Request schemas
# ============================================================================


class GuestAccessRuleCreate(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = Field(
        default=None,
        description="Scopes the rule to one location. Omit for org-wide.",
    )
    identifier: str = Field(..., min_length=1, max_length=255)
    rule_type: AccessRuleType
    reason: str | None = Field(default=None, max_length=2000)
    email: EmailStr | None = Field(
        default=None,
        description="Optional contact email for whoever this rule was created for.",
    )
    expires_at: datetime | None = Field(
        default=None,
        description=(
            "Required for rule_type=temporary. Optional (but permitted) for "
            "every other rule type."
        ),
    )

    _normalize_expires_at = field_validator("expires_at")(_assume_utc_if_naive)


class DeviceAccessRuleCreate(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = Field(default=None)
    mac_address: str = Field(..., min_length=12, max_length=17)
    rule_type: AccessRuleType
    reason: str | None = Field(default=None, max_length=2000)
    email: EmailStr | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)

    _normalize_expires_at = field_validator("expires_at")(_assume_utc_if_naive)


class AccessCheckRequest(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = None
    identifier: str | None = Field(default=None, max_length=255)
    mac_address: str | None = Field(default=None, max_length=17)


# ============================================================================
# Response schemas
# ============================================================================


class GuestAccessRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    identifier: str
    rule_type: str
    reason: str | None
    email: str | None
    expires_at: datetime | None
    is_active: bool
    # -- block enforcement -------------------------------------------------
    #
    # Surfaced so the dashboard can stop asserting something it has no way
    # of knowing. "Blocked" and "blocked, and the two sessions they were in
    # were ended" are different outcomes, and before these fields existed
    # the UI showed the same toast for both -- and for the case where the
    # router could not be reached at all.
    #
    # ``sessions_ended`` is a count of sessions *confirmed* gone from the
    # router's own active table, never of removals attempted. It is
    # legitimately ``0`` for a blocked guest who was not online, which is
    # why the status is carried alongside it rather than inferred from it.
    #
    # See ``constants.BlockEnforcementStatus``. ``None`` on rows written
    # before enforcement existed -- see migration 0107 for why those are
    # not backfilled.
    enforcement_status: str | None = None
    enforcement_error: str | None = None
    enforced_at: datetime | None = None
    sessions_ended: int | None = None
    created_at: datetime
    updated_at: datetime


class DeviceAccessRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    mac_address: str
    rule_type: str
    reason: str | None
    email: str | None
    expires_at: datetime | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class GuestAccessRuleListResponse(BaseModel):
    items: list[GuestAccessRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class DeviceAccessRuleListResponse(BaseModel):
    items: list[DeviceAccessRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class AccessCheckResponse(BaseModel):
    allowed: bool
    rule_type: str | None
    matched_rule_id: uuid.UUID | None
    reason: str | None
