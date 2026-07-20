"""Pydantic request/response schemas for the Guest Teams API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py`` -- including the
guest-facing ``join`` endpoint (mirroring OTP's/Voucher's/Guest's own
guest-facing-but-still-enveloped precedent).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .constants import GuestTeamStatus

__all__ = [
    "GuestTeamCreateRequest",
    "GuestTeamJoinRequest",
    "GuestTeamRevokeRequest",
    "GuestTeamMemberRemoveRequest",
    "GuestTeamResponse",
    "GuestTeamListResponse",
    "GuestTeamMemberResponse",
    "GuestTeamSummaryResponse",
    "GuestTeamDetailResponse",
    "GuestTeamJoinResponse",
    "GuestTeamMemberRemovalResponse",
    "GuestTeamRevokeResponse",
]


# ============================================================================
# Admin-facing request schemas
# ============================================================================


class GuestTeamCreateRequest(BaseModel):
    organization_id: uuid.UUID = Field(...)
    location_id: uuid.UUID | None = Field(
        default=None,
        description="Optional -- omit for an org-wide team spanning every location.",
    )
    name: str = Field(..., min_length=1, max_length=200)
    max_members: int | None = Field(
        default=None, ge=1, description="Null means unlimited membership."
    )
    shared_data_limit_mb: int | None = Field(
        default=None,
        ge=1,
        description="Optional pooled data quota shared across every member's "
        "sessions. Null means no team-level pooling.",
    )
    expires_at: datetime | None = Field(default=None)


class GuestTeamRevokeRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class GuestTeamMemberRemoveRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


# ============================================================================
# Guest-facing request schema
# ============================================================================


class GuestTeamJoinRequest(BaseModel):
    team_code: str = Field(..., min_length=1, max_length=32)
    identifier: str = Field(..., min_length=1, max_length=255)
    device_mac: str | None = Field(default=None, max_length=17)
    device_name: str | None = Field(default=None, max_length=200)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "team_code": "AB23CD45",
                "identifier": "+15551234567",
                "device_mac": "AA:BB:CC:DD:EE:FF",
            }
        }
    )


# ============================================================================
# Response schemas
# ============================================================================


class GuestTeamResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str | None
    name: str
    team_code: str
    status: GuestTeamStatus
    max_members: int | None
    shared_data_limit_mb: int | None
    expires_at: datetime | None
    created_by_user_id: str | None
    revoked_at: datetime | None
    revoked_reason: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GuestTeamListResponse(BaseModel):
    items: list[GuestTeamResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class GuestTeamMemberResponse(BaseModel):
    id: str
    team_id: str
    guest_id: str
    joined_at: datetime
    is_active: bool
    left_at: datetime | None
    removal_reason: str | None

    model_config = ConfigDict(from_attributes=True)


class GuestTeamSummaryResponse(BaseModel):
    member_count: int
    active_session_count: int
    total_bandwidth_bytes: int
    shared_data_limit_mb: int | None
    remaining_shared_quota_mb: float | None
    quota_exceeded: bool


class GuestTeamDetailResponse(GuestTeamResponse):
    summary: GuestTeamSummaryResponse


class GuestTeamJoinResponse(BaseModel):
    team_id: str
    guest_id: str
    identifier: str
    is_new_guest: bool
    is_new_membership: bool
    membership: GuestTeamMemberResponse


class GuestTeamMemberRemovalResponse(BaseModel):
    team_id: str
    guest_id: str
    terminated_session_ids: list[str]


class GuestTeamRevokeResponse(BaseModel):
    team: GuestTeamResponse
    member_count: int
    terminated_session_ids: list[str]
    failed_member_ids: list[str]
