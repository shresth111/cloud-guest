"""Pydantic request/response schemas for the Campaigns domain API.

Follows the same pydantic v2 conventions as every other recently-built
domain (``app.domains.qos.schemas``, ``app.domains.hotspot.schemas``):
plain ``str`` fields for every UUID, explicit response-builder functions
in ``router.py`` doing the ``str(...)`` conversion rather than
``ConfigDict(from_attributes=True)`` auto-mapping, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.

Two distinct response families: the admin-facing ``Campaign*Response``
schemas (full record, every field) and the guest-facing
``NextCampaignResponse`` (only what a captive portal needs to render one
campaign -- never the admin metadata).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

from .constants import (
    DEFAULT_DISPLAY_INTERVAL_DAYS,
    DEFAULT_DISPLAY_RULE,
    DEFAULT_IS_SKIPPABLE,
)

__all__ = [
    "MessageResponse",
    "CampaignCreateRequest",
    "CampaignUpdateRequest",
    "CampaignCloneRequest",
    "CampaignResponse",
    "CampaignListResponse",
    "CampaignQuestionCreateRequest",
    "CampaignQuestionUpdateRequest",
    "CampaignQuestionResponse",
    "CampaignAssetCreateRequest",
    "CampaignAssetUpdateRequest",
    "CampaignAssetResponse",
    "QuestionResultBreakdownResponse",
    "CampaignResultsResponse",
    "NextCampaignQuestionPayload",
    "NextCampaignAssetPayload",
    "NextCampaignResponse",
    "CampaignRespondRequest",
    "CampaignImpressionRequest",
]


class CampaignCreateRequest(BaseModel):
    location_id: str | None = Field(
        default=None, description="Null means an org-wide campaign."
    )
    name: str
    campaign_type: str
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    display_rule: str = DEFAULT_DISPLAY_RULE.value
    display_interval_days: int | None = Field(
        default=DEFAULT_DISPLAY_INTERVAL_DAYS, ge=1
    )
    target_networks: list[str] = Field(default_factory=list)
    # See app.domains.campaigns's own module docstring: EVERY_LOGIN +
    # is_skippable=False is a guest-experience-hostile combination and
    # should be avoided -- defaulting to True keeps a new campaign
    # skippable unless an admin deliberately opts out.
    is_skippable: bool = DEFAULT_IS_SKIPPABLE


class CampaignUpdateRequest(BaseModel):
    location_id: str | None = None
    name: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    display_rule: str | None = None
    display_interval_days: int | None = Field(default=None, ge=1)
    target_networks: list[str] | None = None
    is_skippable: bool | None = None


class CampaignCloneRequest(BaseModel):
    new_name: str


class CampaignResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str | None
    name: str
    campaign_type: str
    status: str
    starts_at: datetime | None
    ends_at: datetime | None
    display_rule: str
    display_interval_days: int | None
    target_networks: list[str]
    is_skippable: bool
    created_at: datetime


class CampaignListResponse(BaseModel):
    items: list[CampaignResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class CampaignQuestionCreateRequest(BaseModel):
    order_index: int = Field(ge=0)
    question_text: str
    answer_type: str
    options: list[str] = Field(default_factory=list)
    is_required: bool = True


class CampaignQuestionUpdateRequest(BaseModel):
    order_index: int | None = Field(default=None, ge=0)
    question_text: str | None = None
    answer_type: str | None = None
    options: list[str] | None = None
    is_required: bool | None = None


class CampaignQuestionResponse(BaseModel):
    id: str
    campaign_id: str
    order_index: int
    question_text: str
    answer_type: str
    options: list[str]
    is_required: bool


class CampaignAssetCreateRequest(BaseModel):
    image_url: str | None = None
    click_url: str | None = None
    alt_text: str | None = None
    locale: str | None = None


class CampaignAssetUpdateRequest(BaseModel):
    image_url: str | None = None
    click_url: str | None = None
    alt_text: str | None = None
    locale: str | None = None


class CampaignAssetResponse(BaseModel):
    id: str
    campaign_id: str
    image_url: str | None
    click_url: str | None
    alt_text: str | None
    locale: str | None


class QuestionResultBreakdownResponse(BaseModel):
    question_id: str
    question_text: str
    answer_type: str
    total_answers: int
    option_counts: dict[str, int] | None
    average_rating: float | None
    rating_distribution: dict[int, int] | None
    free_text_answers: list[str] | None


class CampaignResultsResponse(BaseModel):
    campaign_id: str
    total_responses: int
    total_impressions: int
    total_skipped: int
    total_clicked: int
    question_breakdowns: list[QuestionResultBreakdownResponse]


class NextCampaignQuestionPayload(BaseModel):
    id: str
    order_index: int
    question_text: str
    answer_type: str
    options: list[str]
    is_required: bool


class NextCampaignAssetPayload(BaseModel):
    image_url: str | None
    click_url: str | None
    alt_text: str | None


class NextCampaignResponse(BaseModel):
    """The guest-facing serving payload -- only what a captive portal
    needs to render one campaign. Deliberately omits every admin-only
    field (``status``, ``target_networks``, timestamps, etc.)."""

    campaign_id: str
    campaign_type: str
    is_skippable: bool
    questions: list[NextCampaignQuestionPayload]
    asset: NextCampaignAssetPayload | None


class CampaignRespondRequest(BaseModel):
    guest_session_id: str
    answers: dict[str, object]


class CampaignImpressionRequest(BaseModel):
    guest_session_id: str
    was_skipped: bool = False
    was_clicked: bool = False
