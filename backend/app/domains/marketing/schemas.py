"""Request schemas for the Guest Marketing API (contract §5).

Every request model sets ``extra="forbid"``: an unknown field is a 422, never
silently dropped (the pydantic ``extra='ignore'`` trap that once stored
nothing and returned 201). In particular no request model has an
``organization_id`` field -- it comes only from ``CurrentOrganization``.

Response bodies are built as plain dicts by ``service.py`` so their shape
can be read side by side with the contract.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .constants import (
    CAMPAIGN_VARIABLE_MAX_LENGTHS,
    MAX_TEST_ADDRESSES,
    NOT_SEEN_FOR_DAYS_MAX,
    Channel,
    TemplateCategory,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AudienceFilter(_Strict):
    channel: Channel
    location_ids: list[uuid.UUID] | None = None
    visited_from: date | None = None
    visited_to: date | None = None
    min_visits: int | None = Field(default=None, ge=0)
    max_visits: int | None = Field(default=None, ge=0)
    not_seen_for_days: int | None = Field(default=None, ge=1, le=NOT_SEEN_FOR_DAYS_MAX)
    require_name: bool = False

    @model_validator(mode="after")
    def _ranges(self) -> AudienceFilter:
        if (
            self.visited_from
            and self.visited_to
            and self.visited_from > self.visited_to
        ):
            raise ValueError("visited_from must not be after visited_to")
        if (
            self.min_visits is not None
            and self.max_visits is not None
            and self.min_visits > self.max_visits
        ):
            raise ValueError("min_visits must not exceed max_visits")
        return self


class PortalConsentUpdate(_Strict):
    location_id: uuid.UUID
    enabled: bool
    text: str | None = Field(default=None, max_length=300)


class StaffOptOutRequest(_Strict):
    channels: list[Channel] = Field(min_length=1)
    note: str | None = Field(default=None, max_length=300)


class SmsContent(_Strict):
    body: str = Field(min_length=1)
    dlt_template_id: str | None = Field(default=None, pattern=r"^\d{12,30}$")


class EmailContent(_Strict):
    subject: str = Field(min_length=1, max_length=150)
    preheader: str | None = Field(default=None, max_length=150)
    body_html: str = Field(min_length=1)


class TemplateCreate(_Strict):
    name: str = Field(min_length=1, max_length=120)
    category: TemplateCategory
    description: str | None = Field(default=None, max_length=300)
    sms: SmsContent | None = None
    whatsapp: dict | None = None
    email: EmailContent | None = None


class TemplateUpdate(_Strict):
    version: int
    name: str | None = Field(default=None, min_length=1, max_length=120)
    category: TemplateCategory | None = None
    description: str | None = Field(default=None, max_length=300)
    sms: SmsContent | None = None
    whatsapp: dict | None = None
    email: EmailContent | None = None


class TemplateDuplicate(_Strict):
    name: str = Field(min_length=1, max_length=120)


class PreviewContent(_Strict):
    sms: SmsContent | None = None
    email: EmailContent | None = None


class TemplatePreviewRequest(_Strict):
    channel: Channel
    template_id: uuid.UUID | None = None
    content: PreviewContent | None = None
    variables: dict[str, str] = Field(default_factory=dict)
    location_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> TemplatePreviewRequest:
        if (self.template_id is None) == (self.content is None):
            raise ValueError("exactly one of template_id / content is required")
        return self


def _check_variables(values: dict[str, str]) -> dict[str, str]:
    unknown = sorted(set(values) - set(CAMPAIGN_VARIABLE_MAX_LENGTHS))
    if unknown:
        # Surfaced as 422 unknown_variable by the service, which re-checks.
        return values
    for key, value in values.items():
        limit = CAMPAIGN_VARIABLE_MAX_LENGTHS[key]
        if len(value) > limit:
            raise ValueError(f"{key} must be at most {limit} characters")
    return values


class CampaignCreate(_Strict):
    name: str = Field(min_length=1, max_length=120)
    channel: Channel
    template_id: uuid.UUID
    location_id: uuid.UUID | None = None
    variables: dict[str, str] = Field(default_factory=dict)
    audience_filter: AudienceFilter

    @model_validator(mode="after")
    def _variable_lengths(self) -> CampaignCreate:
        _check_variables(self.variables)
        return self


class CampaignUpdate(_Strict):
    version: int
    name: str | None = Field(default=None, min_length=1, max_length=120)
    channel: Channel | None = None
    template_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    variables: dict[str, str] | None = None
    audience_filter: AudienceFilter | None = None

    @model_validator(mode="after")
    def _variable_lengths(self) -> CampaignUpdate:
        if self.variables is not None:
            _check_variables(self.variables)
        return self


class TestSendRequest(_Strict):
    __test__ = False  # not a pytest class

    to: list[str] = Field(min_length=1, max_length=MAX_TEST_ADDRESSES)
    sample_guest_name: str | None = Field(default=None, max_length=20)


class ScheduleRequest(_Strict):
    scheduled_at: datetime | None = None
    idempotency_key: str = Field(min_length=8, max_length=64)
    # Spec §12.4 (Q11 = Option A): required only when the channel has an own
    # provider that is not usable and the campaign would go through Wyfy.
    acknowledge_wyfy_fallback: bool = False


class EmptyRequest(_Strict):
    pass


class GuestConsentRequest(_Strict):
    guest_id: uuid.UUID
    session_id: uuid.UUID
    opt_in: bool
    consent_text_version: str | None = Field(default=None, max_length=50)


# -- Bring-your-own providers (spec §12.4) ------------------------------------


class ProviderPutRequest(_Strict):
    provider_type: str | None = Field(default=None, max_length=20)
    # Per-type fields are validated by providers.normalize_config (unknown
    # keys are refused there -- the extra="forbid" rule, applied per type).
    config: dict[str, str | int | bool | None] = Field(default_factory=dict)
    enabled: bool | None = None


class ProviderVerifyRequest(_Strict):
    test_to: str | None = Field(default=None, max_length=255)
    template_id: uuid.UUID | None = None


# -- Price book (spec §13.7, Master) ------------------------------------------


class PlatformPrice(_Strict):
    channel: Channel
    unit_price_minor: int = Field(strict=True, ge=0, le=10_000)


class PriceBookUpdate(_Strict):
    prices: list[PlatformPrice] = Field(min_length=1, max_length=3)
    note: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def _unique(self) -> PriceBookUpdate:
        channels = [p.channel for p in self.prices]
        if len(set(channels)) != len(channels):
            raise ValueError("each channel may appear once")
        return self


class OrgPrice(_Strict):
    channel: Channel
    # null clears the override (inherit the platform price).
    unit_price_minor: int | None = Field(strict=True, ge=0, le=10_000)


class OrgPricesUpdate(_Strict):
    prices: list[OrgPrice] = Field(min_length=1, max_length=3)
    note: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def _unique(self) -> OrgPricesUpdate:
        channels = [p.channel for p in self.prices]
        if len(set(channels)) != len(channels):
            raise ValueError("each channel may appear once")
        return self
