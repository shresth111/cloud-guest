"""Pure validation/computation helpers for the Campaigns domain -- no I/O,
easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

from datetime import datetime

from .constants import (
    CAMPAIGN_STATUS_TRANSITIONS,
    AnswerType,
    CampaignStatus,
    DisplayRule,
)
from .exceptions import (
    InvalidAssetUrlsError,
    InvalidCampaignStatusTransitionError,
    InvalidDisplayIntervalError,
    InvalidQuestionOptionsError,
)

_CHOICE_ANSWER_TYPES = frozenset({AnswerType.SINGLE_CHOICE, AnswerType.MULTI_CHOICE})


def validate_status_transition(current: CampaignStatus, target: CampaignStatus) -> None:
    legal_targets = CAMPAIGN_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidCampaignStatusTransitionError(current.value, target.value)


def compute_effective_status(
    status: CampaignStatus,
    *,
    starts_at: datetime | None,
    ends_at: datetime | None,
    now: datetime,
) -> CampaignStatus:
    """The *real* status a campaign should be treated as right now,
    re-derived from ``starts_at``/``ends_at`` rather than trusting the
    stored ``Campaign.status`` alone -- see ``__init__.py``'s own module
    docstring for why the guest-facing read path always calls this
    instead. ``DRAFT``/``PAUSED``/``ENDED`` are stable, admin-only states
    the sweep never overrides and this function never reinterprets
    either -- only ``SCHEDULED``/``ACTIVE`` are time-derived."""
    if status in (CampaignStatus.DRAFT, CampaignStatus.PAUSED, CampaignStatus.ENDED):
        return status
    if ends_at is not None and now >= ends_at:
        return CampaignStatus.ENDED
    if status == CampaignStatus.SCHEDULED:
        if starts_at is not None and now >= starts_at:
            return CampaignStatus.ACTIVE
        return CampaignStatus.SCHEDULED
    return CampaignStatus.ACTIVE


def validate_question_options(answer_type: AnswerType, options: list[str]) -> None:
    """``SINGLE_CHOICE``/``MULTI_CHOICE`` require at least one real
    option; ``RATING_5``/``FREE_TEXT`` have no options at all (a rating
    scale/free-text box needs no admin-authored choice list)."""
    if answer_type in _CHOICE_ANSWER_TYPES:
        if not options:
            raise InvalidQuestionOptionsError(
                f"{answer_type.value} requires at least one option"
            )
    elif options:
        raise InvalidQuestionOptionsError(f"{answer_type.value} must not have options")


def validate_asset_urls(
    image_url: str | None,
    click_url: str | None,
    *,
    headline: str | None = None,
    coupon_code: str | None = None,
) -> None:
    """A ``BANNER``/``REDIRECT`` asset must carry at least one renderable
    thing, or the row is inert (see ``models.CampaignAsset``'s docstring).

    Historically that meant an image or a click-through URL. A "Banner &
    Discounts" banner may instead be pure text-and-coupon copy -- a
    ``headline`` and/or a ``coupon_code`` with no image or link at all --
    which is equally renderable (the frontend ``CampaignOverlay`` draws a
    coupon card from it), so those two count toward the "at least one"
    requirement as well. The keyword-only ``headline``/``coupon_code``
    default to ``None`` so every pre-existing image/redirect call site
    (and its tests) keeps its exact prior behaviour."""
    if not any((image_url, click_url, headline, coupon_code)):
        raise InvalidAssetUrlsError()


def validate_display_rule_fields(
    display_rule: DisplayRule, display_interval_days: int | None
) -> None:
    if display_rule == DisplayRule.ONCE_PER_N_DAYS and (
        display_interval_days is None or display_interval_days <= 0
    ):
        raise InvalidDisplayIntervalError()


__all__ = [
    "validate_status_transition",
    "compute_effective_status",
    "validate_question_options",
    "validate_asset_urls",
    "validate_display_rule_fields",
]
