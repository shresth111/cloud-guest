"""Constants for the Campaigns domain.

Plain module constants, not ``Settings``/``Organization.settings``
fields -- mirrors ``app.domains.isp.constants``'s own "no new Settings
fields" discipline; per-organization tunability is a real future seam,
not implemented in this first pass.
"""

from __future__ import annotations

from enum import StrEnum


class CampaignType(StrEnum):
    """What a campaign shows a guest after login.

    ``SURVEY`` is backed by ``CampaignQuestion``/``CampaignResponse``.
    ``BANNER``/``REDIRECT`` both share ``CampaignAsset`` -- a ``BANNER``
    typically sets both ``image_url``/``click_url``; a pure ``REDIRECT``
    (no visible banner, just a post-login bounce) sets only
    ``click_url``. See ``models.CampaignAsset``'s own module docstring.
    """

    SURVEY = "survey"
    BANNER = "banner"
    REDIRECT = "redirect"


class CampaignStatus(StrEnum):
    """Lifecycle status of a :class:`~.models.Campaign`.

    * ``DRAFT`` -- created, not yet scheduled. Freely editable.
    * ``SCHEDULED`` -- an admin has committed to running this (requires
      ``starts_at`` set); waiting for the sweep to flip it live.
    * ``ACTIVE`` -- currently eligible to be shown to guests (subject to
      the *runtime* effective-status check -- see
      ``validators.compute_effective_status``; the stored value here can
      lag up to ``constants.CAMPAIGN_STATUS_SWEEP_INTERVAL_SECONDS``
      behind reality).
    * ``PAUSED`` -- an admin-only manual state; the sweep never places a
      campaign into or out of ``PAUSED`` on its own.
    * ``ENDED`` -- terminal. Reached either by the sweep (``ends_at`` in
      the past) or by an admin ending a campaign early/cancelling a
      ``DRAFT``/``SCHEDULED`` one before it ever ran -- this codebase
      does not add a separate "cancelled" status distinct from ``ENDED``
      for that case (see ``CAMPAIGN_STATUS_TRANSITIONS``: both
      ``DRAFT``/``SCHEDULED`` may transition directly to ``ENDED``).
    """

    DRAFT = "draft"
    SCHEDULED = "scheduled"
    ACTIVE = "active"
    PAUSED = "paused"
    ENDED = "ended"


CAMPAIGN_STATUS_TRANSITIONS: dict[CampaignStatus, frozenset[CampaignStatus]] = {
    CampaignStatus.DRAFT: frozenset({CampaignStatus.SCHEDULED, CampaignStatus.ENDED}),
    CampaignStatus.SCHEDULED: frozenset(
        {CampaignStatus.ACTIVE, CampaignStatus.DRAFT, CampaignStatus.ENDED}
    ),
    CampaignStatus.ACTIVE: frozenset({CampaignStatus.PAUSED, CampaignStatus.ENDED}),
    CampaignStatus.PAUSED: frozenset({CampaignStatus.ACTIVE, CampaignStatus.ENDED}),
    CampaignStatus.ENDED: frozenset(),
}


class DisplayRule(StrEnum):
    """How often one guest should be shown a given campaign.

    ``ONCE_PER_N_DAYS`` (7 days) is this domain's own default -- see
    ``__init__.py``'s own module docstring for why ``EVERY_LOGIN``
    combined with ``Campaign.is_skippable=False`` is called out as a
    guest-experience-hostile combination to avoid, not enforced/blocked
    outright (an admin may have a real reason to require a one-time
    mandatory survey)."""

    EVERY_LOGIN = "every_login"
    FIRST_LOGIN_ONLY = "first_login_only"
    ONCE_PER_N_DAYS = "once_per_n_days"


class AnswerType(StrEnum):
    """The input shape one :class:`~.models.CampaignQuestion` expects.

    ``options`` (JSONB on the question row) is only meaningful for
    ``SINGLE_CHOICE``/``MULTI_CHOICE`` -- validated at the service layer
    (``validators.validate_question_options``), not a database
    constraint."""

    SINGLE_CHOICE = "single_choice"
    MULTI_CHOICE = "multi_choice"
    RATING_5 = "rating_5"
    FREE_TEXT = "free_text"


# Friction-avoidance defaults (see __init__.py's own module docstring):
# a survey/banner is real, unavoidable interruption to a guest's login
# flow, so this domain defaults to the least-intrusive real configuration
# rather than the most aggressive one.
DEFAULT_IS_SKIPPABLE = True
DEFAULT_DISPLAY_RULE = DisplayRule.ONCE_PER_N_DAYS
DEFAULT_DISPLAY_INTERVAL_DAYS = 7

# How often the Celery beat sweep re-evaluates every non-terminal
# campaign's stored `status` against `starts_at`/`ends_at`. The guest-
# facing "what should this guest see right now" read path never trusts
# this stored value alone -- it always re-derives the effective status
# at request time (see `validators.compute_effective_status`), since a
# campaign that ended 30 seconds ago must never be served just because
# the sweep hasn't ticked yet.
CAMPAIGN_STATUS_SWEEP_INTERVAL_SECONDS = 300.0

TASK_SWEEP_CAMPAIGN_STATUS_TRANSITIONS = (
    "app.domains.campaigns.tasks.sweep_campaign_status_transitions"
)

__all__ = [
    "CampaignType",
    "CampaignStatus",
    "CAMPAIGN_STATUS_TRANSITIONS",
    "DisplayRule",
    "AnswerType",
    "DEFAULT_IS_SKIPPABLE",
    "DEFAULT_DISPLAY_RULE",
    "DEFAULT_DISPLAY_INTERVAL_DAYS",
    "CAMPAIGN_STATUS_SWEEP_INTERVAL_SECONDS",
    "TASK_SWEEP_CAMPAIGN_STATUS_TRANSITIONS",
]
