"""Starter campaign definitions -- authoring sugar over the endpoints that
already exist, and nothing else.

A template is a *shape* a venue can start from: a name, a description, a
campaign type, and a list of questions to pre-seed. Applying one is
``POST /campaigns`` followed by N ``POST /campaigns/{id}/questions``, which
the dashboard already knows how to call. **No template creates a row, adds
a column, or introduces a code path a hand-authored campaign does not
already take.**

## Why the shapes live in the backend rather than in the dashboard

Because the copy is the feature. A "Dish feedback" starter is worth having
only if it produces a survey a guest will actually finish, and the things
that decide that -- how many questions, what they are called, which display
rule -- are product judgements with reasons behind them. Reasons written in
a TypeScript constant are reasons the API contract does not know about, and
the second client (the legacy operator shell, a partner integration, a
support script) gets none of them.

It also keeps one specific mistake from being made twice. See
``_DISH_FEEDBACK`` below on what must never appear in a suggested review
string.

## What this deliberately is not

**Not a `DISH` campaign type.** A dish survey is a survey: one
``rating_5`` question per dish, ``question_text`` set to the dish name.
That works today, end to end, including the results view. A new
``CampaignType`` member with no new behaviour behind it is a migration
that buys a label.

**Not a catalogue.** See the sequencing note at the bottom of this module
-- it is the single most useful thing in this file and it is addressed to
whoever builds menu cards, not to whoever reads this one.

**Not stored.** Templates are constants, not rows. A venue does not "own"
a template and cannot edit one; they apply it and then own the campaign it
produced. There is no template CRUD and there should not be.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .constants import (
    DEFAULT_DISPLAY_INTERVAL_DAYS,
    AnswerType,
    CampaignType,
    DisplayRule,
)


@dataclass(frozen=True, slots=True)
class TemplateQuestion:
    """One pre-seeded question. ``question_text`` empty means "the venue
    fills this in" -- a dish name, in the only template that has any."""

    answer_type: AnswerType
    question_text: str
    is_required: bool = False
    options: list[str] = field(default_factory=list)
    # Whether the dashboard should offer an "add another" control for
    # rows of this kind. A dish survey is a repeating list of identical
    # questions with different names; a satisfaction survey is not.
    repeatable: bool = False


@dataclass(frozen=True, slots=True)
class CampaignTemplate:
    key: str
    name: str
    # Shown on the starter card. Says what the template is *for*, and
    # where it is a poor fit -- see `_DISH_FEEDBACK`'s own text for why
    # the second half matters more than the first.
    description: str
    campaign_type: CampaignType
    display_rule: DisplayRule
    display_interval_days: int | None
    questions: tuple[TemplateQuestion, ...]


_DISH_FEEDBACK = CampaignTemplate(
    key="dish_feedback",
    name="Dish feedback",
    description=(
        "One star rating per dish, answered on the connected screen and "
        "visible only to you. Best for a short menu that regulars order "
        "from often -- a cafe with eight items, a cloud kitchen, a QSR. "
        "A long menu, or guests who connect once and never return, will "
        "collect a handful of ratings a month; that is the feature "
        "working as designed, not failing."
    ),
    campaign_type=CampaignType.SURVEY,
    # A rating is not an every-visit question. A daily regular asked to
    # rate the chai every single day produces a dataset of annoyed 3s.
    display_rule=DisplayRule.ONCE_PER_N_DAYS,
    display_interval_days=DEFAULT_DISPLAY_INTERVAL_DAYS,
    questions=(
        # "Which did you order?" first, as a convention rather than a
        # feature. `CampaignQuestion` has no conditional-display concept
        # and adding one is not worth it here -- this does not hide the
        # rating rows below it. What it does is tell the venue which of
        # those ratings to trust, which is most of the value and costs a
        # single question slot.
        TemplateQuestion(
            answer_type=AnswerType.MULTI_CHOICE,
            question_text="Which did you order?",
            options=[],
        ),
        TemplateQuestion(
            answer_type=AnswerType.RATING_5,
            question_text="",
            repeatable=True,
        ),
        TemplateQuestion(
            answer_type=AnswerType.FREE_TEXT,
            question_text="Anything you'd like to add?",
        ),
    ),
)


_VISIT_FEEDBACK = CampaignTemplate(
    key="visit_feedback",
    name="How was your visit?",
    description=(
        "A single rating out of five, plus an optional comment. Private "
        "-- it goes to your results page and nowhere public."
    ),
    campaign_type=CampaignType.SURVEY,
    display_rule=DisplayRule.ONCE_PER_N_DAYS,
    display_interval_days=30,
    questions=(
        TemplateQuestion(
            answer_type=AnswerType.RATING_5,
            question_text="How's it going?",
        ),
        TemplateQuestion(
            answer_type=AnswerType.FREE_TEXT,
            question_text="Anything you'd like to add?",
        ),
    ),
)


CAMPAIGN_TEMPLATES: tuple[CampaignTemplate, ...] = (
    _DISH_FEEDBACK,
    _VISIT_FEEDBACK,
)


def get_template(key: str) -> CampaignTemplate | None:
    return next((t for t in CAMPAIGN_TEMPLATES if t.key == key), None)


# ---------------------------------------------------------------------------
# Two things that must not be added to this file
# ---------------------------------------------------------------------------
#
# **No template may suggest review copy.** Not "tell us if you loved it",
# not "5 stars if we earned them", not a Google link. Google's Rating
# Manipulation policy forbids a merchant "attempting to influence the
# rating or the contents of the review", and the fastest possible route to
# a violation is a venue pasting a suggested string that this platform
# wrote for them. The penalty lands on the venue's own Business Profile --
# reviews unpublished, a public "fake reviews were removed" banner,
# account-level suspension across every profile that account owns -- not on
# this platform. A star survey and a public-review request are separate
# products on separate surfaces, and nothing in this file may blur them.
#
# **No template may set `is_skippable=False`.** `Campaign.is_skippable` can
# be set false today and the domain's own docstring calls
# `EVERY_LOGIN` + `is_skippable=False` a guest-experience-hostile
# combination "to avoid, not enforced/blocked outright". A starter that
# shipped one would make the hostile case the default case.
#
# ---------------------------------------------------------------------------
# Sequencing note -- for whoever builds menu cards, not for whoever reads
# this file
# ---------------------------------------------------------------------------
#
# `_DISH_FEEDBACK` above keys a dish on `CampaignQuestion.question_text`,
# which is a plain `Text` column. **That is fine for asking and useless for
# remembering.** Concretely, today:
#
#   * "Masala Chai" typed on Monday and "masala chai" typed in next
#     month's campaign are two unrelated questions. There is no trend for a
#     dish over time; every campaign's results start from zero.
#   * The same dish at two branches is two strings, so there is no
#     cross-location comparison.
#   * A venue fixing a typo -- "Flat White" to "Flat white" -- silently
#     orphans every rating the old spelling ever collected. No error, no
#     warning, nothing in the UI that shows it happened.
#
# None of that is fixable from inside this domain, and it is deliberately
# not fixed here: a dish catalogue is a subsystem, and building one
# speculatively, before a venue has used the manual version and asked for
# history, is how a quarter gets spent on a feature nobody requested.
#
# **The decision that does have to be made now belongs to the menu-cards
# ticket.** Menu cards are specced (`build/post-connect-content.md` §3.1)
# and not built, and the spec's item shape is:
#
#     items: [ { name, price_minor, currency } ]
#
# If menu items ship as an inline JSON array keyed by name, dish ratings
# inherit every problem above permanently, and fixing it later means
# migrating live venue data. If they ship as a real `menu_items` table with
# server-assigned ids -- stable, never reused, with `archived` rather than
# deletion so historical ratings still resolve to a name -- then a rating
# can carry a `menu_item_id` and all of it works. It is one field, decided
# once, and it is cheap now and expensive later.
#
# Two smaller notes for the same reader:
#
#   * Name the rating's foreign key `catalog_item_id`, not `dish_id`. The
#     same mechanism serves hotel service tiles and salon treatments, and
#     `dish_id` costs a migration the first time a salon turns it on.
#   * `POST /portal/campaigns/{id}/respond` is unauthenticated and, under
#     the default `once_per_n_days` display rule, not deduplicated by any
#     database constraint. That is tolerable for an anonymous satisfaction
#     survey. It is not tolerable for anything a venue would treat as a
#     product rating, and it must be fixed before dish ratings influence a
#     menu decision, a price, or anything guest-visible.


__all__ = [
    "TemplateQuestion",
    "CampaignTemplate",
    "CAMPAIGN_TEMPLATES",
    "get_template",
]
