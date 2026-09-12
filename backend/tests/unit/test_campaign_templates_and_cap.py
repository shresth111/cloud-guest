"""The campaign question cap and the starter templates.

Both are authoring-side: they shape what a venue can build in the
dashboard, and neither changes anything a guest sees at a venue that does
not use them. Split out of the post-connect-asks work deliberately -- see
that PR -- because they share no code with it and land independently.

Same plain-``assert``/native-``async def`` style as ``test_campaigns.py``,
whose fakes are reused rather than rebuilt so a change to the real service
signature breaks here too.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.campaigns.constants import (
    MAX_QUESTIONS_PER_CAMPAIGN,
    AnswerType,
    CampaignType,
    DisplayRule,
)
from app.domains.campaigns.exceptions import TooManyCampaignQuestionsError
from app.domains.campaigns.templates import CAMPAIGN_TEMPLATES, get_template

from .test_campaigns import _create_campaign, _make_organization, make_harness

# ============================================================================
# Campaign question cap and templates
# ============================================================================


class TestQuestionCap:
    """There was no cap at all. A venue could author two hundred questions
    and the guest overlay would render every one as a flat stacked list,
    on a phone, inside a captive-portal websheet."""

    @staticmethod
    async def _survey():
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org, campaign_type=CampaignType.SURVEY)
        return h, org, campaign

    @staticmethod
    async def _add(h, org, campaign, index: int):
        return await h.service.add_question(
            campaign.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org.id,
            order_index=index,
            question_text=f"Dish {index}",
            answer_type=AnswerType.RATING_5,
            options=[],
            is_required=False,
        )

    async def test_the_limit_binds_at_the_cap_and_not_before(self) -> None:
        h, org, campaign = await self._survey()
        for index in range(MAX_QUESTIONS_PER_CAMPAIGN):
            await self._add(h, org, campaign, index)
        with pytest.raises(TooManyCampaignQuestionsError):
            await self._add(h, org, campaign, MAX_QUESTIONS_PER_CAMPAIGN)

    async def test_deleting_a_question_frees_a_slot(self) -> None:
        """The error tells the venue to remove a question, so that has to
        actually work -- which means counting live rows, not every row
        that ever existed."""
        h, org, campaign = await self._survey()
        questions = [
            await self._add(h, org, campaign, index)
            for index in range(MAX_QUESTIONS_PER_CAMPAIGN)
        ]
        with pytest.raises(TooManyCampaignQuestionsError):
            await self._add(h, org, campaign, 99)
        await h.service.delete_question(
            questions[0].id, requesting_organization_id=org.id
        )
        assert await self._add(h, org, campaign, 99) is not None

    async def test_the_error_carries_the_numbers(self) -> None:
        """A bare "limit reached" reads as an arbitrary product
        restriction; the dashboard needs the ceiling to show progress
        against it rather than surprising the venue on the eleventh."""
        h, org, campaign = await self._survey()
        for index in range(MAX_QUESTIONS_PER_CAMPAIGN):
            await self._add(h, org, campaign, index)
        with pytest.raises(TooManyCampaignQuestionsError) as excinfo:
            await self._add(h, org, campaign, 99)
        assert excinfo.value.data["max_questions"] == MAX_QUESTIONS_PER_CAMPAIGN
        assert excinfo.value.data["current_questions"] == MAX_QUESTIONS_PER_CAMPAIGN

    async def test_cloning_an_over_limit_campaign_is_not_blocked(self) -> None:
        """Deliberate. A clone copies a campaign that was legal when it
        was authored; refusing to duplicate it would strand a venue with a
        survey they can neither run twice nor shrink except one question
        at a time. The limit binds on the next *add*, which is the only
        moment it does any good -- the same grandfathering the splash-text
        ceilings use.
        """
        h, org, campaign = await self._survey()
        for index in range(MAX_QUESTIONS_PER_CAMPAIGN):
            await self._add(h, org, campaign, index)
        clone = await h.service.clone_campaign(
            campaign.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org.id,
            new_name="Copy",
        )
        cloned_questions = await h.service.list_questions(
            clone.id, requesting_organization_id=org.id
        )
        assert len(cloned_questions) == MAX_QUESTIONS_PER_CAMPAIGN


class TestCampaignTemplates:
    def test_the_dish_template_exists_and_is_a_plain_survey(self) -> None:
        """"Asking about dishes is a content type. Managing dishes is a
        subsystem." This is the content type: a survey with one
        ``rating_5`` question per dish, which works end to end today
        including the results view."""
        template = get_template("dish_feedback")
        assert template is not None
        assert template.campaign_type == CampaignType.SURVEY

    def test_no_template_exceeds_the_question_cap(self) -> None:
        """A starter that could not be applied would be a bug shipped as a
        feature."""
        for template in CAMPAIGN_TEMPLATES:
            assert len(template.questions) <= MAX_QUESTIONS_PER_CAMPAIGN

    def test_no_template_uses_every_login(self) -> None:
        """A daily regular asked to rate the chai every single day
        produces a dataset of annoyed 3s."""
        for template in CAMPAIGN_TEMPLATES:
            assert template.display_rule != DisplayRule.EVERY_LOGIN

    def test_the_dish_template_leaves_the_dish_names_to_the_venue(self) -> None:
        template = get_template("dish_feedback")
        assert template is not None
        rating_rows = [
            q for q in template.questions if q.answer_type == AnswerType.RATING_5
        ]
        assert rating_rows
        assert all(q.question_text == "" for q in rating_rows)
        assert all(q.repeatable for q in rating_rows)

    @pytest.mark.parametrize(
        "forbidden",
        [
            "5 star",
            "five star",
            "5-star",
            "positive",
            "good review",
            "google",
            "happy",
        ],
    )
    def test_no_template_suggests_review_copy(self, forbidden: str) -> None:
        """The fastest possible route to a Google Rating Manipulation
        violation is a venue pasting a suggested string that this platform
        wrote for them -- and the penalty lands on the venue's own
        Business Profile, not on this platform.

        Asserted over every string a template can put in front of a venue,
        so a well-meaning copy edit cannot reintroduce it quietly.
        """
        for template in CAMPAIGN_TEMPLATES:
            haystack = " ".join(
                [template.name, template.description]
                + [q.question_text for q in template.questions]
                + [option for q in template.questions for option in q.options]
            ).lower()
            assert forbidden not in haystack

    def test_no_template_carries_a_review_link(self) -> None:
        for template in CAMPAIGN_TEMPLATES:
            blob = " ".join(
                [template.description]
                + [q.question_text for q in template.questions]
            )
            assert "http" not in blob


class TestTemplatesAreStatic:
    def test_keys_are_unique(self) -> None:
        keys = [template.key for template in CAMPAIGN_TEMPLATES]
        assert len(keys) == len(set(keys))

    def test_an_unknown_key_returns_none_rather_than_raising(self) -> None:
        assert get_template("no-such-template") is None


