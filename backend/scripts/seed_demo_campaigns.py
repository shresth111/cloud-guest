"""Idempotent Campaigns seeder for the Wyfy Demo tenant.

Companion to ``scripts/seed_demo.py`` (which seeds the demo organization
``wyfy-demo``, its admin login, locations, routers and guest traffic) and
``scripts/seed_demo_portal.py`` (which seeds branding + captive-portal
configs). Those two leave the **Campaigns** dashboard empty and, more
importantly, leave the real guest-facing captive portal with nothing to
show -- a guest connecting through a demo location's portal reaches the
post-login screen and no campaign is served, because none is seeded ACTIVE
for that location. This script fills exactly that gap and nothing else, in
the same insert-only, idempotent, demo-org-scoped style.

It seeds two live campaigns -- one of each product-facing "type of
campaign" -- each attached to a distinct active demo location so a demo can
show BOTH by connecting at two venues (the guest-facing resolver serves
exactly one campaign per session, so two on one location would hide each
other -- see ``CampaignsService.get_next_campaign_for_session``):

1. **Survey & Feedback** -> ``brew-and-bytes-cafe``. A three-question guest
   satisfaction survey: food quality and staff courteousness as single
   choice (Excellent / Good / Average / Could be better) and cleanliness as
   a 1-5 star rating -- the exact questions the product's own "Create Survey
   Campaign" flow describes. Rendered live by the frontend
   ``CampaignOverlay`` on the post-login session screen.

2. **Banner & Discounts** -> ``grand-horizon-hotel``. A promo banner with a
   redeemable coupon: "Flat 20% off this weekend" / "Show this coupon at
   checkout" / code ``SAVE20`` / a validity date. Rendered live by
   ``CampaignOverlay`` as a copyable coupon card (the ``headline`` /
   ``subtext`` / ``coupon_code`` / ``coupon_expires_at`` columns added to
   ``campaign_assets`` in migration 0099).

Both are seeded ``status=ACTIVE`` with no ``starts_at``/``ends_at`` window
(so ``validators.compute_effective_status`` treats them as ACTIVE
indefinitely for the demo), ``display_rule=EVERY_LOGIN`` (so the demo shows
them on every connect, not once-per-7-days), ``is_skippable=True``, and
empty ``target_networks`` (every router at the location is in scope).

**Insert-only + idempotent.** Each campaign is guarded by a lookup on its
natural scope key -- ``(organization_id, name)`` among non-deleted rows --
so a re-run creates nothing new and mutates nothing. Its questions/asset
are only created when the campaign itself was just created, so they can
never be double-inserted. This script never updates or deletes an existing
row.

**Demo-org-scoped.** Every write is keyed on the ``wyfy-demo`` organization
resolved by slug; if that org (or a target location) does not exist yet
(``seed_demo.py`` has not been run), this script seeds what it can and says
what it skipped. It can never touch another tenant.

Run (against a NON-production database only)::

    python -m scripts.seed_demo_campaigns

Safe to re-run. Owns no transaction of its own beyond the single commit in
``_main_async`` -- mirrors ``seed_demo.py``/``seed_demo_portal.py``.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select

from app.database.session import SessionLocal
from app.domains.auth.repository import AuthRepository
from app.domains.campaigns.constants import (
    AnswerType,
    CampaignStatus,
    CampaignType,
    DisplayRule,
)
from app.domains.campaigns.models import Campaign
from app.domains.campaigns.repository import CampaignsRepository

# Imported (some only for SQLAlchemy's declarative registry, like
# seed_demo.py's own note) so every string-based ForeignKey resolves at
# flush time in this narrow script.
from app.domains.location.models import Location  # noqa: F401
from app.domains.location.repository import LocationRepository
from app.domains.organization.models import Organization  # noqa: F401
from app.domains.organization.repository import OrganizationRepository

logger = logging.getLogger(__name__)

# -- stable idempotency keys (must match scripts/seed_demo.py) ---------------

DEMO_ORG_SLUG = "wyfy-demo"
DEMO_USER_EMAIL = "demo@wyfyguest.com"

SURVEY_LOCATION_SLUG = "brew-and-bytes-cafe"
BANNER_LOCATION_SLUG = "grand-horizon-hotel"

SURVEY_CAMPAIGN_NAME = "Guest Satisfaction Survey"
BANNER_CAMPAIGN_NAME = "Weekend Discount"

# Shared single-choice scale for the rating-style survey questions -- the
# exact four the product's "Create Survey Campaign" spec lists.
_RATING_CHOICES = ["Excellent", "Good", "Average", "Could be better"]

# A comfortably-future coupon validity so the demo banner always renders as
# live ("Valid until 31 Dec 2026"), never as an already-expired coupon. The
# campaign itself carries no ends_at, so it stays ACTIVE regardless.
_COUPON_EXPIRES_AT = datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)


@dataclass
class DemoCampaignSeedResult:
    organization_found: bool = False
    survey_created: bool = False
    banner_created: bool = False
    survey_existing: bool = False
    banner_existing: bool = False
    warnings: list[str] = field(default_factory=list)


async def _find_campaign_by_name(
    repository: CampaignsRepository, *, organization_id: uuid.UUID, name: str
) -> Campaign | None:
    """Insert-only guard: the natural scope key for a demo campaign is
    ``(organization_id, name)`` among non-deleted rows. No repository
    method expresses this lookup (admin listing is paginated and location-
    scoped), so this narrow seeder issues its own select -- exactly the
    "seeder owns a small direct query when no repository method fits"
    latitude ``seed_demo.py`` already takes."""
    statement = select(Campaign).where(
        Campaign.organization_id == organization_id,
        Campaign.name == name,
        Campaign.is_deleted.is_(False),
    )
    result = await repository.session.execute(statement)
    return result.scalar_one_or_none()


async def ensure_survey_campaign(
    repository: CampaignsRepository,
    location_repository: LocationRepository,
    *,
    organization_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
    result: DemoCampaignSeedResult,
) -> None:
    location = await location_repository.get_by_slug(
        organization_id, SURVEY_LOCATION_SLUG
    )
    if location is None:
        result.warnings.append(
            f"location '{SURVEY_LOCATION_SLUG}' not found -- skipped survey "
            f"campaign '{SURVEY_CAMPAIGN_NAME}' (run seed_demo.py first)."
        )
        return

    existing = await _find_campaign_by_name(
        repository, organization_id=organization_id, name=SURVEY_CAMPAIGN_NAME
    )
    if existing is not None:
        result.survey_existing = True
        return

    campaign = await repository.create_campaign(
        organization_id=organization_id,
        location_id=location.id,
        name=SURVEY_CAMPAIGN_NAME,
        campaign_type=CampaignType.SURVEY.value,
        status=CampaignStatus.ACTIVE.value,
        display_rule=DisplayRule.EVERY_LOGIN.value,
        target_networks=[],
        is_skippable=True,
        created_by=actor_user_id,
    )
    questions = [
        ("Rate our food quality?", AnswerType.SINGLE_CHOICE, list(_RATING_CHOICES)),
        (
            "Rate the courteousness of our staff?",
            AnswerType.SINGLE_CHOICE,
            list(_RATING_CHOICES),
        ),
        ("How do you rate cleanliness?", AnswerType.RATING_5, []),
    ]
    for order_index, (text, answer_type, options) in enumerate(questions):
        await repository.create_question(
            campaign_id=campaign.id,
            order_index=order_index,
            question_text=text,
            answer_type=answer_type.value,
            options=options,
            is_required=True,
            created_by=actor_user_id,
        )
    result.survey_created = True


async def ensure_banner_campaign(
    repository: CampaignsRepository,
    location_repository: LocationRepository,
    *,
    organization_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
    result: DemoCampaignSeedResult,
) -> None:
    location = await location_repository.get_by_slug(
        organization_id, BANNER_LOCATION_SLUG
    )
    if location is None:
        result.warnings.append(
            f"location '{BANNER_LOCATION_SLUG}' not found -- skipped banner "
            f"campaign '{BANNER_CAMPAIGN_NAME}' (run seed_demo.py first)."
        )
        return

    existing = await _find_campaign_by_name(
        repository, organization_id=organization_id, name=BANNER_CAMPAIGN_NAME
    )
    if existing is not None:
        result.banner_existing = True
        return

    campaign = await repository.create_campaign(
        organization_id=organization_id,
        location_id=location.id,
        name=BANNER_CAMPAIGN_NAME,
        campaign_type=CampaignType.BANNER.value,
        status=CampaignStatus.ACTIVE.value,
        display_rule=DisplayRule.EVERY_LOGIN.value,
        target_networks=[],
        is_skippable=True,
        created_by=actor_user_id,
    )
    await repository.create_asset(
        campaign_id=campaign.id,
        headline="Flat 20% off this weekend",
        subtext="Show this coupon at checkout to redeem your discount.",
        coupon_code="SAVE20",
        coupon_expires_at=_COUPON_EXPIRES_AT,
        alt_text="Flat 20% off this weekend -- use code SAVE20",
        created_by=actor_user_id,
    )
    result.banner_created = True


async def run_seed_demo_campaigns(session) -> DemoCampaignSeedResult:
    """Seed the demo survey + banner campaigns against ``session``. Does
    not commit -- the CLI entrypoint owns the transaction boundary,
    mirroring ``seed_demo.py``."""
    result = DemoCampaignSeedResult()

    org = await OrganizationRepository(session).get_by_slug(DEMO_ORG_SLUG)
    if org is None:
        result.warnings.append(
            f"demo organization '{DEMO_ORG_SLUG}' not found -- run "
            f"scripts/seed_demo.py first. Nothing seeded."
        )
        return result
    result.organization_found = True

    # created_by: the demo org-admin if seed_demo already made them, else
    # None (BaseModel.created_by is nullable) -- never a hard dependency.
    actor_user_id: uuid.UUID | None = None
    demo_user = await AuthRepository(session).get_user_by_email(DEMO_USER_EMAIL)
    if demo_user is not None:
        actor_user_id = demo_user.id

    repository = CampaignsRepository(session)
    location_repository = LocationRepository(session)

    await ensure_survey_campaign(
        repository,
        location_repository,
        organization_id=org.id,
        actor_user_id=actor_user_id,
        result=result,
    )
    await ensure_banner_campaign(
        repository,
        location_repository,
        organization_id=org.id,
        actor_user_id=actor_user_id,
        result=result,
    )
    return result


async def _main_async() -> None:
    async with SessionLocal() as session:
        result = await run_seed_demo_campaigns(session)
        await session.commit()

    logger.info("seed_demo_campaigns_completed", extra={"result": result})
    lines: list[str] = []
    if not result.organization_found:
        lines.append("Demo organization NOT found -- nothing seeded.")
    else:
        lines.append(
            "Survey & Feedback campaign: "
            + (
                "created (+3 questions)"
                if result.survey_created
                else "already existed"
                if result.survey_existing
                else "skipped"
            )
        )
        lines.append(
            "Banner & Discounts campaign: "
            + (
                "created (+coupon SAVE20)"
                if result.banner_created
                else "already existed"
                if result.banner_existing
                else "skipped"
            )
        )
    for warning in result.warnings:
        lines.append(f"WARNING: {warning}")
    print("\n".join(lines))  # noqa: T201 -- CLI entrypoint output


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Seed one Survey & Feedback and one Banner & Discounts campaign "
            "(both ACTIVE, one per demo location) for the Wyfy Demo tenant so "
            "the Campaigns dashboard is populated and the live captive portal "
            "renders both. Requires scripts/seed_demo.py to have run first. "
            "Safe to re-run."
        )
    )
    parser.parse_args(argv)
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
