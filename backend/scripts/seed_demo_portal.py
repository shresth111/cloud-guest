"""Idempotent captive-portal + branding seeder for the Wyfy Demo tenant.

Companion to ``scripts/seed_demo.py`` -- that script seeds the demo
organization (slug ``wyfy-demo``), its org-admin login, locations, routers,
and ~30 days of guest traffic, but explicitly seeds **no**
``captive_portal_configs`` and **no** branding content, so the customer
dashboard's Portal Settings / branding surfaces come up empty. This script
fills exactly that gap and nothing else, in the same insert-only,
idempotent, demo-org-scoped style, so the demo visibly shows "here is how
you change the image / text / redirect / survey":

1. One **Branding** row for the demo org (company name, brand colours,
   logo URL, theme) -- the org-level branding ``BrandAssetPage`` reads.
2. One org-level **default** captive portal config (``is_default=True``,
   ``location_id IS NULL``) in ``redirect`` content mode -- the fallback a
   location with no config of its own inherits.
3. One captive portal config per demo location, each showcasing a different
   content mode so the demo has a live example of every one:
     * Brew & Bytes Cafe      -> ``image``   (a promo graphic)
     * The Grand Horizon Hotel-> ``text``    (a welcome note)
     * Nexus Coworking Hub    -> ``survey``  (a short guest survey)

Combined with the org default's ``redirect`` mode, all four configurable
content modes (image / text / redirect / survey) are demonstrated live.

**Insert-only + idempotent.** Every row is guarded by a lookup on its
natural scope key -- the branding by organization, the org default by
``find_default_for_organization``, each location config by
``find_active_for_location`` -- so a re-run creates nothing new and mutates
nothing. This script never updates or deletes an existing row.

**Demo-org-scoped.** Every write is keyed on the ``wyfy-demo`` organization
resolved by slug; if that org does not exist yet (``seed_demo.py`` has not
been run), this script does nothing but say so. It can never touch another
tenant.

**Example images.** ``background_image_url`` / ``content_image_url`` point
at small, optimized SVGs committed to the *frontend* repo under
``public/demo/portal/`` (``cloudguest-foundation``), served by the portal
SPA's own origin. They are stored as plain URL strings on
``captive_portal_configs`` (the column supports a typed-in URL directly);
this deliberately does **not** push bytes into object storage, so the
seeder needs no storage backend and touches no infrastructure.

**HONEST GAP.** The survey content mode is seeded as a real, rendered
survey, but this demo captures no survey *responses* -- the guest-facing
survey (``PortalContentBlock``) is a local, non-networked form (it thanks
the guest and lets them connect); there is no responses table or analytics
tie-in yet. Likewise the per-location configs set ``background_image_url``
directly on ``captive_portal_configs`` rather than through the
``brandings`` object-storage upload pipeline, so the v7 luminance/entropy
measurements those uploads compute are absent for these demo rows (the
portal correctly falls back to its unconditional scrim floor, exactly as a
real venue with a typed-in URL does).

Run (against a NON-production database only)::

    python -m scripts.seed_demo_portal

Safe to re-run. Owns no transaction of its own beyond the single commit in
``_main_async`` -- mirrors ``seed_demo.py``.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import uuid
from dataclasses import dataclass, field

from app.database.session import SessionLocal

# Imported (some only for SQLAlchemy's declarative registry, like
# seed_demo.py's own note) so every string-based ForeignKey on
# captive_portal_configs / brandings resolves at flush time in this narrow
# script.
from app.domains.auth.repository import AuthRepository
from app.domains.branding.models import Branding  # noqa: F401
from app.domains.branding.repository import BrandingRepository
from app.domains.captive_portal.constants import PortalContentMode
from app.domains.captive_portal.models import CaptivePortalConfig  # noqa: F401
from app.domains.captive_portal.repository import CaptivePortalRepository
from app.domains.location.models import Location  # noqa: F401
from app.domains.location.repository import LocationRepository
from app.domains.organization.models import Organization  # noqa: F401
from app.domains.organization.repository import OrganizationRepository

logger = logging.getLogger(__name__)

# -- stable idempotency keys (must match scripts/seed_demo.py) ---------------

DEMO_ORG_SLUG = "wyfy-demo"

# Brand colours + assets for the demo org's branding row.
DEMO_PRIMARY_COLOR = "#6D28D9"
DEMO_SECONDARY_COLOR = "#22D3EE"
DEMO_LOGO_URL = "/demo/portal/backgrounds/default.svg"

# Example images (small, optimized SVGs) committed to the frontend repo under
# cloudguest-foundation/public/demo/portal/ -- served by the portal SPA's own
# origin, referenced here as plain URL strings.
BG_DEFAULT = "/demo/portal/backgrounds/default.svg"
BG_CAFE = "/demo/portal/backgrounds/cafe.svg"
BG_HOTEL = "/demo/portal/backgrounds/hotel.svg"
BG_COWORKING = "/demo/portal/backgrounds/coworking.svg"
IMG_CAFE_PROMO = "/demo/portal/content/cafe-promo.svg"

# The survey rendered in the coworking venue's "survey" content mode. Same
# shape the frontend's PortalSurvey narrows to (questions[] + submitLabel).
NEXUS_SURVEY: dict = {
    "questions": [
        {
            "id": "purpose",
            "label": "What brings you to Nexus today?",
            "type": "choice",
            "options": ["Focused work", "Team meeting", "Client call", "Event"],
        },
        {
            "id": "nps",
            "label": "How likely are you to recommend us?",
            "type": "rating",
        },
        {
            "id": "notes",
            "label": "Anything we can improve?",
            "type": "text",
        },
    ],
    "submitLabel": "Submit & get online",
}

HOTEL_WELCOME_BODY = (
    "You're connected to complimentary high-speed WiFi throughout the "
    "property.\n\n"
    "Reception is available 24/7 on extension 0. Breakfast is served in the "
    "Atrium from 7:00 to 10:30. Enjoy your stay with us."
)


@dataclass
class DemoPortalConfigSpec:
    """One captive portal config to seed. ``location_slug=None`` is the
    org-level default row (``is_default=True``, ``location_id IS NULL``)."""

    location_slug: str | None
    name: str
    content_mode: PortalContentMode
    background_image_url: str
    primary_color: str
    secondary_color: str
    splash_headline: str
    splash_welcome_message: str
    content_heading: str | None = None
    content_body: str | None = None
    content_image_url: str | None = None
    content_survey: dict | None = None
    redirect_url: str | None = None


# Order: the org default first (so re-run detection and the single-default
# constraint are settled before the per-location rows), then one row per demo
# location, each a different content mode.
DEMO_PORTAL_CONFIGS: list[DemoPortalConfigSpec] = [
    DemoPortalConfigSpec(
        location_slug=None,
        name="Wyfy Demo - Default Portal (redirect)",
        content_mode=PortalContentMode.REDIRECT,
        background_image_url=BG_DEFAULT,
        primary_color=DEMO_PRIMARY_COLOR,
        secondary_color=DEMO_SECONDARY_COLOR,
        splash_headline="Welcome to Wyfy Guest",
        splash_welcome_message="Free, fast guest WiFi.",
        content_heading="Visit our website",
        redirect_url="https://wyfyguest.com/welcome",
    ),
    DemoPortalConfigSpec(
        location_slug="brew-and-bytes-cafe",
        name="Brew & Bytes Cafe Portal",
        content_mode=PortalContentMode.IMAGE,
        background_image_url=BG_CAFE,
        primary_color="#B5651D",
        secondary_color="#E0A066",
        splash_headline="Welcome to Brew & Bytes",
        splash_welcome_message="Grab a coffee and hop online.",
        content_heading="Today at Brew & Bytes",
        content_image_url=IMG_CAFE_PROMO,
    ),
    DemoPortalConfigSpec(
        location_slug="grand-horizon-hotel",
        name="The Grand Horizon Hotel Portal",
        content_mode=PortalContentMode.TEXT,
        background_image_url=BG_HOTEL,
        primary_color="#16386B",
        secondary_color="#3F6FAE",
        splash_headline="Welcome, valued guest",
        splash_welcome_message="Complimentary high-speed WiFi awaits.",
        content_heading="A warm welcome to The Grand Horizon",
        content_body=HOTEL_WELCOME_BODY,
    ),
    DemoPortalConfigSpec(
        location_slug="nexus-coworking-hub",
        name="Nexus Coworking Hub Portal",
        content_mode=PortalContentMode.SURVEY,
        background_image_url=BG_COWORKING,
        primary_color="#6D28D9",
        secondary_color="#22D3EE",
        splash_headline="Welcome to Nexus",
        splash_welcome_message="Two quick questions, then you're online.",
        content_heading="Before you connect",
        content_survey=NEXUS_SURVEY,
    ),
]


@dataclass
class DemoPortalSeedResult:
    organization_found: bool = False
    branding_created: bool = False
    configs_created: int = 0
    configs_existing: int = 0
    warnings: list[str] = field(default_factory=list)


async def ensure_branding(
    branding_repository: BrandingRepository,
    *,
    organization_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
) -> bool:
    """Insert a branding row for the demo org, only if one does not already
    exist. ``upsert`` would overwrite an existing row's fields; this seeder
    is insert-only, so it checks first and returns early on a re-run."""
    existing = await branding_repository.get_by_organization(organization_id)
    if existing is not None:
        return False
    await branding_repository.upsert(
        organization_id,
        {
            "company_name": "Wyfy Demo",
            "logo_url": DEMO_LOGO_URL,
            "primary_color": DEMO_PRIMARY_COLOR,
            "secondary_color": DEMO_SECONDARY_COLOR,
            "accent_color": DEMO_SECONDARY_COLOR,
            "theme": "light",
        },
        actor_user_id=actor_user_id,
    )
    return True


async def ensure_portal_configs(
    cp_repository: CaptivePortalRepository,
    location_repository: LocationRepository,
    *,
    organization_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
    result: DemoPortalSeedResult,
) -> None:
    for spec in DEMO_PORTAL_CONFIGS:
        is_default = spec.location_slug is None
        location_id: uuid.UUID | None = None

        if not is_default:
            location = await location_repository.get_by_slug(
                organization_id, spec.location_slug
            )
            if location is None:
                result.warnings.append(
                    f"location '{spec.location_slug}' not found -- skipped "
                    f"portal config '{spec.name}' (run seed_demo.py first)."
                )
                continue
            location_id = location.id
            existing = await cp_repository.find_active_for_location(
                organization_id, location_id
            )
        else:
            existing = await cp_repository.find_default_for_organization(
                organization_id
            )

        if existing is not None:
            result.configs_existing += 1
            continue

        await cp_repository.create_config(
            organization_id=organization_id,
            location_id=location_id,
            name=spec.name,
            is_active=True,
            is_default=is_default,
            primary_color=spec.primary_color,
            secondary_color=spec.secondary_color,
            background_image_url=spec.background_image_url,
            splash_headline=spec.splash_headline,
            splash_welcome_message=spec.splash_welcome_message,
            redirect_url=spec.redirect_url,
            content_mode=spec.content_mode.value,
            content_heading=spec.content_heading,
            content_body=spec.content_body,
            content_image_url=spec.content_image_url,
            content_survey=spec.content_survey,
            created_by=actor_user_id,
        )
        result.configs_created += 1


async def run_seed_demo_portal(session) -> DemoPortalSeedResult:
    """Seed branding + captive portal configs for the demo org against
    ``session``. Does not commit -- the CLI entrypoint owns the transaction
    boundary, mirroring ``seed_demo.py``."""
    result = DemoPortalSeedResult()

    org_repository = OrganizationRepository(session)
    org = await org_repository.get_by_slug(DEMO_ORG_SLUG)
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
    demo_user = await AuthRepository(session).get_user_by_email("demo@wyfyguest.com")
    if demo_user is not None:
        actor_user_id = demo_user.id

    branding_repository = BrandingRepository(session)
    result.branding_created = await ensure_branding(
        branding_repository,
        organization_id=org.id,
        actor_user_id=actor_user_id,
    )

    cp_repository = CaptivePortalRepository(session)
    location_repository = LocationRepository(session)
    await ensure_portal_configs(
        cp_repository,
        location_repository,
        organization_id=org.id,
        actor_user_id=actor_user_id,
        result=result,
    )
    return result


async def _main_async() -> None:
    async with SessionLocal() as session:
        result = await run_seed_demo_portal(session)
        await session.commit()

    logger.info("seed_demo_portal_completed", extra={"result": result})
    lines: list[str] = []
    if not result.organization_found:
        lines.append("Demo organization NOT found -- nothing seeded.")
    else:
        lines.append(
            f"Branding: {'created' if result.branding_created else 'already existed'}"
        )
        lines.append(
            f"Captive portal configs: +{result.configs_created} new, "
            f"{result.configs_existing} already existed"
        )
    for warning in result.warnings:
        lines.append(f"WARNING: {warning}")
    print("\n".join(lines))  # noqa: T201 -- CLI entrypoint output


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Seed captive-portal configs (one per content mode) and branding "
            "for the Wyfy Demo tenant so the dashboard's Portal Settings and "
            "branding surfaces render populated. Requires scripts/seed_demo.py "
            "to have run first. Safe to re-run."
        )
    )
    parser.parse_args(argv)
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
