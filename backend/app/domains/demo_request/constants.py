"""Enumerations for the Demo Request domain.

``DemoRequestStatus``/``DemoRequestPropertyType`` are both stored as plain
``String`` columns, never a native PostgreSQL enum type -- the same reason
every other domain in this codebase documents (see e.g.
``app.domains.support_tickets.constants``): adding a new status/vertical
never requires an ``ALTER TYPE`` migration, only a code change.
"""

from __future__ import annotations

from enum import StrEnum


class DemoRequestStatus(StrEnum):
    """The internal team's own tracking states for a submitted demo
    request -- distinct from a support ticket's lifecycle (there is no
    "resolved"/"closed-won" ambiguity to model here, just where the lead
    currently sits in the outbound follow-up flow)."""

    NEW = "new"
    CONTACTED = "contacted"
    SCHEDULED = "scheduled"
    CLOSED = "closed"


class DemoRequestPropertyType(StrEnum):
    """The prospect's own vertical, self-selected on the public "Book a
    Demo" form. Values mirror the real taxonomy wyfy-guest-website already
    markets to (one blog post per vertical under
    ``src/content/blog/guest-wifi-for-*``, plus the hotel/cafe comparison
    post) -- a bounded enum, not an unbounded free-text field, so the
    Master console can actually filter/triage a queue by it (see
    ``repository.py``'s ``_list_filters``). ``OTHER`` is the deliberate
    escape hatch for a real prospect whose property doesn't fit any listed
    vertical -- the free-text ``message`` field still carries whatever
    detail matters for that case."""

    HOTEL = "hotel"
    PG_CO_LIVING = "pg_co_living"
    CAFE_RESTAURANT = "cafe_restaurant"
    COWORKING_SPACE = "coworking_space"
    COLLEGE_UNIVERSITY = "college_university"
    GYM_FITNESS = "gym_fitness"
    SALON_SPA = "salon_spa"
    RETAIL_MALL = "retail_mall"
    BANK_SERVICE_BRANCH = "bank_service_branch"
    GATED_COMMUNITY = "gated_community"
    HOSPITAL_CLINIC = "hospital_clinic"
    EVENT_VENUE = "event_venue"
    OTHER = "other"


class DemoRequestLeadPriority(StrEnum):
    """A computed (never stored) triage signal -- see ``schemas
    .compute_lead_priority`` for the actual tiering logic and why it is
    derived on read rather than persisted as its own column. Tier names
    deliberately echo the language of wyfyguest.com's own real pricing
    tiers (``src/pages/pricing.astro`` on the marketing site: Starter ->
    "one location", Professional -> "multiple routers", Business ->
    "multiple locations under one account", Enterprise -> "larger groups
    of properties") so a Master console operator can read a lead's
    priority as "this looks like a $TIER-shaped prospect" without
    translating units."""

    UNKNOWN = "unknown"
    SINGLE_SITE = "single_site"
    MULTI_ROUTER_SINGLE_SITE = "multi_router_single_site"
    MULTI_LOCATION = "multi_location"
    ENTERPRISE = "enterprise"


__all__ = [
    "DemoRequestStatus",
    "DemoRequestPropertyType",
    "DemoRequestLeadPriority",
]
