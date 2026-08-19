"""Pydantic request/response schemas for the Demo Request API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict(from_attributes=True)``, explicit ``Field`` descriptions,
``field_validator``-checked status values -- see
``app.domains.support_tickets.schemas``) and is wrapped in the project's
standard ``ApiResponse``/``build_response`` envelope by ``router.py``.

``DemoRequestCreateRequest`` (the public form submission) carries no
``status``/``internal_notes`` fields at all -- those are Master-console-only
and set exclusively by ``DemoRequestUpdateRequest``, mirroring
``TicketCreateRequest``'s own "the submitter's request body can never set
admin-only fields" posture.

``lead_priority`` is deliberately **not** a request field anywhere -- it is
a read-only signal computed by ``compute_lead_priority`` from
``location_count``/``router_count`` and exposed only on
``DemoRequestResponse``. Storing it as its own column would let it drift
from the fields it's derived from (e.g. an operator correcting
``location_count`` via a future update path without also recomputing a
stale priority); computing it on every read makes that class of bug
impossible.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .constants import (
    DemoRequestLeadPriority,
    DemoRequestPropertyType,
    DemoRequestStatus,
)

__all__ = [
    "DemoRequestCreateRequest",
    "DemoRequestUpdateRequest",
    "DemoRequestResponse",
    "DemoRequestListResponse",
    "compute_lead_priority",
]

_ALLOWED_STATUSES = {s.value for s in DemoRequestStatus}
_ALLOWED_PROPERTY_TYPES = {p.value for p in DemoRequestPropertyType}

# Upper bounds on the self-reported integer fields -- generous enough to
# never reject a real prospect (Wyfy Guest's largest real customers today
# are low hundreds of locations/routers), tight enough to reject obvious
# garbage/abuse input on a public, unauthenticated endpoint. Not a business
# rule, just sanity bounds -- see DemoRequestCreateRequest's own fields.
_MAX_LOCATION_COUNT = 100_000
_MAX_ROUTER_COUNT = 1_000_000

# ============================================================================
# Lead priority: computed, never stored -- see this module's own docstring.
# ============================================================================

# Thresholds mirror wyfyguest.com's own real pricing-tier language
# (src/pages/pricing.astro on the marketing site):
#   Starter      -- "For one location"
#   Professional -- "For multiple routers" (still one location)
#   Business     -- "For multiple locations under one account"
#   Enterprise   -- "For larger groups of properties"
# There is no public, authoritative cutoff for "multiple locations" vs.
# "larger groups of properties" -- 10 is a deliberately simple, documented
# line sales can move later without touching any stored data (this is a
# triage signal, not a scoring algorithm).
_MULTI_LOCATION_MIN = 2
_ENTERPRISE_LOCATION_MIN = 11
_MULTI_ROUTER_MIN = 2


def compute_lead_priority(
    location_count: int | None, router_count: int | None
) -> DemoRequestLeadPriority:
    """Tier a lead from its self-reported ``location_count``/
    ``router_count`` alone -- a simple, explainable triage signal, not a
    scoring model. Rules, in order:

    1. Neither field known -> ``UNKNOWN`` (most demo requests today --
       both fields are optional and the free-text ``message`` may be all
       a prospect gave).
    2. ``location_count`` known and >= ``_ENTERPRISE_LOCATION_MIN`` ->
       ``ENTERPRISE``.
    3. ``location_count`` known and >= ``_MULTI_LOCATION_MIN`` ->
       ``MULTI_LOCATION``.
    4. Otherwise the prospect looks single-site (``location_count`` is 0/1,
       or unknown but a router count was still given) -- ``router_count``
       then decides between ``MULTI_ROUTER_SINGLE_SITE`` (>= 2 routers,
       Professional-shaped) and ``SINGLE_SITE`` (Starter-shaped).
    """
    if location_count is None and router_count is None:
        return DemoRequestLeadPriority.UNKNOWN

    if location_count is not None:
        if location_count >= _ENTERPRISE_LOCATION_MIN:
            return DemoRequestLeadPriority.ENTERPRISE
        if location_count >= _MULTI_LOCATION_MIN:
            return DemoRequestLeadPriority.MULTI_LOCATION

    # Single-site (or location unknown, decided by router count alone).
    if router_count is not None and router_count >= _MULTI_ROUTER_MIN:
        return DemoRequestLeadPriority.MULTI_ROUTER_SINGLE_SITE
    return DemoRequestLeadPriority.SINGLE_SITE


# ============================================================================
# Request schemas
# ============================================================================


class DemoRequestCreateRequest(BaseModel):
    """The public "Book a Demo" form submission -- no auth, no platform
    identity. ``email`` is validated as a real address by ``EmailStr``
    (requires the ``email-validator`` package, already a dependency via
    ``app.domains.auth.schemas``'s own identical use)."""

    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr = Field(..., description="Work email address")
    phone: str | None = Field(default=None, max_length=30)
    company_name: str = Field(..., min_length=1, max_length=255)
    message: str | None = Field(
        default=None,
        max_length=5_000,
        description="What the prospect is looking for -- optional free text.",
    )
    property_type: str | None = Field(
        default=None,
        description=(
            "The prospect's own vertical -- one of "
            "DemoRequestPropertyType, e.g. 'hotel', 'cafe_restaurant'."
        ),
    )
    location_count: int | None = Field(
        default=None,
        ge=0,
        le=_MAX_LOCATION_COUNT,
        description="Number of properties/locations the prospect has.",
    )
    router_count: int | None = Field(
        default=None,
        ge=0,
        le=_MAX_ROUTER_COUNT,
        description=(
            "Number of routers/APs, if known -- optional and often less "
            "certain than location_count."
        ),
    )

    @field_validator("property_type")
    @classmethod
    def validate_property_type(cls, value: str | None) -> str | None:
        if value is not None and value not in _ALLOWED_PROPERTY_TYPES:
            raise ValueError(
                f"property_type must be one of {sorted(_ALLOWED_PROPERTY_TYPES)}"
            )
        return value


class DemoRequestUpdateRequest(BaseModel):
    """Master-console-only fields -- status/internal notes. Both optional
    so a caller can update just one at a time, mirroring
    ``TicketUpdateRequest``'s identical partial-update shape."""

    status: str | None = Field(default=None)
    internal_notes: str | None = Field(default=None, max_length=5_000)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str | None) -> str | None:
        if value is not None and value not in _ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {sorted(_ALLOWED_STATUSES)}")
        return value


# ============================================================================
# Response schemas
# ============================================================================


class DemoRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    full_name: str
    email: str
    phone: str | None
    company_name: str
    message: str | None
    property_type: str | None
    location_count: int | None
    router_count: int | None
    lead_priority: DemoRequestLeadPriority
    status: str
    internal_notes: str | None
    submitted_at: datetime
    updated_at: datetime


class DemoRequestListResponse(BaseModel):
    items: list[DemoRequestResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
