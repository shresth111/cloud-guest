"""Pydantic response schemas for the Security domain API.

Follows the same pydantic v2 conventions as ``app.domains.mac_authorization
.schemas``: plain ``str`` for every UUID, explicit builder functions in
``router.py`` doing the ``str(...)`` conversion rather than
``ConfigDict(from_attributes=True)`` auto-mapping, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.

There is no request schema in this module. The whole domain is read-only in
this pass; ``tests/unit/test_security.py`` asserts that no write route exists
on its router, so the absence of a request model is a property under test
rather than an oversight.

## Why ``available`` and ``unavailable_reason`` are separate fields

Every counter carries both. A ``count`` of ``0`` is only meaningful when the
source was actually read; when a source could not be read, the honest answer
is "we do not know", which is not the number zero. Collapsing the two into a
nullable count would push that distinction onto every consumer and guarantee
at least one of them renders an unknown as a zero.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

from .constants import SecurityAvailability, SecurityScoreBand

__all__ = [
    "MessageResponse",
    "SecurityCounterResponse",
    "SecurityFleetSummaryResponse",
    "SecurityScoreFactorResponse",
    "SecurityScoreResponse",
    "SecurityOverviewResponse",
    "SecurityFeatureResponse",
    "SecurityCapabilityListResponse",
]


class SecurityCounterResponse(BaseModel):
    """One headline number, with its own availability.

    ``available=False`` means the source could not be read or does not apply
    here; ``key`` is a stable identifier so the dashboard can map a counter
    to its own copy without matching on a display label.
    """

    key: str
    label: str
    count: int | None
    available: bool
    unavailable_reason: str | None = None
    #: Where the number came from, in one line, so a support conversation
    #: starts from the source rather than from the screenshot.
    source: str | None = None


class SecurityFleetSummaryResponse(BaseModel):
    """Fleet and infrastructure health, as the venue's own dashboard saw it."""

    routers_total: int
    routers_reporting: int
    routers_stale: int
    routers_unhealthy: int
    vpn_peers_active: int
    vpn_peers_total: int
    #: True when no agent-managed gateway exists for this scope, in which case
    #: every infrastructure figure above is ``0`` by absence rather than by
    #: health, and the dashboard must say so instead of showing green.
    no_managed_gateway: bool


class SecurityScoreFactorResponse(BaseModel):
    """One term of the score, itemised so the number is never unexplained."""

    key: str
    label: str
    penalty: int
    max_penalty: int
    affected: int
    available: bool
    detail: str


class SecurityScoreResponse(BaseModel):
    score: int | None
    band: SecurityScoreBand | None
    max_score: int
    available: bool
    unavailable_reason: str | None = None
    factors: list[SecurityScoreFactorResponse] = Field(default_factory=list)
    computed_at: datetime


class SecurityOverviewResponse(BaseModel):
    """The Security Overview page in one response.

    ``generated_at`` is returned so the UI can show the age of what it is
    displaying; a posture page whose numbers could be hours old and says
    nothing about it reads as live.
    """

    score: SecurityScoreResponse
    counters: list[SecurityCounterResponse]
    fleet: SecurityFleetSummaryResponse
    generated_at: datetime


class SecurityFeatureResponse(BaseModel):
    """One row of the capability matrix -- see ``constants.SECURITY_FEATURES``."""

    key: str
    label: str
    availability: SecurityAvailability
    enforcement: str | None
    detail: str


class SecurityCapabilityListResponse(BaseModel):
    """What this platform can and cannot enforce, for the venue's gateways.

    Served from the API rather than hardcoded in the dashboard for the reason
    the whole module exists: when a capability changes, exactly one place
    changes, and a dashboard cannot keep advertising a feature the backend
    has stopped claiming.
    """

    features: list[SecurityFeatureResponse]
