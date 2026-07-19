"""Pydantic response schemas for BE-012 Part 4's Business Analytics endpoint
(``GET /analytics/business``).

Follows this domain's own ``dashboard_schemas.py``/``domain_analytics_schemas
.py`` conventions exactly. Customer Growth reuses ``GrowthPointResponse``
directly (the same shape Part 2's growth figures already use -- no new
schema needed for a real, already-modeled concept). Plan Distribution is its
own, real schema (a genuine ``GROUP BY Organization.subscription_tier``
result, not a placeholder).

Revenue Trends / Subscription Trends / Churn Rate / Renewal Rate / License
Utilization are honest ``available: false`` placeholders -- there is no
billing/subscription/payment domain anywhere in this codebase (confirmed
repeatedly across BE-012 Parts 2-3; ``Organization.subscription_tier`` is a
lightweight, unpopulated label with zero pricing/entitlement logic behind
it, per Module 005's own documented decision). Each mirrors
``dashboard_schemas.RevenueMetricsResponse``'s exact honesty posture
(``available: bool``, every numeric field ``None``, an explanatory
``message``) -- but is its own schema, not a verbatim reuse, since the
fields genuinely differ: Revenue Trends/Subscription Trends want a **list**
shape (a trend is inherently a time series -- mirroring
``CountryStatisticsResponse.by_country``'s own "unavailable list" precedent
rather than ``RevenueMetricsResponse``'s scalar shape), while Churn
Rate/Renewal Rate/License Utilization are naturally **scalar** percentages
and reuse ``RevenueMetricsResponse``'s exact scalar shape most directly.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .dashboard_schemas import GrowthPointResponse

__all__ = [
    "PlanDistributionItem",
    "PlanDistributionResponse",
    "RevenueTrendsResponse",
    "SubscriptionTrendsResponse",
    "ChurnRateResponse",
    "RenewalRateResponse",
    "LicenseUtilizationResponse",
    "BusinessAnalyticsResponse",
]


class PlanDistributionItem(BaseModel):
    tier: str = Field(
        description="Organization.subscription_tier's real value, or the "
        "literal string 'unset' for organizations where it is NULL."
    )
    organization_count: int


class PlanDistributionResponse(BaseModel):
    """A real ``GROUP BY Organization.subscription_tier`` result -- reports
    whatever the actual distribution is, even though the field is known to
    be sparsely populated in practice (see module docstring). Never skipped
    just because the underlying data happens to be unimpressive."""

    available: bool = True
    total_organizations: int
    populated_organizations: int
    unset_organizations: int
    by_tier: list[PlanDistributionItem]
    message: str | None = None


class RevenueTrendsResponse(BaseModel):
    """Honest placeholder -- see module docstring. Shaped as a trend list
    (mirroring ``CountryStatisticsResponse.by_country``) since a genuine
    Revenue Trends figure is inherently a time series, not one scalar."""

    available: bool = False
    trend: list[dict[str, object]] = Field(default_factory=list)
    message: str = (
        "Not available: no billing/subscription/payment domain exists in "
        "this codebase. Organization.subscription_tier is a lightweight "
        "label only (see app.domains.organization.models.Organization's "
        "module docstring) with no pricing/entitlement logic behind it."
    )


class SubscriptionTrendsResponse(BaseModel):
    """Honest placeholder -- same reasoning and shape as
    :class:`RevenueTrendsResponse`. There is also no historical snapshot of
    ``subscription_tier`` distribution over time anywhere in this codebase
    (``AnalyticsSnapshot`` never captured a per-tier breakdown), so even a
    real *count* of tier changes over time cannot be honestly derived --
    only the current-moment distribution (:class:`PlanDistributionResponse`)
    is real."""

    available: bool = False
    trend: list[dict[str, object]] = Field(default_factory=list)
    message: str = (
        "Not available: no billing/subscription domain exists in this "
        "codebase, and no historical snapshot of subscription_tier "
        "distribution over time exists to derive a trend from -- only the "
        "current-moment distribution (plan_distribution, above) is real."
    )


class ChurnRateResponse(BaseModel):
    """Honest placeholder -- mirrors ``RevenueMetricsResponse``'s exact
    scalar shape (this is naturally a single percentage, not a list)."""

    available: bool = False
    churn_rate_percent: float | None = None
    message: str = (
        "Not available: churn requires a real subscription-cancellation "
        "event with a timestamp, which does not exist anywhere in this "
        "codebase -- there is no billing/subscription/payment domain to "
        "derive it from."
    )


class RenewalRateResponse(BaseModel):
    available: bool = False
    renewal_rate_percent: float | None = None
    message: str = (
        "Not available: renewal requires a real subscription-renewal event "
        "with a timestamp, which does not exist anywhere in this codebase "
        "-- there is no billing/subscription/payment domain to derive it "
        "from."
    )


class LicenseUtilizationResponse(BaseModel):
    available: bool = False
    utilization_percent: float | None = None
    message: str = (
        "Not available: license utilization requires a real, purchased "
        "license/seat-count entitlement to measure usage against, which "
        "does not exist anywhere in this codebase -- there is no billing/"
        "subscription/payment domain to derive it from."
    )


class BusinessAnalyticsResponse(BaseModel):
    customer_growth: GrowthPointResponse
    plan_distribution: PlanDistributionResponse
    revenue_trends: RevenueTrendsResponse
    subscription_trends: SubscriptionTrendsResponse
    churn_rate: ChurnRateResponse
    renewal_rate: RenewalRateResponse
    license_utilization: LicenseUtilizationResponse

    model_config = ConfigDict(arbitrary_types_allowed=True)
