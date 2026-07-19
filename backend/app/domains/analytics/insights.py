"""Insight Engine (BE-012 Part 4): a real, deterministic RULE ENGINE.

**This is explicitly NOT an AI system.** Every function below is a plain,
pure Python function: real, already-aggregated numbers go in (guest/customer
growth percentages, alert counts, router CPU history, ...), and either an
:class:`Insight` (a human-readable message plus a severity) or ``None``
comes out -- no LLM call, no generated free text beyond simple, deterministic
string formatting of real numbers against real, configurable thresholds
(``app.core.config.Settings`` -- see ``docs/analytics/FLOW.md`` for the
exact rule-to-threshold cross-reference). This module is "AI-ready" only in
the sense the module brief itself uses the term: a real LLM integration
could later enhance or *replace* this text generation with something more
sophisticated -- it does not claim to already BE one, and no AI provider of
any kind is invoked, mocked, or configured anywhere in this codebase.

## Two families of rules

* **Business Insights** (``rule_customer_growth``/``rule_guest_growth``/
  ``rule_plan_distribution_coverage``) -- fire over growth/business-adjacent
  real data: platform-wide customer (organization) count trend, platform-wide
  guest count trend, and ``Organization.subscription_tier`` population
  coverage. Composed by ``insight_service.InsightService
  .get_business_insights`` (``GET /analytics/insights/business``).
* **Operational Recommendations** (``rule_offline_routers``/
  ``rule_location_guest_volume_drop``/``rule_rising_router_cpu``/
  ``rule_persistent_critical_alerts``) -- fire over monitoring/router/network
  real data: routers offline past a duration threshold (per organization),
  a location's week-over-week guest-volume drop, a router's consecutive
  rising-CPU streak, and organizations with aged, still-open CRITICAL
  alerts. Composed by ``InsightService.get_operational_recommendations``
  (``GET /analytics/insights/operational``).

Every rule is exercised in
``tests/unit/test_analytics_forecast_insights.py`` for BOTH outcomes: a
constructed input that should fire, and one (just below/at the threshold)
that should not.

## Why "3 organizations have had 2+ CRITICAL alerts..." becomes N separate insights

The module brief's own illustrative example phrases this rule as one
platform-wide rolled-up sentence ("3 organizations have had..."). This
engine instead emits **one insight per qualifying organization**
(``rule_persistent_critical_alerts`` is called once per organization that
meets the count/age threshold, each carrying its own real count) -- the same
one-item-per-qualifying-entity shape every other Operational Recommendation
rule already uses (``rule_offline_routers`` per organization,
``rule_location_guest_volume_drop`` per location,
``rule_rising_router_cpu`` per router). This is a deliberate, documented
consistency choice: a caller (dashboard or, eventually, a real LLM consuming
this engine's output) always gets one addressable, per-entity finding per
rule, never a mix of aggregate-sentence rules and per-entity rules that would
need different downstream handling.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "InsightSeverity",
    "Insight",
    "rule_customer_growth",
    "rule_guest_growth",
    "rule_plan_distribution_coverage",
    "rule_offline_routers",
    "rule_location_guest_volume_drop",
    "rule_rising_router_cpu",
    "rule_persistent_critical_alerts",
]


class InsightSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Insight:
    rule: str
    severity: InsightSeverity
    message: str


# ============================================================================
# Business Insight rules
# ============================================================================


def rule_customer_growth(
    *,
    delta_percent: float | None,
    direction: str,
    significant_percent_threshold: float,
) -> Insight | None:
    """Fires when the platform's organization count has grown or shrunk by
    at least ``significant_percent_threshold`` (absolute value) over the
    comparison period -- ``severity`` is ``INFO`` for growth, ``WARNING``
    for decline (a shrinking customer base is worth a human's attention)."""
    if delta_percent is None or abs(delta_percent) < significant_percent_threshold:
        return None
    severity = (
        InsightSeverity.INFO if direction == "increasing" else InsightSeverity.WARNING
    )
    verb = "increased" if direction == "increasing" else "decreased"
    return Insight(
        rule="customer_growth",
        severity=severity,
        message=(
            f"Customer (organization) count {verb} {abs(delta_percent):.1f}% "
            f"over the comparison period."
        ),
    )


def rule_guest_growth(
    *,
    delta_percent: float | None,
    direction: str,
    significant_percent_threshold: float,
) -> Insight | None:
    """Same shape as :func:`rule_customer_growth`, for platform-wide unique
    guest count."""
    if delta_percent is None or abs(delta_percent) < significant_percent_threshold:
        return None
    severity = (
        InsightSeverity.INFO if direction == "increasing" else InsightSeverity.WARNING
    )
    verb = "increased" if direction == "increasing" else "decreased"
    return Insight(
        rule="guest_growth",
        severity=severity,
        message=(
            f"Guest growth {verb} {abs(delta_percent):.1f}% over the "
            f"comparison period."
        ),
    )


def rule_plan_distribution_coverage(
    *,
    populated_count: int,
    total_count: int,
    min_coverage_percent_threshold: float,
) -> Insight | None:
    """Fires (``INFO``) when fewer than ``min_coverage_percent_threshold``
    percent of organizations have a populated ``subscription_tier`` -- an
    honest signal that Plan Distribution reporting is not yet meaningful,
    rather than silently presenting a mostly-``"unset"`` breakdown without
    comment. Does not fire when ``total_count`` is ``0`` (nothing to report
    coverage over) or when coverage already meets the threshold."""
    if total_count == 0:
        return None
    coverage_percent = populated_count / total_count * 100.0
    if coverage_percent >= min_coverage_percent_threshold:
        return None
    return Insight(
        rule="plan_distribution_coverage",
        severity=InsightSeverity.INFO,
        message=(
            f"Only {coverage_percent:.0f}% of organizations have a "
            f"subscription_tier set ({populated_count}/{total_count}); Plan "
            f"Distribution reporting is not yet meaningful platform-wide."
        ),
    )


# ============================================================================
# Operational Recommendation rules
# ============================================================================


def rule_offline_routers(
    *,
    organization_id: uuid.UUID,
    organization_name: str,
    offline_count: int,
    hours_threshold: int,
    count_threshold: int,
    critical_count_threshold: int,
) -> Insight | None:
    """Fires when an organization has at least ``count_threshold`` routers
    that have been offline for over ``hours_threshold`` hours -- escalates
    to ``CRITICAL`` at/above ``critical_count_threshold``."""
    if offline_count < count_threshold:
        return None
    severity = (
        InsightSeverity.CRITICAL
        if offline_count >= critical_count_threshold
        else InsightSeverity.WARNING
    )
    return Insight(
        rule="offline_routers",
        severity=severity,
        message=(
            f"Organization '{organization_name}' has {offline_count} "
            f"router(s) offline for over {hours_threshold} hours."
        ),
    )


def rule_location_guest_volume_drop(
    *,
    location_id: uuid.UUID,
    location_name: str,
    delta_percent: float | None,
    drop_percent_threshold: float,
) -> Insight | None:
    """Fires (``WARNING``) when a location's guest session volume dropped
    at least ``drop_percent_threshold`` percent versus the immediately
    preceding period of equal length. ``delta_percent`` is negative for a
    decline (``dashboard_aggregation.compute_growth``'s own sign
    convention) -- fires when ``delta_percent <= -drop_percent_threshold``."""
    if delta_percent is None or delta_percent > -drop_percent_threshold:
        return None
    return Insight(
        rule="location_guest_volume_drop",
        severity=InsightSeverity.WARNING,
        message=(
            f"Location '{location_name}' guest volume dropped "
            f"{abs(delta_percent):.1f}% week-over-week."
        ),
    )


def rule_rising_router_cpu(
    *,
    router_id: uuid.UUID,
    router_name: str,
    consecutive_rises: int,
    consecutive_threshold: int,
    first_value: float,
    last_value: float,
) -> Insight | None:
    """Fires (``WARNING``) when a router's CPU usage has risen on at least
    ``consecutive_threshold`` consecutive readings in a row (see
    ``trends.count_trailing_consecutive_increases``) -- a simple monotonic-
    run check, distinct from (and cheaper than) the Forecast Engine's own
    linear-regression slope signal, answering "has this been rising every
    single recent reading" rather than "what is the average rate of rise"."""
    if consecutive_rises < consecutive_threshold:
        return None
    return Insight(
        rule="rising_router_cpu",
        severity=InsightSeverity.WARNING,
        message=(
            f"Router '{router_name}' has shown rising CPU usage for "
            f"{consecutive_rises} consecutive readings "
            f"({first_value:.0f}% -> {last_value:.0f}%)."
        ),
    )


def rule_persistent_critical_alerts(
    *,
    organization_id: uuid.UUID,
    organization_name: str,
    count: int,
    count_threshold: int,
    age_hours_threshold: int,
) -> Insight | None:
    """Fires (``CRITICAL``) when an organization has at least
    ``count_threshold`` CRITICAL-severity alerts that have been open
    (non-``RESOLVED``) for over ``age_hours_threshold`` hours -- see module
    docstring for why this is one insight per qualifying organization
    rather than one rolled-up platform-wide sentence."""
    if count < count_threshold:
        return None
    return Insight(
        rule="persistent_critical_alerts",
        severity=InsightSeverity.CRITICAL,
        message=(
            f"Organization '{organization_name}' has {count} CRITICAL "
            f"alert(s) open for over {age_hours_threshold} hours."
        ),
    )
