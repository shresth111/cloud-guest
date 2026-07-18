"""Organization Health Score (BE-012 Part 2: Organization Dashboard).

**This is a heuristic composite score, not a scientific/statistical
measure.** It is a weighted combination of three real, already-available
signals this codebase actually has -- it is presented to the caller as
exactly that (a documented, best-effort heuristic), never as more rigorous
than it is.

## The exact formula

::

    health_score = round(
        0.50 * router_health_component
      + 0.30 * alert_health_component
      + 0.20 * growth_health_component
    )

Clamped to ``[0, 100]``. The three components:

1. **Router health component (weight 0.50)** -- the percentage of the
   organization's own routers currently ``ONLINE`` (see
   ``app.domains.router.enums.RouterStatus``), out of every non-deleted
   router the organization owns. An organization with zero routers scores
   ``100`` on this component (there is nothing unhealthy to detect -- an
   organization that has not yet deployed any router should not be penalized
   for a router fleet that does not exist).

2. **Alert health component (weight 0.30)** -- ``100`` minus a penalty
   accumulated from the organization's own currently-*open* (non-``RESOLVED``,
   see ``app.domains.monitoring.constants.AlertStatus``) alerts, weighted by
   severity (``app.domains.monitoring.constants.AlertSeverity``):
   ``CRITICAL`` costs 25 points each, ``WARNING`` costs 10, ``INFO`` costs 3.
   The total penalty is capped at 100 (the component floors at 0, it never
   goes negative). This captures both "severity" (a single critical alert
   already costs a quarter of this component) and, indirectly, "how many
   things are currently wrong" (more open alerts of any severity compound).
   It does not weight by *recency* beyond "still open" -- there is no
   continuous alert-age decay function in this codebase's data to draw a
   real one from, and inventing a decay curve with no real data to calibrate
   it against would be exactly the kind of unjustified precision this
   module's own documented "heuristic, not scientific" posture argues
   against.

3. **Growth health component (weight 0.20)** -- the *sign* of the
   organization's guest-count trend (comparing the current period's unique
   guest count, from ``AnalyticsSnapshot`` history, against the immediately
   preceding period of equal length): ``100`` if growing, ``70`` if flat
   (unchanged), ``40`` if declining. Only the direction is used (never the
   magnitude) -- see ``GrowthDirection``, reused from ``dashboard_aggregation
   .compute_growth``'s own trend classification, so "growth" means the exact
   same thing here as it does on every other growth figure this dashboard
   reports.

## Why these three inputs, and why these weights

Router uptime is weighted highest (0.50) because it is the most directly
actionable, most objective signal of "is this organization's deployed
infrastructure currently working" -- a router being offline is an
unambiguous, real fact, not an interpretation. Alerts (0.30) capture
everything the platform's own monitoring domain has already judged worth
surfacing (including signals *besides* router connectivity -- SLA breaches,
provisioning failures, whatever else an ``AlertRule`` watches), so it adds
information the router component alone would miss, but is weighted below it
because an alert can be lower-severity/informational and because some
alert-worthy conditions (a note, a soft warning) are less unambiguously "this
organization is unhealthy" than an offline router is. Growth (0.20) is
weighted lowest: a *declining* guest count is a real signal worth surfacing,
but is the most business/context-dependent of the three (a seasonal
business's low season is not the same as a genuinely churning organization)
and the least directly "healthy infrastructure" flavored, so it moves the
score the least. These weights are a documented judgment call, not derived
from any statistical fit -- there is no historical health-score-vs-actual-
outcome dataset in this codebase to calibrate against, and this module does
not pretend otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

ROUTER_HEALTH_WEIGHT = 0.50
ALERT_HEALTH_WEIGHT = 0.30
GROWTH_HEALTH_WEIGHT = 0.20

ALERT_SEVERITY_PENALTY = {
    "critical": 25.0,
    "warning": 10.0,
    "info": 3.0,
}
MAX_ALERT_PENALTY = 100.0


class GrowthDirection(StrEnum):
    GROWING = "growing"
    FLAT = "flat"
    DECLINING = "declining"
    UNKNOWN = "unknown"


_GROWTH_COMPONENT_SCORE = {
    GrowthDirection.GROWING: 100.0,
    GrowthDirection.FLAT: 70.0,
    GrowthDirection.DECLINING: 40.0,
    # No prior-period data to compare against -- treated as neutral rather
    # than penalizing an organization purely for being new / lacking history.
    GrowthDirection.UNKNOWN: 70.0,
}


@dataclass(frozen=True, slots=True)
class HealthScoreResult:
    """The composite score plus each contributing component, so a caller can
    show *why* the score is what it is, not just the final number."""

    score: int
    router_health_component: float
    alert_health_component: float
    growth_health_component: float
    router_online_count: int
    router_total_count: int
    open_alert_penalty: float
    growth_direction: GrowthDirection


def compute_router_health_component(*, online_count: int, total_count: int) -> float:
    if total_count <= 0:
        return 100.0
    return max(0.0, min(100.0, (online_count / total_count) * 100.0))


def compute_alert_health_component(
    open_alert_counts_by_severity: dict[str, int],
) -> tuple[float, float]:
    """Returns ``(component_score, raw_penalty)``."""
    penalty = sum(
        ALERT_SEVERITY_PENALTY.get(severity, 0.0) * count
        for severity, count in open_alert_counts_by_severity.items()
    )
    capped_penalty = min(penalty, MAX_ALERT_PENALTY)
    return max(0.0, 100.0 - capped_penalty), capped_penalty


def compute_growth_health_component(direction: GrowthDirection) -> float:
    return _GROWTH_COMPONENT_SCORE[direction]


def compute_health_score(
    *,
    router_online_count: int,
    router_total_count: int,
    open_alert_counts_by_severity: dict[str, int],
    growth_direction: GrowthDirection,
) -> HealthScoreResult:
    router_component = compute_router_health_component(
        online_count=router_online_count, total_count=router_total_count
    )
    alert_component, penalty = compute_alert_health_component(
        open_alert_counts_by_severity
    )
    growth_component = compute_growth_health_component(growth_direction)

    weighted = (
        ROUTER_HEALTH_WEIGHT * router_component
        + ALERT_HEALTH_WEIGHT * alert_component
        + GROWTH_HEALTH_WEIGHT * growth_component
    )
    score = max(0, min(100, round(weighted)))
    return HealthScoreResult(
        score=score,
        router_health_component=router_component,
        alert_health_component=alert_component,
        growth_health_component=growth_component,
        router_online_count=router_online_count,
        router_total_count=router_total_count,
        open_alert_penalty=penalty,
        growth_direction=growth_direction,
    )


__all__ = [
    "ROUTER_HEALTH_WEIGHT",
    "ALERT_HEALTH_WEIGHT",
    "GROWTH_HEALTH_WEIGHT",
    "ALERT_SEVERITY_PENALTY",
    "MAX_ALERT_PENALTY",
    "GrowthDirection",
    "HealthScoreResult",
    "compute_router_health_component",
    "compute_alert_health_component",
    "compute_growth_health_component",
    "compute_health_score",
]
