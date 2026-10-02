"""Security posture service -- read-only aggregation and the score model.

## What the score is

A subtraction from a clean slate, where every term is a fact this platform
already stores: whether the fleet is reporting, whether enabled blocks actually
reached a device, whether the DHCP guard is on, whether anything is already
alerting. The platform's own management tunnel is deliberately not a term: it
is this platform's plumbing, not a venue's control, and this page is served to
the venue (see ``constants``' "What this domain never shows a venue").

Each term is returned itemised with its own penalty so the number can always
be explained rather than asserted -- "your score is 82" is only useful with
"because three gateways stopped reporting".

It is a diagnostic of this platform's own configuration hygiene, not a measure
of threat. Nothing here observes an attack, so nothing here claims to.

## Availability is a first-class answer

Every counter and every score carries its own availability, and a score cannot
be produced at all for a scope with no agent-managed gateway -- there is no
posture to measure, and reporting 100 would render an unmonitored venue as a
hardened one. The two headline threat counters are returned as explicitly
unavailable, with the missing pipeline named, because this platform has no
event capture: a dashboard that showed "0 threats blocked" for a venue nobody
is watching would be the exact lie the security brief forbids.

## Read-only, enforced by construction

This service takes exactly one collaborator: a repository of aggregate read
queries. It has no device adapter, no audit writer, and no session of its own to
write through, so no code path in it can change a database row -- let alone a
router's firewall.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domains.monitoring.constants import ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES

from .constants import (
    MIN_ROUTERS_FOR_SCORE,
    SCORE_FACTOR_WEIGHTS,
    SECURITY_FEATURES,
    SECURITY_SCORE_MAX,
    ScoreFactorKey,
    SecurityAvailability,
    feature_by_key,
    score_band_for,
)
from .repository import (
    BlockCounts,
    FleetCounts,
    SecurityRepositoryProtocol,
)
from .schemas import (
    SecurityCapabilityListResponse,
    SecurityCounterResponse,
    SecurityFeatureResponse,
    SecurityFleetSummaryResponse,
    SecurityOverviewResponse,
    SecurityScoreFactorResponse,
    SecurityScoreResponse,
)

__all__ = ["SecurityOverviewService"]


#: Factors that need a denominator to become a rate. Everything else is a
#: straight count, because "3 gateways are silent" does not become more or less
#: true depending on how many gateways exist.
_RATE_FACTORS = frozenset(
    {
        ScoreFactorKey.FLEET_REPORTING,
        ScoreFactorKey.BLOCK_PUSH_INTEGRITY,
        ScoreFactorKey.ROGUE_DHCP_GUARD,
    }
)


def _rate_penalty(
    key: ScoreFactorKey, affected: int, denominator: int
) -> int:
    """Penalty for one factor, capped at that factor's maximum.

    A rate factor with no denominator has nothing to be a rate *of* -- zero
    blocks configured is not a push failure, and zero checked interfaces is not
    an unguarded one -- so it scores no penalty rather than dividing by zero.

    That guard belongs *inside* the rate branch and nowhere else. Applied on
    entry it would also zero every count factor, since those are called with no
    denominator at all: ``min(cap, per * affected)`` would collapse to zero and
    a venue with unresolved alerts would score a clean slate.
    """
    per_occurrence, max_penalty = SCORE_FACTOR_WEIGHTS[key]
    if key in _RATE_FACTORS:
        if denominator <= 0:
            return 0
        return min(max_penalty, round(per_occurrence * affected / denominator))
    return min(max_penalty, per_occurrence * affected)


class SecurityOverviewService:
    """Builds the Security Overview and the capability matrix."""

    def __init__(self, repository: SecurityRepositoryProtocol) -> None:
        self._repository = repository

    async def build_overview(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        requesting_location_id: uuid.UUID | None,
    ) -> SecurityOverviewResponse:
        blocks = await self._repository.block_counts(
            organization_id=requesting_organization_id,
            location_id=requesting_location_id,
        )
        fleet = await self._repository.fleet_counts(
            organization_id=requesting_organization_id,
            location_id=requesting_location_id,
            stale_after_minutes=ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES,
        )
        rules = await self._repository.firewall_rule_counts(
            organization_id=requesting_organization_id,
            location_id=requesting_location_id,
        )
        devices = await self._repository.device_rule_counts(
            organization_id=requesting_organization_id,
            location_id=requesting_location_id,
        )
        rogue = await self._repository.rogue_dhcp_counts(
            organization_id=requesting_organization_id,
            location_id=requesting_location_id,
        )
        open_alerts = await self._repository.open_alert_count(
            organization_id=requesting_organization_id,
            location_id=requesting_location_id,
        )

        score = self._build_score(
            fleet=fleet, blocks=blocks, rogue_unguarded=rogue.unguarded,
            rogue_total=rogue.guarded + rogue.unguarded + rogue.unknown,
            open_alerts=open_alerts,
        )

        return SecurityOverviewResponse(
            score=score,
            counters=self._build_counters(
                blocks=blocks,
                rules_enabled=rules.enabled,
                blocked_devices=devices.active_blocks,
                rogue_unguarded=rogue.unguarded,
                open_alerts=open_alerts,
            ),
            fleet=SecurityFleetSummaryResponse(
                routers_total=fleet.total,
                routers_reporting=fleet.reporting,
                routers_stale=fleet.stale,
                routers_unhealthy=fleet.unhealthy,
                no_managed_gateway=fleet.total < MIN_ROUTERS_FOR_SCORE,
            ),
            generated_at=datetime.now(UTC),
        )

    async def build_score(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        requesting_location_id: uuid.UUID | None,
    ) -> SecurityScoreResponse:
        overview = await self.build_overview(
            requesting_organization_id=requesting_organization_id,
            requesting_location_id=requesting_location_id,
        )
        return overview.score

    def capabilities(self) -> SecurityCapabilityListResponse:
        """The capability matrix, served from one place.

        The dashboard renders from this rather than hardcoding a feature list,
        so a capability can only be advertised where it can be enforced.
        """
        return SecurityCapabilityListResponse(
            features=[
                SecurityFeatureResponse(
                    key=feature.key,
                    label=feature.label,
                    availability=feature.availability,
                    enforcement=feature.enforcement,
                    detail=feature.detail,
                )
                for feature in SECURITY_FEATURES
            ]
        )

    # -- internals ---------------------------------------------------------

    def _build_score(
        self,
        *,
        fleet: FleetCounts,
        blocks: BlockCounts,
        rogue_unguarded: int,
        rogue_total: int,
        open_alerts: int,
    ) -> SecurityScoreResponse:
        now = datetime.now(UTC)

        if fleet.total < MIN_ROUTERS_FOR_SCORE:
            # No agent-managed gateway means no posture to score. Naming the
            # reason is the point: an absent measurement and a perfect one are
            # different answers and must not share a rendering.
            return SecurityScoreResponse(
                score=None,
                band=None,
                max_score=SECURITY_SCORE_MAX,
                available=False,
                unavailable_reason=(
                    "No managed gateway is attached, so there is no security "
                    "posture to score yet."
                ),
                factors=[],
                computed_at=now,
            )

        factors: list[SecurityScoreFactorResponse] = [
            SecurityScoreFactorResponse(
                key=ScoreFactorKey.FLEET_REPORTING.value,
                label="Gateways reporting",
                penalty=_rate_penalty(
                    ScoreFactorKey.FLEET_REPORTING, fleet.stale, fleet.total
                ),
                max_penalty=SCORE_FACTOR_WEIGHTS[ScoreFactorKey.FLEET_REPORTING][1],
                affected=fleet.stale,
                available=True,
                detail=(
                    f"{fleet.reporting} of {fleet.total} gateways checked in "
                    f"within the last "
                    f"{ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES} minutes."
                ),
            ),
            SecurityScoreFactorResponse(
                key=ScoreFactorKey.BLOCK_PUSH_INTEGRITY.value,
                label="Blocks applied to the gateway",
                penalty=_rate_penalty(
                    ScoreFactorKey.BLOCK_PUSH_INTEGRITY,
                    blocks.enabled_not_applied,
                    blocks.domains_enabled + blocks.addresses_enabled,
                ),
                max_penalty=SCORE_FACTOR_WEIGHTS[
                    ScoreFactorKey.BLOCK_PUSH_INTEGRITY
                ][1],
                affected=blocks.enabled_not_applied,
                available=True,
                detail=(
                    "Enabled blocks that have not reached a gateway are not "
                    "blocking anything yet."
                    if blocks.enabled_not_applied
                    else "Every enabled block has reached its gateway."
                ),
            ),
            SecurityScoreFactorResponse(
                key=ScoreFactorKey.ROGUE_DHCP_GUARD.value,
                label="Rogue DHCP guard",
                penalty=_rate_penalty(
                    ScoreFactorKey.ROGUE_DHCP_GUARD, rogue_unguarded, rogue_total
                ),
                max_penalty=SCORE_FACTOR_WEIGHTS[ScoreFactorKey.ROGUE_DHCP_GUARD][1],
                affected=rogue_unguarded,
                available=True,
                detail=(
                    f"{rogue_unguarded} interface(s) hand out addresses with "
                    "nothing watching for a second DHCP server."
                    if rogue_unguarded
                    else "Every checked interface is guarded."
                ),
            ),
            SecurityScoreFactorResponse(
                key=ScoreFactorKey.ALERT_PRESSURE.value,
                label="Unresolved alerts",
                penalty=_rate_penalty(
                    ScoreFactorKey.ALERT_PRESSURE, open_alerts, 0
                ),
                max_penalty=SCORE_FACTOR_WEIGHTS[ScoreFactorKey.ALERT_PRESSURE][1],
                affected=open_alerts,
                available=True,
                detail=(
                    f"{open_alerts} alert(s) are triggered or acknowledged and "
                    "not yet resolved."
                ),
            ),
        ]

        total_penalty = sum(factor.penalty for factor in factors)
        score = max(0, SECURITY_SCORE_MAX - total_penalty)
        return SecurityScoreResponse(
            score=score,
            band=score_band_for(score),
            max_score=SECURITY_SCORE_MAX,
            available=True,
            factors=factors,
            computed_at=now,
        )

    def _build_counters(
        self,
        *,
        blocks: BlockCounts,
        rules_enabled: int,
        blocked_devices: int,
        rogue_unguarded: int,
        open_alerts: int,
    ) -> list[SecurityCounterResponse]:
        return [
            SecurityCounterResponse(
                key="blocked_domains",
                label="Blocked domains",
                count=blocks.domains_enabled,
                available=True,
                source="content_filter_rules (value_type=domain, enabled)",
            ),
            SecurityCounterResponse(
                key="blocked_addresses",
                label="Blocked IP addresses",
                count=blocks.addresses_enabled,
                available=True,
                source="content_filter_rules (value_type=ip_cidr, enabled)",
            ),
            SecurityCounterResponse(
                key="blocks_not_applied",
                label="Blocks not yet applied",
                count=blocks.enabled_not_applied,
                available=True,
                source="content_filter_rules.device_push_status",
            ),
            SecurityCounterResponse(
                key="blocked_devices",
                label="Blocked devices",
                count=blocked_devices,
                available=True,
                source="device_access_rules (active blocklist rules)",
            ),
            SecurityCounterResponse(
                key="firewall_rules",
                label="Firewall rules",
                count=rules_enabled,
                available=True,
                source="firewall_rules (enabled)",
            ),
            SecurityCounterResponse(
                key="rogue_dhcp_unguarded",
                label="Interfaces without a DHCP guard",
                count=rogue_unguarded,
                available=True,
                source="router_rogue_dhcp_statuses (alert_state=unguarded)",
            ),
            SecurityCounterResponse(
                key="open_alerts",
                label="Unresolved alerts",
                count=open_alerts,
                available=True,
                source="alerts (status=triggered or acknowledged)",
            ),
            # The brief's two headline numbers. This platform has no event
            # capture -- not a firewall log pipeline, not a syslog collector --
            # so there is no source for either, and they are returned as
            # explicitly unavailable with the missing piece named. A zero here
            # would read as "we looked and found nothing", which is false.
            SecurityCounterResponse(
                key="threats_detected",
                label="Threats detected",
                count=None,
                available=False,
                unavailable_reason=(
                    "This platform does not collect gateway log events, so no "
                    "threat count can be produced. Firewall rule hit counters "
                    "are readable per rule and are not an event stream."
                ),
                source=None,
            ),
            SecurityCounterResponse(
                key="threats_blocked",
                label="Threats blocked",
                count=None,
                available=False,
                unavailable_reason=(
                    "Requires the same event capture as threats detected. "
                    "Configured blocks are reported separately, and each says "
                    "whether it has reached a gateway."
                ),
                source=None,
            ),
        ]


def is_available(feature_key: str) -> SecurityAvailability:
    """Small helper for callers that gate on one capability.

    Raises ``KeyError`` for an unknown key rather than defaulting to
    available: a typo silently granting a capability is precisely the failure
    mode this module's matrix exists to make impossible.
    """
    return feature_by_key()[feature_key].availability
