"""Read-only aggregate queries for the Security domain.

## Why this domain reads other domains' tables

The alternative -- one duck-typed ``Protocol`` per data source, each satisfied
by another domain's service -- would mean seven collaborator dependencies on
one read endpoint, seven more places to keep in step, and no way to answer
"what is this venue's posture" in fewer than seven round trips.

``app.domains.analytics.repository`` is the established precedent for the
other reading: a domain whose job is to *aggregate* imports the models it
aggregates, read-only, and rolls the arithmetic up in SQL. This module does
exactly that, and only that. It issues no ``INSERT``, ``UPDATE`` or ``DELETE``,
and it never constructs a device adapter -- so it cannot write to a router even
by accident. ``tests/unit/test_security.py`` asserts the read-only property
against the module's own source.

## ``agent_managed_only`` on every ``routers`` read

The fleet counters here are heartbeat-based, and only agent-managed routers
have a heartbeat: a controller-managed (Omada) venue is reached through its
controller, not through ``router_agent_credentials``. Counting one as a stale
MikroTik would report a working venue as a broken one. So every statement that
reads ``routers`` is narrowed with
``app.domains.router.fleet_scope.agent_managed_only``, which is also what
``tests/unit/test_router_read_vendor_coverage.py`` requires of every
router-reading call site.

"Last agent contact" is read from ``router_agent_credentials.last_used_at``
rather than ``routers.last_seen_at``, on ``Router.last_seen_at``'s own
documented instruction: the credential's ``last_used_at`` is written on *every*
device-authenticated request, including the 60-second authorized-MACs poll,
where ``last_seen_at`` only moves with the 5-minute heartbeat. Measuring
staleness from the slower signal would report a working venue as stale roughly
a third of the time.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.content_filtering.constants import (
    ContentFilterDevicePushStatus,
    ContentFilterValueType,
)
from app.domains.content_filtering.models import ContentFilterRule
from app.domains.dhcp.constants import RogueDhcpAlertState
from app.domains.dhcp.models import RouterRogueDhcpStatus
from app.domains.firewall.models import FirewallRule
from app.domains.guest_access.constants import AccessRuleType
from app.domains.guest_access.models import DeviceAccessRule
from app.domains.monitoring.constants import AlertStatus
from app.domains.monitoring.models import Alert
from app.domains.router.enums import RouterHealthStatus
from app.domains.router.fleet_scope import agent_managed_only
from app.domains.router.models import Router
from app.domains.router_agent.models import RouterAgentCredential
from app.domains.wireguard.constants import PeerStatus
from app.domains.wireguard.models import WireGuardPeer

__all__ = [
    "BlockCounts",
    "DeviceRuleCounts",
    "FleetCounts",
    "RogueDhcpCounts",
    "RuleCounts",
    "SecurityRepository",
    "SecurityRepositoryProtocol",
    "VpnPeerCounts",
]


@dataclass(frozen=True, slots=True)
class FleetCounts:
    """Agent-managed gateway health, counted from credential activity."""

    total: int
    reporting: int
    stale: int
    unhealthy: int


@dataclass(frozen=True, slots=True)
class VpnPeerCounts:
    total: int
    active: int


@dataclass(frozen=True, slots=True)
class BlockCounts:
    """Enabled blocks, split by the mechanism they compile to, plus whether
    they actually reached a device.

    ``enabled_not_applied`` is the honest number behind the dashboard's
    "Applied" badge: a rule can be enabled and still never have been pushed
    (see ``ContentFilterDevicePushStatus``'s own docstring for the incident
    that column was added to stop repeating)."""

    domains_enabled: int
    addresses_enabled: int
    enabled_not_applied: int
    failed: int


@dataclass(frozen=True, slots=True)
class RuleCounts:
    total: int
    enabled: int


@dataclass(frozen=True, slots=True)
class DeviceRuleCounts:
    active_blocks: int
    active_allowlists: int


@dataclass(frozen=True, slots=True)
class RogueDhcpCounts:
    """``unknown`` is kept separate from ``unguarded`` on purpose -- see
    ``RogueDhcpAlertState``'s own "three states, because two would lie"."""

    guarded: int
    unguarded: int
    unknown: int


class SecurityRepositoryProtocol(Protocol):
    """Every read is scoped by organization and, when the caller names one, by
    location -- see ``_scoped`` for why they are applied in one place rather
    than at each call site."""

    async def fleet_counts(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        stale_after_minutes: int,
    ) -> FleetCounts: ...

    async def vpn_peer_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> VpnPeerCounts: ...

    async def block_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> BlockCounts: ...

    async def firewall_rule_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> RuleCounts: ...

    async def device_rule_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> DeviceRuleCounts: ...

    async def rogue_dhcp_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> RogueDhcpCounts: ...

    async def open_alert_count(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> int: ...


def _scoped(
    statement: Select,
    model: type,
    organization_id: uuid.UUID | None,
    location_id: uuid.UUID | None,
) -> Select:
    """Apply the tenant filters and the soft-delete filter together.

    All three are always wanted, so they are applied in one place rather than
    at each call site: a query that forgets ``is_deleted`` silently
    overcounts, and one that forgets the venue filter reports an
    organization-wide number on a single venue's own page -- the more
    misleading of the two, because nothing about the number looks wrong.

    ``location_id`` is optional because a platform-scoped caller (Super Admin)
    legitimately reads across venues. A customer surface always sends it,
    since its own page is already scoped to one venue."""
    statement = statement.where(model.is_deleted.is_(False))  # type: ignore[attr-defined]
    if organization_id is not None:
        statement = statement.where(model.organization_id == organization_id)
    if location_id is not None:
        statement = statement.where(model.location_id == location_id)
    return statement


class SecurityRepository:
    """Concrete read-only implementation. See the module docstring."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _scalar(self, statement: Select) -> int:
        result = await self._session.execute(statement)
        return int(result.scalar_one() or 0)

    def _agent_managed_router_count_base(
        self, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> Select:
        """The one ``routers`` read in this module, narrowed once.

        Every caller adds its own ``WHERE`` and counts, so the vendor question
        -- and the soft-delete filter, and the outer join to the agent
        credential -- are answered here rather than re-decided per count. That
        is also what ``tests/unit/test_router_read_vendor_coverage.py`` asks
        for: one classified call site instead of four.

        ``RouterAgentCredential`` is an outer join on purpose: a router that
        has never checked in has no credential row at all, and that router is
        the *most* stale one there is. An inner join would drop it and hide
        the worst case.
        """
        statement = (
            select(func.count())
            .select_from(Router)
            .outerjoin(
                RouterAgentCredential,
                RouterAgentCredential.router_id == Router.id,
            )
            .where(Router.is_deleted.is_(False))
        )
        if organization_id is not None:
            statement = statement.where(
                Router.organization_id == organization_id
            )
        if location_id is not None:
            statement = statement.where(Router.location_id == location_id)
        return agent_managed_only(statement)

    async def fleet_counts(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        stale_after_minutes: int,
    ) -> FleetCounts:
        cutoff = datetime.now(UTC) - timedelta(minutes=stale_after_minutes)
        base = self._agent_managed_router_count_base(organization_id, location_id)

        total = await self._scalar(base)
        stale = await self._scalar(
            base.where(
                or_(
                    RouterAgentCredential.last_used_at.is_(None),
                    RouterAgentCredential.last_used_at < cutoff,
                )
            )
        )
        # health_status is NULL until the first check ever runs, which is
        # "unknown", not "unhealthy" -- see RouterHealthStatus. Counting an
        # unknown as unhealthy would fail a venue for not having been
        # inspected yet.
        unhealthy = await self._scalar(
            base.where(
                Router.health_status == RouterHealthStatus.UNHEALTHY.value
            )
        )
        return FleetCounts(
            total=total,
            reporting=max(0, total - stale),
            stale=stale,
            unhealthy=unhealthy,
        )

    async def vpn_peer_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> VpnPeerCounts:
        """``wireguard_peers`` carries no organization of its own -- a peer
        belongs to a router -- so an organization-scoped count has to go
        through ``routers``, the same shape ``rogue_dhcp_counts`` uses below.

        Every peer belongs to an agent-managed router by construction (the
        tunnel *is* the agent path), but ``agent_managed_only`` is applied
        anyway: this statement reads ``routers``, and the vendor question is
        one to answer explicitly rather than to assume."""

        def base() -> Select:
            statement = (
                select(func.count())
                .select_from(WireGuardPeer)
                .join(Router, Router.id == WireGuardPeer.router_id)
                .where(WireGuardPeer.is_deleted.is_(False))
                .where(Router.is_deleted.is_(False))
            )
            if organization_id is not None:
                statement = statement.where(
                    Router.organization_id == organization_id
                )
            if location_id is not None:
                statement = statement.where(Router.location_id == location_id)
            return agent_managed_only(statement)

        total = await self._scalar(base())
        active = await self._scalar(
            base().where(WireGuardPeer.status == PeerStatus.ACTIVE.value)
        )
        return VpnPeerCounts(total=total, active=active)

    async def block_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> BlockCounts:
        def base() -> Select:
            return _scoped(
                select(func.count()).select_from(ContentFilterRule),
                ContentFilterRule,
                organization_id,
                location_id,
            )

        en = ContentFilterRule.is_enabled.is_(True)
        applied = (
            ContentFilterRule.device_push_status
            == ContentFilterDevicePushStatus.ACTIVE.value
        )
        domains = await self._scalar(
            base().where(
                en,
                ContentFilterRule.value_type
                == ContentFilterValueType.DOMAIN.value,
            )
        )
        addresses = await self._scalar(
            base().where(
                en,
                ContentFilterRule.value_type
                == ContentFilterValueType.IP_CIDR.value,
            )
        )
        not_applied = await self._scalar(base().where(en, ~applied))
        failed = await self._scalar(
            base().where(
                ContentFilterRule.device_push_status
                == ContentFilterDevicePushStatus.FAILED.value
            )
        )
        return BlockCounts(
            domains_enabled=domains,
            addresses_enabled=addresses,
            enabled_not_applied=not_applied,
            failed=failed,
        )

    async def firewall_rule_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> RuleCounts:
        total = await self._scalar(
            _scoped(
                select(func.count()).select_from(FirewallRule),
                FirewallRule,
                organization_id,
                location_id,
            )
        )
        enabled = await self._scalar(
            _scoped(
                select(func.count())
                .select_from(FirewallRule)
                .where(FirewallRule.is_enabled.is_(True)),
                FirewallRule,
                organization_id,
                location_id,
            )
        )
        return RuleCounts(total=total, enabled=enabled)

    async def device_rule_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> DeviceRuleCounts:
        active = DeviceAccessRule.is_active.is_(True)
        blocks = await self._scalar(
            _scoped(
                select(func.count())
                .select_from(DeviceAccessRule)
                .where(
                    active,
                    DeviceAccessRule.rule_type == AccessRuleType.BLOCKLIST.value,
                ),
                DeviceAccessRule,
                organization_id,
                location_id,
            )
        )
        allowlists = await self._scalar(
            _scoped(
                select(func.count())
                .select_from(DeviceAccessRule)
                .where(
                    active,
                    DeviceAccessRule.rule_type == AccessRuleType.WHITELIST.value,
                ),
                DeviceAccessRule,
                organization_id,
                location_id,
            )
        )
        return DeviceRuleCounts(active_blocks=blocks, active_allowlists=allowlists)

    async def rogue_dhcp_counts(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> RogueDhcpCounts:
        # RouterRogueDhcpStatus is keyed on (router_id, interface) and has no
        # organization_id of its own, so an organization-scoped count has to
        # go through its routers.
        #
        # Agent-managed only: a rogue-DHCP alert is a RouterOS
        # ``/ip dhcp-server alert`` row, a construct a controller-managed
        # venue does not have. Counting a controller's absent alerts as
        # unguarded interfaces would report a working venue as an exposed one.
        def base() -> Select:
            statement = select(func.count()).select_from(RouterRogueDhcpStatus)
            # The join is needed for a location filter even when no
            # organization is named -- this row set has neither column, so
            # either filter has to come from `routers`.
            if organization_id is not None or location_id is not None:
                statement = statement.join(
                    Router, Router.id == RouterRogueDhcpStatus.router_id
                )
                if organization_id is not None:
                    statement = statement.where(
                        Router.organization_id == organization_id
                    )
                if location_id is not None:
                    statement = statement.where(
                        Router.location_id == location_id
                    )
            return agent_managed_only(statement)

        guarded = await self._scalar(
            base().where(
                RouterRogueDhcpStatus.alert_state
                == RogueDhcpAlertState.GUARDED.value
            )
        )
        unguarded = await self._scalar(
            base().where(
                RouterRogueDhcpStatus.alert_state
                == RogueDhcpAlertState.UNGUARDED.value
            )
        )
        unknown = await self._scalar(
            base().where(
                RouterRogueDhcpStatus.alert_state
                == RogueDhcpAlertState.UNKNOWN.value
            )
        )
        return RogueDhcpCounts(
            guarded=guarded, unguarded=unguarded, unknown=unknown
        )

    async def open_alert_count(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> int:
        """Alerts that are triggered or acknowledged, i.e. not yet resolved.

        ``ACKNOWLEDGED`` is counted as open, deliberately: acknowledging an
        alert records that a human has seen it, not that the condition has
        stopped. Treating it as closed would let a venue's pressure drop to
        zero while the fault is still live."""
        statement = select(func.count()).select_from(Alert).where(
            Alert.status.in_(
                (AlertStatus.TRIGGERED.value, AlertStatus.ACKNOWLEDGED.value)
            )
        )
        statement = _scoped(statement, Alert, organization_id, location_id)
        return await self._scalar(statement)
