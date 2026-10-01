"""Persistence for security activity: the counter collector's writes and the
activity view's reads.

Kept apart from ``repository.SecurityRepository`` on purpose. That class is
read-only by construction and its module docstring says so; this one writes
``security_counter_samples`` (and nothing else), and only ever from the
Celery collector.

Every read takes the caller's ``organization_id`` and applies it in SQL,
together with an optional location filter that is either one id or the list
of sites a location-confined caller may see -- never a path id taken on
trust (``wyfy_path_id_scoping_defect``).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.domains.auth.models import User
from app.domains.content_filtering.models import ContentFilterRule
from app.domains.dns_filtering.models import (
    DnsFilteringProfile,
    DnsFilteringRouterLocation,
)
from app.domains.firewall.models import FirewallRule
from app.domains.guest_access.constants import AccessRuleType
from app.domains.guest_access.models import DeviceAccessRouterBlock, DeviceAccessRule
from app.domains.rbac.models import AuditLogEntry
from app.domains.router.fleet_scope import agent_managed_only
from app.domains.router.models import Router

from .models import SecurityCounterSample

__all__ = [
    "SECURITY_AUDIT_ACTIONS",
    "CloudflareScope",
    "LocationFilter",
    "CollectionTarget",
    "PreviousSample",
    "ProtectionTotals",
    "RuleTotals",
    "SecurityActivityRepository",
    "StaffChange",
]

LocationFilter = uuid.UUID | Sequence[uuid.UUID] | None

#: Audit actions that are a staff member changing a protection. Values of
#: ``app.domains.rbac.enums.AuditAction`` -- strings here so a renamed enum
#: member fails ``test_security_activity`` rather than silently matching
#: nothing.
SECURITY_AUDIT_ACTIONS: tuple[str, ...] = (
    "firewall_rule_created",
    "firewall_rule_updated",
    "firewall_rule_deleted",
    "firewall_rules_pushed",
    "firewall_flood_limit_changed",
    "content_filter_rule_created",
    "content_filter_rule_updated",
    "content_filter_rule_deleted",
    "dns_filtering_policy_updated",
    "dns_filtering_enabled",
    "dns_filtering_disabled",
    "dns_filtering_bypass_hardening_changed",
    "guest_access_rule_created",
    "guest_access_rule_deleted",
    "guest_access_rules_imported",
    "connected_device_blocked",
    "connected_device_unblocked",
    "mac_authorization_entry_created",
    "mac_authorization_entry_updated",
    "mac_authorization_entry_deleted",
)


@dataclass(frozen=True, slots=True)
class CollectionTarget:
    router_id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    host: str | None
    api_username: str | None
    api_credentials_encrypted: str | bytes | None


@dataclass(frozen=True, slots=True)
class PreviousSample:
    packets_total: int
    bytes_total: int
    sampled_at: datetime


@dataclass(frozen=True, slots=True)
class ProtectionTotals:
    protection: str
    packets: int
    routers: int
    last_sampled_at: datetime | None


@dataclass(frozen=True, slots=True)
class RuleTotals:
    protection: str
    label: str
    packets: int


@dataclass(frozen=True, slots=True)
class StaffChange:
    at: datetime
    action: str
    description: str | None
    actor_name: str | None


@dataclass(frozen=True, slots=True)
class CloudflareScope:
    """The Cloudflare Gateway locations behind this scope's routers, split
    by whether counts at that location can be attributed to this scope.

    A Gateway location is shared by every router whose category set is the
    same (``DnsFilteringProfile`` is keyed by a fingerprint of the
    categories), and Cloudflare's analytics cannot tell those routers apart.
    A location shared with a router outside the scope is therefore
    ``shared``: its count would include other venues' guests."""

    exclusive_location_ids: list[str]
    shared_location_ids: list[str]
    routers_filtering: int


def _location_condition(column: ColumnElement, location: LocationFilter):
    if location is None:
        return None
    if isinstance(location, uuid.UUID):
        return column == location
    return column.in_(list(location))


class SecurityActivityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- collector -------------------------------------------------------------

    async def list_collection_router_ids(self) -> list[uuid.UUID]:
        """Every agent-managed router with stored API credentials -- the
        counter sweep's fan-out list. A controller-managed row has no
        RouterOS API and is never loaded (contract 11.5)."""
        result = await self.session.execute(
            agent_managed_only(
                select(Router.id).where(
                    Router.is_deleted.is_(False),
                    Router.api_credentials_encrypted.is_not(None),
                    Router.api_username.is_not(None),
                )
            ).order_by(Router.id)
        )
        return list(result.scalars().all())

    async def get_collection_target(
        self, router_id: uuid.UUID
    ) -> CollectionTarget | None:
        """One router's connection material, or ``None`` when it is gone,
        controller-managed, or has no credentials."""
        result = await self.session.execute(
            agent_managed_only(
                select(
                    Router.id,
                    Router.organization_id,
                    Router.location_id,
                    Router.management_ip_address,
                    Router.public_ip_address,
                    Router.api_username,
                    Router.api_credentials_encrypted,
                ).where(Router.id == router_id, Router.is_deleted.is_(False))
            )
        )
        row = result.first()
        if row is None:
            return None
        return CollectionTarget(
            router_id=row.id,
            organization_id=row.organization_id,
            location_id=row.location_id,
            host=row.management_ip_address or row.public_ip_address,
            api_username=row.api_username,
            api_credentials_encrypted=row.api_credentials_encrypted,
        )

    async def latest_samples(self, router_id: uuid.UUID) -> dict[str, PreviousSample]:
        """The most recent stored totals per rule on this router -- what the
        next read is diffed against."""
        result = await self.session.execute(
            select(
                SecurityCounterSample.rule_key,
                SecurityCounterSample.packets_total,
                SecurityCounterSample.bytes_total,
                SecurityCounterSample.sampled_at,
            )
            .where(SecurityCounterSample.router_id == router_id)
            .distinct(SecurityCounterSample.rule_key)
            .order_by(
                SecurityCounterSample.rule_key, SecurityCounterSample.sampled_at.desc()
            )
        )
        return {
            row.rule_key: PreviousSample(
                packets_total=int(row.packets_total),
                bytes_total=int(row.bytes_total),
                sampled_at=row.sampled_at,
            )
            for row in result.all()
        }

    async def upsert_sample(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID,
        protection: str,
        rule_key: str,
        label: str,
        bucket_start: datetime,
        sampled_at: datetime,
        packets_total: int,
        bytes_total: int,
        packets_delta: int,
        bytes_delta: int,
    ) -> None:
        """Add this sample's delta to its hour's row (creating it), and move
        the row's stored totals to this read."""
        table = SecurityCounterSample.__table__
        statement = pg_insert(table).values(
            id=uuid.uuid4(),
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
            protection=protection,
            rule_key=rule_key,
            label=label,
            bucket_start=bucket_start,
            sampled_at=sampled_at,
            packets_total=packets_total,
            bytes_total=bytes_total,
            packets_delta=packets_delta,
            bytes_delta=bytes_delta,
        )
        statement = statement.on_conflict_do_update(
            index_elements=["router_id", "rule_key", "bucket_start"],
            set_={
                "label": statement.excluded.label,
                "protection": statement.excluded.protection,
                "sampled_at": statement.excluded.sampled_at,
                "packets_total": statement.excluded.packets_total,
                "bytes_total": statement.excluded.bytes_total,
                "packets_delta": table.c.packets_delta
                + statement.excluded.packets_delta,
                "bytes_delta": table.c.bytes_delta + statement.excluded.bytes_delta,
            },
        )
        await self.session.execute(statement)

    async def rule_names(
        self,
        *,
        organization_id: uuid.UUID,
        firewall_rule_ids: Sequence[str],
        content_filter_rule_ids: Sequence[str],
    ) -> dict[str, str]:
        """The venue's own names for the platform rows a router comment
        points at, keyed by id. Scoped to the router's organization so a
        comment can never pull another tenant's rule name."""
        names: dict[str, str] = {}

        def ids(values: Sequence[str]) -> list[uuid.UUID]:
            out: list[uuid.UUID] = []
            for value in values:
                try:
                    out.append(uuid.UUID(value))
                except ValueError:
                    continue
            return out

        fw_ids = ids(firewall_rule_ids)
        if fw_ids:
            result = await self.session.execute(
                select(FirewallRule.id, FirewallRule.name).where(
                    FirewallRule.id.in_(fw_ids),
                    FirewallRule.organization_id == organization_id,
                )
            )
            names.update({str(r.id): r.name for r in result.all()})
        cf_ids = ids(content_filter_rule_ids)
        if cf_ids:
            result = await self.session.execute(
                select(
                    ContentFilterRule.id,
                    ContentFilterRule.name,
                    ContentFilterRule.value,
                ).where(
                    ContentFilterRule.id.in_(cf_ids),
                    ContentFilterRule.organization_id == organization_id,
                )
            )
            names.update({str(r.id): r.name or r.value for r in result.all()})
        return names

    # -- activity view -----------------------------------------------------------

    async def protection_totals(
        self,
        *,
        organization_id: uuid.UUID,
        location: LocationFilter,
        since: datetime,
    ) -> list[ProtectionTotals]:
        conditions = [
            SecurityCounterSample.organization_id == organization_id,
            SecurityCounterSample.bucket_start >= since,
        ]
        where_location = _location_condition(
            SecurityCounterSample.location_id, location
        )
        if where_location is not None:
            conditions.append(where_location)
        result = await self.session.execute(
            select(
                SecurityCounterSample.protection,
                func.coalesce(func.sum(SecurityCounterSample.packets_delta), 0),
                func.count(func.distinct(SecurityCounterSample.router_id)),
                func.max(SecurityCounterSample.sampled_at),
            )
            .where(*conditions)
            .group_by(SecurityCounterSample.protection)
        )
        return [
            ProtectionTotals(
                protection=row[0],
                packets=int(row[1] or 0),
                routers=int(row[2] or 0),
                last_sampled_at=row[3],
            )
            for row in result.all()
        ]

    async def top_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location: LocationFilter,
        since: datetime,
        limit: int = 30,
    ) -> list[RuleTotals]:
        conditions = [
            SecurityCounterSample.organization_id == organization_id,
            SecurityCounterSample.bucket_start >= since,
        ]
        where_location = _location_condition(
            SecurityCounterSample.location_id, location
        )
        if where_location is not None:
            conditions.append(where_location)
        total = func.sum(SecurityCounterSample.packets_delta)
        result = await self.session.execute(
            select(
                SecurityCounterSample.protection,
                SecurityCounterSample.label,
                total,
            )
            .where(*conditions)
            .group_by(SecurityCounterSample.protection, SecurityCounterSample.label)
            .having(total > 0)
            .order_by(total.desc())
            .limit(limit)
        )
        return [
            RuleTotals(protection=row[0], label=row[1], packets=int(row[2] or 0))
            for row in result.all()
        ]

    async def agent_managed_router_count(
        self, *, organization_id: uuid.UUID, location: LocationFilter
    ) -> int:
        """How many routers in scope the collector could be reading -- the
        denominator for "N of M routers reported". A count only."""
        statement = agent_managed_only(
            select(func.count())
            .select_from(Router)
            .where(
                Router.organization_id == organization_id,
                Router.is_deleted.is_(False),
            )
        )
        where_location = _location_condition(Router.location_id, location)
        if where_location is not None:
            statement = statement.where(where_location)
        return int((await self.session.execute(statement)).scalar_one() or 0)

    async def device_block_counts(
        self,
        *,
        organization_id: uuid.UUID,
        location: LocationFilter,
        since: datetime,
    ) -> tuple[int, int]:
        """(devices blocked right now, devices newly blocked on a router in
        the window). ip-binding rows have no hit counter, so this is the
        honest number: how many, not how often."""
        active = (
            select(func.count())
            .select_from(DeviceAccessRule)
            .where(
                DeviceAccessRule.organization_id == organization_id,
                DeviceAccessRule.is_deleted.is_(False),
                DeviceAccessRule.is_active.is_(True),
                DeviceAccessRule.rule_type == AccessRuleType.BLOCKLIST.value,
            )
        )
        where_location = _location_condition(DeviceAccessRule.location_id, location)
        if where_location is not None:
            active = active.where(
                where_location | DeviceAccessRule.location_id.is_(None)
            )
        recent = (
            select(func.count())
            .select_from(DeviceAccessRouterBlock)
            .where(
                DeviceAccessRouterBlock.organization_id == organization_id,
                DeviceAccessRouterBlock.blocked_at >= since,
            )
        )
        where_location = _location_condition(
            DeviceAccessRouterBlock.location_id, location
        )
        if where_location is not None:
            recent = recent.where(where_location)
        active_count = int((await self.session.execute(active)).scalar_one() or 0)
        recent_count = int((await self.session.execute(recent)).scalar_one() or 0)
        return active_count, recent_count

    async def recent_staff_changes(
        self,
        *,
        organization_id: uuid.UUID,
        location: LocationFilter,
        since: datetime,
        limit: int = 20,
    ) -> list[StaffChange]:
        """Who changed a protection, newest first. Entries with no location
        (organization-wide changes, and router-level actions that did not
        record one) are included for a location view too -- they apply
        there."""
        statement = (
            select(
                AuditLogEntry.created_at,
                AuditLogEntry.action,
                AuditLogEntry.description,
                User.first_name,
                User.last_name,
            )
            .outerjoin(User, User.id == AuditLogEntry.actor_user_id)
            .where(
                AuditLogEntry.organization_id == organization_id,
                AuditLogEntry.created_at >= since,
                AuditLogEntry.action.in_(SECURITY_AUDIT_ACTIONS),
            )
            .order_by(AuditLogEntry.created_at.desc())
            .limit(limit)
        )
        where_location = _location_condition(AuditLogEntry.location_id, location)
        if where_location is not None:
            statement = statement.where(
                where_location | AuditLogEntry.location_id.is_(None)
            )
        result = await self.session.execute(statement)
        changes = []
        for row in result.all():
            name = " ".join(p for p in (row.first_name, row.last_name) if p) or None
            changes.append(
                StaffChange(
                    at=row.created_at,
                    action=row.action,
                    description=row.description,
                    actor_name=name,
                )
            )
        return changes

    async def cloudflare_scope(
        self, *, organization_id: uuid.UUID, location: LocationFilter
    ) -> CloudflareScope:
        in_scope = select(
            DnsFilteringRouterLocation.router_id,
            DnsFilteringRouterLocation.applied_profile_id,
        ).where(
            DnsFilteringRouterLocation.organization_id == organization_id,
            DnsFilteringRouterLocation.applied_profile_id.is_not(None),
        )
        where_location = _location_condition(
            DnsFilteringRouterLocation.location_id, location
        )
        if where_location is not None:
            in_scope = in_scope.where(where_location)
        rows = (await self.session.execute(in_scope)).all()
        if not rows:
            return CloudflareScope([], [], 0)
        router_ids = {r.router_id for r in rows}
        profile_ids = {r.applied_profile_id for r in rows}

        # Every router (any tenant) on those profiles: a profile is exclusive
        # only if all of them are in this scope.
        users = (
            await self.session.execute(
                select(
                    DnsFilteringRouterLocation.applied_profile_id,
                    DnsFilteringRouterLocation.router_id,
                ).where(DnsFilteringRouterLocation.applied_profile_id.in_(profile_ids))
            )
        ).all()
        shared_profiles = {
            u.applied_profile_id for u in users if u.router_id not in router_ids
        }
        locations = (
            await self.session.execute(
                select(
                    DnsFilteringProfile.id, DnsFilteringProfile.cf_location_id
                ).where(
                    DnsFilteringProfile.id.in_(profile_ids),
                    DnsFilteringProfile.cf_location_id.is_not(None),
                )
            )
        ).all()
        exclusive = sorted(
            {p.cf_location_id for p in locations if p.id not in shared_profiles}
        )
        shared = sorted(
            {p.cf_location_id for p in locations if p.id in shared_profiles}
        )
        return CloudflareScope(exclusive, shared, len(router_ids))
