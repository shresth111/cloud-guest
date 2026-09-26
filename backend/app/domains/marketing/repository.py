"""Data access for the Guest Marketing domain.

Every read that returns tenant data takes ``organization_id`` and filters on
it in SQL. There is deliberately no ``get_by_id`` that takes an id alone:
the path-id defect class in this codebase (permission checked against the
header organization, row read by a path id) needs a lookup-by-id-only to
exist, so none does. Location confinement is applied by the service, which
passes the resolved location filter down.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, exists, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.auth.models import User
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.guest.models import Guest, GuestSession
from app.domains.location.models import Location
from app.domains.organization.models import Organization

from .constants import (
    ACTIVE_CAMPAIGN_STATUSES,
    CampaignStatus,
    CancelReason,
    ConsentStatus,
    RecipientStatus,
    SkipReason,
)
from .models import (
    GuestMarketingConsent,
    GuestMarketingConsentEvent,
    MarketingCampaign,
    MarketingCampaignRecipient,
    MarketingSuppression,
    MarketingTemplate,
    OrgMarketingProvider,
)

_ACTIVE = [status.value for status in ACTIVE_CAMPAIGN_STATUSES]


@dataclass(frozen=True)
class AudienceCriteria:
    organization_id: uuid.UUID
    channel: str
    location_ids: list[uuid.UUID] | None
    visited_from: datetime | None
    visited_before: datetime | None
    min_visits: int | None
    max_visits: int | None
    last_seen_before: datetime | None
    require_name: bool


@dataclass(frozen=True)
class AudienceCandidate:
    guest_id: uuid.UUID
    identifier: str
    email: str | None
    display_name: str | None
    is_blocked: bool
    last_seen_at: datetime
    total_visit_count: int


@dataclass(frozen=True)
class AudienceCounts:
    matched: int
    no_consent: int
    opted_out: int
    opted_in: list[AudienceCandidate]


def _page(page: int, page_size: int) -> PageParams:
    return PageParams(page=page, page_size=page_size)


class MarketingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def commit(self) -> None:
        await self.session.commit()

    async def flush(self) -> None:
        await self.session.flush()

    # ======================================================================
    # Organization / location / portal lookups
    # ======================================================================

    async def get_organization(self, organization_id: uuid.UUID) -> Organization | None:
        return await self.session.get(Organization, organization_id)

    async def get_location(
        self, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> Location | None:
        result = await self.session.execute(
            select(Location).where(
                Location.id == location_id,
                Location.organization_id == organization_id,
                Location.is_deleted.is_(False),
            )
        )
        return result.scalar_one_or_none()

    async def get_portal_config(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> CaptivePortalConfig | None:
        """Most-specific-wins: the location's own config, else the org's
        default (``location_id IS NULL AND is_default``)."""
        if location_id is not None:
            result = await self.session.execute(
                select(CaptivePortalConfig)
                .where(
                    CaptivePortalConfig.organization_id == organization_id,
                    CaptivePortalConfig.location_id == location_id,
                    CaptivePortalConfig.is_deleted.is_(False),
                )
                .order_by(CaptivePortalConfig.updated_at.desc())
                .limit(1)
            )
            config = result.scalar_one_or_none()
            if config is not None:
                return config
        result = await self.session.execute(
            select(CaptivePortalConfig)
            .where(
                CaptivePortalConfig.organization_id == organization_id,
                CaptivePortalConfig.location_id.is_(None),
                CaptivePortalConfig.is_deleted.is_(False),
            )
            .order_by(
                CaptivePortalConfig.is_default.desc(),
                CaptivePortalConfig.updated_at.desc(),
            )
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def update_portal_config(
        self, config: CaptivePortalConfig, data: dict[str, Any]
    ) -> CaptivePortalConfig:
        for key, value in data.items():
            setattr(config, key, value)
        await self.session.flush()
        return config

    async def get_user_names(
        self, user_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, str]:
        ids = [user_id for user_id in set(user_ids) if user_id is not None]
        if not ids:
            return {}
        result = await self.session.execute(
            select(User.id, User.first_name, User.last_name).where(User.id.in_(ids))
        )
        return {
            row.id: " ".join(part for part in (row.first_name, row.last_name) if part)
            for row in result
        }

    # ======================================================================
    # Guests
    # ======================================================================

    async def get_guest(
        self, organization_id: uuid.UUID, guest_id: uuid.UUID
    ) -> Guest | None:
        result = await self.session.execute(
            select(Guest).where(
                Guest.id == guest_id,
                Guest.organization_id == organization_id,
                Guest.is_deleted.is_(False),
            )
        )
        return result.scalar_one_or_none()

    async def guest_visited_location(
        self, guest_id: uuid.UUID, location_id: uuid.UUID
    ) -> bool:
        result = await self.session.execute(
            select(
                exists().where(
                    GuestSession.guest_id == guest_id,
                    GuestSession.location_id == location_id,
                )
            )
        )
        return bool(result.scalar())

    async def get_session(self, session_id: uuid.UUID) -> GuestSession | None:
        return await self.session.get(GuestSession, session_id)

    def _visited_clause(
        self,
        organization_id: uuid.UUID,
        location_ids: list[uuid.UUID] | None,
        visited_from: datetime | None = None,
        visited_before: datetime | None = None,
    ):
        clause = select(GuestSession.id).where(
            GuestSession.guest_id == Guest.id,
            GuestSession.organization_id == organization_id,
        )
        if location_ids is not None:
            clause = clause.where(GuestSession.location_id.in_(location_ids))
        if visited_from is not None:
            clause = clause.where(GuestSession.started_at >= visited_from)
        if visited_before is not None:
            clause = clause.where(GuestSession.started_at < visited_before)
        return exists(clause)

    # ======================================================================
    # Consent
    # ======================================================================

    async def get_consents(
        self, guest_id: uuid.UUID
    ) -> dict[str, GuestMarketingConsent]:
        result = await self.session.execute(
            select(GuestMarketingConsent).where(
                GuestMarketingConsent.guest_id == guest_id,
                GuestMarketingConsent.is_deleted.is_(False),
            )
        )
        return {row.channel: row for row in result.scalars()}

    async def has_any_consent(self, guest_id: uuid.UUID) -> bool:
        result = await self.session.execute(
            select(
                exists().where(
                    GuestMarketingConsent.guest_id == guest_id,
                    GuestMarketingConsent.is_deleted.is_(False),
                )
            )
        )
        return bool(result.scalar())

    async def upsert_consent(
        self,
        *,
        organization_id: uuid.UUID,
        guest_id: uuid.UUID,
        channel: str,
        status: str,
        source: str,
        consent_text_version: str | None,
        location_id: uuid.UUID | None,
        ip_address: str | None,
        actor_user_id: uuid.UUID | None,
        now: datetime,
    ) -> bool:
        """Write the consent row and its append-only event. Returns ``False``
        (and writes nothing) when the row is already in ``status`` --
        repeated opt-outs are idempotent and do not pile up events."""
        existing = (await self.get_consents(guest_id)).get(channel)
        if existing is not None and existing.status == status:
            return False
        if existing is None:
            self.session.add(
                GuestMarketingConsent(
                    organization_id=organization_id,
                    guest_id=guest_id,
                    channel=channel,
                    status=status,
                    source=source,
                    consent_text_version=consent_text_version,
                    captured_at_location_id=location_id,
                    ip_address=ip_address,
                    status_changed_at=now,
                    created_by=actor_user_id,
                )
            )
        else:
            existing.status = status
            existing.source = source
            existing.consent_text_version = consent_text_version
            existing.ip_address = ip_address
            existing.status_changed_at = now
            existing.updated_by = actor_user_id
            if location_id is not None:
                existing.captured_at_location_id = location_id
        self.session.add(
            GuestMarketingConsentEvent(
                organization_id=organization_id,
                guest_id=guest_id,
                channel=channel,
                action="opt_in"
                if status == ConsentStatus.OPTED_IN.value
                else "opt_out",
                source=source,
                consent_text_version=consent_text_version,
                actor_user_id=actor_user_id,
                ip_address=ip_address,
                occurred_at=now,
            )
        )
        await self.session.flush()
        return True

    async def add_suppression(
        self,
        *,
        organization_id: uuid.UUID,
        channel: str,
        address_normalized: str,
        reason: str,
        source_recipient_id: uuid.UUID | None = None,
    ) -> None:
        now = datetime.now(UTC)
        statement = (
            pg_insert(MarketingSuppression)
            .values(
                id=uuid.uuid4(),
                organization_id=organization_id,
                channel=channel,
                address_normalized=address_normalized,
                reason=reason,
                source_recipient_id=source_recipient_id,
                created_at=now,
                updated_at=now,
                is_deleted=False,
                version=1,
            )
            .on_conflict_do_nothing(
                index_elements=["organization_id", "channel", "address_normalized"]
            )
        )
        await self.session.execute(statement)

    async def suppressed_addresses(
        self, organization_id: uuid.UUID, channel: str, addresses: Sequence[str]
    ) -> set[str]:
        found: set[str] = set()
        unique = list(dict.fromkeys(addresses))
        if len(unique) > 1000:
            # Whole-org audiences: one indexed read of the org's (small)
            # suppression list beats N chunked IN-lists.
            result = await self.session.execute(
                select(MarketingSuppression.address_normalized).where(
                    MarketingSuppression.organization_id == organization_id,
                    MarketingSuppression.channel == channel,
                    MarketingSuppression.is_deleted.is_(False),
                )
            )
            return set(result.scalars()) & set(unique)
        for start in range(0, len(unique), 1000):
            chunk = unique[start : start + 1000]
            result = await self.session.execute(
                select(MarketingSuppression.address_normalized).where(
                    MarketingSuppression.organization_id == organization_id,
                    MarketingSuppression.channel == channel,
                    MarketingSuppression.is_deleted.is_(False),
                    MarketingSuppression.address_normalized.in_(chunk),
                )
            )
            found.update(result.scalars())
        return found

    async def is_suppressed(
        self, organization_id: uuid.UUID, channel: str, address: str
    ) -> bool:
        return bool(
            await self.suppressed_addresses(organization_id, channel, [address])
        )

    async def consent_counts(
        self, organization_id: uuid.UUID, location_ids: list[uuid.UUID] | None
    ) -> dict[str, int]:
        statement = (
            select(GuestMarketingConsent.channel, func.count())
            .join(Guest, Guest.id == GuestMarketingConsent.guest_id)
            .where(
                GuestMarketingConsent.organization_id == organization_id,
                Guest.organization_id == organization_id,
                GuestMarketingConsent.is_deleted.is_(False),
                GuestMarketingConsent.status == ConsentStatus.OPTED_IN.value,
                Guest.is_deleted.is_(False),
            )
            .group_by(GuestMarketingConsent.channel)
        )
        if location_ids is not None:
            statement = statement.where(
                self._visited_clause(organization_id, location_ids)
            )
        result = await self.session.execute(statement)
        return {channel: int(count) for channel, count in result.all()}

    async def list_contacts(
        self,
        *,
        organization_id: uuid.UUID,
        channel: str,
        consent_status: str,
        location_ids: list[uuid.UUID] | None,
        search: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[tuple[Guest, GuestMarketingConsent | None]], PaginationMeta]:
        consent = GuestMarketingConsent
        join_on = and_(
            consent.guest_id == Guest.id,
            consent.channel == channel,
            consent.is_deleted.is_(False),
        )
        base = (
            select(Guest, consent)
            .outerjoin(consent, join_on)
            .where(
                Guest.organization_id == organization_id, Guest.is_deleted.is_(False)
            )
        )
        if consent_status == "none":
            base = base.where(consent.id.is_(None))
        else:
            base = base.where(consent.status == consent_status)
        if location_ids is not None:
            base = base.where(self._visited_clause(organization_id, location_ids))
        if search:
            term = search.strip()
            conditions = [Guest.display_name.ilike(f"%{term}%")]
            if term.isdigit() and len(term) <= 4:
                conditions.append(Guest.identifier.like(f"%{term}"))
            if term and "@" not in term:
                conditions.append(Guest.email.ilike(f"{term}%@%"))
                conditions.append(Guest.identifier.ilike(f"{term}%@%"))
            base = base.where(or_(*conditions))
        params = _page(page, page_size)
        total = (
            await self.session.execute(
                select(func.count()).select_from(base.order_by(None).subquery())
            )
        ).scalar_one()
        rows = await self.session.execute(
            base.order_by(Guest.last_seen_at.desc(), Guest.id)
            .limit(params.page_size)
            .offset(params.offset)
        )
        return [(row[0], row[1]) for row in rows.all()], PaginationMeta.from_total(
            params, int(total)
        )

    # ======================================================================
    # Audience
    # ======================================================================

    def _audience_statement(self, criteria: AudienceCriteria):
        statement = select(Guest).where(
            Guest.organization_id == criteria.organization_id,
            Guest.is_deleted.is_(False),
        )
        if (
            criteria.location_ids is not None
            or criteria.visited_from is not None
            or criteria.visited_before is not None
        ):
            statement = statement.where(
                self._visited_clause(
                    criteria.organization_id,
                    criteria.location_ids,
                    criteria.visited_from,
                    criteria.visited_before,
                )
            )
        if criteria.min_visits is not None:
            statement = statement.where(Guest.total_visit_count >= criteria.min_visits)
        if criteria.max_visits is not None:
            statement = statement.where(Guest.total_visit_count <= criteria.max_visits)
        if criteria.last_seen_before is not None:
            statement = statement.where(Guest.last_seen_at < criteria.last_seen_before)
        if criteria.require_name:
            statement = statement.where(
                Guest.display_name.is_not(None), func.trim(Guest.display_name) != ""
            )
        return statement

    async def audience(self, criteria: AudienceCriteria) -> AudienceCounts:
        """Exact counts in SQL, and the opted-in rows (the only ones that can
        become recipients) for the per-address checks the service does."""
        base = self._audience_statement(criteria).subquery()
        consent = GuestMarketingConsent
        joined = select(base.c.id, consent.status).outerjoin(
            consent,
            and_(
                consent.guest_id == base.c.id,
                consent.channel == criteria.channel,
                consent.is_deleted.is_(False),
            ),
        )
        consent_rows = joined.subquery()
        counts = (
            await self.session.execute(
                select(
                    func.count(),
                    func.count().filter(consent_rows.c.status.is_(None)),
                    func.count().filter(
                        consent_rows.c.status == ConsentStatus.OPTED_OUT.value
                    ),
                ).select_from(consent_rows)
            )
        ).one()
        opted_in_rows = await self.session.execute(
            select(
                base.c.id,
                base.c.identifier,
                base.c.email,
                base.c.display_name,
                base.c.is_blocked,
                base.c.last_seen_at,
                base.c.total_visit_count,
            )
            .join(
                consent,
                and_(
                    consent.guest_id == base.c.id,
                    consent.channel == criteria.channel,
                    consent.is_deleted.is_(False),
                    consent.status == ConsentStatus.OPTED_IN.value,
                ),
            )
            .order_by(base.c.last_seen_at.desc(), base.c.id)
        )
        candidates = [
            AudienceCandidate(
                guest_id=row.id,
                identifier=row.identifier,
                email=row.email,
                display_name=row.display_name,
                is_blocked=row.is_blocked,
                last_seen_at=row.last_seen_at,
                total_visit_count=row.total_visit_count,
            )
            for row in opted_in_rows.all()
        ]
        return AudienceCounts(
            matched=int(counts[0]),
            no_consent=int(counts[1]),
            opted_out=int(counts[2]),
            opted_in=candidates,
        )

    # ======================================================================
    # Templates
    # ======================================================================

    async def list_templates(
        self,
        *,
        organization_id: uuid.UUID,
        channel: str | None,
        category: str | None,
        include_system: bool,
        page: int,
        page_size: int,
    ) -> tuple[list[MarketingTemplate], PaginationMeta]:
        owner = (
            or_(
                MarketingTemplate.organization_id == organization_id,
                MarketingTemplate.organization_id.is_(None),
            )
            if include_system
            else MarketingTemplate.organization_id == organization_id
        )
        statement = select(MarketingTemplate).where(
            owner, MarketingTemplate.is_deleted.is_(False)
        )
        if category:
            statement = statement.where(MarketingTemplate.category == category)
        if channel == "sms":
            statement = statement.where(MarketingTemplate.sms_body.is_not(None))
        elif channel == "whatsapp":
            statement = statement.where(MarketingTemplate.whatsapp_body.is_not(None))
        elif channel == "email":
            statement = statement.where(MarketingTemplate.email_body_html.is_not(None))
        params = _page(page, page_size)
        total = (
            await self.session.execute(
                select(func.count()).select_from(statement.subquery())
            )
        ).scalar_one()
        rows = await self.session.execute(
            statement.order_by(
                MarketingTemplate.organization_id.is_(None).desc(),
                MarketingTemplate.system_key.asc(),
                MarketingTemplate.updated_at.desc(),
            )
            .limit(params.page_size)
            .offset(params.offset)
        )
        return list(rows.scalars()), PaginationMeta.from_total(params, int(total))

    async def get_template(
        self, organization_id: uuid.UUID, template_id: uuid.UUID
    ) -> MarketingTemplate | None:
        """A system template, or a custom one owned by this organization."""
        result = await self.session.execute(
            select(MarketingTemplate).where(
                MarketingTemplate.id == template_id,
                MarketingTemplate.is_deleted.is_(False),
                or_(
                    MarketingTemplate.organization_id == organization_id,
                    MarketingTemplate.organization_id.is_(None),
                ),
            )
        )
        return result.scalar_one_or_none()

    async def count_system_templates(self) -> int:
        result = await self.session.execute(
            select(func.count()).where(
                MarketingTemplate.organization_id.is_(None),
                MarketingTemplate.is_deleted.is_(False),
            )
        )
        return int(result.scalar_one())

    async def template_name_taken(
        self,
        organization_id: uuid.UUID,
        name: str,
        *,
        exclude_id: uuid.UUID | None = None,
    ) -> bool:
        statement = select(MarketingTemplate.id).where(
            MarketingTemplate.organization_id == organization_id,
            MarketingTemplate.is_deleted.is_(False),
            func.lower(MarketingTemplate.name) == name.strip().lower(),
        )
        if exclude_id is not None:
            statement = statement.where(MarketingTemplate.id != exclude_id)
        return (await self.session.execute(statement.limit(1))).first() is not None

    async def create_template(self, **fields: Any) -> MarketingTemplate:
        template = MarketingTemplate(**fields)
        self.session.add(template)
        await self.session.flush()
        await self.session.refresh(template)
        return template

    async def update_template_cas(
        self,
        template: MarketingTemplate,
        *,
        expected_version: int,
        data: dict[str, Any],
    ) -> bool:
        """Compare-and-set on ``version``: returns ``False`` if another write
        landed first (the caller raises ``version_conflict``)."""
        result = await self.session.execute(
            update(MarketingTemplate)
            .where(
                MarketingTemplate.id == template.id,
                MarketingTemplate.organization_id == template.organization_id,
                MarketingTemplate.version == expected_version,
            )
            .values(**data, version=expected_version + 1, updated_at=datetime.now(UTC))
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            return False
        await self.session.refresh(template)
        return True

    async def soft_delete_template(self, template: MarketingTemplate) -> None:
        template.mark_deleted()
        await self.session.flush()

    async def template_in_use(self, template_id: uuid.UUID) -> bool:
        result = await self.session.execute(
            select(
                exists().where(
                    MarketingCampaign.template_id == template_id,
                    MarketingCampaign.is_deleted.is_(False),
                    MarketingCampaign.status.in_(_ACTIVE),
                )
            )
        )
        return bool(result.scalar())

    async def template_names(
        self, template_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, MarketingTemplate]:
        ids = list(set(template_ids))
        if not ids:
            return {}
        result = await self.session.execute(
            select(MarketingTemplate).where(MarketingTemplate.id.in_(ids))
        )
        return {row.id: row for row in result.scalars()}

    # ======================================================================
    # Campaigns
    # ======================================================================

    def _campaign_scope(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> list[Any]:
        """Tenant filter, plus the location confinement of a
        location-scoped caller: they see only their own location's
        campaigns, never org-wide ones (contract §5.0 rule 2)."""
        clauses: list[Any] = [
            MarketingCampaign.organization_id == organization_id,
            MarketingCampaign.is_deleted.is_(False),
        ]
        if location_id is not None:
            clauses.append(MarketingCampaign.location_id == location_id)
        return clauses

    async def get_campaign(
        self,
        organization_id: uuid.UUID,
        campaign_id: uuid.UUID,
        *,
        scope_location_id: uuid.UUID | None,
    ) -> MarketingCampaign | None:
        result = await self.session.execute(
            select(MarketingCampaign).where(
                MarketingCampaign.id == campaign_id,
                *self._campaign_scope(organization_id, scope_location_id),
            )
        )
        return result.scalar_one_or_none()

    async def list_campaigns(
        self,
        *,
        organization_id: uuid.UUID,
        scope_location_id: uuid.UUID | None,
        statuses: list[str] | None,
        channel: str | None,
        search: str | None,
        page: int,
        page_size: int,
        venue_location_id: uuid.UUID | None = None,
    ) -> tuple[list[MarketingCampaign], PaginationMeta]:
        statement = select(MarketingCampaign).where(
            *self._campaign_scope(organization_id, scope_location_id)
        )
        if venue_location_id is not None:
            # Venue filter (contract change 2026-09-25): campaigns owned by
            # the venue, or whose audience explicitly names it. An
            # all-venues campaign (audience location_ids null) is not tied
            # to any one venue and is not matched.
            statement = statement.where(
                or_(
                    MarketingCampaign.location_id == venue_location_id,
                    MarketingCampaign.audience_filter["location_ids"].contains(
                        [str(venue_location_id)]
                    ),
                )
            )
        if statuses:
            statement = statement.where(MarketingCampaign.status.in_(statuses))
        if channel:
            statement = statement.where(MarketingCampaign.channel == channel)
        if search:
            statement = statement.where(
                MarketingCampaign.name.ilike(f"%{search.strip()}%")
            )
        params = _page(page, page_size)
        total = (
            await self.session.execute(
                select(func.count()).select_from(statement.subquery())
            )
        ).scalar_one()
        rows = await self.session.execute(
            statement.order_by(MarketingCampaign.created_at.desc())
            .limit(params.page_size)
            .offset(params.offset)
        )
        return list(rows.scalars()), PaginationMeta.from_total(params, int(total))

    async def create_campaign(self, **fields: Any) -> MarketingCampaign:
        campaign = MarketingCampaign(**fields)
        self.session.add(campaign)
        await self.session.flush()
        await self.session.refresh(campaign)
        return campaign

    async def update_campaign_cas(
        self,
        campaign: MarketingCampaign,
        *,
        expected_status: str | Sequence[str],
        data: dict[str, Any],
        expected_version: int | None = None,
    ) -> bool:
        """Compare-and-set on status (and optionally version). This is the
        idempotency guard for every state transition: two concurrent
        schedules, or a cancel racing the dispatcher, cannot both win."""
        statuses = (
            [expected_status]
            if isinstance(expected_status, str)
            else list(expected_status)
        )
        conditions = [
            MarketingCampaign.id == campaign.id,
            MarketingCampaign.organization_id == campaign.organization_id,
            MarketingCampaign.status.in_(statuses),
            MarketingCampaign.is_deleted.is_(False),
        ]
        values = dict(data)
        if expected_version is not None:
            conditions.append(MarketingCampaign.version == expected_version)
        values["version"] = MarketingCampaign.version + 1
        values["updated_at"] = datetime.now(UTC)
        result = await self.session.execute(
            update(MarketingCampaign)
            .where(*conditions)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            return False
        await self.session.refresh(campaign)
        return True

    async def refresh(self, instance: Any) -> None:
        await self.session.refresh(instance)

    async def soft_delete_campaign(self, campaign: MarketingCampaign) -> None:
        campaign.mark_deleted()
        await self.session.flush()

    async def find_campaign_by_idempotency_key(
        self, organization_id: uuid.UUID, key: str
    ) -> MarketingCampaign | None:
        result = await self.session.execute(
            select(MarketingCampaign).where(
                MarketingCampaign.organization_id == organization_id,
                MarketingCampaign.schedule_idempotency_key == key,
            )
        )
        return result.scalar_one_or_none()

    async def count_active_campaigns(self, organization_id: uuid.UUID) -> int:
        result = await self.session.execute(
            select(func.count()).where(
                MarketingCampaign.organization_id == organization_id,
                MarketingCampaign.is_deleted.is_(False),
                MarketingCampaign.status.in_(_ACTIVE),
            )
        )
        return int(result.scalar_one())

    async def cancel_active_campaigns_for_lock(
        self,
        organization_id: uuid.UUID,
        *,
        own_only: bool = False,
        cancel_reason: str = CancelReason.ADDON_LOCKED.value,
        last_error: str = "Marketing add-on was locked",
    ) -> int:
        """The add-on was locked: cancel every scheduled/sending campaign (or,
        for the BYO add-on, only those snapshotted to an own provider) and
        skip its pending recipients. Runs inside the Master write's
        transaction (see ``feature_entitlement.addons``)."""
        now = datetime.now(UTC)
        conditions = [
            MarketingCampaign.organization_id == organization_id,
            MarketingCampaign.is_deleted.is_(False),
            MarketingCampaign.status.in_(_ACTIVE),
        ]
        if own_only:
            conditions.append(MarketingCampaign.provider_source == "own")
        result = await self.session.execute(
            update(MarketingCampaign)
            .where(*conditions)
            .values(
                status=CampaignStatus.CANCELLED.value,
                cancel_reason=cancel_reason,
                cancelled_at=now,
                last_error=last_error,
                version=MarketingCampaign.version + 1,
                updated_at=now,
            )
            .returning(MarketingCampaign.id)
            .execution_options(synchronize_session=False)
        )
        cancelled_ids = list(result.scalars())
        for campaign_id in cancelled_ids:
            await self.skip_pending_recipients(
                campaign_id, SkipReason.ADDON_LOCKED.value
            )
        return len(cancelled_ids)

    async def count_active_campaigns_for(
        self,
        organization_id: uuid.UUID,
        *,
        own_only: bool = False,
        org_provider_id: uuid.UUID | None = None,
    ) -> int:
        conditions = [
            MarketingCampaign.organization_id == organization_id,
            MarketingCampaign.is_deleted.is_(False),
            MarketingCampaign.status.in_(_ACTIVE),
        ]
        if own_only:
            conditions.append(MarketingCampaign.provider_source == "own")
        if org_provider_id is not None:
            conditions.append(MarketingCampaign.org_provider_id == org_provider_id)
        result = await self.session.execute(select(func.count()).where(*conditions))
        return int(result.scalar_one())

    # ======================================================================
    # Own providers (spec §12)
    # ======================================================================

    async def list_providers(
        self, organization_id: uuid.UUID
    ) -> dict[str, OrgMarketingProvider]:
        result = await self.session.execute(
            select(OrgMarketingProvider).where(
                OrgMarketingProvider.organization_id == organization_id,
                OrgMarketingProvider.is_deleted.is_(False),
            )
        )
        return {row.channel: row for row in result.scalars()}

    async def get_provider(
        self, organization_id: uuid.UUID, channel: str
    ) -> OrgMarketingProvider | None:
        return (await self.list_providers(organization_id)).get(channel)

    async def get_provider_by_id(
        self, organization_id: uuid.UUID, provider_id: uuid.UUID
    ) -> OrgMarketingProvider | None:
        """Includes soft-deleted rows: the worker must be able to tell
        "deleted after schedule" apart from "never existed"."""
        result = await self.session.execute(
            select(OrgMarketingProvider).where(
                OrgMarketingProvider.id == provider_id,
                OrgMarketingProvider.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def create_provider(self, **fields: Any) -> OrgMarketingProvider:
        row = OrgMarketingProvider(**fields)
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        return row

    async def update_provider(
        self, row: OrgMarketingProvider, data: dict[str, Any]
    ) -> OrgMarketingProvider:
        for key, value in data.items():
            setattr(row, key, value)
        row.version = (row.version or 1) + 1
        await self.session.flush()
        return row

    async def soft_delete_provider(self, row: OrgMarketingProvider) -> None:
        row.mark_deleted()
        await self.session.flush()

    async def trip_provider(self, provider_id: uuid.UUID, last_error: str) -> bool:
        """verified -> failed, exactly once (compare-and-set): concurrent
        batches hitting the same auth error do not race."""
        result = await self.session.execute(
            update(OrgMarketingProvider)
            .where(
                OrgMarketingProvider.id == provider_id,
                OrgMarketingProvider.status == "verified",
            )
            .values(
                status="failed",
                last_error=last_error[:500],
                updated_at=datetime.now(UTC),
            )
            .execution_options(synchronize_session=False)
        )
        return result.rowcount == 1

    async def fail_unsent_recipients(
        self,
        campaign_id: uuid.UUID,
        *,
        error_code: str,
        error_message: str,
        claimed_ids: Sequence[uuid.UUID] = (),
    ) -> int:
        """Fail every pending recipient, plus this batch's own claimed rows
        that were not sent. Never touches rows another worker holds."""
        now = datetime.now(UTC)
        condition = MarketingCampaignRecipient.status == RecipientStatus.PENDING.value
        if claimed_ids:
            condition = or_(
                condition,
                and_(
                    MarketingCampaignRecipient.id.in_(list(claimed_ids)),
                    MarketingCampaignRecipient.status == RecipientStatus.SENDING.value,
                ),
            )
        result = await self.session.execute(
            update(MarketingCampaignRecipient)
            .where(MarketingCampaignRecipient.campaign_id == campaign_id, condition)
            .values(
                status=RecipientStatus.FAILED.value,
                error_code=error_code,
                error_message=error_message[:500],
                failed_at=now,
                updated_at=now,
            )
            .returning(MarketingCampaignRecipient.id)
            .execution_options(synchronize_session=False)
        )
        count = len(list(result.scalars()))
        if count:
            # A claimed (`sending`) row still counts in count_pending until it
            # finishes, so every row failed here leaves `pending`.
            await self.adjust_counters(campaign_id, pending=-count, failed=count)
        return count

    # -- WABA-synced templates (BE-11b) ----------------------------------

    async def list_synced_templates(
        self, organization_id: uuid.UUID
    ) -> list[MarketingTemplate]:
        result = await self.session.execute(
            select(MarketingTemplate).where(
                MarketingTemplate.organization_id == organization_id,
                MarketingTemplate.whatsapp_source == "own_waba",
                MarketingTemplate.is_deleted.is_(False),
            )
        )
        return list(result.scalars())

    async def update_template(
        self, template: MarketingTemplate, data: dict[str, Any]
    ) -> MarketingTemplate:
        for key, value in data.items():
            setattr(template, key, value)
        template.version = (template.version or 1) + 1
        await self.session.flush()
        return template

    async def due_campaign_ids(self, now: datetime, limit: int = 20) -> list[uuid.UUID]:
        result = await self.session.execute(
            select(MarketingCampaign.id)
            .where(
                MarketingCampaign.status == CampaignStatus.SCHEDULED.value,
                MarketingCampaign.scheduled_at <= now,
                MarketingCampaign.is_deleted.is_(False),
            )
            .order_by(MarketingCampaign.scheduled_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list(result.scalars())

    async def get_campaign_for_worker(
        self, campaign_id: uuid.UUID
    ) -> MarketingCampaign | None:
        """Worker-side read (no caller, no tenant header): the campaign row
        itself carries its organization, and every write the worker makes is
        keyed on that row's own ``organization_id``."""
        result = await self.session.execute(
            select(MarketingCampaign).where(
                MarketingCampaign.id == campaign_id,
                MarketingCampaign.is_deleted.is_(False),
            )
        )
        return result.scalar_one_or_none()

    async def sending_campaigns_without_progress(
        self, started_before: datetime
    ) -> list[MarketingCampaign]:
        """Campaigns in ``sending`` whose first batch never ran (no recipient
        ever claimed) -- the "no worker consumes the marketing queue" tell."""
        claimed = exists().where(
            MarketingCampaignRecipient.campaign_id == MarketingCampaign.id,
            MarketingCampaignRecipient.attempt_count > 0,
        )
        result = await self.session.execute(
            select(MarketingCampaign).where(
                MarketingCampaign.status == CampaignStatus.SENDING.value,
                MarketingCampaign.started_at < started_before,
                MarketingCampaign.recipient_count > 0,
                MarketingCampaign.is_deleted.is_(False),
                ~claimed,
            )
        )
        return list(result.scalars())

    async def adjust_counters(self, campaign_id: uuid.UUID, **deltas: int) -> None:
        values = {
            f"count_{name}": getattr(MarketingCampaign, f"count_{name}") + delta
            for name, delta in deltas.items()
            if delta
        }
        if not values:
            return
        await self.session.execute(
            update(MarketingCampaign)
            .where(MarketingCampaign.id == campaign_id)
            .values(**values)
            .execution_options(synchronize_session=False)
        )

    # ======================================================================
    # Recipients
    # ======================================================================

    async def insert_recipients(self, rows: list[dict[str, Any]]) -> int:
        """``ON CONFLICT (campaign_id, guest_id) DO NOTHING`` -- the
        materialization idempotency guarantee."""
        inserted = 0
        now = datetime.now(UTC)
        for start in range(0, len(rows), 500):
            chunk = [
                {
                    "id": uuid.uuid4(),
                    "created_at": now,
                    "updated_at": now,
                    "is_deleted": False,
                    "version": 1,
                    "status": RecipientStatus.PENDING.value,
                    "attempt_count": 0,
                    "unsubscribe_token": new_unsubscribe_token(),
                    **row,
                }
                for row in rows[start : start + 500]
            ]
            result = await self.session.execute(
                pg_insert(MarketingCampaignRecipient)
                .values(chunk)
                .on_conflict_do_nothing(index_elements=["campaign_id", "guest_id"])
                .returning(MarketingCampaignRecipient.id)
            )
            inserted += len(list(result.scalars()))
        return inserted

    async def attribute_locations(
        self,
        *,
        organization_id: uuid.UUID,
        guest_ids: Sequence[uuid.UUID],
        location_ids: list[uuid.UUID] | None,
        visited_from: datetime | None,
        visited_before: datetime | None,
    ) -> dict[uuid.UUID, uuid.UUID]:
        """guest -> the location of their most recent session among
        ``location_ids`` (all org locations when ``None``) inside the visit
        window. One ``DISTINCT ON`` query per 1000 guests."""
        attributed: dict[uuid.UUID, uuid.UUID] = {}
        ids = list(dict.fromkeys(guest_ids))
        for start in range(0, len(ids), 1000):
            chunk = ids[start : start + 1000]
            statement = (
                select(GuestSession.guest_id, GuestSession.location_id)
                .where(
                    GuestSession.organization_id == organization_id,
                    GuestSession.guest_id.in_(chunk),
                )
                .order_by(GuestSession.guest_id, GuestSession.started_at.desc())
                .distinct(GuestSession.guest_id)
            )
            if location_ids is not None:
                statement = statement.where(GuestSession.location_id.in_(location_ids))
            if visited_from is not None:
                statement = statement.where(GuestSession.started_at >= visited_from)
            if visited_before is not None:
                statement = statement.where(GuestSession.started_at < visited_before)
            result = await self.session.execute(statement)
            attributed.update({row.guest_id: row.location_id for row in result})
        return attributed

    async def count_pending(self, campaign_id: uuid.UUID) -> int:
        result = await self.session.execute(
            select(func.count()).where(
                MarketingCampaignRecipient.campaign_id == campaign_id,
                MarketingCampaignRecipient.status == RecipientStatus.PENDING.value,
            )
        )
        return int(result.scalar_one())

    async def claim_batch(
        self, campaign_id: uuid.UUID, limit: int, now: datetime
    ) -> list[MarketingCampaignRecipient]:
        pending = (
            select(MarketingCampaignRecipient.id)
            .where(
                MarketingCampaignRecipient.campaign_id == campaign_id,
                MarketingCampaignRecipient.status == RecipientStatus.PENDING.value,
                or_(
                    MarketingCampaignRecipient.next_attempt_at.is_(None),
                    MarketingCampaignRecipient.next_attempt_at <= now,
                ),
            )
            .order_by(MarketingCampaignRecipient.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        result = await self.session.execute(
            update(MarketingCampaignRecipient)
            .where(MarketingCampaignRecipient.id.in_(pending))
            .values(
                status=RecipientStatus.SENDING.value,
                attempt_count=MarketingCampaignRecipient.attempt_count + 1,
                sending_started_at=now,
                updated_at=now,
            )
            .returning(MarketingCampaignRecipient)
            .execution_options(synchronize_session=False)
        )
        return list(result.scalars())

    async def update_recipient(self, recipient_id: uuid.UUID, **values: Any) -> None:
        values["updated_at"] = datetime.now(UTC)
        await self.session.execute(
            update(MarketingCampaignRecipient)
            .where(MarketingCampaignRecipient.id == recipient_id)
            .values(**values)
            .execution_options(synchronize_session=False)
        )

    async def skip_pending_recipients(self, campaign_id: uuid.UUID, reason: str) -> int:
        result = await self.session.execute(
            update(MarketingCampaignRecipient)
            .where(
                MarketingCampaignRecipient.campaign_id == campaign_id,
                MarketingCampaignRecipient.status == RecipientStatus.PENDING.value,
            )
            .values(
                status=RecipientStatus.SKIPPED.value,
                skip_reason=reason,
                updated_at=datetime.now(UTC),
            )
            .returning(MarketingCampaignRecipient.id)
            .execution_options(synchronize_session=False)
        )
        count = len(list(result.scalars()))
        if count:
            await self.adjust_counters(campaign_id, pending=-count, skipped=count)
        return count

    async def reap_stuck_recipients(self, stuck_before: datetime) -> list[uuid.UUID]:
        """At-most-once: a row a dead worker left in ``sending`` becomes
        ``failed/worker_lost`` and is never re-sent."""
        now = datetime.now(UTC)
        result = await self.session.execute(
            update(MarketingCampaignRecipient)
            .where(
                MarketingCampaignRecipient.status == RecipientStatus.SENDING.value,
                MarketingCampaignRecipient.sending_started_at < stuck_before,
            )
            .values(
                status=RecipientStatus.FAILED.value,
                error_code="worker_lost",
                error_message=(
                    "The worker stopped mid-send; not retried to avoid a duplicate."
                ),
                failed_at=now,
                updated_at=now,
            )
            .returning(MarketingCampaignRecipient.campaign_id)
            .execution_options(synchronize_session=False)
        )
        campaign_ids = list(result.scalars())
        per_campaign: dict[uuid.UUID, int] = {}
        for campaign_id in campaign_ids:
            per_campaign[campaign_id] = per_campaign.get(campaign_id, 0) + 1
        for campaign_id, count in per_campaign.items():
            await self.adjust_counters(campaign_id, failed=count)
        return list(per_campaign)

    async def get_recipient_by_token(
        self, token: str
    ) -> MarketingCampaignRecipient | None:
        result = await self.session.execute(
            select(MarketingCampaignRecipient).where(
                MarketingCampaignRecipient.unsubscribe_token == token
            )
        )
        return result.scalar_one_or_none()

    async def list_recipients(
        self,
        *,
        organization_id: uuid.UUID,
        campaign_id: uuid.UUID | None,
        scope_location_id: uuid.UUID | None,
        statuses: list[str] | None,
        channel: str | None,
        created_from: datetime | None,
        created_before: datetime | None,
        page: int,
        page_size: int,
        venue_location_id: uuid.UUID | None = None,
    ) -> tuple[
        list[
            tuple[MarketingCampaignRecipient, MarketingCampaign, str | None, str | None]
        ],
        PaginationMeta,
    ]:
        recipient = MarketingCampaignRecipient
        statement = (
            select(recipient, MarketingCampaign, Guest.display_name, Location.name)
            .join(MarketingCampaign, MarketingCampaign.id == recipient.campaign_id)
            .outerjoin(Guest, Guest.id == recipient.guest_id)
            .outerjoin(Location, Location.id == recipient.location_id)
            .where(
                recipient.organization_id == organization_id,
                *self._campaign_scope(organization_id, scope_location_id),
            )
        )
        if venue_location_id is not None:
            # Deliveries attributed to this venue (see
            # MarketingCampaignRecipient.location_id).
            statement = statement.where(recipient.location_id == venue_location_id)
        if campaign_id is not None:
            statement = statement.where(recipient.campaign_id == campaign_id)
        if statuses:
            statement = statement.where(recipient.status.in_(statuses))
        if channel:
            statement = statement.where(recipient.channel == channel)
        if created_from is not None:
            statement = statement.where(recipient.created_at >= created_from)
        if created_before is not None:
            statement = statement.where(recipient.created_at < created_before)
        params = _page(page, page_size)
        total = (
            await self.session.execute(
                select(func.count()).select_from(statement.subquery())
            )
        ).scalar_one()
        rows = await self.session.execute(
            statement.order_by(recipient.created_at.desc(), recipient.id)
            .limit(params.page_size)
            .offset(params.offset)
        )
        return [
            (row[0], row[1], row[2], row[3]) for row in rows.all()
        ], PaginationMeta.from_total(params, int(total))

    async def prune_recipient_pii(self, older_than: datetime) -> int:
        """Retention (§9.8): drop the address and rendered preview after
        180 days. Consent events are never touched."""
        result = await self.session.execute(
            update(MarketingCampaignRecipient)
            .where(
                MarketingCampaignRecipient.created_at < older_than,
                or_(
                    MarketingCampaignRecipient.address.is_not(None),
                    MarketingCampaignRecipient.rendered_preview.is_not(None),
                ),
            )
            .values(address=None, rendered_preview=None)
            .execution_options(synchronize_session=False)
        )
        return int(result.rowcount or 0)


class ByoCampaignLockHook:
    """``AddonCampaignHookProtocol`` for ``guest_marketing_byo``: locking
    BYO cancels only the campaigns snapshotted to an own provider, with
    ``cancel_reason="byo_locked"`` (spec §12.1)."""

    def __init__(self, repository: MarketingRepository) -> None:
        self.repository = repository

    async def count_active_campaigns(self, organization_id: uuid.UUID) -> int:
        return await self.repository.count_active_campaigns_for(
            organization_id, own_only=True
        )

    async def cancel_active_campaigns_for_lock(self, organization_id: uuid.UUID) -> int:
        return await self.repository.cancel_active_campaigns_for_lock(
            organization_id,
            own_only=True,
            cancel_reason="byo_locked",
            last_error="Own-provider add-on was locked",
        )


def new_unsubscribe_token() -> str:
    return secrets.token_urlsafe(16)[:32]


def day_bounds(
    start: datetime | None, end: datetime | None
) -> tuple[datetime | None, datetime | None]:
    """Inclusive date range -> half-open datetime range."""
    return start, (end + timedelta(days=1)) if end is not None else None


__all__ = [
    "AudienceCandidate",
    "ByoCampaignLockHook",
    "AudienceCounts",
    "AudienceCriteria",
    "MarketingRepository",
    "new_unsubscribe_token",
]
