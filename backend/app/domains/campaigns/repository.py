"""Data access layer for the Campaigns domain.

A ``Protocol`` describing every operation the service layer needs
(``CampaignsRepositoryProtocol``), and a concrete, mostly
``GenericRepository``-backed implementation (``CampaignsRepository``) --
mirrors ``app.domains.rbac.repository.RBACRepository``'s own "one
repository class composing several ``GenericRepository`` instances, one
per table" shape, since this domain owns five tables.

A handful of methods (guest-level impression-history lookups, joined
through ``GuestSession`` since ``CampaignImpression`` has no ``guest_id``
of its own -- see ``models.CampaignImpression``'s own module docstring)
use a raw SQLAlchemy ``select().join(...)`` rather than
``GenericRepository``, mirroring ``app.domains.guest.repository``'s own
identical "join for a cross-table lookup `GenericRepository`'s
equality-only filters can't express" precedent.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.guest.models import GuestSession

from .constants import CampaignStatus
from .models import (
    Campaign,
    CampaignAsset,
    CampaignImpression,
    CampaignQuestion,
    CampaignResponse,
)

_NON_TERMINAL_STATUSES = (
    CampaignStatus.SCHEDULED.value,
    CampaignStatus.ACTIVE.value,
)


class CampaignsRepositoryProtocol(Protocol):
    # -- Campaign --------------------------------------------------------

    async def create_campaign(self, **fields: object) -> Campaign: ...

    async def get_campaign_by_id(
        self, campaign_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Campaign | None: ...

    async def update_campaign(
        self, campaign: Campaign, data: dict[str, object]
    ) -> Campaign: ...

    async def soft_delete_campaign(self, campaign: Campaign) -> Campaign: ...

    async def list_campaigns(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[Campaign], PaginationMeta]: ...

    async def list_non_terminal_campaigns(self) -> list[Campaign]: ...

    async def list_candidate_campaigns(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
    ) -> list[Campaign]: ...

    # -- CampaignQuestion --------------------------------------------------

    async def create_question(self, **fields: object) -> CampaignQuestion: ...

    async def get_question_by_id(
        self, question_id: uuid.UUID
    ) -> CampaignQuestion | None: ...

    async def update_question(
        self, question: CampaignQuestion, data: dict[str, object]
    ) -> CampaignQuestion: ...

    async def soft_delete_question(
        self, question: CampaignQuestion
    ) -> CampaignQuestion: ...

    async def list_questions_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignQuestion]: ...

    # -- CampaignResponse --------------------------------------------------

    async def create_response(self, **fields: object) -> CampaignResponse: ...

    async def get_response_for_campaign_and_guest(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> CampaignResponse | None: ...

    async def list_responses_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignResponse]: ...

    async def count_responses_for_campaign(self, campaign_id: uuid.UUID) -> int: ...

    # -- CampaignAsset -------------------------------------------------------

    async def create_asset(self, **fields: object) -> CampaignAsset: ...

    async def get_asset_by_id(self, asset_id: uuid.UUID) -> CampaignAsset | None: ...

    async def update_asset(
        self, asset: CampaignAsset, data: dict[str, object]
    ) -> CampaignAsset: ...

    async def soft_delete_asset(self, asset: CampaignAsset) -> CampaignAsset: ...

    async def list_assets_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignAsset]: ...

    # -- CampaignImpression -----------------------------------------------

    async def create_impression(self, **fields: object) -> CampaignImpression: ...

    async def has_guest_been_shown_campaign(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> bool: ...

    async def get_last_shown_at_for_guest(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> datetime | None: ...

    async def list_impressions_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignImpression]: ...


class CampaignsRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``CampaignsRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.campaigns = GenericRepository(Campaign, session)
        self.questions = GenericRepository(CampaignQuestion, session)
        self.responses = GenericRepository(CampaignResponse, session)
        self.assets = GenericRepository(CampaignAsset, session)
        self.impressions = GenericRepository(CampaignImpression, session)

    # -- Campaign --------------------------------------------------------

    async def create_campaign(self, **fields: object) -> Campaign:
        return await self.campaigns.create(fields)

    async def get_campaign_by_id(
        self, campaign_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Campaign | None:
        return await self.campaigns.get_by_id(
            campaign_id, include_deleted=include_deleted
        )

    async def update_campaign(
        self, campaign: Campaign, data: dict[str, object]
    ) -> Campaign:
        return await self.campaigns.update(campaign, data)

    async def soft_delete_campaign(self, campaign: Campaign) -> Campaign:
        return await self.campaigns.soft_delete(campaign)

    async def list_campaigns(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[Campaign], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        return await self.campaigns.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=DEFAULT_SORT_FIELD,
            sort_order=SortOrder.DESC,
        )

    async def list_non_terminal_campaigns(self) -> list[Campaign]:
        """Every ``SCHEDULED``/``ACTIVE`` campaign, across every
        organization -- backs ``tasks.sweep_campaign_status_transitions``,
        mirroring ``app.domains.queue_management.service
        .QueueManagementService.sweep_schedule_transitions``'s own
        platform-wide sweep scope."""
        statement = select(Campaign).where(
            Campaign.is_deleted.is_(False),
            Campaign.status.in_(_NON_TERMINAL_STATUSES),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_candidate_campaigns(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
    ) -> list[Campaign]:
        """Every non-deleted, non-terminal campaign visible to a guest at
        this organization/location -- org-wide (``location_id IS NULL``)
        or scoped to this exact location. Effective-status/
        target_networks/display_rule eligibility is computed by the
        service layer on top of this candidate set, not here (see
        ``service.get_next_campaign_for_session``)."""
        location_clause = Campaign.location_id.is_(None)
        if location_id is not None:
            location_clause = or_(location_clause, Campaign.location_id == location_id)
        statement = select(Campaign).where(
            Campaign.is_deleted.is_(False),
            Campaign.organization_id == organization_id,
            Campaign.status.in_(_NON_TERMINAL_STATUSES),
            location_clause,
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- CampaignQuestion --------------------------------------------------

    async def create_question(self, **fields: object) -> CampaignQuestion:
        return await self.questions.create(fields)

    async def get_question_by_id(
        self, question_id: uuid.UUID
    ) -> CampaignQuestion | None:
        return await self.questions.get_by_id(question_id)

    async def update_question(
        self, question: CampaignQuestion, data: dict[str, object]
    ) -> CampaignQuestion:
        return await self.questions.update(question, data)

    async def soft_delete_question(
        self, question: CampaignQuestion
    ) -> CampaignQuestion:
        return await self.questions.soft_delete(question)

    async def list_questions_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignQuestion]:
        statement = (
            select(CampaignQuestion)
            .where(
                CampaignQuestion.is_deleted.is_(False),
                CampaignQuestion.campaign_id == campaign_id,
            )
            .order_by(CampaignQuestion.order_index.asc())
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- CampaignResponse --------------------------------------------------

    async def create_response(self, **fields: object) -> CampaignResponse:
        return await self.responses.create(fields)

    async def get_response_for_campaign_and_guest(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> CampaignResponse | None:
        results = await self.responses.get_all(
            filters={"campaign_id": campaign_id, "guest_id": guest_id}, limit=1
        )
        return results[0] if results else None

    async def list_responses_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignResponse]:
        return await self.responses.get_all(filters={"campaign_id": campaign_id})

    async def count_responses_for_campaign(self, campaign_id: uuid.UUID) -> int:
        return await self.responses.count(filters={"campaign_id": campaign_id})

    # -- CampaignAsset -------------------------------------------------------

    async def create_asset(self, **fields: object) -> CampaignAsset:
        return await self.assets.create(fields)

    async def get_asset_by_id(self, asset_id: uuid.UUID) -> CampaignAsset | None:
        return await self.assets.get_by_id(asset_id)

    async def update_asset(
        self, asset: CampaignAsset, data: dict[str, object]
    ) -> CampaignAsset:
        return await self.assets.update(asset, data)

    async def soft_delete_asset(self, asset: CampaignAsset) -> CampaignAsset:
        return await self.assets.soft_delete(asset)

    async def list_assets_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignAsset]:
        return await self.assets.get_all(filters={"campaign_id": campaign_id})

    # -- CampaignImpression -----------------------------------------------

    async def create_impression(self, **fields: object) -> CampaignImpression:
        return await self.impressions.create(fields)

    async def has_guest_been_shown_campaign(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> bool:
        statement = (
            select(func.count())
            .select_from(CampaignImpression)
            .join(GuestSession, GuestSession.id == CampaignImpression.guest_session_id)
            .where(
                CampaignImpression.is_deleted.is_(False),
                CampaignImpression.campaign_id == campaign_id,
                GuestSession.guest_id == guest_id,
            )
        )
        result = await self.session.execute(statement)
        return (result.scalar_one() or 0) > 0

    async def get_last_shown_at_for_guest(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> datetime | None:
        statement = (
            select(func.max(CampaignImpression.shown_at))
            .select_from(CampaignImpression)
            .join(GuestSession, GuestSession.id == CampaignImpression.guest_session_id)
            .where(
                CampaignImpression.is_deleted.is_(False),
                CampaignImpression.campaign_id == campaign_id,
                GuestSession.guest_id == guest_id,
            )
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def list_impressions_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignImpression]:
        return await self.impressions.get_all(filters={"campaign_id": campaign_id})


__all__ = ["CampaignsRepositoryProtocol", "CampaignsRepository"]
