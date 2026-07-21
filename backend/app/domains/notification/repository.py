"""Data access layer for the notification domain.

A narrow ``Protocol`` (``NotificationRepositoryProtocol``) plus a concrete,
``GenericRepository``-backed implementation (``NotificationRepository``),
mirroring every other domain's identical shape (see
``app.domains.isp_routing.repository`` for the closest sibling example).
``list_due_deliveries`` is hand-written SQL -- the generic layer's
``apply_filters`` only expresses equality/``IN`` filters, not the
``next_attempt_at <= now`` comparison a dispatch sweep needs (same
precedent as ``app.domains.billing.repository.BillingRepository
.list_issued_past_due``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import NotificationDelivery, NotificationTemplate


class NotificationRepositoryProtocol(Protocol):
    async def create_template(self, **fields: object) -> NotificationTemplate: ...

    async def get_template_by_id(
        self, template_id: uuid.UUID
    ) -> NotificationTemplate | None: ...

    async def find_active_template(
        self,
        *,
        organization_id: uuid.UUID | None,
        event_type: str,
        channel: str,
    ) -> NotificationTemplate | None: ...

    async def update_template(
        self, template: NotificationTemplate, data: dict[str, object]
    ) -> NotificationTemplate: ...

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NotificationTemplate], PaginationMeta]: ...

    async def create_delivery(self, **fields: object) -> NotificationDelivery: ...

    async def get_delivery_by_id(
        self, delivery_id: uuid.UUID
    ) -> NotificationDelivery | None: ...

    async def update_delivery(
        self, delivery: NotificationDelivery, data: dict[str, object]
    ) -> NotificationDelivery: ...

    async def list_deliveries(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        status: str | None,
        event_type: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NotificationDelivery], PaginationMeta]: ...

    async def list_due_deliveries(
        self, *, statuses: list[str], now: datetime, limit: int
    ) -> list[NotificationDelivery]: ...


class NotificationRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``NotificationRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.templates = GenericRepository(NotificationTemplate, session)
        self.deliveries = GenericRepository(NotificationDelivery, session)

    # -- templates -----------------------------------------------------------

    async def create_template(self, **fields: object) -> NotificationTemplate:
        return await self.templates.create(fields)

    async def get_template_by_id(
        self, template_id: uuid.UUID
    ) -> NotificationTemplate | None:
        return await self.templates.get_by_id(template_id)

    async def find_active_template(
        self,
        *,
        organization_id: uuid.UUID | None,
        event_type: str,
        channel: str,
    ) -> NotificationTemplate | None:
        """Prefers an org-specific template over the platform default for
        the same ``(event_type, channel)`` pair."""
        if organization_id is not None:
            org_matches = await self.templates.get_all(
                filters={
                    "organization_id": organization_id,
                    "event_type": event_type,
                    "channel": channel,
                    "is_active": True,
                },
                limit=1,
            )
            if org_matches:
                return org_matches[0]

        statement = select(NotificationTemplate).where(
            NotificationTemplate.is_deleted.is_(False),
            NotificationTemplate.organization_id.is_(None),
            NotificationTemplate.event_type == event_type,
            NotificationTemplate.channel == channel,
            NotificationTemplate.is_active.is_(True),
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def update_template(
        self, template: NotificationTemplate, data: dict[str, object]
    ) -> NotificationTemplate:
        return await self.templates.update(template, data)

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NotificationTemplate], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        return await self.templates.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=DEFAULT_SORT_FIELD,
            sort_order=SortOrder.DESC,
        )

    # -- deliveries ------------------------------------------------------------

    async def create_delivery(self, **fields: object) -> NotificationDelivery:
        return await self.deliveries.create(fields)

    async def get_delivery_by_id(
        self, delivery_id: uuid.UUID
    ) -> NotificationDelivery | None:
        return await self.deliveries.get_by_id(delivery_id)

    async def update_delivery(
        self, delivery: NotificationDelivery, data: dict[str, object]
    ) -> NotificationDelivery:
        return await self.deliveries.update(delivery, data)

    async def list_deliveries(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        status: str | None,
        event_type: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NotificationDelivery], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if status is not None:
            filters["status"] = status
        if event_type is not None:
            filters["event_type"] = event_type
        return await self.deliveries.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=DEFAULT_SORT_FIELD,
            sort_order=SortOrder.DESC,
        )

    async def list_due_deliveries(
        self, *, statuses: list[str], now: datetime, limit: int
    ) -> list[NotificationDelivery]:
        statement = (
            select(NotificationDelivery)
            .where(
                NotificationDelivery.is_deleted.is_(False),
                NotificationDelivery.status.in_(statuses),
                (NotificationDelivery.next_attempt_at.is_(None))
                | (NotificationDelivery.next_attempt_at <= now),
            )
            .order_by(NotificationDelivery.created_at.asc())
            .limit(limit)
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())


__all__ = ["NotificationRepositoryProtocol", "NotificationRepository"]
