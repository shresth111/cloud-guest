"""Repository layer for the Events domain."""

import uuid
from typing import Sequence
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.domains.events.models import Event

class EventsRepository(GenericRepository[Event]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Event, session)

    async def get_events_by_organization(self, organization_id: uuid.UUID, limit: int = 50) -> Sequence[Event]:
        stmt = (
            select(Event)
            .where(Event.organization_id == organization_id)
            .order_by(desc(Event.created_at))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
