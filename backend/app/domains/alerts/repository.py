"""Repository layer for the Alerts domain."""

import uuid
from typing import Sequence
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.domains.alerts.models import Alert, AlertRule

class AlertsRepository(GenericRepository[Alert]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Alert, session)
        self.rules_repo = GenericRepository(AlertRule, session)

    async def get_active_alerts_for_router(self, router_id: uuid.UUID) -> Sequence[Alert]:
        stmt = (
            select(Alert)
            .where(
                and_(
                    Alert.router_id == router_id,
                    Alert.status == "active"
                )
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_all_active_rules(self) -> Sequence[AlertRule]:
        stmt = select(AlertRule).where(AlertRule.is_enabled == True)
        result = await self.rules_repo.session.execute(stmt)
        return result.scalars().all()
