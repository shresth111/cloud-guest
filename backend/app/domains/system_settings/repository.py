"""System Settings repository: protocol + async SQLAlchemy implementation.

A thin wrapper over ``GenericRepository[SystemSetting]`` exposing exactly
the three operations the service needs: read the whole store as a
``{key: value}`` map, read one key, and upsert one key. Keys are the
closed ``SystemSettingKey`` set (see ``constants``), so this never deals in
free-form strings from a caller.
"""

from __future__ import annotations

from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository

from .models import SystemSetting


class SystemSettingsRepositoryProtocol(Protocol):
    """Minimal surface the service needs from the repo."""

    async def get_all_values(self) -> dict[str, Any]: ...

    async def get_value(self, key: str) -> Any | None: ...

    async def upsert(
        self,
        key: str,
        value: Any | None,
        *,
        actor_user_id: object | None = None,
    ) -> SystemSetting: ...


class SystemSettingsRepository(SystemSettingsRepositoryProtocol):
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.generic = GenericRepository(SystemSetting, db)

    async def get_all_values(self) -> dict[str, Any]:
        stmt = select(SystemSetting).where(SystemSetting.is_deleted.is_(False))
        result = await self.db.execute(stmt)
        return {row.key: row.value for row in result.scalars().all()}

    async def _get_row(self, key: str) -> SystemSetting | None:
        stmt = select(SystemSetting).where(
            SystemSetting.key == key,
            SystemSetting.is_deleted.is_(False),
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_value(self, key: str) -> Any | None:
        row = await self._get_row(key)
        return row.value if row is not None else None

    async def upsert(
        self,
        key: str,
        value: Any | None,
        *,
        actor_user_id: object | None = None,
    ) -> SystemSetting:
        existing = await self._get_row(key)
        if existing is not None:
            existing.value = value
            existing.updated_by = actor_user_id  # type: ignore[assignment]
            await self.db.flush()
            await self.db.refresh(existing)
            return existing

        return await self.generic.create(
            {
                "key": key,
                "value": value,
                "created_by": actor_user_id,
                "updated_by": actor_user_id,
            }
        )
