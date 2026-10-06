from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import get_db_session

from .repository import DeviceLogsRepository
from .service import DeviceLogsService


def get_device_logs_service(
    db: AsyncSession = Depends(get_db_session),
) -> DeviceLogsService:
    return DeviceLogsService(DeviceLogsRepository(db), get_settings())
