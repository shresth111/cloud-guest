from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import get_db_session

from .repository import DeviceLogsRepository
from .service import DeviceLogsService
from .session_events import GuestDeviceEventsReader


def get_device_logs_service(
    db: AsyncSession = Depends(get_db_session),
) -> DeviceLogsService:
    return DeviceLogsService(DeviceLogsRepository(db), get_settings())


def get_guest_device_events_reader(
    db: AsyncSession = Depends(get_db_session),
) -> GuestDeviceEventsReader:
    return GuestDeviceEventsReader(DeviceLogsRepository(db))
