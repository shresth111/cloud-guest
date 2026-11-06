from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session

from .customer_service import NetLogsCustomerService
from .repository import CustomerLogsRepository, DeviceLogsRepository
from .service import DeviceLogsService
from .session_events import GuestDeviceEventsReader


def get_device_logs_service(
    db: AsyncSession = Depends(get_db_session),
    # The router's forward-chain lock, held while firewall-logging rows are
    # written (app.common.router_firewall_lock) -- same client as firewall.
    redis: Redis = Depends(get_redis_client),
) -> DeviceLogsService:
    return DeviceLogsService(DeviceLogsRepository(db), get_settings(), redis=redis)


def get_guest_device_events_reader(
    db: AsyncSession = Depends(get_db_session),
) -> GuestDeviceEventsReader:
    return GuestDeviceEventsReader(DeviceLogsRepository(db))


def get_netlogs_customer_service(
    db: AsyncSession = Depends(get_db_session),
) -> NetLogsCustomerService:
    return NetLogsCustomerService(CustomerLogsRepository(db), get_settings())
