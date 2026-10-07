"""``python -m app.domains.device_logs.backfill_guest_events``

Derive ``guest_device_events`` for device log lines stored before the
derivation existed (or before a parser fix). Idempotent: lines that already
have a derived row are skipped by the query, and the insert ignores
duplicates, so it can be re-run at any time. Read-mostly: writes only
``guest_device_events``.

Run once after the migration on each environment:

    docker exec deploy-api-1 python -m app.domains.device_logs.backfill_guest_events
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


async def _main() -> None:
    # Every mapper must be registered before the first query (the FKs on
    # these tables point into four other domains) -- importing the app does
    # that, exactly as the API process does.
    import app.main  # noqa: F401
    from app.core.config import get_settings
    from app.database.session import SessionLocal

    from .repository import DeviceLogsRepository
    from .service import DeviceLogsService

    async with SessionLocal() as session:
        service = DeviceLogsService(DeviceLogsRepository(session), get_settings())
        inserted = await service.backfill_guest_events()
        await session.commit()
    logger.info("device_logs_guest_events_backfill", extra={"inserted": inserted})
    print(f"guest_device_events inserted: {inserted}")  # noqa: T201 -- CLI output


if __name__ == "__main__":
    asyncio.run(_main())
