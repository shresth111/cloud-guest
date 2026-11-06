"""``python -m app.domains.device_logs.backfill_classification``

Fill the structured NetLogs columns (category, protocol, src_ip, dst_ip,
status, device_mac) on device log lines stored before migration 0167.
Idempotent and batched (1000 rows per round trip, committed per run): only
rows with ``category IS NULL`` are read, and each gets a category (``other``
at worst), so it can be re-run at any time. Writes only those six columns.

Run once after the migration on each environment:

    docker exec deploy-api-1 python -m app.domains.device_logs.backfill_classification
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


async def _main() -> None:
    # Register every mapper before the first query, as the API process does.
    import app.main  # noqa: F401
    from app.core.config import get_settings
    from app.database.session import SessionLocal

    from .repository import DeviceLogsRepository
    from .service import DeviceLogsService

    async with SessionLocal() as session:
        service = DeviceLogsService(DeviceLogsRepository(session), get_settings())
        updated = await service.backfill_classification()
        await session.commit()
    logger.info("device_logs_classification_backfill", extra={"updated": updated})
    print(f"device_log_events classified: {updated}")  # noqa: T201 -- CLI output


if __name__ == "__main__":
    asyncio.run(_main())
