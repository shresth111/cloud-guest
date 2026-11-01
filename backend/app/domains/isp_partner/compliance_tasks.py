"""J17 scheduled compliance emails.

Runs inside the existing ISP daily job (``tasks._billing_daily_async``), so
no new Celery beat entry is needed. Off unless
``ISP_COMPLIANCE_SCHEDULES_ENABLED=true``. Each schedule sends the previous
calendar month's report once (``last_period_sent``), on or after its day.
Attachments are stored under ``isp-reports/`` and sent through the existing
notification outbox.
"""

from __future__ import annotations

import os
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select

from app.core.logging import get_logger

from .compliance_models import IspReportSchedule

logger = get_logger(__name__)
IST = ZoneInfo("Asia/Kolkata")


def schedules_enabled() -> bool:
    return os.environ.get("ISP_COMPLIANCE_SCHEDULES_ENABLED", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def previous_period(today: date) -> str:
    year, month = (
        (today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12)
    )
    return f"{year:04d}-{month:02d}"


def due(schedule: Any, today: date) -> bool:
    return (
        schedule.enabled
        and bool(schedule.recipients)
        and today.day >= schedule.day_of_month
        and schedule.last_period_sent != previous_period(today)
    )


async def build_attachment(
    session: Any, isp: Any, key: str, period: str
) -> tuple[bytes, str]:
    from .compliance_logic import month_bounds
    from .compliance_reports import IspComplianceReports
    from .compliance_router import agr_csv, report_csv, trai_csv
    from .compliance_service import IspComplianceService

    if key == "trai_pmr":
        data = await IspComplianceService(session).trai_pmr(isp, period=period)
        parts = [
            trai_csv(data, r).decode()
            for r in ("subscriptions", "hotspots", "gigabit", "data_usage")
        ]
        return "\n".join(parts).encode(), f"trai-pmr-{period}.csv"
    start, end = month_bounds(period)
    if key == "agr":
        data = await IspComplianceService(session).agr(
            isp, since=start.date(), until=end.date() - timedelta(days=1)
        )
        return agr_csv(data), f"agr-{period}.csv"
    data = await IspComplianceReports(session).run(
        isp, key, since=start, until=end, unmasked=True
    )
    return report_csv(data), f"{key}-{period}.csv"


async def run_report_schedules(
    session: Any, isp: Any, *, now: datetime | None = None
) -> int:
    """Called once per ISP by the daily job. Returns emails queued."""
    if not schedules_enabled():
        return 0
    from app.core.storage import get_object_storage
    from app.domains.notification.constants import (
        NotificationChannelType,
        NotificationEventType,
    )
    from app.domains.notification.repository import NotificationRepository
    from app.domains.notification.service import NotificationService

    today = (now or datetime.now(UTC)).astimezone(IST).date()
    period = previous_period(today)
    rows = (
        (
            await session.execute(
                select(IspReportSchedule).where(
                    IspReportSchedule.isp_organization_id == isp.isp_org_id,
                    IspReportSchedule.is_deleted.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    sent = 0
    for schedule in rows:
        if not due(schedule, today):
            continue
        try:
            content, filename = await build_attachment(
                session, isp, schedule.report_key, period
            )
            key = f"isp-reports/{isp.isp_org_id}/{period}/{filename}"
            await get_object_storage().upload(
                key=key, content=content, content_type="text/csv"
            )
            outbox = NotificationService(NotificationRepository(session))
            for recipient in schedule.recipients:
                await outbox.enqueue(
                    event_type=NotificationEventType.SCHEDULED_REPORT,
                    channel=NotificationChannelType.EMAIL,
                    recipient=recipient,
                    subject=f"{isp.organization.name}: {schedule.report_key} {period}",
                    body=(
                        f"<p>The {schedule.report_key.replace('_', ' ')} report for "
                        f"{period} is attached. Check it before filing.</p>"
                    ),
                    organization_id=isp.isp_org_id,
                    attachment_storage_key=key,
                    attachment_filename=filename,
                )
            schedule.last_period_sent = period
            schedule.last_sent_at = datetime.now(UTC)
            schedule.last_status = f"queued to {len(schedule.recipients)}"
            sent += 1
        except Exception as exc:  # noqa: BLE001 -- one report never blocks the rest
            schedule.last_status = f"failed: {type(exc).__name__}"[:200]
            logger.exception(
                "isp_report_schedule_failed",
                extra={"isp": str(isp.isp_org_id), "report": schedule.report_key},
            )
    await session.flush()
    return sent
