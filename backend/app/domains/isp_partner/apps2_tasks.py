"""APPS-2 frequent pass: scheduled announcements + helpdesk escalations.

Called from the existing 120 s ``retry_pending_service_actions`` beat task
(``tasks._retry_async``), the same way JAZE-4 hooks its frequent work, so
``celery_app.py`` is not edited. A no-op while ``ISP_APPS_ENABLED`` is off.
Every ISP runs in its own savepoint: one ISP's failure never blocks another.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from .finance_tasks import _step  # BE-HARDEN isolated step

__all__ = ["run_apps_frequent"]

logger = logging.getLogger(__name__)


def _notifications(session: Any) -> Any:
    from app.core.config import get_settings
    from app.core.storage import get_object_storage
    from app.domains.notification.dependencies import get_notification_service
    from app.domains.notification.repository import NotificationRepository

    return get_notification_service(
        repository=NotificationRepository(session),
        object_storage=get_object_storage(),
        settings=get_settings(),
    )


async def run_apps_frequent(
    session: Any,
    *,
    now: datetime | None = None,
    telegram: Any = None,
    commit_each: bool = False,
) -> dict[str, int]:
    from .apps2_models import IspTicketEscalationRule
    from .apps2_service import Apps2Service
    from .apps_announcements import AnnouncementService
    from .apps_common import get_isp_apps_settings
    from .apps_models import IspAnnouncement
    from .models import IspPartnerProfile
    from .repository import IspRepository
    from .tasks import _SystemContext

    summary = {"isps": 0, "announcements": 0, "escalations": 0, "errors": 0}
    if not get_isp_apps_settings().enabled:
        return summary
    now = now or datetime.now(UTC)
    due = dict(
        (
            await session.execute(
                select(IspAnnouncement.id, IspAnnouncement.isp_organization_id).where(
                    IspAnnouncement.status == "draft",
                    IspAnnouncement.is_deleted.is_(False),
                    IspAnnouncement.scheduled_at.is_not(None),
                    IspAnnouncement.scheduled_at <= now,
                )
            )
        ).all()
    )
    rule_isps = set(
        (
            await session.execute(
                select(IspTicketEscalationRule.isp_organization_id)
                .where(
                    IspTicketEscalationRule.active.is_(True),
                    IspTicketEscalationRule.is_deleted.is_(False),
                )
                .distinct()
            )
        ).scalars()
    )
    isp_ids = set(due.values()) | rule_isps
    if not isp_ids:
        return summary
    repo = IspRepository(session)
    notifications = _notifications(session) if due else None
    for isp_id in isp_ids:
        profile = (
            (
                await session.execute(
                    select(IspPartnerProfile).where(
                        IspPartnerProfile.organization_id == isp_id,
                        IspPartnerProfile.status == "active",
                        IspPartnerProfile.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        org = await repo.get_organization(isp_id)
        if profile is None or org is None or org.status != "active":
            continue
        isp = _SystemContext(org, profile, repo)
        summary["isps"] += 1
        for ann_id in [a for a, i in due.items() if i == isp_id]:
            try:
                await _step(
                    session,
                    commit_each,
                    lambda ann_id=ann_id, isp=isp: AnnouncementService(
                        session, notifications
                    ).send(isp, ann_id),
                )
                summary["announcements"] += 1
            except Exception:  # noqa: BLE001 -- e.g. no customer left to send to
                summary["errors"] += 1
                logger.exception(
                    "isp_announcement_scheduled_send_failed",
                    extra={"announcement": str(ann_id)},
                )
        if isp_id in rule_isps:
            try:
                summary["escalations"] += await _step(
                    session,
                    commit_each,
                    lambda isp=isp: Apps2Service(session).run_escalations(
                        isp, now=now, telegram=telegram
                    ),
                )
            except Exception:  # noqa: BLE001
                summary["errors"] += 1
                logger.exception(
                    "isp_ticket_escalation_failed", extra={"isp": str(isp_id)}
                )
    return summary
