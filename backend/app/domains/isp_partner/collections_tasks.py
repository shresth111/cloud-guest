"""COLLECTIONS-1 daily pass, called once per ISP from the existing
``run_isp_billing_daily`` task (``tasks.py``; ``core/celery_app.py`` is not
edited). Does nothing while ``ISP_COLLECTIONS_ENABLED`` is off.

* Every open promise whose date has passed without the money arriving
  becomes ``broken``; one that was paid becomes ``kept``. Each change writes
  one timeline line. Idempotent: a resolved promise is never looked at again.
* A broken promise is the reminder: while ``ISP_APPS_ENABLED`` is on, a JAZE-5
  field task "Collection follow-up" is raised once for it, assigned to the
  staff member who took the promise when they still cover that customer,
  otherwise left unclaimed. Nothing is ever sent to the subscriber.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger

from .collections_config import get_collections_settings

logger = get_logger(__name__)


async def run_collections_daily(session: Any, isp: Any) -> dict[str, int]:
    from .collections_service import IspCollectionsService

    out = {"kept": 0, "broken": 0, "followups": 0}
    if not get_collections_settings().collections_enabled:
        return out
    svc = IspCollectionsService(session=session)
    out |= await svc.resolve_promises(isp)
    for p in getattr(svc, "_just_broken", []):
        if p.followup_task_id is not None:
            continue
        task_id = await _followup_task(session, isp, svc, p)
        if task_id is not None:
            p.followup_task_id = task_id
            out["followups"] += 1
    await session.flush()
    return out


async def _followup_task(session: Any, isp: Any, svc: Any, p: Any) -> Any:
    from .apps_common import (
        IspAppsInvalidError,
        assert_assignee,
        get_isp_apps_settings,
    )
    from .apps_tasks import FieldTaskService

    if not get_isp_apps_settings().enabled:
        return None
    name = (await svc.promise_views(isp, [p]))[0]["name"] or "customer"
    assignee = None
    if p.created_by is not None:
        try:
            await assert_assignee(
                isp, p.created_by, customer_id=p.customer_organization_id
            )
            assignee = p.created_by
        except IspAppsInvalidError:
            assignee = None
    rupees = f"{p.target_paise / 100:,.2f}"
    try:
        async with session.begin_nested():
            view = await FieldTaskService(session).create(
                isp,
                {
                    "isp_customer_id": p.customer_organization_id,
                    "subscriber_id": p.subscriber_id,
                    "kind": "other",
                    "title": f"Collection follow-up: {name}"[:200],
                    "notes": (
                        f"Promised to pay Rs {rupees} by "
                        f"{p.promised_on.isoformat()}; the money has not arrived."
                    ),
                    "assignee_user_id": assignee,
                },
            )
    except Exception:  # noqa: BLE001 -- the promise stays broken either way
        logger.exception(
            "isp_collections_followup_failed", extra={"promise": str(p.id)}
        )
        return None
    import uuid

    vid = view["id"]
    return vid if isinstance(vid, uuid.UUID) else uuid.UUID(str(vid))


__all__ = ["run_collections_daily"]
