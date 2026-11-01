"""JAZE-4 sweeps, called from the existing ISP Celery tasks in ``tasks.py``
(no new beat entry; ``core/celery_app.py`` is untouched).

* ``run_finance_frequent`` -- from the 120 s ``retry_pending_service_actions``:
  WhatsApp receipts / renewal confirmations and Telegram DOWN/UP alerts.
* ``run_finance_daily`` -- from ``run_isp_billing_daily``, per ISP: static-IP
  lease invoices, WhatsApp pre-expiry and unpaid reminders.

Every step checks its own flag first and runs in its own SAVEPOINT, so a
failure in one ISP or one step never blocks another.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.core.logging import get_logger

from .finance_config import get_finance_settings

logger = get_logger(__name__)


async def _step(session: Any, commit_each: bool, fn: Any) -> Any:
    """One isolated step. ``commit_each`` (BE-HARDEN, the caller owns a
    dedicated session): commit on success / roll back on failure, so nothing
    this step locked is held while a later step calls out. Otherwise the old
    SAVEPOINT inside the caller's transaction."""
    if not commit_each:
        async with session.begin_nested():
            return await fn()
    try:
        out = await fn()
        await session.commit()
        return out
    except Exception:
        await session.rollback()
        raise


async def run_finance_frequent(
    session: Any, *, commit_each: bool = False
) -> dict[str, int]:
    from .automation import run_telegram, run_whatsapp_events
    from .finance_models import IspAutomationSettings
    from .models import IspPartnerProfile
    from .repository import IspRepository

    cfg = get_finance_settings()
    out = {"isps": 0, "errors": 0}
    if not (cfg.whatsapp_automation_enabled or cfg.telegram_alerts_enabled):
        return out
    rows = (
        (
            await session.execute(
                select(IspAutomationSettings.isp_organization_id)
                .join(
                    IspPartnerProfile,
                    IspPartnerProfile.organization_id
                    == IspAutomationSettings.isp_organization_id,
                )
                .where(
                    IspAutomationSettings.is_deleted.is_(False),
                    IspPartnerProfile.status == "active",
                    (IspAutomationSettings.whatsapp_enabled.is_(True))
                    | (IspAutomationSettings.telegram_enabled.is_(True)),
                )
            )
        )
        .scalars()
        .all()
    )
    repo = IspRepository(session)
    for isp_id in rows:
        out["isps"] += 1
        for step in ("whatsapp", "telegram"):
            try:
                if step == "whatsapp":
                    await _step(
                        session,
                        commit_each,
                        lambda isp_id=isp_id: run_whatsapp_events(
                            session, isp_id, commit_each=commit_each
                        ),
                    )
                else:

                    async def _tg(isp_id=isp_id) -> Any:  # noqa: ANN001
                        return await run_telegram(
                            session, isp_id, await repo.child_ids(isp_id)
                        )

                    await _step(session, commit_each, _tg)
            except Exception:  # noqa: BLE001 -- one ISP never blocks the rest
                out["errors"] += 1
                logger.exception(
                    "isp_finance_frequent_failed",
                    extra={"isp": str(isp_id), "step": step},
                )
    return out


async def run_finance_daily(
    session: Any, isp: Any, today: Any, *, commit_each: bool = False
) -> dict[str, int]:
    from .automation import run_whatsapp_daily
    from .finance_service import IspFinanceService

    cfg = get_finance_settings()
    out = {"lease_invoices": 0, "errors": 0}
    if cfg.finance_extras_enabled:
        try:
            res = await _step(
                session,
                commit_each,
                lambda: IspFinanceService(session=session).bill_leases(
                    isp, as_of=today
                ),
            )
            out["lease_invoices"] = res["invoices_issued"]
        except Exception:  # noqa: BLE001
            out["errors"] += 1
            logger.exception(
                "isp_lease_billing_failed", extra={"isp": str(isp.isp_org_id)}
            )
    # FRANCHISE-2: recurring zone charges + min-balance alerts (own flag).
    from .franchise_service import get_franchise_settings, run_franchise_daily

    if get_franchise_settings().franchise_enabled:
        try:
            out |= await _step(
                session, commit_each, lambda: run_franchise_daily(session, isp, today)
            )
        except Exception:  # noqa: BLE001
            out["errors"] += 1
            logger.exception(
                "isp_franchise_daily_failed", extra={"isp": str(isp.isp_org_id)}
            )
    if cfg.whatsapp_automation_enabled:
        try:
            await _step(
                session,
                commit_each,
                lambda: run_whatsapp_daily(
                    session, isp.isp_org_id, today, commit_each=commit_each
                ),
            )
        except Exception:  # noqa: BLE001
            out["errors"] += 1
            logger.exception(
                "isp_whatsapp_daily_failed", extra={"isp": str(isp.isp_org_id)}
            )
    return out
