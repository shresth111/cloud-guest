"""ISP partner Celery tasks (exception E7, founder Q7 = yes).

* ``retry_pending_service_actions`` (every 120 s): re-kicks live sessions
  of suspended customers whose router was unreachable (ADDENDUM_01 §A.4).
  The RADIUS cut itself never waits on this: NAS rows are disabled in the
  request transaction.
* ``run_isp_billing_daily`` (02:30 IST): issues due cycle invoices for every
  ISP with billing set up and, only where the ISP turned it on (default
  OFF), suspends customers overdue by more than ``auto_suspend_after_days``.

Both do nothing while ``ISP_PARTNER_ENABLED`` is off, and both run each ISP
or customer in its own SAVEPOINT so one failure never blocks the rest.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.logging import get_logger

from .config import get_isp_partner_settings

logger = get_logger(__name__)

TASK_ISP_SERVICE_RETRY = "app.domains.isp_partner.tasks.retry_pending_service_actions"
TASK_ISP_BILLING_DAILY = "app.domains.isp_partner.tasks.run_isp_billing_daily"
TASK_ISP_ENFORCEMENT_SWEEP = "app.domains.isp_partner.tasks.run_isp_enforcement_sweep"


def _build_services(session: Any, redis: Any) -> dict[str, Any]:
    """The real service graph a worker needs, mirroring
    ``provisioning_engine.tasks._build_provisioning_engine_service``."""
    from app.core.config import get_settings
    from app.domains.captive_portal.repository import CaptivePortalRepository
    from app.domains.captive_portal.service import CaptivePortalService
    from app.domains.guest.repository import (
        GuestRepository,
        RadiusNasCodeCounterRepository,
    )
    from app.domains.guest.service import GuestService, RadiusService
    from app.domains.guest.tasks import _build_session_terminator
    from app.domains.location.repository import (
        LocationCodeCounterRepository,
        LocationRepository,
    )
    from app.domains.location.service import LocationService
    from app.domains.organization.repository import OrganizationRepository
    from app.domains.organization.service import OrganizationService
    from app.domains.otp.repository import OtpRepository
    from app.domains.otp.service import OtpService
    from app.domains.rbac.repository import RBACRepository
    from app.domains.router.repository import RouterRepository
    from app.domains.router.service import RouterService
    from app.domains.voucher.repository import VoucherRepository
    from app.domains.voucher.service import VoucherService

    from .providers import make_live_disconnect

    settings = get_settings()
    audit = RBACRepository(session)
    organization_service = OrganizationService(
        OrganizationRepository(session), audit_writer=audit
    )
    location_service = LocationService(
        LocationRepository(session),
        organization_service,
        location_code_counter=LocationCodeCounterRepository(session),
        audit_writer=audit,
    )
    router_service = RouterService(
        RouterRepository(session),
        location_service,
        organization_service,
        audit_writer=audit,
        provisioning_token_ttl_hours=settings.router_provisioning_token_expire_hours,
    )
    captive_portal_service = CaptivePortalService(
        CaptivePortalRepository(session),
        organization_service,
        location_service,
        audit_writer=audit,
    )
    guest_repository = GuestRepository(session)
    terminator = _build_session_terminator(session, guest_repository)
    guest_service = GuestService(
        guest_repository,
        OtpService(OtpRepository(session), redis, audit_writer=audit),
        VoucherService(
            VoucherRepository(session),
            redis,
            organization_service,
            location_service,
            audit_writer=audit,
        ),
        captive_portal_service,
        router_service,
        audit_writer=audit,
        session_end_hook=terminator,
    )
    radius_service = RadiusService(
        guest_repository,
        guest_service,
        router_service,
        location_service,
        RadiusNasCodeCounterRepository(session),
        audit_writer=audit,
    )
    from .service_control import IspServiceControl

    control = IspServiceControl(
        session=session,
        radius_service=radius_service,
        guest_service=guest_service,
        captive_portal_service=captive_portal_service,
        organization_service=organization_service,
        audit=audit,
        live_disconnect=make_live_disconnect(guest_repository, terminator),
    )
    return {"control": control, "audit": audit}


#: BE-HARDEN overlap guard for the 120 s pass: a Redis lock with a TTL, so a
#: pass that outlives its slot (slow routers) never runs beside the next one,
#: and a crashed worker frees the slot when the TTL ends.
RETRY_LOCK_KEY = "isp:lock:service-retry"
RETRY_LOCK_TTL_S = 900
_RELEASE = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


async def _own_tx(name: str, fn: Any, summary: dict, **log: Any) -> Any:
    """Run ``fn(session)`` in its OWN session and transaction: committed on
    success, rolled back on failure, never sharing locks with another step
    (BE-HARDEN: each hook isolated; nothing it locked is held while a later
    step calls a router or a messaging API)."""
    from app.database.session import SessionLocal

    async with SessionLocal() as session:
        try:
            out = await fn(session)
            await session.commit()
            return out
        except Exception:  # noqa: BLE001 -- one step never blocks the rest
            await session.rollback()
            summary["errors"] = summary.get("errors", 0) + 1
            logger.exception(
                f"{name}_failed", extra={k: str(v) for k, v in log.items()}
            )
            return None


async def _coupon_sync_isps(session: Any) -> list[uuid.UUID]:
    from .models import IspPartnerProfile
    from .plans_models import IspCouponBatch

    return list(
        (
            await session.execute(
                select(IspCouponBatch.isp_organization_id)
                .join(
                    IspPartnerProfile,
                    IspPartnerProfile.organization_id
                    == IspCouponBatch.isp_organization_id,
                )
                .where(
                    IspPartnerProfile.status == "active",
                    IspPartnerProfile.is_deleted.is_(False),
                    IspCouponBatch.is_deleted.is_(False),
                )
                .distinct()
            )
        ).scalars()
    )


async def _system_ctx(session: Any, isp_id: uuid.UUID) -> Any:
    from .repository import IspRepository

    repo = IspRepository(session)
    org = await repo.get_organization(isp_id)
    prof = await repo.get_profile(isp_id)
    if org is None or prof is None or org.status != "active":
        return None
    return _SystemContext(org, prof, repo)


async def _retry_async() -> dict[str, int]:
    from app.database.redis import create_redis_client

    summary = {"customers": 0, "ran": 0, "errors": 0}
    if not get_isp_partner_settings().enabled:
        return summary
    redis = create_redis_client()
    token = uuid.uuid4().hex
    try:
        if not await redis.set(RETRY_LOCK_KEY, token, nx=True, ex=RETRY_LOCK_TTL_S):
            summary["skipped_overlap"] = 1
            logger.info("isp_service_retry_overlap_skipped")
            return summary
        try:
            await _retry_steps(redis, summary)
        finally:
            await redis.eval(_RELEASE, 1, RETRY_LOCK_KEY, token)
    finally:
        await redis.aclose()
    return summary


async def _retry_steps(redis: Any, summary: dict) -> None:
    from app.database.session import SessionLocal

    # 1. suspend/resume re-kicks: one customer per transaction. The list is
    #    read in a short transaction of its own; each customer's kick runs
    #    with autoflush off, so its state row is not written (locked) until
    #    after the router call, and commits at once.
    async with SessionLocal() as session:
        pairs = await _build_services(session, redis)["control"].pending_customers()
    for isp_id, customer_id in pairs:
        summary["customers"] += 1

        async def _one(session: Any, isp_id=isp_id, customer_id=customer_id) -> int:  # noqa: ANN001
            control = _build_services(session, redis)["control"]
            with session.no_autoflush:
                return int(await control.retry(isp_id, customer_id, force=True))

        ran = await _own_tx("isp_service_retry", _one, summary, customer=customer_id)
        summary["ran"] += int(ran or 0)

    # 2. JAZE-4 WhatsApp receipts / renewals + Telegram alerts: committed per
    #    ISP step and per message (a sent message is never re-sent because a
    #    later step rolled back).
    from .finance_tasks import run_finance_frequent

    await _own_tx(
        "isp_finance_frequent",
        lambda s: run_finance_frequent(s, commit_each=True),
        summary,
    )

    # 3. BE-HARDEN coupon -> subscriber sync, incremental, one ISP per tx.
    async with SessionLocal() as session:
        coupon_isps = await _coupon_sync_isps(session)
    for isp_id in coupon_isps:

        async def _sync(session: Any, isp_id=isp_id) -> int:  # noqa: ANN001
            from app.domains.rbac.repository import RBACRepository

            from .plans_service import IspPlansService

            ctx = await _system_ctx(session, isp_id)
            if ctx is None:
                return 0
            return await IspPlansService(
                session=session, audit=RBACRepository(session)
            ).sync_subscribers(ctx, force=True)

        await _own_tx("isp_coupon_sync", _sync, summary, isp=isp_id)

    # 4. QUEUED-RENEWAL plan switches (no network; rows SKIP LOCKED).
    from .queued_renewal_service import run_queued_renewals

    await _own_tx("isp_queued_renewals", run_queued_renewals, summary)

    # 5. REFERRAL-1 (no network; keyset pages, committed per page).
    from .referrals_service import run_referrals

    await _own_tx(
        "isp_referrals", lambda s: run_referrals(s, commit_each=True), summary
    )

    # 6. APPS-2 scheduled announcements + escalations, committed per item.
    from .apps2_tasks import run_apps_frequent

    await _own_tx(
        "isp_apps_frequent",
        lambda s: run_apps_frequent(s, commit_each=True),
        summary,
    )

    # 7. SMALL-3 win-back saves (no network; one ISP per transaction inside,
    #    flag ISP_REVENUE_HUB_ENABLED; a failure never blocks the pass).
    try:
        from .winback_service import run_winback_saves

        summary["winback_saved"] = (await run_winback_saves()).get("saved", 0)
    except Exception:  # noqa: BLE001 -- logged, the pass goes on
        summary["errors"] = summary.get("errors", 0) + 1
        logger.exception("isp_winback_saves_failed")


class _SystemContext:
    """An ``IspContext`` for the daily job: no human actor, no confinement."""

    def __init__(self, organization: Any, profile: Any, repository: Any) -> None:
        self.isp_org_id = organization.id
        self.user_id = None
        self.role_slug = "system"
        self.confined_customer_ids = None
        self.organization = organization
        self.profile = profile
        self.repository = repository

    async def child_ids(self) -> list[uuid.UUID]:
        return await self.repository.child_ids(self.isp_org_id)


async def _billing_daily_async() -> dict[str, int]:
    """BE-HARDEN: one transaction per ISP (and per step after billing), never
    one for the whole run. The invoice / receipt / circuit sequence rows and
    the postpaid subscribers ``generate_due`` locks are released when that
    ISP's billing commits, before the next ISP starts and before any router
    (auto-suspend) or messaging (WhatsApp) call. A failing ISP rolls back only
    itself."""
    from app.database.redis import create_redis_client
    from app.database.session import SessionLocal

    from .billing_models import IspBillingSettings
    from .models import IspPartnerProfile

    summary = {"isps": 0, "invoices": 0, "auto_suspended": 0, "errors": 0}
    if not get_isp_partner_settings().enabled:
        return summary
    redis = create_redis_client()
    try:
        async with SessionLocal() as session:
            isp_ids = list(
                (
                    await session.execute(
                        select(IspPartnerProfile.organization_id)
                        .join(
                            IspBillingSettings,
                            IspBillingSettings.isp_organization_id
                            == IspPartnerProfile.organization_id,
                        )
                        .where(
                            IspPartnerProfile.status == "active",
                            IspPartnerProfile.is_deleted.is_(False),
                        )
                    )
                ).scalars()
            )
        for isp_id in isp_ids:
            summary["isps"] += 1
            await _billing_daily_one(isp_id, redis, summary)
    finally:
        await redis.aclose()
    return summary


async def _billing_daily_one(isp_id: uuid.UUID, redis: Any, summary: dict) -> None:
    from .billing_models import IspBillingSettings
    from .billing_service import IspBillingService
    from .constants import AUDIT_ISP_AUTO_SUSPENDED

    # 1. coupon sync + cycle invoices: one transaction for this ISP only.
    async def _bill(session: Any) -> Any:
        from .plans_service import IspPlansService

        isp = await _system_ctx(session, isp_id)
        if isp is None:
            return None
        audit = _build_services(session, redis)["audit"]
        billing = IspBillingService(session=session, audit=audit)
        async with session.begin_nested():
            # coupon activations -> subscribers + paid invoices (ADDENDUM_03 §7)
            await IspPlansService(session=session, audit=audit).sync_subscribers(
                isp, force=True
            )
        async with session.begin_nested():
            summary["invoices"] += len(await billing.generate_due(isp))
        return billing.today(isp)

    today = await _own_tx("isp_billing_daily", _bill, summary, isp=isp_id)
    if today is None:
        return

    # 2. JAZE-4 lease invoices / FRANCHISE-2 charges / WhatsApp reminders:
    #    each step committed on its own, messages committed one by one.
    async def _finance(session: Any) -> None:
        from .finance_tasks import run_finance_daily

        isp = await _system_ctx(session, isp_id)
        if isp is not None:
            await run_finance_daily(session, isp, today, commit_each=True)

    await _own_tx("isp_finance_daily", _finance, summary, isp=isp_id)

    # 3. auto-suspend (per-ISP setting, OFF by default): the overdue list is
    #    read first; each customer is suspended (router kicks) in its own
    #    transaction.
    async def _overdue(session: Any) -> dict | None:
        isp = await _system_ctx(session, isp_id)
        if isp is None:
            return None
        settings = (
            await session.execute(
                select(IspBillingSettings).where(
                    IspBillingSettings.isp_organization_id == isp_id,
                    IspBillingSettings.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()
        if not (
            settings
            and settings.auto_suspend_enabled
            and settings.auto_suspend_after_days
        ):
            return None
        overdue = await IspBillingService(session=session).overdue_invoices(
            isp, await isp.child_ids(), min_days=settings.auto_suspend_after_days
        )
        by_customer: dict[uuid.UUID, list[str]] = {}
        for inv in overdue:
            by_customer.setdefault(inv.customer_organization_id, []).append(str(inv.id))
        return by_customer

    by_customer = await _own_tx("isp_auto_suspend_scan", _overdue, summary, isp=isp_id)
    for customer_id, invoice_ids in (by_customer or {}).items():

        async def _suspend(
            session: Any,
            customer_id=customer_id,
            invoice_ids=invoice_ids,  # noqa: ANN001
        ) -> int:
            isp = await _system_ctx(session, isp_id)
            services = _build_services(session, redis)
            customer = await isp.repository.get_organization(customer_id)
            control = services["control"]
            if customer is None or await control.is_cut(customer_id):
                return 0
            await control.suspend(
                isp_id,
                customer,
                actor=None,
                reason="non_payment",
                support_line=isp.profile.support_phone,
                isp_name=isp.organization.name,
                extra_audit={"invoice_ids": invoice_ids, "automatic": True},
            )
            await services["audit"].create_audit_log_entry(
                actor_user_id=None,
                action=AUDIT_ISP_AUTO_SUSPENDED,
                entity_type="organization",
                entity_id=customer_id,
                description="ISP customer auto-suspended for dues",
                event_metadata={
                    "console": "isp",
                    "isp_organization_id": str(isp_id),
                    "invoice_ids": invoice_ids,
                },
                organization_id=customer_id,
                location_id=None,
            )
            return 1

        summary["auto_suspended"] += int(
            await _own_tx("isp_auto_suspend", _suspend, summary, customer=customer_id)
            or 0
        )

    # 4. COLLECTIONS-1 promises (own flag) and 5. JAZE-3 J17 report emails.
    async def _collections(session: Any) -> None:
        from .collections_tasks import run_collections_daily

        isp = await _system_ctx(session, isp_id)
        if isp is not None:
            await run_collections_daily(session, isp)

    await _own_tx("isp_collections_daily", _collections, summary, isp=isp_id)

    async def _reports(session: Any) -> int:
        from .compliance_tasks import run_report_schedules

        isp = await _system_ctx(session, isp_id)
        return 0 if isp is None else await run_report_schedules(session, isp)

    summary["reports"] = summary.get("reports", 0) + int(
        await _own_tx("isp_report_schedules", _reports, summary, isp=isp_id) or 0
    )

    # 6. SMALL-4 revenue snapshot (MRR history), own transaction + savepoint;
    #    ISP_REVENUE_HUB_ENABLED off = nothing written.
    async def _snapshot(session: Any) -> int:
        from .revenue_snapshot import take_snapshot

        isp = await _system_ctx(session, isp_id)
        if isp is None:
            return 0
        async with session.begin_nested():
            return int(await take_snapshot(session, isp) is not None)

    summary["revenue_snapshots"] = summary.get("revenue_snapshots", 0) + int(
        await _own_tx("isp_revenue_snapshot", _snapshot, summary, isp=isp_id) or 0
    )


@celery_app.task(name=TASK_ISP_SERVICE_RETRY)
def retry_pending_service_actions() -> dict[str, int]:
    summary = run_celery_task(_retry_async())
    logger.info("isp_service_retry_completed", extra={"isp": summary})
    return summary


@celery_app.task(name=TASK_ISP_BILLING_DAILY)
def run_isp_billing_daily() -> dict[str, int]:
    summary = run_celery_task(_billing_daily_async())
    logger.info("isp_billing_daily_completed", extra={"isp": summary})
    return summary


async def _enforcement_async() -> dict[str, int]:
    """JAZE-2 minute sweep (enforcement_sweep.py). Does nothing unless both
    ISP_PARTNER_ENABLED and ISP_PARTNER_ENFORCEMENT_ENABLED are on."""
    from app.database.redis import create_redis_client
    from app.database.session import SessionLocal

    from .enforcement_sweep import run_sweep

    settings = get_isp_partner_settings()
    if not (settings.enabled and settings.enforcement_enabled):
        return {"skipped": 1}
    redis = create_redis_client()
    try:
        async with SessionLocal() as session:
            guest_service = _build_services(session, redis)["control"].guest_service

            async def _disconnect(session_id, organization_id, reason):  # noqa: ANN001, ANN202
                return await guest_service.disconnect_session(
                    session_id=session_id,
                    requesting_organization_id=organization_id,
                    reason=f"isp_enforcement:{reason}",
                )

            summary = await run_sweep(session, disconnect=_disconnect)
            await session.commit()
            return summary
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_ISP_ENFORCEMENT_SWEEP)
def run_isp_enforcement_sweep() -> dict[str, int]:
    summary = run_celery_task(_enforcement_async())
    logger.info("isp_enforcement_sweep_completed", extra={"isp": summary})
    return summary


__all__ = [
    "TASK_ISP_BILLING_DAILY",
    "TASK_ISP_ENFORCEMENT_SWEEP",
    "TASK_ISP_SERVICE_RETRY",
    "retry_pending_service_actions",
    "run_isp_billing_daily",
    "run_isp_enforcement_sweep",
]
