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


async def _retry_async() -> dict[str, int]:
    from app.database.redis import create_redis_client
    from app.database.session import SessionLocal

    summary = {"customers": 0, "ran": 0, "errors": 0}
    if not get_isp_partner_settings().enabled:
        return summary
    redis = create_redis_client()
    try:
        async with SessionLocal() as session:
            control = _build_services(session, redis)["control"]
            for isp_id, customer_id in await control.pending_customers():
                summary["customers"] += 1
                try:
                    async with session.begin_nested():
                        summary["ran"] += int(
                            await control.retry(isp_id, customer_id, force=True)
                        )
                except Exception:  # noqa: BLE001 -- one customer never blocks the rest
                    summary["errors"] += 1
                    logger.exception(
                        "isp_service_retry_failed", extra={"customer": str(customer_id)}
                    )
            await session.commit()
    finally:
        await redis.aclose()
    return summary


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
    from app.database.redis import create_redis_client
    from app.database.session import SessionLocal

    from .billing_models import IspBillingSettings
    from .billing_service import IspBillingService
    from .constants import AUDIT_ISP_AUTO_SUSPENDED
    from .models import IspPartnerProfile
    from .repository import IspRepository

    summary = {"isps": 0, "invoices": 0, "auto_suspended": 0, "errors": 0}
    if not get_isp_partner_settings().enabled:
        return summary
    redis = create_redis_client()
    try:
        async with SessionLocal() as session:
            services = _build_services(session, redis)
            rows = (
                await session.execute(
                    select(IspPartnerProfile, IspBillingSettings)
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
            ).all()
            repo = IspRepository(session)
            for profile, settings in rows:
                summary["isps"] += 1
                org = await repo.get_organization(profile.organization_id)
                if org is None or org.status != "active":
                    continue
                isp = _SystemContext(org, profile, repo)
                billing = IspBillingService(session=session, audit=services["audit"])
                try:
                    from .plans_service import IspPlansService

                    async with session.begin_nested():
                        # coupon activations -> subscribers + paid invoices
                        # (ADDENDUM_03 §7), then customer + postpaid cycles
                        await IspPlansService(
                            session=session, audit=services["audit"]
                        ).sync_subscribers(isp, force=True)
                    async with session.begin_nested():
                        summary["invoices"] += len(await billing.generate_due(isp))
                    if (
                        settings.auto_suspend_enabled
                        and settings.auto_suspend_after_days
                    ):
                        overdue = await billing.overdue_invoices(
                            isp,
                            await isp.child_ids(),
                            min_days=settings.auto_suspend_after_days,
                        )
                        by_customer: dict[uuid.UUID, list[str]] = {}
                        for inv in overdue:
                            by_customer.setdefault(
                                inv.customer_organization_id, []
                            ).append(str(inv.id))
                        for customer_id, invoice_ids in by_customer.items():
                            customer = await repo.get_organization(customer_id)
                            control = services["control"]
                            if customer is None or await control.is_cut(customer_id):
                                continue
                            async with session.begin_nested():
                                await control.suspend(
                                    org.id,
                                    customer,
                                    actor=None,
                                    reason="non_payment",
                                    support_line=profile.support_phone,
                                    isp_name=org.name,
                                    extra_audit={
                                        "invoice_ids": invoice_ids,
                                        "automatic": True,
                                    },
                                )
                                await services["audit"].create_audit_log_entry(
                                    actor_user_id=None,
                                    action=AUDIT_ISP_AUTO_SUSPENDED,
                                    entity_type="organization",
                                    entity_id=customer_id,
                                    description="ISP customer auto-suspended for dues",
                                    event_metadata={
                                        "console": "isp",
                                        "isp_organization_id": str(org.id),
                                        "invoice_ids": invoice_ids,
                                    },
                                    organization_id=customer_id,
                                    location_id=None,
                                )
                            summary["auto_suspended"] += 1
                except Exception:  # noqa: BLE001 -- one ISP never blocks the rest
                    summary["errors"] += 1
                    logger.exception(
                        "isp_billing_daily_failed", extra={"isp": str(org.id)}
                    )
            await session.commit()
    finally:
        await redis.aclose()
    return summary


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


__all__ = [
    "TASK_ISP_BILLING_DAILY",
    "TASK_ISP_SERVICE_RETRY",
    "retry_pending_service_actions",
    "run_isp_billing_daily",
]
