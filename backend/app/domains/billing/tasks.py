"""Celery task definitions for the Billing domain's Renewal Engine (BE-013
Part 2: ``run_subscription_renewal_sweep``, the Beat-scheduled task
``app.core.celery_app``'s own ``beat_schedule`` registers).

Mirrors ``app.domains.analytics.tasks``/``report_tasks``'s exact async-
bridge pattern -- a plain, synchronous ``@celery_app.task`` body delegating
immediately to a module-level ``async def`` via ``asyncio.run``, which opens
a fresh ``AsyncSession``, builds the real repository/service graph, does the
actual work, commits, and returns a plain, JSON-serializable result. See
``app.domains.analytics.tasks``'s own module docstring for why
``asyncio.run`` is safe here (a Celery worker task body never itself has a
running event loop underneath it).

## Payment gateway wiring in a Celery worker process

``renewal_service.RenewalService`` is constructed here with
``dependencies.build_payment_gateway(db=session, settings=settings)`` --
the exact same, single provider-selection function the FastAPI dependency
graph's ``get_payment_gateway`` calls (``dependencies.get_renewal_service``).
This keeps exactly one place in this codebase that decides which real
``PaymentGatewayProtocol`` implementation (Stripe vs. Razorpay) is live:
BE-013 Part 3's ``build_payment_gateway`` wires the same real gateway into
both the HTTP API path and this Celery worker path simultaneously. This
task passes its own already-open ``session``/``settings`` explicitly
rather than calling the FastAPI dependency function with no arguments --
``get_payment_gateway``'s parameters merely *default* to
``Depends(get_db_session)``/``Depends(get_settings)``, which are only ever
resolved by FastAPI's own DI container, not by a bare function call from
plain Python code such as this task body.
"""

from __future__ import annotations

import asyncio

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.storage import get_object_storage
from app.database.session import SessionLocal
from app.domains.notification.repository import NotificationRepository
from app.domains.notification.service import NotificationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.otp.service import (
    get_configured_email_provider,
    get_configured_sms_provider,
)
from app.domains.rbac.repository import RBACRepository

from .constants import (
    TASK_RUN_INVOICE_OVERDUE_SWEEP,
    TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP,
)
from .dependencies import build_payment_gateway
from .renewal_service import RenewalService, RenewalSweepReport
from .repository import (
    BillingProfileRepository,
    CreditDebitNoteRepository,
    InvoiceRepository,
    LicenseRepository,
    NumberCounterRepository,
    PlanRepository,
    SubscriptionRepository,
    TaxRateRepository,
)
from .service import InvoiceService, LicenseService

logger = get_logger(__name__)


async def _run_renewal_sweep_async() -> RenewalSweepReport:
    """The actual async work behind ``run_subscription_renewal_sweep`` -- a
    fresh session per task run (never a session shared across separate
    task invocations/worker ticks)."""
    settings = get_settings()
    async with SessionLocal() as session:
        try:
            subscription_repository = SubscriptionRepository(session)
            plan_repository = PlanRepository(session)
            license_repository = LicenseRepository(session)
            organization_repository = OrganizationRepository(session)
            audit_repository = RBACRepository(session)

            license_service = LicenseService(
                license_repository,
                plan_repository,
                audit_writer=audit_repository,
            )
            organization_service = OrganizationService(
                organization_repository, audit_writer=audit_repository
            )
            notification_service = NotificationService(
                NotificationRepository(session),
                object_storage=get_object_storage(),
                email_provider=get_configured_email_provider(settings),
                sms_provider=get_configured_sms_provider(settings),
                max_attempts=settings.notification_max_delivery_attempts,
                retry_backoff_seconds=settings.notification_retry_backoff_seconds,
            )
            renewal_service = RenewalService(
                subscription_repository,
                plan_repository,
                license_service=license_service,
                organization_lookup=organization_service,
                payment_gateway=build_payment_gateway(db=session, settings=settings),
                notification_service=notification_service,
                audit_writer=audit_repository,
                grace_period_days=settings.subscription_renewal_grace_period_days,
                renewal_reminder_days_before=(
                    settings.subscription_renewal_reminder_days_before
                ),
                expiry_reminder_days_before=(
                    settings.subscription_expiry_reminder_days_before
                ),
            )
            report = await renewal_service.run_renewal_sweep()
            await session.commit()
            return report
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP)
def run_subscription_renewal_sweep() -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- hourly, see ``constants
    .SUBSCRIPTION_RENEWAL_SWEEP_INTERVAL_SECONDS``'s own docstring for why).
    Runs ``RenewalService.run_renewal_sweep`` -- due-renewal processing,
    grace-period expiry, and both reminder kinds -- with real per-phase and
    per-subscription failure isolation (see that method's own docstring);
    this task simply reports the aggregate result, it never re-raises a
    single subscription's or phase's failure."""
    report = asyncio.run(_run_renewal_sweep_async())
    logger.info(
        "billing_task_run_subscription_renewal_sweep_completed",
        extra={
            "subscriptions_checked": report.renewal.subscriptions_checked,
            "renewed": report.renewal.renewed,
            "failed_count": len(report.renewal.failed),
            "expired_count": len(report.expired_subscription_ids),
            "renewal_reminders_sent": report.renewal_reminders_sent,
            "expiry_reminders_sent": report.expiry_reminders_sent,
        },
    )
    return {
        "subscriptions_checked": report.renewal.subscriptions_checked,
        "renewed": report.renewal.renewed,
        "failed": [
            {"subscription_id": str(sub_id), "error": error}
            for sub_id, error in report.renewal.failed
        ],
        "expired_subscription_ids": [
            str(sub_id) for sub_id in report.expired_subscription_ids
        ],
        "renewal_reminders_sent": report.renewal_reminders_sent,
        "expiry_reminders_sent": report.expiry_reminders_sent,
    }


# ============================================================================
# BE-013 Part 4: Invoice overdue sweep
#
# ## Honest scope boundary: this task exists and works, but is not
# ## Beat-registered here
#
# Mirrors BE-013 Part 1's own explicit "expire_license is fully built,
# tested, and ready for a future part's Beat schedule to call" deferral
# (see service.LicenseService's own module docstring): this task is a real,
# fully working, independently callable Celery task -- but wiring its
# entry into ``app.core.celery_app``'s ``beat_schedule`` is a change to
# ``app/core/celery_app.py``, a file outside this Part's own directory-rule
# boundary (only ``app/domains/billing/``, ``app/core/config.py``,
# ``alembic/versions/``, ``tests/unit/``, ``docs/billing/``, and a few
# other explicitly-named files are in scope for BE-013 Part 4). Registering
# ``TASK_RUN_INVOICE_OVERDUE_SWEEP`` in that file's ``beat_schedule`` dict
# (the same one-line addition ``TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP``
# already has) is the one remaining step to make this run automatically,
# on an interval of ``Settings.invoice_overdue_sweep_interval_seconds`` --
# deliberately left to that dedicated, narrow follow-up edit rather than
# reaching outside this part's own directory rule.
# ============================================================================


async def _run_invoice_overdue_sweep_async() -> list[str]:
    """The actual async work behind ``run_invoice_overdue_sweep`` -- a
    fresh session per task run, mirroring
    ``_run_renewal_sweep_async``'s identical pattern."""
    settings = get_settings()
    async with SessionLocal() as session:
        try:
            invoice_repository = InvoiceRepository(session)
            subscription_repository = SubscriptionRepository(session)
            plan_repository = PlanRepository(session)
            billing_profile_repository = BillingProfileRepository(session)
            tax_rate_repository = TaxRateRepository(session)
            number_counter_repository = NumberCounterRepository(session)
            note_repository = CreditDebitNoteRepository(session)
            audit_repository = RBACRepository(session)

            invoice_service = InvoiceService(
                invoice_repository,
                subscription_repository=subscription_repository,
                plan_repository=plan_repository,
                billing_profile_repository=billing_profile_repository,
                tax_rate_repository=tax_rate_repository,
                number_counter_repository=number_counter_repository,
                note_repository=note_repository,
                platform_gst_state=settings.platform_gst_state,
                platform_gst_country=settings.platform_gst_country,
                invoice_due_days=settings.invoice_due_days,
                audit_writer=audit_repository,
            )
            overdue_ids = await invoice_service.mark_overdue_invoices()
            await session.commit()
            return [str(invoice_id) for invoice_id in overdue_ids]
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_INVOICE_OVERDUE_SWEEP)
def run_invoice_overdue_sweep() -> dict[str, object]:
    """Real, callable Celery task -- transitions every ``ISSUED`` invoice
    whose ``due_date`` has passed to ``OVERDUE``, with real per-invoice
    failure isolation (``InvoiceService.mark_overdue_invoices``'s own
    docstring). See the module-level note above for why this is not yet
    registered in ``app.core.celery_app``'s ``beat_schedule``."""
    overdue_ids = asyncio.run(_run_invoice_overdue_sweep_async())
    logger.info(
        "billing_task_run_invoice_overdue_sweep_completed",
        extra={"overdue_count": len(overdue_ids)},
    )
    return {"overdue_invoice_ids": overdue_ids}


__all__ = ["run_subscription_renewal_sweep", "run_invoice_overdue_sweep"]
