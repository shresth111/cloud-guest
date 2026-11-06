"""Operator-initiated billing reminder emails (Master Console > Billing >
Reminders > "Send").

The Reminders panel lists three kinds of row, all derived from real billing
data: a failed payment, an organization with unpaid invoices, and a
subscription whose current period ends soon. Until this module existed the
panel's "Send" button resolved a client-side ``delay()`` and toasted
"Reminder sent" while nothing was sent.

Design rules:

* **The server decides what the email says.** The request names only the
  organization and the reminder kind. The facts in the email (which
  invoices, which payment, which date) are read here from the billing
  tables, never taken from the client. If there is nothing to remind about
  (no failed payment, no unpaid invoice, no subscription), the call is
  refused with ``409`` instead of sending a vague nag.
* **Synchronous, honest outcome.** Like ``POST /invoices/generate-and-send``,
  the send happens inline and the response carries ``email_sent`` /
  ``email_error``. A server with no real provider configured
  (``LoggingEmailProvider``) reports ``email_sent=False``; it never claims a
  send that did not happen.
* **Every attempt is audited**, success or failure, as
  ``AuditAction.BILLING_REMINDER_EMAILED`` with the outcome in the
  description and metadata.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from fastapi import status

from app.core.email_layout import (
    callout,
    esc,
    heading,
    info_box,
    paragraph,
    render_email,
)
from app.domains.otp.service import EmailProviderProtocol, LoggingEmailProvider
from app.domains.rbac.enums import AuditAction

from .constants import InvoiceStatus
from .exceptions import BillingError

logger = logging.getLogger(__name__)

NO_PROVIDER_ERROR = "No real email delivery provider is configured on this server."
NO_RECIPIENT_ERROR = "This organization has no contact email on file."

# How many unpaid invoices one reminder lists. An organization with more
# than this gets the first N plus a count of the rest.
_MAX_INVOICES_LISTED = 10


class ReminderKind(StrEnum):
    PAYMENT_FAILED = "payment_failed"
    INVOICE_DUE = "invoice_due"
    EXPIRY = "expiry"


class NothingToRemindError(BillingError):
    def __init__(self, kind: ReminderKind) -> None:
        reasons = {
            ReminderKind.PAYMENT_FAILED: "has no failed payment",
            ReminderKind.INVOICE_DUE: "has no unpaid invoice",
            ReminderKind.EXPIRY: "has no subscription",
        }
        super().__init__(
            f"Nothing to remind about: this organization {reasons[kind]}.",
            status_code=status.HTTP_409_CONFLICT,
            data={"error_code": "nothing_to_remind", "kind": kind.value},
        )


# ---------------------------------------------------------------------------
# Narrow collaborator protocols (satisfied structurally by the real
# repositories / OrganizationService / RBACRepository).
# ---------------------------------------------------------------------------


class _OrganizationLookup(Protocol):
    async def get_organization(self, organization_id: uuid.UUID) -> Any: ...


class _PaymentLookup(Protocol):
    async def list_failed_payments(
        self, organization_id: uuid.UUID | None = None
    ) -> list[Any]: ...


class _InvoiceLookup(Protocol):
    async def list_invoices(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
    ) -> tuple[list[Any], Any]: ...


class _SubscriptionLookup(Protocol):
    async def get_by_organization_id(self, organization_id: uuid.UUID) -> Any: ...


class _PlanLookup(Protocol):
    async def get_by_id(self, plan_id: uuid.UUID) -> Any: ...


class _AuditWriter(Protocol):
    async def create_audit_log_entry(self, **fields: Any) -> Any: ...


@dataclass(frozen=True)
class ReminderSendResult:
    kind: ReminderKind
    organization_id: uuid.UUID
    email_sent: bool
    email_recipient: str | None
    email_error: str | None


@dataclass(frozen=True)
class _ReminderEmail:
    subject: str
    body: str
    summary: str  # one line for the audit description
    entity_type: str
    entity_id: uuid.UUID | None


def _fmt_date(value: datetime) -> str:
    return value.strftime("%d %b %Y")


class BillingReminderService:
    def __init__(
        self,
        *,
        organizations: _OrganizationLookup,
        payments: _PaymentLookup,
        invoices: _InvoiceLookup,
        subscriptions: _SubscriptionLookup,
        plans: _PlanLookup,
        audit_writer: _AuditWriter | None,
    ) -> None:
        self.organizations = organizations
        self.payments = payments
        self.invoices = invoices
        self.subscriptions = subscriptions
        self.plans = plans
        self.audit_writer = audit_writer

    async def send(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        kind: ReminderKind,
        email_provider_factory: Callable[[], EmailProviderProtocol],
    ) -> ReminderSendResult:
        """``email_provider_factory`` is called inside the send's error
        handling, so a half-configured mailbox (``MailIdentityMismatchError``)
        is reported as ``email_error`` rather than a 500."""
        organization = await self.organizations.get_organization(organization_id)
        email = await self._build(organization_id, kind)
        recipient: str | None = getattr(organization, "contact_email", None) or None

        email_sent = False
        email_error: str | None = None
        if recipient is None:
            email_error = NO_RECIPIENT_ERROR
        else:
            try:
                email_provider = email_provider_factory()
                if isinstance(email_provider, LoggingEmailProvider):
                    email_error = NO_PROVIDER_ERROR
                else:
                    await email_provider.send(recipient, email.subject, email.body)
                    email_sent = True
            except Exception as exc:  # noqa: BLE001 -- reported back, never raised as a 500
                logger.warning(
                    "billing_reminder_email_send_failed",
                    extra={
                        "organization_id": str(organization_id),
                        "kind": kind.value,
                        "error": str(exc),
                    },
                )
                email_error = str(exc) or exc.__class__.__name__

        await self._audit(
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            kind=kind,
            email=email,
            recipient=recipient,
            email_sent=email_sent,
            email_error=email_error,
        )
        return ReminderSendResult(
            kind=kind,
            organization_id=organization_id,
            email_sent=email_sent,
            email_recipient=recipient,
            email_error=email_error,
        )

    # ------------------------------------------------------------------
    # Content, built from server-side billing data only
    # ------------------------------------------------------------------

    async def _build(
        self, organization_id: uuid.UUID, kind: ReminderKind
    ) -> _ReminderEmail:
        if kind is ReminderKind.PAYMENT_FAILED:
            return await self._build_payment_failed(organization_id)
        if kind is ReminderKind.INVOICE_DUE:
            return await self._build_invoice_due(organization_id)
        return await self._build_expiry(organization_id)

    async def _build_payment_failed(self, organization_id: uuid.UUID) -> _ReminderEmail:
        failed = await self.payments.list_failed_payments(organization_id)
        if not failed:
            raise NothingToRemindError(ReminderKind.PAYMENT_FAILED)
        payment = failed[0]  # newest first
        amount = f"{payment.currency} {payment.amount}"
        rows = [("Amount", esc(amount))]
        if getattr(payment, "failure_reason", None):
            rows.append(("Reason", esc(payment.failure_reason)))
        content = (
            heading("Your recent payment did not go through")
            + paragraph(
                "We could not collect your most recent Wyfy Guest payment. "
                "Please update your payment details or retry the payment "
                "from your Wyfy Guest dashboard."
            )
            + info_box(rows)
            + callout(
                "Resolving this soon avoids any interruption to your service.",
                tone="danger",
            )
        )
        return _ReminderEmail(
            subject="Action needed: your Wyfy Guest payment failed",
            body=render_email(
                preheader=f"Your payment of {amount} did not go through.",
                content_html=content,
                accent="#dc2626",
            ),
            summary=f"failed payment of {amount}",
            entity_type="payment",
            entity_id=payment.id,
        )

    async def _build_invoice_due(self, organization_id: uuid.UUID) -> _ReminderEmail:
        unpaid: list[Any] = []
        for invoice_status in (InvoiceStatus.OVERDUE, InvoiceStatus.ISSUED):
            rows, _meta = await self.invoices.list_invoices(
                page=1,
                page_size=50,
                organization_id=organization_id,
                status=invoice_status.value,
            )
            unpaid.extend(rows)
        if not unpaid:
            raise NothingToRemindError(ReminderKind.INVOICE_DUE)
        unpaid.sort(key=lambda inv: inv.due_date)
        listed: Sequence[Any] = unpaid[:_MAX_INVOICES_LISTED]
        rows = [
            (
                esc(inv.invoice_number),
                esc(
                    f"{inv.currency} {inv.total_amount}, due {_fmt_date(inv.due_date)}"
                ),
            )
            for inv in listed
        ]
        more = len(unpaid) - len(listed)
        noun = "invoice" if len(unpaid) == 1 else "invoices"
        content = (
            heading(f"You have {len(unpaid)} unpaid {noun}")
            + paragraph(
                "This is a reminder that the following Wyfy Guest "
                f"{noun} {'is' if len(unpaid) == 1 else 'are'} still unpaid."
            )
            + info_box(rows)
            + (
                paragraph(f"And {more} more in your dashboard.", muted=True)
                if more > 0
                else ""
            )
            + paragraph(
                "You can view and pay your invoices from your Wyfy Guest "
                "dashboard. If you have already paid, please ignore this email.",
                muted=True,
            )
        )
        return _ReminderEmail(
            subject=f"Reminder: {len(unpaid)} unpaid Wyfy Guest {noun}",
            body=render_email(
                preheader=f"You have {len(unpaid)} unpaid {noun}.",
                content_html=content,
            ),
            summary=f"{len(unpaid)} unpaid {noun}",
            entity_type="organization",
            entity_id=organization_id,
        )

    async def _build_expiry(self, organization_id: uuid.UUID) -> _ReminderEmail:
        subscription = await self.subscriptions.get_by_organization_id(organization_id)
        if subscription is None:
            raise NothingToRemindError(ReminderKind.EXPIRY)
        plan = await self.plans.get_by_id(subscription.plan_id)
        plan_name = getattr(plan, "name", None) or "Wyfy Guest"
        end = _fmt_date(subscription.current_period_end)
        renews = bool(getattr(subscription, "auto_renew", False))
        content = (
            heading("Your subscription period is ending")
            + paragraph(
                f"Your <strong>{esc(plan_name)}</strong> plan's current period "
                f"ends on <strong>{esc(end)}</strong>."
            )
            + info_box([("Plan", esc(plan_name)), ("Period ends", esc(end))])
            + paragraph(
                (
                    "It is set to renew automatically. Please make sure your "
                    "payment details are up to date."
                )
                if renews
                else (
                    "Automatic renewal is off. Renew from your Wyfy Guest "
                    "dashboard to keep your service running."
                ),
                muted=renews,
            )
        )
        return _ReminderEmail(
            subject=f"Your Wyfy Guest {plan_name} plan period ends on {end}",
            body=render_email(
                preheader=f"Your plan's current period ends on {end}.",
                content_html=content,
            ),
            summary=f"{plan_name} period ending {end}",
            entity_type="subscription",
            entity_id=subscription.id,
        )

    async def _audit(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        kind: ReminderKind,
        email: _ReminderEmail,
        recipient: str | None,
        email_sent: bool,
        email_error: str | None,
    ) -> None:
        if email_sent:
            outcome = f"emailed to {recipient}"
        else:
            outcome = f"NOT sent to {recipient or '(no recipient)'}: {email_error}"
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=AuditAction.BILLING_REMINDER_EMAILED.value,
                entity_type=email.entity_type,
                entity_id=email.entity_id,
                description=(
                    f"Billing reminder ({kind.value}, {email.summary}) {outcome}"
                ),
                event_metadata={
                    "kind": kind.value,
                    "email_sent": email_sent,
                    "recipient": recipient,
                    "error": email_error,
                },
                organization_id=organization_id,
                location_id=None,
            )
        logger.info(
            "billing_reminder_dispatch",
            extra={"kind": kind.value, "email_sent": email_sent},
        )
