"""Quotation domain business logic: ``QuotationService`` -- compute totals,
create the quotation + its line items, render its branded PDF, and email it
to the client. All Master-console-only, RBAC-gated (no public/unauthenticated
path -- unlike ``app.domains.demo_request``'s own public lead-capture form).

## Composition, not a router-level thin wrapper

``app.domains.billing.router.generate_and_send_invoice`` puts its own
render-PDF + send-email composition directly in the router function. This
module instead puts it here, in the service, deliberately: the service
constructor takes an injected ``pdf_renderer`` callable and
``email_provider`` (``EmailProviderProtocol``) exactly the way
``app.domains.notification.service.NotificationService`` injects its own
``email_provider``/``sms_provider`` -- so a unit test can exercise the full
"create quotation -> render PDF -> send email -> record outcome" flow
against small fakes (a stub PDF renderer returning fixed bytes, a fake
email provider recording/raising) without booting the FastAPI app or a real
SMTP connection, and without needing a router-level integration test the
way billing's own docstring explicitly says it deliberately skips (see that
module's ``_send_invoice_email_and_build_response`` docstring).

A failed or unconfigured email send is never a rollback of the quotation
itself -- same reasoning ``billing.router``'s own docstring gives: a real
quotation record already exists by the time delivery is attempted, and
discarding it over an email hiccup would be worse than a manual resend.
``status=FAILED`` (with ``email_error`` set) tells the operator plainly
that the quotation exists but hasn't reached the client, so they know to
retry or download the PDF directly.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from app.database.utils.pagination import PaginationMeta
from app.domains.otp.service import (
    EmailAttachment,
    EmailProviderProtocol,
    LoggingEmailProvider,
)

from .constants import QUOTATION_NUMBER_PREFIX, QUOTATION_PRODUCT_NAME, QuotationStatus
from .exceptions import QuotationNotFoundError
from .models import Quotation, QuotationLineItem
from .quotation_pdf import render_quotation_pdf
from .repository import QuotationRepositoryProtocol

logger = logging.getLogger(__name__)

PdfRenderer = Callable[[Quotation, list[QuotationLineItem]], bytes]


@dataclass
class LineItemInput:
    description: str
    quantity: Decimal
    unit_price: Decimal


@dataclass
class QuotationListResult:
    items: list[Quotation]
    meta: PaginationMeta


def _quotation_number(quotation_id: uuid.UUID, *, at: datetime) -> str:
    """``"QUO-2026-A1B2C3D4"``-shaped -- derived from the row's own UUID,
    guaranteed unique without a separate atomic-counter table. See
    ``constants.QUOTATION_NUMBER_PREFIX``'s own docstring for why this
    domain deliberately does not reuse
    ``app.domains.billing.number_generator``'s sequential-counter
    machinery."""
    return f"{QUOTATION_NUMBER_PREFIX}-{at.year}-{str(quotation_id)[:8].upper()}"


class QuotationService:
    def __init__(
        self,
        repository: QuotationRepositoryProtocol,
        *,
        email_provider: EmailProviderProtocol | None = None,
        pdf_renderer: PdfRenderer | None = None,
    ) -> None:
        self.repository = repository
        self.email_provider = email_provider
        # Defaults to the real reportlab renderer; tests inject a stub that
        # returns fixed bytes so PDF byte generation is never re-exercised
        # by every service-layer test (only quotation_pdf.py's own tests
        # check real PDF bytes -- see that module's own docstring).
        self.pdf_renderer = pdf_renderer or render_quotation_pdf

    # -- create + send (Master console) --------------------------------------

    async def create_and_send_quotation(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        client_name: str,
        client_email: str,
        client_company_name: str,
        line_items: list[LineItemInput],
        tax_percentage: Decimal,
        currency: str,
        valid_until: datetime,
        notes: str | None,
    ) -> Quotation:
        subtotal = sum(
            (item.quantity * item.unit_price for item in line_items),
            Decimal("0"),
        )
        tax_amount = (subtotal * tax_percentage / Decimal("100")).quantize(
            Decimal("0.01")
        )
        total_amount = subtotal + tax_amount

        quotation = await self.repository.create_quotation(
            quotation_number=f"{QUOTATION_NUMBER_PREFIX}-pending",
            status=QuotationStatus.DRAFT.value,
            client_name=client_name.strip(),
            client_email=str(client_email).strip().lower(),
            client_company_name=client_company_name.strip(),
            subtotal=subtotal,
            tax_percentage=tax_percentage,
            tax_amount=tax_amount,
            total_amount=total_amount,
            currency=currency.upper(),
            valid_until=valid_until,
            notes=notes.strip() if notes else None,
            sent_at=None,
            email_error=None,
            created_by=actor_user_id,
        )
        # quotation_number is derived from the row's own id (see
        # _quotation_number's own docstring), so it can only be computed
        # after the row -- and its id -- exist; one extra update, same
        # "create then finalize" shape app.domains.billing.service's own
        # invoice-number assignment already needs for the identical reason.
        quotation = await self.repository.update_quotation(
            quotation,
            {
                "quotation_number": _quotation_number(
                    quotation.id, at=quotation.created_at
                )
            },
        )

        items: list[QuotationLineItem] = []
        for line in line_items:
            amount = (line.quantity * line.unit_price).quantize(Decimal("0.01"))
            items.append(
                await self.repository.create_line_item(
                    quotation_id=quotation.id,
                    description=line.description.strip(),
                    quantity=line.quantity,
                    unit_price=line.unit_price,
                    amount=amount,
                )
            )

        logger.info(
            "quotation_created",
            extra={
                "quotation_id": str(quotation.id),
                "quotation_number": quotation.quotation_number,
            },
        )

        quotation = await self._send_quotation_email(quotation, items)
        return quotation

    async def _send_quotation_email(
        self, quotation: Quotation, items: list[QuotationLineItem]
    ) -> Quotation:
        pdf_bytes = self.pdf_renderer(quotation, items)

        # A bare LoggingEmailProvider means no real delivery provider is
        # actually configured on this deployment -- same
        # "isinstance(email_provider, LoggingEmailProvider) => honest
        # failure, not a fabricated success" check
        # app.domains.billing.router._get_invoice_email_provider's own
        # caller already performs, so an operator never sees a false
        # "sent" status when nothing was actually delivered.
        if self.email_provider is None or isinstance(
            self.email_provider, LoggingEmailProvider
        ):
            return await self.repository.update_quotation(
                quotation,
                {
                    "status": QuotationStatus.FAILED.value,
                    "email_error": (
                        "No real email delivery provider is configured on "
                        "this server."
                    ),
                },
            )

        try:
            subject = (
                f"Your {QUOTATION_PRODUCT_NAME} quotation "
                f"{quotation.quotation_number}"
            )
            body = (
                f"Hello {quotation.client_name},\n\n"
                f"Please find attached your {QUOTATION_PRODUCT_NAME} quotation "
                f"{quotation.quotation_number} for {quotation.client_company_name}.\n\n"
                f"Total: {quotation.currency} {quotation.total_amount}\n"
                f"Valid until: {quotation.valid_until.strftime('%d %b %Y')}\n\n"
                "If you have any questions, just reply to this email.\n\n"
                f"Thank you for considering {QUOTATION_PRODUCT_NAME}."
            )
            await self.email_provider.send(
                quotation.client_email,
                subject,
                body,
                attachment=EmailAttachment(
                    filename=f"{quotation.quotation_number}.pdf",
                    content=pdf_bytes,
                    content_type="application/pdf",
                ),
            )
        except Exception as exc:  # noqa: BLE001 -- a send failure must never
            # crash quotation creation; mirrors
            # app.domains.billing.router._send_invoice_email_and_build_response's
            # identical resilience contract.
            logger.warning(
                "quotation_email_send_failed",
                extra={"quotation_id": str(quotation.id), "error": str(exc)},
            )
            return await self.repository.update_quotation(
                quotation,
                {"status": QuotationStatus.FAILED.value, "email_error": str(exc)},
            )

        return await self.repository.update_quotation(
            quotation,
            {
                "status": QuotationStatus.SENT.value,
                "sent_at": datetime.now(UTC),
                "email_error": None,
            },
        )

    # -- read (Master console) ------------------------------------------------

    async def get_quotation(self, quotation_id: uuid.UUID) -> Quotation:
        quotation = await self.repository.get_by_id(quotation_id)
        if quotation is None or quotation.is_deleted:
            raise QuotationNotFoundError(quotation_id)
        return quotation

    async def list_line_items(
        self, quotation_id: uuid.UUID
    ) -> list[QuotationLineItem]:
        return await self.repository.list_items(quotation_id)

    async def list_quotations(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        status: str | None = None,
        search: str | None = None,
    ) -> QuotationListResult:
        items, meta = await self.repository.list_quotations(
            page=page, page_size=page_size, status=status, search=search
        )
        return QuotationListResult(items=items, meta=meta)


__all__ = [
    "QuotationService",
    "QuotationListResult",
    "LineItemInput",
    "EmailProviderProtocol",
]
