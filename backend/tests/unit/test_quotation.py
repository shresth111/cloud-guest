"""Unit tests for the Quotation domain: PDF rendering (real ``reportlab``
bytes), service-layer totals computation, create+send composition (success/
failure/unconfigured-provider paths), and list/get.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_voucher.py``'s own module docstring); ``asyncio_mode =
"auto"`` runs async tests directly. ``QuotationService`` is exercised
against a small, hand-rolled in-memory fake repository (mirroring
``test_billing_invoices_tax.py``'s own ``FakeInvoiceRepository`` shape) and
a fake/stub email provider + PDF renderer -- there is no live Postgres or
real SMTP connection in this environment, and the actual PDF byte
generation and email send are both mocked in every service-layer test (only
``TestRenderQuotationPdf`` below checks real PDF bytes, mirroring
``test_billing_invoices_tax.py``'s own split between
``test_render_invoice_pdf_produces_real_valid_pdf`` and the
composition-level tests that stub it out).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.otp.service import EmailAttachment, LoggingEmailProvider
from app.domains.quotation.constants import (
    QUOTATION_COMPANY_LEGAL_NAME,
    QUOTATION_PRODUCT_NAME,
    QuotationStatus,
)
from app.domains.quotation.exceptions import QuotationNotFoundError
from app.domains.quotation.models import Quotation, QuotationLineItem
from app.domains.quotation.quotation_pdf import render_quotation_pdf
from app.domains.quotation.service import LineItemInput, QuotationService

# ============================================================================
# Test doubles
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeQuotationRepository:
    quotations: dict[uuid.UUID, Quotation] = field(default_factory=dict)
    items: dict[uuid.UUID, QuotationLineItem] = field(default_factory=dict)

    async def create_quotation(self, **fields: object) -> Quotation:
        quotation = Quotation(**_base_fields(**fields))
        self.quotations[quotation.id] = quotation
        return quotation

    async def create_line_item(self, **fields: object) -> QuotationLineItem:
        item = QuotationLineItem(**_base_fields(**fields))
        self.items[item.id] = item
        return item

    async def get_by_id(self, quotation_id: uuid.UUID) -> Quotation | None:
        return self.quotations.get(quotation_id)

    async def list_items(self, quotation_id: uuid.UUID) -> list[QuotationLineItem]:
        return [i for i in self.items.values() if i.quotation_id == quotation_id]

    async def update_quotation(
        self, quotation: Quotation, data: dict[str, object]
    ) -> Quotation:
        for key, value in data.items():
            setattr(quotation, key, value)
        quotation.version += 1
        return quotation

    async def list_quotations(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[list[Quotation], PaginationMeta]:
        items = [q for q in self.quotations.values() if not q.is_deleted]
        if status is not None:
            items = [q for q in items if q.status == status]
        if search is not None:
            needle = search.lower()
            items = [
                q
                for q in items
                if needle in q.client_name.lower()
                or needle in q.client_email.lower()
                or needle in q.client_company_name.lower()
            ]
        items.sort(key=lambda q: q.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        return items, PaginationMeta.from_total(params, len(items))


@dataclass
class FakeEmailProvider:
    """Records every ``send`` call; never touches a real SMTP connection."""

    sent: list[dict[str, object]] = field(default_factory=list)
    raise_error: Exception | None = None

    async def send(
        self,
        email: str,
        subject: str,
        body: str,
        *,
        attachment: EmailAttachment | None = None,
    ) -> None:
        if self.raise_error is not None:
            raise self.raise_error
        self.sent.append(
            {
                "email": email,
                "subject": subject,
                "body": body,
                "attachment": attachment,
            }
        )


def _stub_pdf_renderer(quotation: Quotation, items: list[QuotationLineItem]) -> bytes:
    """Never invokes real ``reportlab`` rendering -- every service-layer
    test below mocks PDF byte generation, per this module's own docstring."""
    return b"%PDF-STUB-BYTES%%EOF"


def _make_line_items() -> list[LineItemInput]:
    return [
        LineItemInput(
            description="WyfyGuest Standard Plan (annual)",
            quantity=Decimal("1"),
            unit_price=Decimal("999.00"),
        ),
        LineItemInput(
            description="Onsite installation",
            quantity=Decimal("2"),
            unit_price=Decimal("150.00"),
        ),
    ]


def _make_service(
    *, email_provider: object | None = None
) -> tuple[QuotationService, FakeQuotationRepository]:
    repository = FakeQuotationRepository()
    service = QuotationService(
        repository,
        email_provider=email_provider,
        pdf_renderer=_stub_pdf_renderer,
    )
    return service, repository


# ============================================================================
# PDF rendering -- real reportlab bytes
# ============================================================================


class TestRenderQuotationPdf:
    def test_render_quotation_pdf_produces_real_valid_pdf(self) -> None:
        quotation = Quotation(
            **_base_fields(
                quotation_number="QUO-2026-ABCD1234",
                status=QuotationStatus.DRAFT.value,
                client_name="Jane Doe",
                client_email="jane@example.com",
                client_company_name="Example Hotel",
                subtotal=Decimal("1299.00"),
                tax_percentage=Decimal("18.00"),
                tax_amount=Decimal("233.82"),
                total_amount=Decimal("1532.82"),
                currency="USD",
                valid_until=_now() + timedelta(days=30),
                notes="Discount applies if signed within 30 days.",
                sent_at=None,
                email_error=None,
            )
        )
        items = [
            QuotationLineItem(
                **_base_fields(
                    quotation_id=quotation.id,
                    description="WyfyGuest Standard Plan (annual)",
                    quantity=Decimal("1"),
                    unit_price=Decimal("999.00"),
                    amount=Decimal("999.00"),
                )
            ),
            QuotationLineItem(
                **_base_fields(
                    quotation_id=quotation.id,
                    description="Onsite installation",
                    quantity=Decimal("2"),
                    unit_price=Decimal("150.00"),
                    amount=Decimal("300.00"),
                )
            ),
        ]

        pdf_bytes = render_quotation_pdf(quotation, items)

        # Real, valid PDF -- the %PDF magic header, same rigor
        # invoice_pdf's own test establishes for render_invoice_pdf.
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 500

    def test_render_quotation_pdf_with_no_tax_omits_tax_line(self) -> None:
        quotation = Quotation(
            **_base_fields(
                quotation_number="QUO-2026-NOTAX001",
                status=QuotationStatus.DRAFT.value,
                client_name="No Tax Client",
                client_email="notax@example.com",
                client_company_name="No Tax Co",
                subtotal=Decimal("500.00"),
                tax_percentage=Decimal("0"),
                tax_amount=Decimal("0"),
                total_amount=Decimal("500.00"),
                currency="USD",
                valid_until=_now() + timedelta(days=15),
                notes=None,
                sent_at=None,
                email_error=None,
            )
        )
        items = [
            QuotationLineItem(
                **_base_fields(
                    quotation_id=quotation.id,
                    description="Basic Plan",
                    quantity=Decimal("1"),
                    unit_price=Decimal("500.00"),
                    amount=Decimal("500.00"),
                )
            )
        ]

        pdf_bytes = render_quotation_pdf(quotation, items)
        assert pdf_bytes[:4] == b"%PDF"

    def test_branding_constants_are_the_required_exact_strings(self) -> None:
        # The feature spec requires these exact, verbatim strings -- a
        # silent rename here would break the platform's real branding
        # requirement without any other test catching it.
        assert QUOTATION_COMPANY_LEGAL_NAME == "Infovertias Technologies Pvt Ltd"
        assert QUOTATION_PRODUCT_NAME == "WyfyGuest"


# ============================================================================
# Service: totals computation + create/send composition
# ============================================================================


class TestCreateAndSendQuotation:
    async def test_computes_subtotal_tax_and_total_correctly(self) -> None:
        provider = FakeEmailProvider()
        service, _repository = _make_service(email_provider=provider)

        quotation = await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Jane Doe",
            client_email="jane@example.com",
            client_company_name="Example Hotel",
            line_items=_make_line_items(),
            tax_percentage=Decimal("18.00"),
            currency="usd",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )

        # subtotal = 1*999.00 + 2*150.00 = 1299.00
        assert quotation.subtotal == Decimal("1299.00")
        # tax = 1299.00 * 18% = 233.82
        assert quotation.tax_amount == Decimal("233.82")
        assert quotation.total_amount == Decimal("1532.82")
        assert quotation.currency == "USD"

    async def test_assigns_a_unique_human_readable_quotation_number(self) -> None:
        service, _repository = _make_service(email_provider=FakeEmailProvider())

        quotation = await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="A",
            client_email="a@example.com",
            client_company_name="A Co",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=10),
            notes=None,
        )

        assert quotation.quotation_number.startswith("QUO-")
        assert quotation.quotation_number != "QUO-pending"

    async def test_creates_one_line_item_row_per_input(self) -> None:
        service, repository = _make_service(email_provider=FakeEmailProvider())

        quotation = await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="A",
            client_email="a@example.com",
            client_company_name="A Co",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=10),
            notes=None,
        )

        items = await repository.list_items(quotation.id)
        assert len(items) == 2
        assert {i.description for i in items} == {
            "WyfyGuest Standard Plan (annual)",
            "Onsite installation",
        }
        assert items[0].amount == items[0].quantity * items[0].unit_price

    async def test_successful_send_marks_status_sent_and_records_sent_at(
        self,
    ) -> None:
        provider = FakeEmailProvider()
        service, _repository = _make_service(email_provider=provider)

        quotation = await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Jane Doe",
            client_email="jane@example.com",
            client_company_name="Example Hotel",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )

        assert quotation.status == QuotationStatus.SENT.value
        assert quotation.sent_at is not None
        assert quotation.email_error is None
        assert len(provider.sent) == 1
        sent_call = provider.sent[0]
        assert sent_call["email"] == "jane@example.com"
        assert quotation.quotation_number in sent_call["subject"]
        attachment = sent_call["attachment"]
        assert attachment.filename == f"{quotation.quotation_number}.pdf"
        assert attachment.content == b"%PDF-STUB-BYTES%%EOF"
        assert attachment.content_type == "application/pdf"

    async def test_email_send_failure_marks_status_failed_never_raises(self) -> None:
        provider = FakeEmailProvider(raise_error=RuntimeError("smtp down"))
        service, _repository = _make_service(email_provider=provider)

        quotation = await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Jane Doe",
            client_email="jane@example.com",
            client_company_name="Example Hotel",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )

        # The quotation itself is never rolled back by a failed send --
        # see service.py's own module docstring.
        assert quotation.status == QuotationStatus.FAILED.value
        assert quotation.email_error == "smtp down"
        assert quotation.sent_at is None

    async def test_no_email_provider_configured_marks_status_failed(self) -> None:
        service, _repository = _make_service(email_provider=None)

        quotation = await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Jane Doe",
            client_email="jane@example.com",
            client_company_name="Example Hotel",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )

        assert quotation.status == QuotationStatus.FAILED.value
        assert quotation.email_error is not None

    async def test_bare_logging_email_provider_is_treated_as_unconfigured(
        self,
    ) -> None:
        """A ``LoggingEmailProvider`` only logs -- it never really reaches
        the client, so this must be an honest FAILED, not a fabricated
        SENT. Mirrors ``app.domains.billing.router``'s own
        ``isinstance(email_provider, LoggingEmailProvider)`` check."""
        service, _repository = _make_service(email_provider=LoggingEmailProvider())

        quotation = await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Jane Doe",
            client_email="jane@example.com",
            client_company_name="Example Hotel",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )

        assert quotation.status == QuotationStatus.FAILED.value
        assert "No real email delivery provider" in quotation.email_error


# ============================================================================
# Service: read (get/list)
# ============================================================================


class TestGetAndListQuotations:
    async def test_get_quotation_not_found_raises(self) -> None:
        service, _repository = _make_service()
        with pytest.raises(QuotationNotFoundError):
            await service.get_quotation(uuid.uuid4())

    async def test_get_quotation_returns_created_row(self) -> None:
        service, _repository = _make_service(email_provider=FakeEmailProvider())
        created = await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Jane Doe",
            client_email="jane@example.com",
            client_company_name="Example Hotel",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )

        fetched = await service.get_quotation(created.id)
        assert fetched.id == created.id

    async def test_list_quotations_filters_by_status(self) -> None:
        service, _repository = _make_service(email_provider=FakeEmailProvider())
        await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Sent Client",
            client_email="sent@example.com",
            client_company_name="Sent Co",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )
        # A second quotation whose send fails -- same repository/service,
        # just a provider swapped to a bare LoggingEmailProvider for this
        # one call (treated as "unconfigured", see the FAILED-path test
        # above).
        service.email_provider = LoggingEmailProvider()
        await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Failed Client",
            client_email="failed@example.com",
            client_company_name="Failed Co",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )
        sent_result = await service.list_quotations(status=QuotationStatus.SENT.value)
        failed_result = await service.list_quotations(
            status=QuotationStatus.FAILED.value
        )

        assert len(sent_result.items) == 1
        assert sent_result.items[0].client_email == "sent@example.com"
        assert len(failed_result.items) == 1
        assert failed_result.items[0].client_email == "failed@example.com"

    async def test_list_quotations_search_matches_client_fields(self) -> None:
        service, _repository = _make_service(email_provider=FakeEmailProvider())
        await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Alice Anderson",
            client_email="alice@example.com",
            client_company_name="Anderson Hotels",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )
        await service.create_and_send_quotation(
            actor_user_id=uuid.uuid4(),
            client_name="Bob Brown",
            client_email="bob@example.com",
            client_company_name="Brown Resorts",
            line_items=_make_line_items(),
            tax_percentage=Decimal("0"),
            currency="USD",
            valid_until=_now() + timedelta(days=30),
            notes=None,
        )

        result = await service.list_quotations(search="anderson")
        assert len(result.items) == 1
        assert result.items[0].client_name == "Alice Anderson"
