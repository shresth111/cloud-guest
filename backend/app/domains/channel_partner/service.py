"""Channel Partner domain business logic: ``ChannelPartnerService`` --
create the partner row + send its welcome message (SMS always, email when
provided) in one composed action, recording each channel's delivery outcome
on the row itself. Master-console-only, RBAC-gated (no public/
unauthenticated path).

## Composition, same shape as ``QuotationService``

Mirrors ``app.domains.quotation.service.QuotationService
.create_and_send_quotation``/``_send_quotation_email`` almost line for
line: the service constructor takes injected ``sms_provider``/
``email_provider`` (``SmsProviderProtocol``/``EmailProviderProtocol``) so a
unit test can exercise the full "create partner -> send SMS -> send email
-> record outcome" flow against small fakes, without booting the FastAPI
app or a real Twilio/SMTP connection.

A failed or unconfigured send on either channel is never a rollback of the
partner row itself -- same reasoning ``QuotationService``'s own docstring
gives: a real partner record already exists by the time delivery is
attempted, and discarding it over an SMS/email hiccup would be worse than a
manual follow-up. ``welcome_sms_error``/``welcome_email_error`` tell the
operator plainly that the partner exists but a channel didn't go out, so
they know to follow up manually.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.core.email_layout import (
    esc,
    heading,
    info_box,
    paragraph,
    render_email,
    welcome_header_illustration,
)
from app.database.exceptions import DuplicateRecordError
from app.database.utils.pagination import PaginationMeta
from app.domains.otp.service import (
    EmailProviderProtocol,
    LoggingEmailProvider,
    LoggingSmsProvider,
    SmsProviderProtocol,
)
from app.domains.rbac.enums import AuditAction

from .constants import CHANNEL_PARTNER_PRODUCT_NAME, ChannelPartnerStatus
from .exceptions import ChannelPartnerNotFoundError, DuplicateGstNumberError
from .models import ChannelPartner
from .repository import ChannelPartnerRepositoryProtocol
from .schemas import ChannelPartnerCreateRequest

logger = logging.getLogger(__name__)

WELCOME_SMS_TEMPLATE = (
    "Welcome to {product}, {name}! You're onboarded as a channel partner. "
    "Our team will be in touch shortly with next steps. Questions? Reply "
    "to this message or contact partners@wyfyguest.com."
)


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table, without depending on the rest of
    ``RBACRepositoryProtocol`` -- mirrors
    ``app.domains.organization.service.AuditLogWriter``/
    ``app.domains.voucher.service.AuditLogWriter``'s identical narrow
    protocol shape exactly."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


@dataclass
class ChannelPartnerListResult:
    items: list[ChannelPartner]
    meta: PaginationMeta


class ChannelPartnerService:
    def __init__(
        self,
        repository: ChannelPartnerRepositoryProtocol,
        *,
        sms_provider: SmsProviderProtocol | None = None,
        email_provider: EmailProviderProtocol | None = None,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.sms_provider = sms_provider
        self.email_provider = email_provider
        self.audit_writer = audit_writer

    # -- onboard (create + send) ---------------------------------------------

    async def onboard_partner(
        self, *, actor_user_id: uuid.UUID | None, data: ChannelPartnerCreateRequest
    ) -> ChannelPartner:
        try:
            partner = await self.repository.create_partner(
                name=data.name.strip(),
                phone=data.phone,  # already normalized by the schema validator
                email=data.email,
                address=data.address.strip(),
                city=data.city.strip(),
                gst_number=data.gst_number,  # already normalized
                status=ChannelPartnerStatus.ACTIVE.value,
                welcome_sms_sent_at=None,
                welcome_sms_error=None,
                welcome_email_sent_at=None,
                welcome_email_error=None,
                created_by=actor_user_id,
            )
        except DuplicateRecordError as exc:
            raise DuplicateGstNumberError(data.gst_number) from exc

        logger.info(
            "channel_partner_onboarded",
            extra={"channel_partner_id": str(partner.id), "city": partner.city},
        )

        partner = await self._send_welcome_sms(partner)
        if partner.email:
            partner = await self._send_welcome_email(partner)
        return partner

    async def _send_welcome_sms(self, partner: ChannelPartner) -> ChannelPartner:
        # A bare LoggingSmsProvider means no real delivery provider is
        # actually configured on this deployment -- same
        # "isinstance(provider, Logging*Provider) => honest failure, not a
        # fabricated success" check QuotationService._send_quotation_email
        # performs for email, so an operator never sees a false "sent"
        # status when nothing was actually delivered.
        if self.sms_provider is None or isinstance(
            self.sms_provider, LoggingSmsProvider
        ):
            return await self.repository.update_partner(
                partner,
                {
                    "welcome_sms_error": (
                        "No real SMS delivery provider is configured on "
                        "this server."
                    )
                },
            )

        message = WELCOME_SMS_TEMPLATE.format(
            product=CHANNEL_PARTNER_PRODUCT_NAME, name=partner.name
        )
        try:
            await self.sms_provider.send(partner.phone, message)
        except Exception as exc:  # noqa: BLE001 -- a send failure must never
            # crash partner onboarding; mirrors
            # QuotationService._send_quotation_email's identical resilience
            # contract.
            logger.warning(
                "channel_partner_welcome_sms_failed",
                extra={"channel_partner_id": str(partner.id), "error": str(exc)},
            )
            return await self.repository.update_partner(
                partner, {"welcome_sms_error": str(exc)}
            )

        return await self.repository.update_partner(
            partner,
            {"welcome_sms_sent_at": datetime.now(UTC), "welcome_sms_error": None},
        )

    async def _send_welcome_email(self, partner: ChannelPartner) -> ChannelPartner:
        if self.email_provider is None or isinstance(
            self.email_provider, LoggingEmailProvider
        ):
            return await self.repository.update_partner(
                partner,
                {
                    "welcome_email_error": (
                        "No real email delivery provider is configured on "
                        "this server."
                    )
                },
            )

        try:
            subject = f"Welcome to {CHANNEL_PARTNER_PRODUCT_NAME}, {partner.name}"
            content = (
                heading(f"Welcome aboard, {esc(partner.name)}")
                + welcome_header_illustration()
                + paragraph(
                    "Thank you for partnering with Wyfy Guest. We're excited "
                    "to work with you to bring guest WiFi to more venues."
                )
                + info_box(
                    [
                        ("Partner", esc(partner.name)),
                        ("City", esc(partner.city)),
                        ("GSTIN", esc(partner.gst_number)),
                    ],
                    mono_values=True,
                )
                + paragraph(
                    "Our partnerships team will reach out shortly with next "
                    "steps -- onboarding materials, pricing, and how to "
                    "start referring venues.",
                )
                + paragraph(
                    "In the meantime, if you have any questions, just reply "
                    "to this email or reach us at partners@wyfyguest.com.",
                    muted=True,
                )
            )
            body = render_email(
                preheader=(
                    f"You're onboarded as a {CHANNEL_PARTNER_PRODUCT_NAME} "
                    f"channel partner, {partner.name}."
                ),
                content_html=content,
            )
            await self.email_provider.send(partner.email, subject, body)
        except Exception as exc:  # noqa: BLE001 -- see _send_welcome_sms's
            # identical resilience contract.
            logger.warning(
                "channel_partner_welcome_email_failed",
                extra={"channel_partner_id": str(partner.id), "error": str(exc)},
            )
            return await self.repository.update_partner(
                partner, {"welcome_email_error": str(exc)}
            )

        return await self.repository.update_partner(
            partner,
            {
                "welcome_email_sent_at": datetime.now(UTC),
                "welcome_email_error": None,
            },
        )

    # -- read (Master console) ------------------------------------------------

    async def get_partner(self, channel_partner_id: uuid.UUID) -> ChannelPartner:
        partner = await self.repository.get_by_id(channel_partner_id)
        if partner is None or partner.is_deleted:
            raise ChannelPartnerNotFoundError(channel_partner_id)
        return partner

    async def list_partners(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        status: str | None = None,
        search: str | None = None,
    ) -> ChannelPartnerListResult:
        items, meta = await self.repository.list_partners(
            page=page, page_size=page_size, status=status, search=search
        )
        return ChannelPartnerListResult(items=items, meta=meta)

    # -- revoke (Master console) ----------------------------------------------

    async def revoke_partner(
        self, channel_partner_id: uuid.UUID, *, actor_user_id: uuid.UUID | None
    ) -> ChannelPartner:
        """Transitions an ``ACTIVE`` partner to ``INACTIVE``.

        Deliberately idempotent: revoking a partner that is already
        ``INACTIVE`` is a true no-op -- returns the row unchanged, with no
        second repository write and no duplicate audit entry -- rather than
        raising the way ``VoucherService.revoke_batch``'s multi-state
        workflow does for a repeat transition. A channel partner's status is
        a plain two-state toggle (see ``models.py``'s own module
        docstring), not a workflow with distinct terminal states to
        protect, so a repeat "revoke" from an operator (e.g. a retried
        click) should read as "yes, it's off" rather than an error."""
        partner = await self.get_partner(channel_partner_id)
        if partner.status == ChannelPartnerStatus.INACTIVE.value:
            return partner

        updated = await self.repository.update_partner(
            partner,
            {
                "status": ChannelPartnerStatus.INACTIVE.value,
                "updated_by": actor_user_id,
            },
        )
        logger.info(
            "channel_partner_revoked", extra={"channel_partner_id": str(updated.id)}
        )
        await self._audit(
            actor_user_id,
            AuditAction.CHANNEL_PARTNER_REVOKED,
            updated,
            f"Channel partner '{updated.name}' revoked",
        )
        return updated

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        partner: ChannelPartner,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="channel_partner",
            entity_id=partner.id,
            description=description,
            event_metadata={},
            organization_id=None,
            location_id=None,
        )


__all__ = [
    "ChannelPartnerService",
    "ChannelPartnerListResult",
    "AuditLogWriter",
    "SmsProviderProtocol",
    "EmailProviderProtocol",
]
