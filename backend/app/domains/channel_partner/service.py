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

``resend_welcome_message`` is that follow-up's actual mechanism -- per
channel, opt-in, re-entering the same private send helpers rather than a
second send path. See its own docstring for the convention it follows and
for why a revoked partner is refused.
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
from .exceptions import (
    ChannelPartnerEmailMissingError,
    ChannelPartnerNotActiveError,
    ChannelPartnerNotFoundError,
    DuplicateGstNumberError,
)
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


@dataclass(frozen=True)
class WelcomeChannelOutcome:
    """One channel's outcome from a single ``resend_welcome_message`` call.

    ``attempted`` and ``sent`` are kept apart on purpose. "We didn't try"
    and "we tried and it didn't work" and "we tried and it worked" are
    three different things an operator needs told apart, and collapsing
    them into one boolean is precisely how an operation ends up reporting
    success while having done nothing."""

    attempted: bool
    sent: bool
    error: str | None
    sent_at: datetime | None


@dataclass(frozen=True)
class ChannelPartnerResendResult:
    partner: ChannelPartner
    sms: WelcomeChannelOutcome
    email: WelcomeChannelOutcome


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

    # -- resend welcome message (Master console) ------------------------------

    @staticmethod
    def _channel_outcome(
        *,
        error: str | None,
        sent_at: datetime | None,
        previous_sent_at: datetime | None,
    ) -> WelcomeChannelOutcome:
        """Decides whether an attempted channel actually delivered.

        Three conditions, all required, rather than the one that looks
        sufficient:

        * ``error is None`` -- ``_send_welcome_sms``/``_send_welcome_email``
          clear the error column only on a real send, and set it on both
          the provider-not-configured and the exception paths.
        * ``sent_at is not None`` -- the timestamp was actually written.
        * ``sent_at`` is *newer* than the value the row carried before this
          attempt -- this is the load-bearing one. A row whose first
          attempt succeeded and whose resend then failed keeps its old
          ``welcome_*_sent_at`` (only the error column is written on
          failure), so "there is a sent_at, therefore it sent" would report
          a fresh success on the strength of a send that happened days ago.
          That is exactly this project's recurring failure mode -- a check
          that passes against stale/empty state and calls it success -- and
          it is not going to be reintroduced here.

        Anything that does not satisfy all three reads as not-verified,
        which is the safe direction: an unverified real success is a
        cosmetic annoyance, a fabricated one costs an operator a partner.
        """
        sent = (
            error is None
            and sent_at is not None
            and (previous_sent_at is None or sent_at > previous_sent_at)
        )
        return WelcomeChannelOutcome(
            attempted=True, sent=sent, error=error, sent_at=sent_at
        )

    async def resend_welcome_message(
        self,
        channel_partner_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        send_sms: bool = False,
        send_email: bool = False,
    ) -> ChannelPartnerResendResult:
        """Re-attempts the welcome message on the channels the caller
        selects, for a partner that already exists.

        This is the follow-up mechanism this module's own docstring has
        always assumed ("discarding it over an SMS/email hiccup would be
        worse than a manual follow-up") but never provided: before this,
        a partner whose welcome email failed -- e.g. the 2026-08 SMTP
        ``(535, 'Authentication Failed')`` outage -- could only be
        "retried" by onboarding them a second time, which just creates a
        duplicate row (and, for a real GSTIN, doesn't even do that: it
        409s).

        Shape follows ``app.domains.location.provisioning_service
        .LocationProvisioningService.resend_welcome_email`` -- this
        codebase's one existing resend action -- which likewise re-enters
        the *same* private send helper the original flow used, is gated on
        its module's ``.manage`` permission, and writes a single audit
        entry. It does not follow ``ProvisioningEngineService.retry_job``'s
        "a retry is a new row" convention: that exists because a provision
        job's per-attempt history is itself the product (``retry_of_job_id``
        lineage, attempt numbers). A welcome message has no such history to
        preserve -- the row carries exactly one outcome pair per channel,
        by design -- so the retry updates it in place.

        Channels are independent and opt-in (see
        ``schemas.ChannelPartnerResendWelcomeRequest``). Each selected
        channel goes through the *same* ``_send_welcome_sms``/
        ``_send_welcome_email`` used at onboarding, so the
        provider-not-configured guard, the ``Logging*Provider`` "that isn't
        a real send" check, the error recording, and the sent-at/error
        clearing can never drift between first attempt and retry.

        Refuses a non-``ACTIVE`` partner (``ChannelPartnerNotActiveError``).
        This is a deliberate decision, not an accident of ordering: the
        message being resent is a *welcome* -- "You're onboarded as a
        channel partner ... our team will be in touch shortly" -- and
        sending that to someone whose partnership was revoked is worse
        than sending nothing. Revoking is also the point at which an
        operator has said "stop contacting this partner as a partner", and
        a 409 that says "reactivate first" makes the contradiction visible
        instead of quietly resolving it in favour of an outbound message.
        (Reactivation has no endpoint yet -- see ``models.py``'s ``status``
        comment -- so today this is a hard stop; that is the correct side
        to fail on when the alternative is an un-recallable SMS/email.)
        """
        partner = await self.get_partner(channel_partner_id)

        if partner.status != ChannelPartnerStatus.ACTIVE.value:
            raise ChannelPartnerNotActiveError(partner.id, partner.status)

        # Checked before anything is sent, so an operator asking for both
        # channels on an email-less partner doesn't get a half-done action:
        # nothing goes out and the response is unambiguous.
        if send_email and not partner.email:
            raise ChannelPartnerEmailMissingError(partner.id)

        sms_sent_at_before = partner.welcome_sms_sent_at
        email_sent_at_before = partner.welcome_email_sent_at

        if send_sms:
            partner = await self._send_welcome_sms(partner)
            sms_outcome = self._channel_outcome(
                error=partner.welcome_sms_error,
                sent_at=partner.welcome_sms_sent_at,
                previous_sent_at=sms_sent_at_before,
            )
        else:
            sms_outcome = WelcomeChannelOutcome(
                attempted=False,
                sent=False,
                error=partner.welcome_sms_error,
                sent_at=partner.welcome_sms_sent_at,
            )

        if send_email:
            partner = await self._send_welcome_email(partner)
            email_outcome = self._channel_outcome(
                error=partner.welcome_email_error,
                sent_at=partner.welcome_email_sent_at,
                previous_sent_at=email_sent_at_before,
            )
        else:
            email_outcome = WelcomeChannelOutcome(
                attempted=False,
                sent=False,
                error=partner.welcome_email_error,
                sent_at=partner.welcome_email_sent_at,
            )

        logger.info(
            "channel_partner_welcome_resent",
            extra={
                "channel_partner_id": str(partner.id),
                "sms_attempted": sms_outcome.attempted,
                "sms_sent": sms_outcome.sent,
                "email_attempted": email_outcome.attempted,
                "email_sent": email_outcome.sent,
            },
        )
        await self._audit(
            actor_user_id,
            AuditAction.CHANNEL_PARTNER_WELCOME_RESENT,
            partner,
            self._resend_audit_description(partner, sms_outcome, email_outcome),
            event_metadata={
                "sms": {
                    "attempted": sms_outcome.attempted,
                    "sent": sms_outcome.sent,
                    "error": sms_outcome.error,
                },
                "email": {
                    "attempted": email_outcome.attempted,
                    "sent": email_outcome.sent,
                    "error": email_outcome.error,
                },
            },
        )
        return ChannelPartnerResendResult(
            partner=partner, sms=sms_outcome, email=email_outcome
        )

    @staticmethod
    def _resend_audit_description(
        partner: ChannelPartner,
        sms: WelcomeChannelOutcome,
        email: WelcomeChannelOutcome,
    ) -> str:
        """Names the real outcome per attempted channel -- an audit line
        reading "welcome message resent" for an attempt that reached
        nobody would be the same lie the response is careful not to
        tell."""
        parts = [
            f"{label} {'sent' if outcome.sent else 'failed'}"
            for label, outcome in (("SMS", sms), ("email", email))
            if outcome.attempted
        ]
        return (
            f"Welcome message resend attempted for channel partner "
            f"'{partner.name}': {', '.join(parts)}"
        )

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
        *,
        event_metadata: dict[str, object] | None = None,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="channel_partner",
            entity_id=partner.id,
            description=description,
            event_metadata=event_metadata or {},
            organization_id=None,
            location_id=None,
        )


__all__ = [
    "ChannelPartnerService",
    "ChannelPartnerListResult",
    "ChannelPartnerResendResult",
    "WelcomeChannelOutcome",
    "AuditLogWriter",
    "SmsProviderProtocol",
    "EmailProviderProtocol",
]
