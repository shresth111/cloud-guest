"""The low-balance email (spec §13.5): ``marketing_credits_low``.

Queued on the existing notification outbox (``app.domains.notification``),
addressed to the organization's account email (``Organization.contact_email``,
the owner's address the renewal reminders already use), sent from
``MailIdentity.DEFAULT`` (the event type is deliberately not routed to another
mailbox). ``CreditWalletService`` calls this once per crossing below the
threshold; it never raises into the charge that triggered it.
"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from .credits_constants import MINOR_PER_CREDIT
from .models import CreditWallet

logger = logging.getLogger(__name__)


def _credits(minor: int) -> str:
    whole, part = divmod(max(minor, 0), MINOR_PER_CREDIT)
    return f"{whole:,}.{part:02d}"


class LowBalanceNotifier:
    """``LowBalanceHook`` for ``CreditWalletService``. Runs in a SAVEPOINT so
    a failing outbox insert can never abort the reserve or debit (and, in a
    worker, the recipient status change) it rides on."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def __call__(self, wallet: CreditWallet) -> None:
        from app.domains.notification.constants import (
            NotificationChannelType,
            NotificationEventType,
        )
        from app.domains.notification.repository import NotificationRepository
        from app.domains.notification.service import NotificationService
        from app.domains.organization.models import Organization

        try:
            async with self.session.begin_nested():
                organization = await self.session.get(
                    Organization, wallet.organization_id
                )
                if organization is None or not organization.contact_email:
                    logger.warning(
                        "marketing_credits_low_unaddressed",
                        extra={"organization_id": str(wallet.organization_id)},
                    )
                    return
                available = _credits(wallet.available_minor)
                threshold = _credits(wallet.low_balance_threshold_minor)
                await NotificationService(NotificationRepository(self.session)).enqueue(
                    event_type=NotificationEventType.MARKETING_CREDITS_LOW,
                    channel=NotificationChannelType.EMAIL,
                    recipient=organization.contact_email,
                    organization_id=wallet.organization_id,
                    subject=(
                        "Your Wyfy marketing credits are running low "
                        f"({available} left)"
                    ),
                    body=(
                        f"Hello {organization.name},\n\n"
                        f"Your marketing credit balance is {available} credits, below "
                        f"your alert level of {threshold} credits. Campaigns sent "
                        "through Wyfy's SMS, WhatsApp and email need credits; a "
                        "campaign that cannot be covered will not be scheduled.\n\n"
                        "To add credits, open Marketing > Credits in your dashboard "
                        "and choose Request top-up.\n\n"
                        "Credits never expire. Campaigns sent through your own "
                        "provider do not use credits.\n\n"
                        "- Wyfy Guest"
                    ),
                    context={
                        "available_minor": wallet.available_minor,
                        "low_balance_threshold_minor": (
                            wallet.low_balance_threshold_minor
                        ),
                    },
                )
        except Exception:  # noqa: BLE001 - an alert never blocks a charge
            logger.warning(
                "marketing_credits_low_enqueue_failed",
                extra={"organization_id": str(wallet.organization_id)},
                exc_info=True,
            )


__all__ = ["LowBalanceNotifier"]
