"""FastAPI dependencies for the Channel Partner domain -- wires the
repository/service layer, composing with ``app.domains.otp.service``'s
``get_configured_sms_provider``/``get_configured_email_provider`` (the same
real, already-configured-in-production Twilio SMS + SMTP/SES email
mechanisms ``app.domains.quotation``, ``app.domains.billing``, and OTP
delivery itself already use) rather than a second delivery path."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.otp.service import (
    EmailProviderNotConfiguredError,
    EmailProviderProtocol,
    SmsProviderNotConfiguredError,
    SmsProviderProtocol,
    get_configured_email_provider,
    get_configured_sms_provider,
)

from .repository import ChannelPartnerRepository, ChannelPartnerRepositoryProtocol
from .service import ChannelPartnerService


def get_channel_partner_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ChannelPartnerRepositoryProtocol:
    return ChannelPartnerRepository(db)


def _resolve_email_provider(settings: Settings) -> EmailProviderProtocol | None:
    """Resolves the configured email provider the same way
    ``app.domains.quotation.dependencies._resolve_email_provider`` does: a
    misconfigured explicit provider selection
    (``EmailProviderNotConfiguredError``) becomes ``None`` here rather than
    an unhandled 500 out of dependency resolution --
    ``ChannelPartnerService`` already treats ``None`` as "no real provider
    available" and records a graceful ``welcome_email_error`` outcome
    instead (see that class's own docstring)."""
    try:
        return get_configured_email_provider(settings)
    except EmailProviderNotConfiguredError:
        return None


def _resolve_sms_provider(settings: Settings) -> SmsProviderProtocol | None:
    """Same resolution contract as :func:`_resolve_email_provider`, for the
    SMS delivery provider."""
    try:
        return get_configured_sms_provider(settings)
    except SmsProviderNotConfiguredError:
        return None


def get_channel_partner_service(
    repository: ChannelPartnerRepositoryProtocol = Depends(
        get_channel_partner_repository
    ),
    settings: Settings = Depends(get_settings),
) -> ChannelPartnerService:
    return ChannelPartnerService(
        repository,
        sms_provider=_resolve_sms_provider(settings),
        email_provider=_resolve_email_provider(settings),
    )


__all__ = ["get_channel_partner_repository", "get_channel_partner_service"]
