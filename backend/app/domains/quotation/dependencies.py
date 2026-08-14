"""FastAPI dependencies for the Quotation domain -- wires the repository/
service layer, composing with ``app.domains.otp.service``'s
``get_configured_email_provider`` (the same real, already-configured-in-
production email mechanism ``app.domains.billing.router``'s invoice-email
endpoint and OTP delivery both already use) rather than a second
email-sending path."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.otp.service import (
    EmailProviderNotConfiguredError,
    EmailProviderProtocol,
    get_configured_email_provider,
)

from .repository import QuotationRepository, QuotationRepositoryProtocol
from .service import QuotationService


def get_quotation_repository(
    db: AsyncSession = Depends(get_db_session),
) -> QuotationRepositoryProtocol:
    return QuotationRepository(db)


def _resolve_email_provider(settings: Settings) -> EmailProviderProtocol | None:
    """Resolves the configured email provider the same way
    ``app.domains.billing.router``'s own invoice-email send does, but one
    step earlier: a misconfigured explicit provider selection
    (``EmailProviderNotConfiguredError``) becomes ``None`` here rather than
    an unhandled 500 out of dependency resolution -- ``QuotationService``
    already treats ``None`` as "no real provider available" and records a
    graceful ``FAILED``/``email_error`` outcome instead (see that class's
    own docstring), the same "a send failure is never a rollback of the
    already-created document" posture billing's own router documents."""
    try:
        return get_configured_email_provider(settings)
    except EmailProviderNotConfiguredError:
        return None


def get_quotation_service(
    repository: QuotationRepositoryProtocol = Depends(get_quotation_repository),
    settings: Settings = Depends(get_settings),
) -> QuotationService:
    return QuotationService(
        repository,
        email_provider=_resolve_email_provider(settings),
    )


__all__ = ["get_quotation_repository", "get_quotation_service"]
