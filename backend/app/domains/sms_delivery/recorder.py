"""Writing one ``sms_delivery_logs`` row per real SMS send attempt.

## Why its own session

Every send site runs inside a request (or task) session that is rolled back
when the send raises -- ``app.database.session.get_db_session`` rolls back on
any exception, and a failed guest-OTP send takes its ``otp_requests`` row
with it. A failed attempt recorded in *that* session would vanish exactly when
it matters. So the recorder opens a short session of its own and commits the
row there, independent of whatever the caller does next.

## Why it never raises

Logging a send must never break the send. A recorder failure (DB down, pool
exhausted) is logged at WARNING and swallowed; the guest still gets the code.

## What is never stored

The full number (masked as ``+91******3210``), the message body (an OTP body
*is* the code), and any secret -- exception text goes through
:func:`app.domains.sms_delivery.dlr.scrub` first, because httpx's error
message embeds the request URL and Ping4SMS puts its API key in the query.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from app.core.logging import get_logger
from app.domains.marketing.validators import mask_phone

from .constants import NON_SENDING_PROVIDERS, ProviderSource, SmsDeliveryStatus
from .dlr import error_code_for, scrub
from .models import SmsDeliveryLog

logger = get_logger(__name__)


class SmsDeliveryRecorderProtocol(Protocol):
    async def record(
        self,
        *,
        purpose: str,
        provider: str,
        phone_number: str | None,
        status: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        provider_source: str = ProviderSource.WYFY.value,
        provider_message_id: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        reference_id: uuid.UUID | None = None,
    ) -> None: ...


def provider_name_of(provider: object) -> str:
    """The short provider name a send went through (``ping4sms``,
    ``twilio``, ``logging``...). Read from the provider's own
    ``provider_name``/``provider`` attribute; unknown implementations are
    named after their class so a row is still attributable."""
    for attr in ("provider_name", "provider"):
        value = getattr(provider, attr, None)
        if isinstance(value, str) and value:
            return value[:32]
    return type(provider).__name__[:32]


class SmsDeliveryRecorder:
    """Commits one row per attempt through its own session (see module
    docstring). ``session_factory`` is an ``async_sessionmaker``."""

    def __init__(self, session_factory: Callable[[], Any]) -> None:
        self.session_factory = session_factory

    async def record(
        self,
        *,
        purpose: str,
        provider: str,
        phone_number: str | None,
        status: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        provider_source: str = ProviderSource.WYFY.value,
        provider_message_id: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        reference_id: uuid.UUID | None = None,
    ) -> None:
        if provider in NON_SENDING_PROVIDERS:
            return
        now = datetime.now(UTC)
        row = SmsDeliveryLog(
            id=uuid.uuid4(),
            created_at=now,
            status_updated_at=now,
            organization_id=organization_id,
            location_id=location_id,
            purpose=purpose,
            provider=provider[:32],
            provider_source=provider_source,
            recipient_masked=(mask_phone(phone_number) or None)
            if phone_number
            else None,
            reference_id=reference_id,
            provider_message_id=(
                str(provider_message_id)[:100] if provider_message_id else None
            ),
            status=status,
            error_code=(error_code or None) and str(error_code)[:64],
            error_message=scrub(error_message),
            dlr_poll_count=0,
        )
        try:
            async with self.session_factory() as session:
                session.add(row)
                await session.commit()
        except Exception as exc:  # noqa: BLE001 -- see module docstring
            logger.warning(
                "sms_delivery_log_write_failed",
                extra={
                    "sms_purpose": purpose,
                    "sms_provider": provider,
                    "sms_status": status,
                    "error_type": type(exc).__name__,
                },
            )


async def send_sms_and_record(
    provider: Any,
    phone_number: str,
    message: str,
    *,
    recorder: SmsDeliveryRecorderProtocol | None,
    purpose: str,
    organization_id: uuid.UUID | None = None,
    location_id: uuid.UUID | None = None,
    reference_id: uuid.UUID | None = None,
) -> str | None:
    """``provider.send(phone_number, message)``, recording the outcome.

    Returns the provider's message id (or ``None``). Re-raises the provider's
    own exception after recording it, so callers keep their existing failure
    handling unchanged. With ``recorder=None`` this is a plain send.
    """
    name = provider_name_of(provider)
    try:
        result = await provider.send(phone_number, message)
    except Exception as exc:
        if recorder is not None:
            await recorder.record(
                purpose=purpose,
                provider=name,
                phone_number=phone_number,
                status=SmsDeliveryStatus.FAILED.value,
                organization_id=organization_id,
                location_id=location_id,
                error_code=error_code_for(exc),
                error_message=str(exc),
                reference_id=reference_id,
            )
        raise
    message_id = result if isinstance(result, str) and result else None
    if recorder is not None:
        await recorder.record(
            purpose=purpose,
            provider=name,
            phone_number=phone_number,
            status=SmsDeliveryStatus.SENT.value,
            organization_id=organization_id,
            location_id=location_id,
            provider_message_id=message_id,
            reference_id=reference_id,
        )
    return message_id


def build_default_recorder() -> SmsDeliveryRecorder:
    """The production recorder, bound to the app's ``SessionLocal``."""
    from app.database.session import SessionLocal

    return SmsDeliveryRecorder(SessionLocal)


__all__ = [
    "SmsDeliveryRecorder",
    "SmsDeliveryRecorderProtocol",
    "build_default_recorder",
    "provider_name_of",
    "send_sms_and_record",
]
