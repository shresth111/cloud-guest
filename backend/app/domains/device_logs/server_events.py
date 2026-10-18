"""Rows the platform writes into ``device_log_events`` itself, next to
router syslog:

* **RADIUS decisions** (``RadiusEventRecorder``) -- every Authorize
  Accept/Reject. Before this, a Reject left nothing but a ``logger.info``
  line, so a venue could not see why a guest was refused. Tenant comes from
  the NAS's router (the NAS is shared-secret authenticated), never from the
  request body.
* **Captive-portal sign-in failures** (``PortalLoginEventRecorder``) --
  wrong/expired OTP, voucher, PIN... The NetLogs "Invalid OTP" row.

Both must never fail or slow the auth path:

* RADIUS writes go into the request's own transaction inside a SAVEPOINT
  (``repository.insert_server_event``): one indexed insert, a failure rolls
  back only that insert, and every exception is swallowed.
* Portal failures use their **own short session and commit**. The login
  path re-raises after recording the failure, and ``get_db_session`` then
  rolls the request transaction back -- a row written there would be rolled
  back with it.

No guest identifier (phone/e-mail/username) is ever written: the reason,
the router, the MAC/IP and the time are what troubleshooting needs. Gated on
``device_logs_enabled`` like the rest of the domain.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings

from .constants import (
    SERVER_SOURCE_PORTAL,
    SERVER_SOURCE_RADIUS,
    SERVER_VENDOR,
    Attribution,
    LogCategory,
    LogStatus,
)
from .repository import insert_server_event

logger = logging.getLogger(__name__)

_MAC = re.compile(r"^[0-9A-Fa-f]{2}(?:[:-]?[0-9A-Fa-f]{2}){5}$")

#: Severity numbers (RFC 5424) for platform rows: a Reject is routine
#: (unknown device, expired session) so ``notice``, not ``warning``.
_SEV_INFO = 6
_SEV_NOTICE = 5

#: Exception class name (what guest_login_history stores) -> the words the
#: customer sees. Unknown names fall back to "Sign-in failed".
FAILURE_REASONS: dict[str, str] = {
    "OtpCodeMismatchError": "Invalid OTP",
    "OtpExpiredError": "OTP expired",
    "OtpNotFoundError": "No OTP requested for this number",
    "OtpAlreadyConsumedError": "OTP already used",
    "OtpAttemptsExceededError": "Too many wrong OTP attempts",
    "InvalidOtpIdentifierError": "Invalid phone number or e-mail",
    "VoucherNotFoundError": "Invalid voucher code",
    "VoucherExpiredError": "Voucher expired",
    "VoucherExhaustedError": "Voucher fully used",
    "VoucherRevokedError": "Voucher revoked",
    "VoucherBatchNotActiveError": "Voucher batch not active",
    "VoucherRedemptionRateLimitExceededError": "Too many voucher attempts",
    "GuestPasswordLoginFailedError": "Wrong password",
    "GuestPinLoginFailedError": "Wrong PIN",
    "WhitelistOnlyAccessDeniedError": "Not on the allowed list",
}


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if not _MAC.match(raw):
        return None
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", raw).upper()
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


def _clock() -> datetime:
    return datetime.now(UTC)


class RadiusDecisionRecorder(Protocol):
    async def record_decision(
        self,
        *,
        router: Any,
        nas_identifier: str | None,
        nas_ip: str | None,
        accepted: bool,
        reason: str | None,
        calling_station_id: str | None,
    ) -> None: ...


class RadiusEventRecorder:
    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        *,
        clock: Callable[[], datetime] = _clock,
    ) -> None:
        self.session = session
        self.settings = settings
        self._clock = clock

    async def record_decision(
        self,
        *,
        router: Any,
        nas_identifier: str | None,
        nas_ip: str | None,
        accepted: bool,
        reason: str | None,
        calling_station_id: str | None,
    ) -> None:
        if not self.settings.device_logs_enabled:
            return
        try:
            row = radius_row(
                now=self._clock(),
                router=router,
                nas_identifier=nas_identifier,
                nas_ip=nas_ip,
                accepted=accepted,
                reason=reason,
                calling_station_id=calling_station_id,
            )
        except Exception as exc:  # noqa: BLE001 -- never break auth
            logger.warning(
                "device_logs_radius_row_failed", extra={"error": str(exc)[:300]}
            )
            return
        await insert_server_event(self.session, row)


def radius_row(
    *,
    now: datetime,
    router: Any,
    nas_identifier: str | None,
    nas_ip: str | None,
    accepted: bool,
    reason: str | None,
    calling_station_id: str | None,
) -> dict[str, Any]:
    message = "Access-Accept" if accepted else "Access-Reject"
    if reason:
        message = f"{message}: {reason}"
    return {
        "received_at": now,
        "device_time": None,
        "organization_id": getattr(router, "organization_id", None),
        "location_id": getattr(router, "location_id", None),
        "router_id": getattr(router, "id", None),
        "source_ip": (nas_ip or "-")[:45],
        "vendor": SERVER_VENDOR,
        "source": SERVER_SOURCE_RADIUS,
        "facility": None,
        "severity": _SEV_INFO if accepted else _SEV_NOTICE,
        "hostname": (nas_identifier or None) and nas_identifier[:255],
        "topics": "radius",
        "message": message,
        "attribution": Attribution.SERVER.value,
        "claimed_tag": None,
        "category": LogCategory.RADIUS.value,
        "protocol": "RADIUS",
        "src_ip": None,
        "dst_ip": None,
        "status": (LogStatus.ACCEPT if accepted else LogStatus.REJECT).value,
        "device_mac": normalize_mac(calling_station_id),
    }


def portal_failure_row(
    *,
    now: datetime,
    organization_id: uuid.UUID | None,
    location_id: uuid.UUID | None,
    auth_method: str,
    reason: str,
    ip_address: str | None,
) -> dict[str, Any]:
    words = FAILURE_REASONS.get(reason, "Sign-in failed")
    return {
        "received_at": now,
        "device_time": None,
        "organization_id": organization_id,
        "location_id": location_id,
        "router_id": None,
        "source_ip": "-",
        "vendor": SERVER_VENDOR,
        "source": SERVER_SOURCE_PORTAL,
        "facility": None,
        "severity": _SEV_NOTICE,
        "hostname": None,
        "topics": "hotspot",
        "message": f"{auth_method} sign-in failed: {words}",
        "attribution": Attribution.SERVER.value,
        "claimed_tag": None,
        "category": LogCategory.HOTSPOT_AUTH.value,
        "protocol": "PORTAL",
        "src_ip": (ip_address or None) and ip_address[:45],
        "dst_ip": None,
        "status": LogStatus.FAILURE.value,
        "device_mac": None,
    }


class PortalLoginRecorder(Protocol):
    async def record_login_failure(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        auth_method: str,
        reason: str,
        ip_address: str | None,
    ) -> None: ...


class PortalLoginEventRecorder:
    """Writes in its own session -- see the module docstring."""

    def __init__(
        self,
        settings: Settings,
        *,
        session_factory: Callable[[], Any] | None = None,
        clock: Callable[[], datetime] = _clock,
    ) -> None:
        self.settings = settings
        self._session_factory = session_factory
        self._clock = clock

    def _factory(self) -> Callable[[], Any]:
        if self._session_factory is None:
            from app.database.session import SessionLocal

            self._session_factory = SessionLocal
        return self._session_factory

    async def record_login_failure(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        auth_method: str,
        reason: str,
        ip_address: str | None,
    ) -> None:
        if not self.settings.device_logs_enabled or organization_id is None:
            return
        try:
            row = portal_failure_row(
                now=self._clock(),
                organization_id=organization_id,
                location_id=location_id,
                auth_method=auth_method,
                reason=reason,
                ip_address=ip_address,
            )
            async with self._factory()() as session:
                if await insert_server_event(session, row):
                    await session.commit()
        except Exception as exc:  # noqa: BLE001 -- never break sign-in
            logger.warning(
                "device_logs_portal_event_failed",
                extra={"error_type": type(exc).__name__, "error": str(exc)[:300]},
            )
