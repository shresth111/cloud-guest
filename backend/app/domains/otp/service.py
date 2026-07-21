"""OTP business logic: code generation/hashing, request/verify, provider
dispatch, and rate limiting.

Design notes worth calling out up front (see ``docs/otp/FLOW.md`` for the
full write-up):

## Hash choice: SHA-256, not Argon2id -- and why

``app.domains.auth.password.PasswordManager`` hashes *user passwords* with
Argon2id: a deliberately slow, memory-hard KDF, because a password is a
long-lived secret an attacker who steals the hash can attack offline,
forever, at their own pace. An OTP code is a fundamentally different kind
of secret: it is a randomly-generated, 6-digit (default,
``Settings.otp_code_length``) value that is *already* useless within
minutes (``Settings.otp_expiry_seconds``) and can be guessed at most
``max_attempts`` times before this row locks itself out -- Argon2id's slow-
hashing property defends against an offline dictionary/brute-force attack
against the hash itself, which is not the threat model here: the actual
defense against guessing a short numeric code is expiry + the attempt cap,
not hash cost. This is exactly the same judgment call this codebase already
made twice: ``app.domains.router.models.RouterProvisioningToken.token_hash``
and ``app.domains.router_agent.models.RouterAgentCredential.credential_hash``
both hash a short-lived, randomly-generated bearer credential with plain
SHA-256 (``app.domains.router_agent.service.hash_credential``) for the
identical reason. Using Argon2id here would only add real per-request
latency (guests verifying a code expect a fast response) for no additional
security the expiry/attempt-cap pair doesn't already provide.

## The two distinct rate-limit dimensions

1. **Request rate limiting** (``OtpRateLimiter``, Redis-backed,
   ``Settings.otp_max_requests_per_window`` /
   ``Settings.otp_request_window_minutes``) -- how many *new* codes a given
   identifier may request in a rolling window. This protects the delivery
   channel itself (a real phone number/email inbox, and this platform's
   SMS/email sending budget) from being spammed with codes nobody asked to
   receive. Enforced in ``request_otp``, *before* any ``OtpRequest`` row is
   even created.
2. **Verification attempt lockout** (a plain database column,
   ``OtpRequest.attempt_count``/``max_attempts``,
   ``Settings.otp_max_verification_attempts``) -- how many times *one
   already-issued* code may be guessed before that specific code locks
   itself out. This protects against brute-forcing a live 6-digit code.
   Enforced in ``verify_otp``.

These mirror ``app.domains.auth``'s own two distinct mechanisms
(``AuthSecurity.check_rate_limit``/``record_login_attempt`` -- Redis-backed,
per email+IP request throttling -- versus ``User.failed_login_attempts``/
``locked_until`` -- a persisted, per-account lockout) exactly in spirit and
in naming convention (``otp_max_verification_attempts`` mirrors
``max_login_attempts``; ``otp_request_window_minutes`` mirrors
``account_lockout_minutes``), just applied to an identifier string instead
of a persistent ``User`` row, since no such row exists for a guest yet.

## Provider interfaces: ``Protocol``, honest logging default

There is no real SMS/email provider anywhere in this codebase -- no
Twilio/SendGrid credentials, no existing "send a message" infrastructure at
all. ``SmsProviderProtocol``/``EmailProviderProtocol`` are typed
structurally (``Protocol``) so a real provider can be substituted later
(via ``dependencies.py``'s dependency injection) without this module
changing at all. ``LoggingSmsProvider``/``LoggingEmailProvider`` are the
honest interim implementation: they log the would-be-sent message via
``app.core.logging.get_logger`` rather than pretending to call a real
gateway -- the identical "honestly documented interim boundary" posture
``app.domains.wireguard`` uses for simulated tunnel health and
``app.domains.router_provisioning``/``app.domains.router_agent`` use for
simulated device dispatch (no live device-side execution, just a durable,
inspectable record of what *would* happen).

## Audit-volume judgment call

Three additive ``AuditAction`` values exist: ``OTP_REQUESTED``,
``OTP_VERIFIED``, ``OTP_VERIFICATION_FAILED``. This service does **not**,
however, write an audit entry for every single ``OTP_REQUESTED`` event:
requesting a code is a high-volume, guest-facing, entirely unauthenticated
action (any caller can trigger it for any identifier, bounded only by rate
limiting) -- writing one row per request to RBAC's ``audit_log_entries``
would flood a table this codebase's own convention documents as scoped to
"moderate-volume, human-attributable, admin-reviewable" events, not general
telemetry (see ``app.domains.router_provisioning.models``'s module
docstring on why ``RouterEvent``/``RouterHealthSnapshot`` are kept separate
from ``audit_log_entries`` for the identical reason). The value still
exists on ``AuditAction`` for forward-compatibility (so a future decision to
start auditing it needs no migration) and every request is still logged
via the structured logger (``otp_requested``) -- just not written to the
audit table.

``OTP_VERIFIED`` (success) and ``OTP_VERIFICATION_FAILED`` (only for the two
*adversarially-relevant* failure reasons -- a wrong code presented against
a still-live OTP, or a code that has already hit its attempt cap) **are**
written to the audit table: these are the moderate-volume, security-
relevant signal an admin/auditor would actually want visibility into (was
this identifier's guest-login flow being brute-forced?). Routine,
non-adversarial failures (no OTP was ever requested, the OTP simply
expired, or it was already consumed) are logged but not audited -- they are
normal guest-side churn (a guest waited too long, or double-submitted a
form), not a signal of an attack.

## Response envelope

``router.py``'s two guest-facing endpoints use the project's standard
``ApiResponse``/``build_response`` envelope, unlike
``app.domains.router_agent``/``app.domains.wireguard``'s device-facing
endpoints, which deliberately do not. The distinction: those device-facing
endpoints are called by an embedded RouterOS agent that has no reason to
parse a rich, structured API contract -- but ``/otp/request``/``/otp/verify``
are called by the guest-facing captive-portal *frontend*, a real web/app
client that benefits from the same consistent, structured
success/message/data/request_id shape every other user-facing endpoint in
this codebase already returns.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from redis.asyncio import Redis

from app.core.config import Settings
from app.domains.rbac.enums import AuditAction

from .constants import OTP_REQUEST_RATE_LIMIT_KEY_TEMPLATE, OtpChannel, OtpPurpose
from .events import OtpRequested, OtpVerificationFailed, OtpVerified
from .exceptions import (
    OtpAlreadyConsumedError,
    OtpAttemptsExceededError,
    OtpCodeMismatchError,
    OtpExpiredError,
    OtpNotFoundError,
    OtpRequestRateLimitExceededError,
)
from .models import OtpRequest
from .repository import OtpRepositoryProtocol
from .validators import validate_identifier

logger = logging.getLogger(__name__)

_CODE_ALPHABET = "0123456789"

# Verification-failure reasons genuinely relevant to an admin/auditor
# reviewing "was this identifier's login flow being attacked" -- see module
# docstring's audit-volume judgment call. Not-found/expired/already-consumed
# are deliberately excluded (routine guest-side churn, not an attack signal).
_AUDITED_FAILURE_REASONS = frozenset({"code_mismatch", "attempts_exceeded"})


def generate_numeric_code(length: int) -> str:
    """Cryptographically-random numeric code, e.g. ``"042817"`` for
    ``length=6``. Uses :mod:`secrets`, not :mod:`random`, since this is the
    guest's one proof of identity for this login attempt -- the same
    "use ``secrets`` for anything security-relevant" posture
    ``app.domains.router_agent.constants.AGENT_CREDENTIAL_BYTES`` /
    ``secrets.token_urlsafe`` already establishes elsewhere in this
    codebase."""
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(length))


def hash_otp_code(code: str) -> str:
    """SHA-256 hex digest -- see module docstring for why this, not
    Argon2id, is the right hash for a short-lived, expiry- and attempt-
    capped OTP code."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


# ============================================================================
# Provider interfaces (composition point for a future real SMS/email
# integration -- see module docstring)
# ============================================================================


class SmsProviderProtocol(Protocol):
    async def send(self, phone_number: str, message: str) -> None: ...


class EmailProviderProtocol(Protocol):
    async def send(self, email: str, subject: str, body: str) -> None: ...


class LoggingSmsProvider:
    """Honest interim SMS provider -- logs the would-be-sent message
    instead of calling a real carrier/gateway API. See module docstring."""

    async def send(self, phone_number: str, message: str) -> None:
        logger.info(
            "otp_sms_would_send",
            extra={"phone_number": phone_number, "message_length": len(message)},
        )


class LoggingEmailProvider:
    """Honest interim email provider -- logs the would-be-sent message
    instead of calling a real transactional-email API. See module
    docstring."""

    async def send(self, email: str, subject: str, body: str) -> None:
        logger.info(
            "otp_email_would_send",
            extra={"email": email, "subject": subject, "body_length": len(body)},
        )


# ============================================================================
# Real providers (app.domains.notification's own driving reason to exist:
# every caller of EmailProviderProtocol/SmsProviderProtocol -- this
# service, app.domains.monitoring's NotificationService,
# app.domains.notification itself -- previously had only the Logging
# providers above to fall back to). Composition, not a second provider
# abstraction: every class below still just implements the exact
# Protocols already defined in this module.
# ============================================================================


class EmailProviderNotConfiguredError(Exception):
    """Raised when ``Settings.email_delivery_provider`` explicitly selects
    a real provider ('smtp'/'ses') whose required credentials are empty --
    mirrors ``app.domains.billing.payment_gateways
    .PaymentGatewayNotConfiguredError``'s identical "explicit selection
    without configuration is a real error, not a silent fallback"
    precedent."""


class SmsProviderNotConfiguredError(Exception):
    """Same as :class:`EmailProviderNotConfiguredError`, for
    ``Settings.sms_delivery_provider``."""


class SmtpEmailProvider:
    """Real ``EmailProviderProtocol`` implementation: sends via any
    standard SMTP server (SendGrid, Mailgun, Postmark, AWS SES's own SMTP
    interface, or a plain relay) using stdlib ``smtplib``/``email`` --
    zero new dependencies. ``smtplib`` is synchronous; ``send`` bridges it
    through ``asyncio.to_thread``, the same sync-in-async bridge
    ``app.core.storage.S3ObjectStorage`` uses for boto3."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        use_tls: bool,
        from_address: str,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.from_address = from_address

    def _send_sync(self, email: str, subject: str, body: str) -> None:
        import smtplib
        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.from_address
        message["To"] = email
        message.set_content(body)

        smtp_class = smtplib.SMTP_SSL if self.port == 465 else smtplib.SMTP
        with smtp_class(self.host, self.port, timeout=10) as smtp:
            if self.use_tls and self.port != 465:
                smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(message)

    async def send(self, email: str, subject: str, body: str) -> None:
        await asyncio.to_thread(self._send_sync, email, subject, body)


class SesEmailProvider:
    """Real ``EmailProviderProtocol`` implementation via AWS SES
    (``boto3``'s ``ses`` client -- already a dependency for
    ``app.core.storage.S3ObjectStorage``). Synchronous client, bridged
    through ``asyncio.to_thread`` like :class:`SmtpEmailProvider` above."""

    def __init__(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        region_name: str,
        from_address: str,
    ) -> None:
        import boto3

        self.from_address = from_address
        self._client = boto3.client(
            "ses",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region_name,
        )

    def _send_sync(self, email: str, subject: str, body: str) -> None:
        self._client.send_email(
            Source=self.from_address,
            Destination={"ToAddresses": [email]},
            Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}},
        )

    async def send(self, email: str, subject: str, body: str) -> None:
        await asyncio.to_thread(self._send_sync, email, subject, body)


class TwilioSmsProvider:
    """Real ``SmsProviderProtocol`` implementation: a plain
    ``httpx.AsyncClient`` POST to Twilio's documented REST API
    (https://www.twilio.com/docs/sms/api) -- the same "real, well-
    documented third-party API, no fabricated payload shape" bar
    ``app.domains.monitoring.service``'s Slack/Teams/Discord notifiers
    already set."""

    _API_URL_TEMPLATE = (
        "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    )
    _TIMEOUT_SECONDS = 10.0

    def __init__(self, *, account_sid: str, auth_token: str, from_number: str) -> None:
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number

    async def send(self, phone_number: str, message: str) -> None:
        import httpx

        url = self._API_URL_TEMPLATE.format(sid=self.account_sid)
        async with httpx.AsyncClient(timeout=self._TIMEOUT_SECONDS) as client:
            response = await client.post(
                url,
                auth=(self.account_sid, self.auth_token),
                data={"From": self.from_number, "To": phone_number, "Body": message},
            )
            response.raise_for_status()


def get_configured_email_provider(settings: Settings) -> EmailProviderProtocol:
    """Selects the real ``EmailProviderProtocol`` implementation
    ``Settings.email_delivery_provider`` names, or :class:`LoggingEmailProvider`
    if unset/``"logging"``. Shared by this domain's own ``dependencies.py``,
    ``app.domains.monitoring``'s ``NotificationService`` wiring, and
    ``app.domains.notification`` -- one place to add a new provider, not
    three copies of the same selection logic."""
    provider = settings.email_delivery_provider.lower()
    if provider == "smtp":
        if not settings.smtp_host:
            raise EmailProviderNotConfiguredError(
                "email_delivery_provider='smtp' but smtp_host is empty."
            )
        return SmtpEmailProvider(
            host=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            use_tls=settings.smtp_use_tls,
            from_address=settings.smtp_from_address,
        )
    if provider == "ses":
        if not settings.ses_access_key_id or not settings.ses_from_address:
            raise EmailProviderNotConfiguredError(
                "email_delivery_provider='ses' but ses_access_key_id/"
                "ses_from_address is empty."
            )
        return SesEmailProvider(
            access_key_id=settings.ses_access_key_id,
            secret_access_key=settings.ses_secret_access_key,
            region_name=settings.ses_region,
            from_address=settings.ses_from_address,
        )
    return LoggingEmailProvider()


def get_configured_sms_provider(settings: Settings) -> SmsProviderProtocol:
    """Same selection contract as :func:`get_configured_email_provider`,
    for ``Settings.sms_delivery_provider``."""
    provider = settings.sms_delivery_provider.lower()
    if provider == "twilio":
        if not settings.twilio_account_sid or not settings.twilio_from_number:
            raise SmsProviderNotConfiguredError(
                "sms_delivery_provider='twilio' but twilio_account_sid/"
                "twilio_from_number is empty."
            )
        return TwilioSmsProvider(
            account_sid=settings.twilio_account_sid,
            auth_token=settings.twilio_auth_token,
            from_number=settings.twilio_from_number,
        )
    return LoggingSmsProvider()


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service (``WireGuardService``,
    ``RouterProvisioningService``, ...) already defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


class OtpRateLimiter:
    """Static-method facade over Redis for OTP *request* rate limiting --
    mirrors ``app.domains.auth.security.AuthSecurity.check_rate_limit``/
    ``record_login_attempt``'s identical INCR+EXPIRE+TTL pattern, reusing
    the existing Redis client (``app.database.redis``) rather than a new
    cache abstraction.

    This enforces exactly one of OTP's two distinct rate-limit dimensions
    -- see ``service.py``'s module docstring for the full "two dimensions"
    write-up. It is scoped by identifier alone, not identifier+purpose or
    +channel: the point is to protect the *contact channel* (a real phone
    number/email inbox) from being spammed with delivery attempts, and that
    risk exists regardless of which purpose a future caller passes --
    scoping per-purpose would let a caller reset an identifier's window
    just by varying purpose, with no stronger justification for the extra
    fragmentation.
    """

    @staticmethod
    async def check_and_increment(
        redis: Redis,
        identifier: str,
        *,
        max_requests: int,
        window_minutes: int,
    ) -> None:
        """Raises ``OtpRequestRateLimitExceededError`` if ``identifier`` has
        already requested ``max_requests`` codes within the current
        ``window_minutes`` window; otherwise increments the counter
        (starting a fresh window on the first request)."""
        key = OTP_REQUEST_RATE_LIMIT_KEY_TEMPLATE.format(identifier=identifier)
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, window_minutes * 60)
        if current > max_requests:
            ttl = await redis.ttl(key)
            raise OtpRequestRateLimitExceededError(
                ttl if ttl and ttl > 0 else window_minutes * 60
            )


class OtpService:
    """Core OTP business logic: request, verify, rate limit."""

    def __init__(
        self,
        repository: OtpRepositoryProtocol,
        redis: Redis,
        *,
        sms_provider: SmsProviderProtocol | None = None,
        email_provider: EmailProviderProtocol | None = None,
        audit_writer: AuditLogWriter | None = None,
        code_length: int = 6,
        expiry_seconds: int = 300,
        max_verification_attempts: int = 5,
        max_requests_per_window: int = 5,
        request_window_minutes: int = 60,
    ) -> None:
        self.repository = repository
        self.redis = redis
        self.sms_provider: SmsProviderProtocol = sms_provider or LoggingSmsProvider()
        self.email_provider: EmailProviderProtocol = (
            email_provider or LoggingEmailProvider()
        )
        self.audit_writer = audit_writer
        self.code_length = code_length
        self.expiry_seconds = expiry_seconds
        self.max_verification_attempts = max_verification_attempts
        self.max_requests_per_window = max_requests_per_window
        self.request_window_minutes = request_window_minutes

    # ========================================================================
    # Request
    # ========================================================================

    async def request_otp(
        self,
        *,
        identifier: str,
        channel: OtpChannel,
        purpose: OtpPurpose,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> OtpRequest:
        identifier = identifier.strip()
        validate_identifier(identifier, channel)

        await OtpRateLimiter.check_and_increment(
            self.redis,
            identifier,
            max_requests=self.max_requests_per_window,
            window_minutes=self.request_window_minutes,
        )

        code = generate_numeric_code(self.code_length)
        now = datetime.now(UTC)
        otp_request = await self.repository.create_otp_request(
            identifier=identifier,
            channel=channel.value,
            purpose=purpose.value,
            code_hash=hash_otp_code(code),
            expires_at=now + timedelta(seconds=self.expiry_seconds),
            verified_at=None,
            attempt_count=0,
            max_attempts=self.max_verification_attempts,
            is_consumed=False,
            organization_id=organization_id,
            location_id=location_id,
        )

        await self._dispatch(otp_request, code=code, channel=channel)

        event = OtpRequested(
            otp_request_id=otp_request.id,
            identifier=identifier,
            channel=channel.value,
            purpose=purpose.value,
        )
        logger.info("otp_requested", extra=_event_extra(event))
        # Deliberately not written to audit_log_entries -- see module
        # docstring's audit-volume judgment call.
        return otp_request

    async def _dispatch(
        self, otp_request: OtpRequest, *, code: str, channel: OtpChannel
    ) -> None:
        minutes = max(self.expiry_seconds // 60, 1)
        message = (
            f"Your CloudGuest guest WiFi verification code is {code}. "
            f"It expires in {minutes} minute(s)."
        )
        if channel == OtpChannel.SMS:
            await self.sms_provider.send(otp_request.identifier, message)
        else:
            await self.email_provider.send(
                otp_request.identifier,
                "Your CloudGuest guest WiFi verification code",
                message,
            )

    # ========================================================================
    # Verify
    # ========================================================================

    async def verify_otp(
        self, *, identifier: str, code: str, purpose: OtpPurpose
    ) -> OtpRequest:
        identifier = identifier.strip()
        otp_request = await self.repository.get_latest_for_identifier(
            identifier, purpose.value
        )
        if otp_request is None:
            await self._record_failure(None, identifier, purpose, reason="not_found")
            raise OtpNotFoundError(identifier, purpose.value)

        if otp_request.is_consumed:
            await self._record_failure(
                otp_request, identifier, purpose, reason="already_consumed"
            )
            raise OtpAlreadyConsumedError()

        if otp_request.is_locked_out():
            await self._record_failure(
                otp_request, identifier, purpose, reason="attempts_exceeded"
            )
            raise OtpAttemptsExceededError()

        now = datetime.now(UTC)
        if otp_request.is_expired(now=now):
            await self._record_failure(
                otp_request, identifier, purpose, reason="expired"
            )
            raise OtpExpiredError()

        if not secrets.compare_digest(hash_otp_code(code), otp_request.code_hash):
            updated = await self.repository.update_otp_request(
                otp_request, {"attempt_count": otp_request.attempt_count + 1}
            )
            await self._record_failure(
                updated, identifier, purpose, reason="code_mismatch"
            )
            remaining = max(updated.max_attempts - updated.attempt_count, 0)
            raise OtpCodeMismatchError(attempts_remaining=remaining)

        verified = await self.repository.update_otp_request(
            otp_request, {"is_consumed": True, "verified_at": now}
        )
        event = OtpVerified(
            otp_request_id=verified.id, identifier=identifier, purpose=purpose.value
        )
        logger.info("otp_verified", extra=_event_extra(event))
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=None,
                action=AuditAction.OTP_VERIFIED.value,
                entity_type="otp_request",
                entity_id=verified.id,
                description=f"OTP verified (purpose={purpose.value})",
                event_metadata={"channel": verified.channel},
                organization_id=verified.organization_id,
                location_id=verified.location_id,
            )
        return verified

    async def _record_failure(
        self,
        otp_request: OtpRequest | None,
        identifier: str,
        purpose: OtpPurpose,
        *,
        reason: str,
    ) -> None:
        otp_request_id = otp_request.id if otp_request is not None else None
        event = OtpVerificationFailed(
            otp_request_id=otp_request_id,
            identifier=identifier,
            purpose=purpose.value,
            reason=reason,
        )
        logger.warning("otp_verification_failed", extra=_event_extra(event))
        if reason not in _AUDITED_FAILURE_REASONS or self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=None,
            action=AuditAction.OTP_VERIFICATION_FAILED.value,
            entity_type="otp_request",
            entity_id=otp_request_id,
            description=f"OTP verification failed (purpose={purpose.value}, "
            f"reason={reason})",
            event_metadata={"reason": reason},
            organization_id=otp_request.organization_id if otp_request else None,
            location_id=otp_request.location_id if otp_request else None,
        )


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.wireguard.service._event_extra``
    (``vars()`` doesn't work on slotted dataclasses)."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


__all__ = [
    "OtpService",
    "SmsProviderProtocol",
    "EmailProviderProtocol",
    "LoggingSmsProvider",
    "LoggingEmailProvider",
    "SmtpEmailProvider",
    "SesEmailProvider",
    "TwilioSmsProvider",
    "EmailProviderNotConfiguredError",
    "SmsProviderNotConfiguredError",
    "get_configured_email_provider",
    "get_configured_sms_provider",
    "AuditLogWriter",
    "OtpRateLimiter",
    "generate_numeric_code",
    "hash_otp_code",
]
