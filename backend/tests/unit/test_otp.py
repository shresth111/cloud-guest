"""Unit tests for the OTP domain (BE-010 Part 1): request/verify happy path
for both channels, expiry enforcement, per-code attempt lockout, per-
identifier request-rate-limit enforcement, consumed-OTP rejection (no
reuse), malformed-identifier rejection, provider-interface invocation (a
test double standing in for the honest ``LoggingSmsProvider``/
``LoggingEmailProvider`` default), and the audit-volume judgment call
(``OTP_VERIFIED``/adversarially-relevant ``OTP_VERIFICATION_FAILED`` reasons
are audited; routine failures and every ``otp_requested`` call are not).

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_wireguard.py``); ``asyncio_mode = "auto"`` runs async
tests directly. ``OtpService`` is exercised against small, hand-rolled
in-memory fakes for both its repository and Redis client (mirroring
``test_rbac.py``'s own ``FakeRedis`` -- there is no live Postgres/Redis in
this environment), plus a recording test double standing in for the
provider protocols.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.config import Settings
from app.database.constants import SortOrder
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.otp.constants import OtpChannel, OtpPurpose
from app.domains.otp.exceptions import (
    InvalidOtpIdentifierError,
    OtpAlreadyConsumedError,
    OtpAttemptsExceededError,
    OtpCodeMismatchError,
    OtpExpiredError,
    OtpNotFoundError,
    OtpRequestRateLimitExceededError,
)
from app.domains.otp.models import OtpRequest
from app.domains.otp.service import (
    LoggingWhatsAppProvider,
    OtpRateLimiter,
    OtpService,
    TwilioWhatsAppProvider,
    WhatsAppProviderNotConfiguredError,
    generate_numeric_code,
    get_configured_whatsapp_provider,
    hash_otp_code,
)
from app.domains.otp.validators import validate_identifier

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
class FakeOtpRepository:
    requests: dict[uuid.UUID, OtpRequest] = field(default_factory=dict)

    async def create_otp_request(self, **fields: object) -> OtpRequest:
        otp_request = OtpRequest(**_base_fields(**fields))
        self.requests[otp_request.id] = otp_request
        return otp_request

    async def get_by_id(
        self, otp_request_id: uuid.UUID, *, include_deleted: bool = False
    ) -> OtpRequest | None:
        otp_request = self.requests.get(otp_request_id)
        if otp_request is None:
            return None
        if otp_request.is_deleted and not include_deleted:
            return None
        return otp_request

    async def get_latest_for_identifier(
        self, identifier: str, purpose: str
    ) -> OtpRequest | None:
        matches = [
            r
            for r in self.requests.values()
            if r.identifier == identifier and r.purpose == purpose
        ]
        if not matches:
            return None
        return max(matches, key=lambda r: r.created_at)

    async def update_otp_request(
        self, otp_request: OtpRequest, data: dict[str, object]
    ) -> OtpRequest:
        for key, value in data.items():
            setattr(otp_request, key, value)
        otp_request.version += 1
        return otp_request

    async def list_requests(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[OtpRequest], PaginationMeta]:
        items = list(self.requests.values())
        for key, value in (filters or {}).items():
            items = [item for item in items if getattr(item, key) == value]
        items.sort(
            key=lambda item: getattr(item, sort_by),
            reverse=(sort_order == SortOrder.DESC),
        )
        params = PageParams(page=page, page_size=page_size)
        total = len(items)
        page_items = items[params.offset : params.offset + params.page_size]
        return page_items, PaginationMeta.from_total(params, total)


class FakeRedis:
    """Minimal async in-memory stand-in for ``redis.asyncio.Redis`` --
    mirrors ``tests/unit/test_rbac.py``'s own ``FakeRedis``, extended with
    ``incr``/``expire``/``ttl`` since ``OtpRateLimiter`` needs those, not
    just ``get``/``set``/``delete``."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._counts: dict[str, int] = {}
        self._ttls: dict[str, int] = {}

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = str(value)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self._counts.pop(key, None)
        self._ttls.pop(key, None)

    async def incr(self, key: str) -> int:
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self._ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class RecordingSmsProvider:
    sent: list[tuple[str, str]] = field(default_factory=list)

    async def send(self, phone_number: str, message: str) -> None:
        self.sent.append((phone_number, message))


@dataclass
class RecordingEmailProvider:
    sent: list[tuple[str, str, str]] = field(default_factory=list)

    async def send(self, email: str, subject: str, body: str) -> None:
        self.sent.append((email, subject, body))


@dataclass
class RecordingWhatsAppProvider:
    sent: list[tuple[str, str, str]] = field(default_factory=list)

    async def send(self, phone_number: str, *, code: str, message: str) -> None:
        self.sent.append((phone_number, code, message))


@dataclass
class Fixture:
    repository: FakeOtpRepository
    redis: FakeRedis
    audit_writer: FakeAuditLogWriter
    sms_provider: RecordingSmsProvider
    email_provider: RecordingEmailProvider
    whatsapp_provider: RecordingWhatsAppProvider
    service: OtpService


def make_service(
    *,
    max_verification_attempts: int = 5,
    max_requests_per_window: int = 5,
    request_window_minutes: int = 60,
    expiry_seconds: int = 300,
    code_length: int = 6,
) -> Fixture:
    repository = FakeOtpRepository()
    redis = FakeRedis()
    audit_writer = FakeAuditLogWriter()
    sms_provider = RecordingSmsProvider()
    email_provider = RecordingEmailProvider()
    whatsapp_provider = RecordingWhatsAppProvider()
    service = OtpService(
        repository,
        redis,
        sms_provider=sms_provider,
        email_provider=email_provider,
        whatsapp_provider=whatsapp_provider,
        audit_writer=audit_writer,
        code_length=code_length,
        expiry_seconds=expiry_seconds,
        max_verification_attempts=max_verification_attempts,
        max_requests_per_window=max_requests_per_window,
        request_window_minutes=request_window_minutes,
    )
    return Fixture(
        repository=repository,
        redis=redis,
        audit_writer=audit_writer,
        sms_provider=sms_provider,
        email_provider=email_provider,
        whatsapp_provider=whatsapp_provider,
        service=service,
    )


_CODE_IN_MESSAGE_RE = re.compile(r"code is (\d+)\.")


def _extract_code(sent: tuple) -> str:
    """Pulls the numeric code back out of a recorded provider message
    (``service.py``'s own ``_dispatch`` message template) -- tests need the
    plaintext code to exercise ``verify_otp``, mirroring how a real guest
    would read it off their phone/inbox."""
    text = sent[1] if len(sent) == 2 else sent[2]
    match = _CODE_IN_MESSAGE_RE.search(text)
    assert match is not None, f"could not find code in message: {text}"
    return match.group(1)


# ============================================================================
# Happy path: request + verify, both channels
# ============================================================================


class TestRequestAndVerifyHappyPath:
    async def test_sms_request_then_verify_succeeds(self) -> None:
        fx = make_service()
        otp_request = await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert otp_request.channel == OtpChannel.SMS.value
        assert otp_request.is_consumed is False
        assert len(fx.sms_provider.sent) == 1
        assert fx.sms_provider.sent[0][0] == "+15551234567"

        code = _extract_code(fx.sms_provider.sent[0])
        verified = await fx.service.verify_otp(
            identifier="+15551234567", code=code, purpose=OtpPurpose.GUEST_LOGIN
        )
        assert verified.is_consumed is True
        assert verified.verified_at is not None

    async def test_email_request_then_verify_succeeds(self) -> None:
        fx = make_service()
        await fx.service.request_otp(
            identifier="guest@example.com",
            channel=OtpChannel.EMAIL,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert len(fx.email_provider.sent) == 1
        assert fx.email_provider.sent[0][0] == "guest@example.com"
        assert len(fx.sms_provider.sent) == 0

        code = _extract_code(fx.email_provider.sent[0])
        verified = await fx.service.verify_otp(
            identifier="guest@example.com", code=code, purpose=OtpPurpose.GUEST_LOGIN
        )
        assert verified.is_consumed is True

    async def test_whatsapp_request_then_verify_succeeds(self) -> None:
        fx = make_service()
        otp_request = await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.WHATSAPP,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert otp_request.channel == OtpChannel.WHATSAPP.value
        assert len(fx.whatsapp_provider.sent) == 1
        assert fx.whatsapp_provider.sent[0][0] == "+15551234567"
        assert len(fx.sms_provider.sent) == 0
        assert len(fx.email_provider.sent) == 0

        code = _extract_code(fx.whatsapp_provider.sent[0])
        # The provider is also handed the raw code directly (unlike
        # SMS/email, which only ever get a composed message) -- see
        # WhatsAppProviderProtocol's own docstring for why. Confirm both
        # sources agree.
        assert fx.whatsapp_provider.sent[0][1] == code
        verified = await fx.service.verify_otp(
            identifier="+15551234567", code=code, purpose=OtpPurpose.GUEST_LOGIN
        )
        assert verified.is_consumed is True

    async def test_request_carries_organization_and_location_context(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        loc_id = uuid.uuid4()
        otp_request = await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=org_id,
            location_id=loc_id,
        )
        assert otp_request.organization_id == org_id
        assert otp_request.location_id == loc_id

    async def test_verify_audits_success(self) -> None:
        fx = make_service()
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        code = _extract_code(fx.sms_provider.sent[0])
        await fx.service.verify_otp(
            identifier="+15551234567", code=code, purpose=OtpPurpose.GUEST_LOGIN
        )
        assert len(fx.audit_writer.entries) == 1
        assert fx.audit_writer.entries[0]["action"] == "otp_verified"

    async def test_request_itself_is_never_audited(self) -> None:
        """See service.py's module docstring: OTP_REQUESTED exists as an
        AuditAction value but is deliberately never written -- high-volume,
        guest-facing, unauthenticated requests would flood the audit table."""
        fx = make_service()
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert fx.audit_writer.entries == []


# ============================================================================
# Expiry enforcement
# ============================================================================


class TestExpiry:
    async def test_expired_otp_raises_and_is_not_consumable(self) -> None:
        fx = make_service(expiry_seconds=30)
        otp_request = await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        code = _extract_code(fx.sms_provider.sent[0])
        # Force expiry without waiting for the real clock.
        otp_request.expires_at = datetime.now(UTC) - timedelta(seconds=1)

        with pytest.raises(OtpExpiredError):
            await fx.service.verify_otp(
                identifier="+15551234567", code=code, purpose=OtpPurpose.GUEST_LOGIN
            )
        assert otp_request.is_consumed is False

    async def test_expired_otp_failure_is_not_audited(self) -> None:
        """Expiry is routine guest-side churn, not an attack signal -- see
        service.py's audit-volume judgment call."""
        fx = make_service()
        otp_request = await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        otp_request.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        with pytest.raises(OtpExpiredError):
            await fx.service.verify_otp(
                identifier="+15551234567", code="000000", purpose=OtpPurpose.GUEST_LOGIN
            )
        assert fx.audit_writer.entries == []


# ============================================================================
# Max-attempts lockout (per-code brute-force protection)
# ============================================================================


class TestAttemptLockout:
    async def test_wrong_code_increments_attempt_count(self) -> None:
        fx = make_service(max_verification_attempts=5)
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        with pytest.raises(OtpCodeMismatchError) as exc_info:
            await fx.service.verify_otp(
                identifier="+15551234567",
                code="000000",
                purpose=OtpPurpose.GUEST_LOGIN,
            )
        assert exc_info.value.data["attempts_remaining"] == 4
        otp_request = next(iter(fx.repository.requests.values()))
        assert otp_request.attempt_count == 1

    async def test_exceeding_max_attempts_locks_out_even_correct_code(self) -> None:
        fx = make_service(max_verification_attempts=2)
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        code = _extract_code(fx.sms_provider.sent[0])

        for _ in range(2):
            with pytest.raises(OtpCodeMismatchError):
                await fx.service.verify_otp(
                    identifier="+15551234567",
                    code="000000",
                    purpose=OtpPurpose.GUEST_LOGIN,
                )

        with pytest.raises(OtpAttemptsExceededError):
            await fx.service.verify_otp(
                identifier="+15551234567", code=code, purpose=OtpPurpose.GUEST_LOGIN
            )

    async def test_code_mismatch_and_attempts_exceeded_are_audited(self) -> None:
        fx = make_service(max_verification_attempts=1)
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        with pytest.raises(OtpCodeMismatchError):
            await fx.service.verify_otp(
                identifier="+15551234567",
                code="000000",
                purpose=OtpPurpose.GUEST_LOGIN,
            )
        with pytest.raises(OtpAttemptsExceededError):
            await fx.service.verify_otp(
                identifier="+15551234567",
                code="111111",
                purpose=OtpPurpose.GUEST_LOGIN,
            )
        actions = [entry["action"] for entry in fx.audit_writer.entries]
        assert actions == ["otp_verification_failed", "otp_verification_failed"]


# ============================================================================
# Request rate limiting (per-identifier spam protection)
# ============================================================================


class TestRequestRateLimit:
    async def test_exceeding_request_rate_limit_raises(self) -> None:
        fx = make_service(max_requests_per_window=3)
        for _ in range(3):
            await fx.service.request_otp(
                identifier="+15551234567",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=None,
            )
        with pytest.raises(OtpRequestRateLimitExceededError):
            await fx.service.request_otp(
                identifier="+15551234567",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=None,
            )
        # Only the first 3 calls actually dispatched a message.
        assert len(fx.sms_provider.sent) == 3

    async def test_rate_limit_is_scoped_per_identifier(self) -> None:
        fx = make_service(max_requests_per_window=1)
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        # A different identifier is unaffected by the first one's limit.
        await fx.service.request_otp(
            identifier="+15559876543",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert len(fx.sms_provider.sent) == 2

    async def test_rate_limiter_direct_raises_with_retry_after(self) -> None:
        redis = FakeRedis()
        await OtpRateLimiter.check_and_increment(
            redis, "+15551234567", max_requests=1, window_minutes=10
        )
        with pytest.raises(OtpRequestRateLimitExceededError) as exc_info:
            await OtpRateLimiter.check_and_increment(
                redis, "+15551234567", max_requests=1, window_minutes=10
            )
        assert exc_info.value.retry_after_seconds == 600


# ============================================================================
# Consumed-OTP rejection (no reuse)
# ============================================================================


class TestConsumedRejection:
    async def test_verified_otp_cannot_be_reused(self) -> None:
        fx = make_service()
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        code = _extract_code(fx.sms_provider.sent[0])
        await fx.service.verify_otp(
            identifier="+15551234567", code=code, purpose=OtpPurpose.GUEST_LOGIN
        )
        with pytest.raises(OtpAlreadyConsumedError):
            await fx.service.verify_otp(
                identifier="+15551234567", code=code, purpose=OtpPurpose.GUEST_LOGIN
            )

    async def test_no_otp_ever_requested_raises_not_found(self) -> None:
        fx = make_service()
        with pytest.raises(OtpNotFoundError):
            await fx.service.verify_otp(
                identifier="+15551234567",
                code="123456",
                purpose=OtpPurpose.GUEST_LOGIN,
            )


# ============================================================================
# Malformed identifier rejection
# ============================================================================


class TestIdentifierValidation:
    def test_valid_phone_number_accepted(self) -> None:
        validate_identifier("+15551234567", OtpChannel.SMS)

    def test_malformed_phone_number_rejected(self) -> None:
        with pytest.raises(InvalidOtpIdentifierError):
            validate_identifier("not-a-phone", OtpChannel.SMS)

    def test_valid_email_accepted(self) -> None:
        validate_identifier("guest@example.com", OtpChannel.EMAIL)

    def test_malformed_email_rejected(self) -> None:
        with pytest.raises(InvalidOtpIdentifierError):
            validate_identifier("not-an-email", OtpChannel.EMAIL)

    def test_valid_whatsapp_phone_number_accepted(self) -> None:
        """WHATSAPP shares SMS's phone-number identifier shape -- see
        validators.validate_identifier's own docstring."""
        validate_identifier("+15551234567", OtpChannel.WHATSAPP)

    def test_malformed_whatsapp_identifier_rejected(self) -> None:
        with pytest.raises(InvalidOtpIdentifierError):
            validate_identifier("not-a-phone", OtpChannel.WHATSAPP)

    async def test_service_rejects_malformed_identifier_before_any_side_effect(
        self,
    ) -> None:
        fx = make_service()
        with pytest.raises(InvalidOtpIdentifierError):
            await fx.service.request_otp(
                identifier="not-a-phone",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=None,
            )
        assert fx.repository.requests == {}
        assert fx.sms_provider.sent == []


# ============================================================================
# Provider interface invocation
# ============================================================================


class TestProviderInvocation:
    async def test_sms_channel_only_invokes_sms_provider(self) -> None:
        fx = make_service()
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert len(fx.sms_provider.sent) == 1
        assert len(fx.email_provider.sent) == 0

    async def test_email_channel_only_invokes_email_provider(self) -> None:
        fx = make_service()
        await fx.service.request_otp(
            identifier="guest@example.com",
            channel=OtpChannel.EMAIL,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert len(fx.email_provider.sent) == 1
        assert len(fx.sms_provider.sent) == 0

    async def test_whatsapp_channel_only_invokes_whatsapp_provider(self) -> None:
        fx = make_service()
        await fx.service.request_otp(
            identifier="+15551234567",
            channel=OtpChannel.WHATSAPP,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert len(fx.whatsapp_provider.sent) == 1
        assert len(fx.sms_provider.sent) == 0
        assert len(fx.email_provider.sent) == 0

    async def test_default_providers_are_the_logging_providers(self) -> None:
        """Without an explicit provider override, OtpService falls back to
        the honest LoggingSmsProvider/LoggingEmailProvider/
        LoggingWhatsAppProvider default -- see service.py's module
        docstring for why no real provider exists."""
        from app.domains.otp.service import (
            LoggingEmailProvider,
            LoggingSmsProvider,
            LoggingWhatsAppProvider,
        )

        service = OtpService(FakeOtpRepository(), FakeRedis())
        assert isinstance(service.sms_provider, LoggingSmsProvider)
        assert isinstance(service.email_provider, LoggingEmailProvider)
        assert isinstance(service.whatsapp_provider, LoggingWhatsAppProvider)

        # Exercising the logging providers directly should not raise -- they
        # only log, never call a real network API.
        await service.sms_provider.send("+15551234567", "hello")
        await service.email_provider.send("guest@example.com", "subject", "body")
        await service.whatsapp_provider.send(
            "+15551234567", code="042817", message="hello"
        )


# ============================================================================
# Code generation / hashing helpers
# ============================================================================


class TestCodeGenerationAndHashing:
    def test_generate_numeric_code_has_requested_length(self) -> None:
        code = generate_numeric_code(6)
        assert len(code) == 6
        assert code.isdigit()

    def test_generate_numeric_code_is_random(self) -> None:
        codes = {generate_numeric_code(6) for _ in range(20)}
        assert len(codes) > 1

    def test_hash_is_deterministic_and_never_equals_the_code(self) -> None:
        code = "042817"
        digest = hash_otp_code(code)
        assert digest == hash_otp_code(code)
        assert digest != code
        assert len(digest) == 64  # SHA-256 hex digest length


# ============================================================================
# Real WhatsApp provider selection + Twilio Content API call shape
#
# Mirrors test_billing_payments_webhooks.py's TestGatewayNotConfigured
# pattern: real classes, genuinely unconfigured Settings (the honest,
# permanent state of this sandbox), no network attempt when unconfigured --
# and, for the configured case, a real outbound HTTP call asserted against
# httpx.AsyncClient.post rather than trusting the implementation blindly.
# ============================================================================


class TestWhatsAppProviderSelection:
    def test_default_is_logging_provider(self) -> None:
        settings = Settings()
        provider = get_configured_whatsapp_provider(settings)
        assert isinstance(provider, LoggingWhatsAppProvider)

    def test_twilio_selected_but_unconfigured_raises(self) -> None:
        """whatsapp_delivery_provider='twilio' with no credentials at all
        is a real error, not a silent fallback -- same posture
        get_configured_sms_provider/get_configured_email_provider already
        establish for their own 'twilio'/'smtp'/'ses' selections."""
        settings = Settings(whatsapp_delivery_provider="twilio")
        with pytest.raises(WhatsAppProviderNotConfiguredError):
            get_configured_whatsapp_provider(settings)

    def test_twilio_selected_with_sms_creds_but_no_whatsapp_sender_raises(self) -> None:
        """Having twilio_account_sid/twilio_auth_token configured for SMS
        is not sufficient on its own -- a real WhatsApp send also needs its
        own sender number and an approved Content Template SID (see
        TwilioWhatsAppProvider's own docstring)."""
        settings = Settings(
            whatsapp_delivery_provider="twilio",
            twilio_account_sid="ACfake",
            twilio_auth_token="tokenfake",
        )
        with pytest.raises(WhatsAppProviderNotConfiguredError):
            get_configured_whatsapp_provider(settings)

    def test_twilio_fully_configured_returns_real_provider(self) -> None:
        settings = Settings(
            whatsapp_delivery_provider="twilio",
            twilio_account_sid="ACfake",
            twilio_auth_token="tokenfake",
            whatsapp_twilio_from_number="+14155238886",
            whatsapp_twilio_content_sid="HXfake",
        )
        provider = get_configured_whatsapp_provider(settings)
        assert isinstance(provider, TwilioWhatsAppProvider)
        assert provider.account_sid == "ACfake"
        assert provider.from_number == "+14155238886"
        assert provider.content_sid == "HXfake"
        assert provider.content_variable_key == "1"


class TestTwilioWhatsAppProvider:
    """Asserts the real outbound HTTP call shape -- ``httpx.AsyncClient``
    is monkeypatched at the method level (no live network in this sandbox),
    mirroring test_monitoring_alerts.py's own httpx.MockTransport
    precedent for asserting a real provider's outbound request shape
    without hitting the network."""

    async def test_send_posts_content_template_not_freeform_body(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        async def fake_post(self, url, *, auth=None, data=None):  # noqa: ANN001
            captured["url"] = url
            captured["auth"] = auth
            captured["data"] = data
            return httpx.Response(201, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        provider = TwilioWhatsAppProvider(
            account_sid="ACfake",
            auth_token="tokenfake",
            from_number="+14155238886",
            content_sid="HXfake",
        )
        await provider.send("+15551234567", code="042817", message="ignored")

        assert captured["url"] == (
            "https://api.twilio.com/2010-04-01/Accounts/ACfake/Messages.json"
        )
        assert captured["auth"] == ("ACfake", "tokenfake")
        data = captured["data"]
        assert data["From"] == "whatsapp:+14155238886"
        assert data["To"] == "whatsapp:+15551234567"
        # The real OTP code must reach Twilio via ContentVariables (the
        # approved template's {{1}} placeholder), never as a freeform Body
        # -- see the provider's own docstring for why WhatsApp rejects a
        # business-initiated freeform message.
        assert data["ContentSid"] == "HXfake"
        assert json.loads(data["ContentVariables"]) == {"1": "042817"}
        assert "Body" not in data

    async def test_send_raises_on_non_2xx_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_post(self, url, *, auth=None, data=None):  # noqa: ANN001
            return httpx.Response(400, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        provider = TwilioWhatsAppProvider(
            account_sid="ACfake",
            auth_token="tokenfake",
            from_number="+14155238886",
            content_sid="HXfake",
        )
        with pytest.raises(httpx.HTTPStatusError):
            await provider.send("+15551234567", code="042817", message="ignored")
