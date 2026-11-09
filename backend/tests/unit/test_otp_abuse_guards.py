"""QA 2026-11-06: OTP abuse guards.

* M1 -- the attempt cap holds under parallel guesses, and a code is
  single-use under concurrency.
* M3 -- the public routes refuse ``account_data_masking``.
* H4 -- ``/otp/request`` needs a venue; per-venue and platform daily caps.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.domains.otp.constants import OtpChannel, OtpPurpose
from app.domains.otp.exceptions import (
    OtpAlreadyConsumedError,
    OtpAttemptsExceededError,
    OtpCodeMismatchError,
    OtpDailyCapReachedError,
)
from tests.unit.test_otp import (
    _extract_code,
    _otp_venue_gate_app,
    _post_otp_request,
    _venue_config,
    make_service,
)

_PHONE = "+15551234567"


async def _issue(fx, location_id: uuid.UUID | None = None) -> str:  # noqa: ANN001
    await fx.service.request_otp(
        identifier=_PHONE,
        channel=OtpChannel.SMS,
        purpose=OtpPurpose.GUEST_LOGIN,
        organization_id=None,
        location_id=location_id,
    )
    return _extract_code(fx.sms_provider.sent[-1])


def _wrong(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"


class TestAttemptCapUnderConcurrency:
    async def test_parallel_wrong_guesses_share_the_cap(self) -> None:
        fx = make_service(max_verification_attempts=5)
        code = await _issue(fx)
        guesses = [_wrong(code)] * 20

        results = await asyncio.gather(
            *[
                fx.service.verify_otp(
                    identifier=_PHONE, code=g, purpose=OtpPurpose.GUEST_LOGIN
                )
                for g in guesses
            ],
            return_exceptions=True,
        )
        mismatches = [r for r in results if isinstance(r, OtpCodeMismatchError)]
        locked = [r for r in results if isinstance(r, OtpAttemptsExceededError)]
        assert len(mismatches) == 5
        assert len(locked) == 15
        row = next(iter(fx.repository.requests.values()))
        assert row.attempt_count == 5

    async def test_the_right_code_after_the_cap_is_refused(self) -> None:
        fx = make_service(max_verification_attempts=5)
        code = await _issue(fx)
        for _ in range(5):
            with pytest.raises(OtpCodeMismatchError):
                await fx.service.verify_otp(
                    identifier=_PHONE, code=_wrong(code), purpose=OtpPurpose.GUEST_LOGIN
                )
        with pytest.raises(OtpAttemptsExceededError):
            await fx.service.verify_otp(
                identifier=_PHONE, code=code, purpose=OtpPurpose.GUEST_LOGIN
            )

    async def test_four_misses_then_the_right_code_still_works(self) -> None:
        fx = make_service(max_verification_attempts=5)
        code = await _issue(fx)
        for _ in range(4):
            with pytest.raises(OtpCodeMismatchError):
                await fx.service.verify_otp(
                    identifier=_PHONE, code=_wrong(code), purpose=OtpPurpose.GUEST_LOGIN
                )
        verified = await fx.service.verify_otp(
            identifier=_PHONE, code=code, purpose=OtpPurpose.GUEST_LOGIN
        )
        assert verified.is_consumed is True


class TestSingleUseUnderConcurrency:
    async def test_two_racing_correct_verifies_one_wins(self) -> None:
        fx = make_service()
        code = await _issue(fx)
        real_consume = fx.repository.consume
        both_checked = asyncio.Event()
        arrivals = 0

        async def gated(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            nonlocal arrivals
            arrivals += 1
            if arrivals == 2:
                both_checked.set()
            else:
                await both_checked.wait()
            return await real_consume(*args, **kwargs)

        fx.repository.consume = gated
        results = await asyncio.gather(
            *[
                fx.service.verify_otp(
                    identifier=_PHONE, code=code, purpose=OtpPurpose.GUEST_LOGIN
                )
                for _ in range(2)
            ],
            return_exceptions=True,
        )
        assert sum(not isinstance(r, Exception) for r in results) == 1
        assert sum(isinstance(r, OtpAlreadyConsumedError) for r in results) == 1


class TestPublicRoutesRefuseTheMaskingPurpose:
    async def test_request(self) -> None:
        fx = make_service()
        app = _otp_venue_gate_app(fx, config=_venue_config())
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/otp/request",
                json={
                    "identifier": "owner@example.com",
                    "channel": "email",
                    "purpose": OtpPurpose.ACCOUNT_DATA_MASKING.value,
                    "location_id": str(uuid.uuid4()),
                },
            )
        assert resp.status_code == 400, resp.text
        assert "OTP_PURPOSE_NOT_ALLOWED" in resp.text
        assert fx.repository.requests == {}
        assert fx.email_provider.sent == []

    async def test_verify(self) -> None:
        fx = make_service()
        app = _otp_venue_gate_app(fx, config=_venue_config())
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/otp/verify",
                json={
                    "identifier": "owner@example.com",
                    "code": "123456",
                    "purpose": OtpPurpose.ACCOUNT_DATA_MASKING.value,
                },
            )
        assert resp.status_code == 400, resp.text
        assert "OTP_PURPOSE_NOT_ALLOWED" in resp.text


class TestOtpRequestNeedsAVenue:
    async def test_no_venue_is_refused_before_any_send(self) -> None:
        fx = make_service()
        app = _otp_venue_gate_app(fx, config=_venue_config())
        resp = await _post_otp_request(app, channel=OtpChannel.SMS, identifier=_PHONE)
        assert resp.status_code == 400, resp.text
        assert "OTP_VENUE_REQUIRED" in resp.text
        assert fx.sms_provider.sent == []

    async def test_a_named_venue_is_served(self) -> None:
        fx = make_service()
        app = _otp_venue_gate_app(fx, config=_venue_config())
        resp = await _post_otp_request(
            app, channel=OtpChannel.SMS, identifier=_PHONE, location_id=uuid.uuid4()
        )
        assert resp.status_code == 201, resp.text


class TestDailyCaps:
    async def test_per_location_cap(self) -> None:
        fx = make_service(max_requests_per_window=100)
        fx.service.daily_cap_per_location = 3
        venue, other = uuid.uuid4(), uuid.uuid4()
        for i in range(3):
            await fx.service.request_otp(
                identifier=f"+1555123456{i}",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=venue,
            )
        with pytest.raises(OtpDailyCapReachedError) as exc:
            await fx.service.request_otp(
                identifier="+15551234569",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=venue,
            )
        assert exc.value.status_code == 429
        assert exc.value.data["scope"] == "location"
        assert len(fx.sms_provider.sent) == 3
        # Another venue is unaffected.
        await fx.service.request_otp(
            identifier="+15551234569",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=other,
        )

    async def test_log_mode_counts_but_still_sends(self) -> None:
        """``otp_daily_cap_mode=log`` (the first-deploy default) must never
        refuse a guest: it only records that the cap was passed."""
        fx = make_service(max_requests_per_window=100)
        fx.service.daily_cap_per_location = 1
        fx.service.daily_cap_enforce = False
        venue = uuid.uuid4()
        for i in range(3):
            await fx.service.request_otp(
                identifier=f"+1555123456{i}",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=venue,
            )
        assert len(fx.sms_provider.sent) == 3

    async def test_platform_cap(self) -> None:
        fx = make_service(max_requests_per_window=100)
        fx.service.daily_cap_platform = 2
        for i in range(2):
            await fx.service.request_otp(
                identifier=f"+1555123456{i}",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=uuid.uuid4(),
            )
        with pytest.raises(OtpDailyCapReachedError) as exc:
            await fx.service.request_otp(
                identifier="+15551234569",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=uuid.uuid4(),
            )
        assert exc.value.data["scope"] == "platform"

    async def test_zero_disables(self) -> None:
        fx = make_service(max_requests_per_window=100)
        assert fx.service.daily_cap_platform == 0
        for i in range(5):
            await _issue_unique(fx, i)


async def _issue_unique(fx, i: int) -> None:  # noqa: ANN001
    await fx.service.request_otp(
        identifier=f"+1555123456{i}",
        channel=OtpChannel.SMS,
        purpose=OtpPurpose.GUEST_LOGIN,
        organization_id=None,
        location_id=uuid.uuid4(),
    )


def test_settings_defaults_are_on() -> None:
    from app.core.config import Settings

    fields = Settings.model_fields
    assert fields["otp_daily_cap_per_location"].default > 0
    assert fields["otp_daily_cap_platform"].default > 0
    # Counted from the first deploy, enforced only once sized against real
    # peaks (no production volume figures were on hand).
    assert fields["otp_daily_cap_mode"].default == "log"


class TestLoggingWhatsAppProviderNeverLogsALiveCode:
    """QA 2026-11-06 L6."""

    async def test_outside_local_the_code_is_not_logged(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import logging

        from app.core.config import get_settings
        from app.domains.otp.service import LoggingWhatsAppProvider

        monkeypatch.setattr(get_settings(), "environment", "production")
        caplog.set_level(logging.INFO, logger="app.domains.otp.service")
        await LoggingWhatsAppProvider().send(
            "+15551234567", code="042817", message="Your code is 042817."
        )
        [record] = [r for r in caplog.records if r.message == "otp_whatsapp_would_send"]
        assert "042817" not in str(record.__dict__)

    async def test_locally_it_still_shows_the_code(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import logging

        from app.core.config import get_settings
        from app.domains.otp.service import LoggingWhatsAppProvider

        monkeypatch.setattr(get_settings(), "environment", "local")
        caplog.set_level(logging.INFO, logger="app.domains.otp.service")
        await LoggingWhatsAppProvider().send(
            "+15551234567", code="042817", message="Your code is 042817."
        )
        [record] = [r for r in caplog.records if r.message == "otp_whatsapp_would_send"]
        assert record.code == "042817"
