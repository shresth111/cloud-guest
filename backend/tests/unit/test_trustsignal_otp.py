"""TrustSignal SMS for guest login codes, and the per-venue "no fallback" mode.

Adapter (HTTP mocked; request shape from https://postman.trustsignal.io/,
SMS > Send SMS > Send SMS (POST) / SMS with Country Code / Fetch All
Template / SMS Credits):

* ``POST https://sms.trustsignal.io/v1/sms?api_key=<key>`` with JSON
  ``{sender_id, to: [<10-digit int>], route, message, template_id}`` for an
  Indian number; ``/v1/sms/countrycode`` with ``to: ["+<E.164>"]`` otherwise;
* the message is the venue's approved DLT text with the code in ``{#var#}``;
* success is ``success: true`` (the ``transaction_id`` is the message id);
  ``errors[0].code/codeMsg`` becomes the vendor code on the error, and
  ``101``/401/403 are credential errors;
* the template text must have one code slot, be GSM-7 and fit three parts;
* preflight checks the template, its sender and the route's credit.

No fallback (``fallback_to_platform_default = false``, Master only): a
failed, slow, or breaker-tripped venue send raises ``OtpVenueSendFailedError``
to the guest and Wyfy's own SMS provider is never called. With the flag at
its default (true) #419's fallback is unchanged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

import httpx
import pytest

from app.domains.guest_messaging import service as messaging_service
from app.domains.guest_messaging.adapters import (
    REGISTRY,
    TrustSignalOtpAdapter,
    gsm7_septets,
)
from app.domains.guest_messaging.exceptions import ProviderConfigInvalidError
from app.domains.guest_messaging.registry import (
    AdapterContext,
    ConfigError,
    OtpMessage,
    ProviderSendError,
    normalize_config,
)
from app.domains.otp.constants import OtpChannel, OtpPurpose
from app.domains.otp.exceptions import OtpVenueSendFailedError
from tests.unit.test_guest_login_messaging import (
    MASTER,
    ORG_A,
    ORG_B,
    VENUE,
    _otp_with_dispatcher,
    _world,
)

API_KEY = "ts-test-key-not-real-0000001"
TEMPLATE = (
    "Enter {#var#} to complete your sign-up for Kenangan Coffee App. "
    "Enjoy using our app!"
)
CONFIG = {
    "api_key": API_KEY,
    "sender_id": "KENCOF",
    "route": "otp",
    "template_id": "1407173226737049269",
    "dlt_entity_id": "1401559060000072247",
    "message_template": TEMPLATE,
}
CODE = "482913"
EXPECTED_TEXT = (
    "Enter 482913 to complete your sign-up for Kenangan Coffee App. "
    "Enjoy using our app!"
)
OK = {
    "message": "Request process successfully",
    "results": [
        {
            "phone": 9876543210,
            "transaction_id": "3309344386358917185547944",
            "sms_cost": 1,
        }
    ],
    "success": True,
}
TEMPLATES = {
    "limit": 50,
    "page": 1,
    "success": True,
    "templates": [
        {
            "id": "rrT1l3a4g",
            "status": "approved",
            "headers": ["KENCOF"],
            "name": "wifi_otp",
            "content": TEMPLATE,
            "dlt_entity_id": "1407173226737049269",
            "isunicode": False,
        }
    ],
    "totalrecords": 1,
}
CREDITS = {
    "credits": {
        "otp": {"remaining": 925, "total": 1001, "used": 76},
        "transactional": {"remaining": 0, "total": 10, "used": 10},
    },
    "success": True,
}


def _error(code: str, name: str, message: str) -> dict:
    return {
        "errors": [{"code": code, "codeMsg": name, "message": message}],
        "success": False,
    }


class TrustSignal:
    """MockTransport for sms.trustsignal.io."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.send: tuple[int, dict] = (200, OK)
        self.templates: tuple[int, dict] = (200, TEMPLATES)
        self.credits: tuple[int, dict] = (200, CREDITS)
        self.delay = 0.0

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        path = request.url.path
        if path == "/v1/api/templates":
            status, body = self.templates
        elif path == "/v1/accounts/credits":
            status, body = self.credits
        else:
            status, body = self.send
        return httpx.Response(status, json=body)

    @property
    def sends(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == "POST"]


def _adapter(ts: TrustSignal, **overrides) -> TrustSignalOtpAdapter:  # noqa: ANN003
    spec = REGISTRY.get("sms", "trustsignal")
    config = normalize_config(spec, {**CONFIG, **overrides})
    return TrustSignalOtpAdapter(
        config, AdapterContext(transport=httpx.MockTransport(ts))
    )


# ============================================================================
# Adapter
# ============================================================================


class TestRegistry:
    def test_listed_with_its_fields_and_the_key_is_secret(self) -> None:
        spec = REGISTRY.get("sms", "trustsignal")
        assert spec is not None and spec.display_name == "TrustSignal"
        assert spec.secret_fields == ("api_key",)
        names = [f["name"] for f in spec.as_schema()["fields"]]
        assert names == [
            "api_key",
            "sender_id",
            "route",
            "template_id",
            "dlt_entity_id",
            "message_template",
        ]
        assert spec.field("route").options == ("otp", "transactional")
        assert spec.field("route").default == "otp"
        assert spec.field("dlt_entity_id").required is False

    def test_kenangan_values_are_valid_and_nothing_is_hard_coded(self) -> None:
        spec = REGISTRY.get("sms", "trustsignal")
        assert normalize_config(spec, CONFIG) == CONFIG
        other = {
            **CONFIG,
            "sender_id": "CAFEWF",
            "template_id": "1107000000000001",
            "message_template": "{#var#} is your Wi-Fi code for Cafe X.",
        }
        assert normalize_config(spec, other)["sender_id"] == "CAFEWF"

    @pytest.mark.parametrize(
        ("template", "error"),
        [
            ("Your code is ready", "must contain {#var#}"),
            ("Enter {#var#} or {#var#}", "exactly one"),
            ("Enter {#var#} — thanks", "Unicode"),
            ("{#var#} " + "x" * 460, "too long"),
        ],
    )
    def test_template_text_checks(self, template: str, error: str) -> None:
        spec = REGISTRY.get("sms", "trustsignal")
        with pytest.raises(ConfigError) as info:
            normalize_config(spec, {**CONFIG, "message_template": template})
        assert error in info.value.fields["message_template"]

    def test_gsm7_counting(self) -> None:
        assert gsm7_septets("Enter 1 now") == 11
        assert gsm7_septets("[]") == 4  # extension table: 2 septets each
        assert gsm7_septets("नमस्ते") is None


class TestSend:
    async def test_exact_request_for_an_indian_number(self) -> None:
        ts = TrustSignal()
        result = await _adapter(ts).send_otp(OtpMessage("+919876543210", CODE, "x"))
        assert result.provider == "trustsignal"
        assert result.message_id == "3309344386358917185547944"
        (request,) = ts.requests
        assert request.method == "POST"
        assert request.url.scheme == "https"
        assert request.url.host == "sms.trustsignal.io"
        assert request.url.path == "/v1/sms"
        assert dict(request.url.params) == {"api_key": API_KEY}
        assert request.headers["content-type"] == "application/json"
        assert json.loads(request.content) == {
            "sender_id": "KENCOF",
            "to": [9876543210],
            "route": "otp",
            "message": EXPECTED_TEXT,
            "template_id": "1407173226737049269",
        }

    async def test_foreign_number_uses_the_country_code_endpoint(self) -> None:
        ts = TrustSignal()
        await _adapter(ts, route="transactional").send_otp(
            OtpMessage("+6591234567", CODE, "x")
        )
        request = ts.requests[-1]
        body = json.loads(request.content)
        assert request.url.path == "/v1/sms/countrycode"
        assert body["to"] == ["+6591234567"]
        assert body["route"] == "transactional"

    async def test_documented_error_carries_the_vendor_code(self) -> None:
        ts = TrustSignal()
        ts.send = (400, _error("114", "INVALID_SENDERID", "Invalid senderid"))
        with pytest.raises(ProviderSendError) as info:
            await _adapter(ts).send_otp(OtpMessage("+919876543210", CODE, "x"))
        assert info.value.code == "sender_rejected"
        assert info.value.vendor_code == "114/INVALID_SENDERID"
        assert info.value.auth is False
        assert API_KEY not in str(info.value)

    @pytest.mark.parametrize(
        ("status", "body"),
        [
            (400, _error("101", "API_KEY_MISSING", "API Key is required")),
            (401, {"success": False}),
        ],
    )
    async def test_credential_errors_are_auth(self, status: int, body: dict) -> None:
        ts = TrustSignal()
        ts.send = (status, body)
        with pytest.raises(ProviderSendError) as info:
            await _adapter(ts).send_otp(OtpMessage("+919876543210", CODE, "x"))
        assert info.value.auth is True
        assert info.value.code == "provider_auth_failed"

    async def test_200_without_success_true_is_a_failure(self) -> None:
        ts = TrustSignal()
        ts.send = (200, {"success": False, "message": "queued?"})
        with pytest.raises(ProviderSendError) as info:
            await _adapter(ts).send_otp(OtpMessage("+919876543210", CODE, "x"))
        assert info.value.vendor_code == "http_200"

    async def test_timeout_is_a_provider_timeout(self) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("slow", request=request)

        spec = REGISTRY.get("sms", "trustsignal")
        adapter = TrustSignalOtpAdapter(
            normalize_config(spec, CONFIG),
            AdapterContext(transport=httpx.MockTransport(boom)),
        )
        with pytest.raises(ProviderSendError) as info:
            await adapter.send_otp(OtpMessage("+919876543210", CODE, "x"))
        assert info.value.code == "provider_timeout"


class TestPreflight:
    async def test_template_sender_text_and_credit_are_checked(self) -> None:
        ts = TrustSignal()
        details = await _adapter(ts).preflight()
        assert details == [
            "Template 1407173226737049269 is approved on TrustSignal for KENCOF "
            "with the same text",
            "925 'otp' route credits left",
        ]
        listing = ts.requests[0]
        assert listing.method == "GET" and listing.url.path == "/v1/api/templates"
        assert listing.url.params["status"] == "approved"
        assert listing.url.params["api_key"] == API_KEY
        assert ts.requests[1].url.path == "/v1/accounts/credits"
        assert ts.sends == []  # preflight never sends an SMS

    async def test_text_that_differs_from_trustsignal_stops_verification(
        self,
    ) -> None:
        ts = TrustSignal()
        with pytest.raises(ProviderSendError) as info:
            await _adapter(
                ts, message_template="Enter {#var#} to sign in to Kenangan WiFi."
            ).preflight()
        assert info.value.code == "template_text_mismatch"

    async def test_unknown_template_and_wrong_sender_stop_verification(self) -> None:
        ts = TrustSignal()
        with pytest.raises(ProviderSendError) as info:
            await _adapter(ts, template_id="1407000000000000000").preflight()
        assert info.value.code == "template_not_found"
        with pytest.raises(ProviderSendError) as info:
            await _adapter(ts, sender_id="OTHERS").preflight()
        assert info.value.code == "template_sender_mismatch"

    async def test_an_empty_route_balance_stops_verification(self) -> None:
        ts = TrustSignal()
        with pytest.raises(ProviderSendError) as info:
            await _adapter(ts, route="transactional").preflight()
        assert info.value.code == "no_credits"

    async def test_an_unexpected_lookup_answer_is_reported_not_fatal(self) -> None:
        ts = TrustSignal()
        ts.templates = (404, {})
        ts.credits = (500, {})
        details = await _adapter(ts).preflight()
        assert details[0].startswith("Could not list templates on TrustSignal")
        assert details[1].startswith("Could not read the TrustSignal balance")

    async def test_a_bad_key_stops_verification(self) -> None:
        ts = TrustSignal()
        ts.templates = (400, _error("101", "API_KEY_MISSING", "API Key is required"))
        with pytest.raises(ProviderSendError) as info:
            await _adapter(ts).preflight()
        assert info.value.auth is True


# ============================================================================
# Per-venue: platform fallback on (default) and off (Kenangan)
# ============================================================================


def _ts_world():
    w = _world(allowed={ORG_A, ORG_B})
    ts = TrustSignal()
    w.service.adapter_context = AdapterContext(transport=httpx.MockTransport(ts))
    w.ts = ts
    return w


async def _setup(w, *, fallback: bool | None) -> None:  # noqa: ANN001
    await w.service.put_provider(
        ORG_A,
        "sms",
        MASTER,
        provider_type="trustsignal",
        config=CONFIG,
        enabled=None,
        fallback_to_platform_default=fallback,
    )
    started = await w.service.start_verification(
        ORG_A, "sms", MASTER, to="+91 98765 43210"
    )
    assert [c["name"] for c in started["checks"]] == ["template", "template", "send"]
    await w.service.confirm_verification(ORG_A, "sms", MASTER, code="246810")


async def _guest_code(fx, org=ORG_A):  # noqa: ANN001
    return await fx.service.request_otp(
        identifier="9876543210",
        channel=OtpChannel.SMS,
        purpose=OtpPurpose.GUEST_LOGIN,
        organization_id=org,
        location_id=None,
    )


class TestFallbackOn:
    async def test_verified_trustsignal_sends_the_login_code(self) -> None:
        w = _ts_world()
        await _setup(w, fallback=None)
        fx = await _otp_with_dispatcher(w)
        await _guest_code(fx)
        assert fx.sms_provider.sent == []
        verify, login = w.ts.sends
        assert json.loads(verify.content)["message"].startswith("Enter 246810 ")
        message = json.loads(login.content)["message"]
        assert message.startswith("Enter ") and message.endswith("Enjoy using our app!")

    async def test_default_keeps_419_fallback(self) -> None:
        w = _ts_world()
        await _setup(w, fallback=None)
        w.ts.send = (400, _error("114", "INVALID_SENDERID", "Invalid senderid"))
        fx = await _otp_with_dispatcher(w)
        await _guest_code(fx)
        assert len(fx.sms_provider.sent) == 1
        row = w.repo.rows[(ORG_A, "sms")]
        assert row.fallback_count == 1


class TestNoFallback:
    async def test_master_sets_it_and_the_view_shows_it(self) -> None:
        w = _ts_world()
        await _setup(w, fallback=False)
        overview = await w.service.overview(ORG_A, for_platform=True)
        sms = next(c for c in overview["channels"] if c["channel"] == "sms")
        assert sms["effective_source"] == "own"
        assert sms["own"]["fallback_to_platform_default"] is False
        assert API_KEY not in json.dumps(overview, default=str)

    async def test_a_venue_cannot_change_it(self) -> None:
        w = _ts_world()
        with pytest.raises(ProviderConfigInvalidError) as info:
            await w.service.put_provider(
                ORG_A,
                "sms",
                VENUE,
                provider_type="trustsignal",
                config=CONFIG,
                enabled=None,
                fallback_to_platform_default=False,
            )
        assert "fallback_to_platform_default" in info.value.data["fields"]

    async def test_no_fallback_on_error(self, caplog) -> None:  # noqa: ANN001
        w = _ts_world()
        await _setup(w, fallback=False)
        w.ts.send = (400, _error("114", "INVALID_SENDERID", "Invalid senderid"))
        fx = await _otp_with_dispatcher(w)
        with (
            caplog.at_level(logging.WARNING),
            pytest.raises(OtpVenueSendFailedError) as info,
        ):
            await _guest_code(fx)
        assert fx.sms_provider.sent == []  # Wyfy's SMS was never used
        assert info.value.status_code == 502
        assert info.value.message == "We couldn't send your code. Please try again."
        assert info.value.data["vendor_error"] == "sender_rejected:114/INVALID_SENDERID"
        records = [
            r
            for r in caplog.records
            if r.getMessage() == "guest_login_byo_send_failed_no_fallback"
        ]
        assert len(records) == 1
        assert records[0].vendor_error_code == "114/INVALID_SENDERID"
        assert records[0].fell_back_to_platform is False
        assert API_KEY not in caplog.text

    async def test_no_fallback_on_timeout(self, monkeypatch) -> None:  # noqa: ANN001
        w = _ts_world()
        await _setup(w, fallback=False)
        monkeypatch.setattr(messaging_service, "SEND_DEADLINE_SECONDS", 0.05)
        w.ts.delay = 1.0
        fx = await _otp_with_dispatcher(w)
        with pytest.raises(OtpVenueSendFailedError) as info:
            await _guest_code(fx)
        assert info.value.data["vendor_error"] == "provider_timeout"
        assert fx.sms_provider.sent == []

    async def test_no_fallback_when_the_breaker_is_open(self) -> None:
        w = _ts_world()
        await _setup(w, fallback=False)
        await w.redis.set(f"guest_messaging:breaker:{ORG_A}:sms", "1")
        fx = await _otp_with_dispatcher(w)
        # The breaker never diverts this venue to Wyfy: its own account is
        # still tried, and the code goes out through it.
        await _guest_code(fx)
        assert fx.sms_provider.sent == []
        assert len(w.ts.sends) == 2  # verify + this login
        # ...and when the vendor is down too, the guest gets the error.
        w.ts.send = (503, {"success": False})
        with pytest.raises(OtpVenueSendFailedError):
            await _guest_code(fx)
        assert fx.sms_provider.sent == []

    async def test_a_failure_does_not_trip_the_breaker_or_turn_the_row_off(
        self,
    ) -> None:
        w = _ts_world()
        await _setup(w, fallback=False)
        w.ts.send = (400, _error("101", "API_KEY_MISSING", "API Key is required"))
        fx = await _otp_with_dispatcher(w)
        for _ in range(2):
            with pytest.raises(OtpVenueSendFailedError):
                await _guest_code(fx)
        row = w.repo.rows[(ORG_A, "sms")]
        # An auth error would turn a fallback row off (so Wyfy sends); here
        # that would quietly move the venue onto Wyfy's SMS, so it stays on.
        assert row.status == "verified" and row.enabled is True
        assert row.last_error.startswith("provider_auth_failed")
        assert f"guest_messaging:breaker:{ORG_A}:sms" not in w.redis.store
        assert len(w.ts.sends) == 3  # verify + both attempts reached TrustSignal
        assert fx.sms_provider.sent == []

    async def test_an_unreadable_provider_is_an_error_not_a_wyfy_send(self) -> None:
        w = _ts_world()
        await _setup(w, fallback=False)
        w.repo.rows[(ORG_A, "sms")].provider_type = "retired_vendor"
        fx = await _otp_with_dispatcher(w)
        with pytest.raises(OtpVenueSendFailedError) as info:
            await _guest_code(fx)
        assert info.value.data["vendor_error"] == "provider_unavailable"
        assert fx.sms_provider.sent == []

    async def test_the_failure_is_recorded_outside_the_failing_request(
        self,
    ) -> None:
        w = _ts_world()
        await _setup(w, fallback=False)
        w.ts.send = (400, _error("114", "INVALID_SENDERID", "Invalid senderid"))
        recorded = []

        async def durable(sender, error, auth):  # noqa: ANN001
            recorded.append((sender.organization_id, error, auth))
            await w.service.record_fallback(sender, error, auth=auth)

        fx = await _otp_with_dispatcher(w)
        fx.service.org_dispatcher.durable_recorder = durable
        with pytest.raises(OtpVenueSendFailedError):
            await _guest_code(fx)
        assert len(recorded) == 1 and recorded[0][0] == ORG_A
        assert recorded[0][1].startswith("sender_rejected: trustsignal 114/")
        row = w.repo.rows[(ORG_A, "sms")]
        assert row.fallback_count == 1
        audits = [e for e in w.audit.entries if e["action"].endswith("_fallback")]
        assert audits[-1]["event_metadata"]["fell_back_to_platform"] is False
        assert "NOT sent" in audits[-1]["description"]

    async def test_other_orgs_are_untouched(self) -> None:
        w = _ts_world()
        await _setup(w, fallback=False)
        w.ts.send = (503, {"success": False})
        fx = await _otp_with_dispatcher(w)
        await _guest_code(fx, org=ORG_B)
        await _guest_code(fx, org=uuid.uuid4())
        assert len(fx.sms_provider.sent) == 2
        assert len(w.ts.sends) == 1  # only ORG_A's verify code

    async def test_until_the_add_on_is_unlocked_the_default_sends(self) -> None:
        w = _ts_world()
        await _setup(w, fallback=False)

        async def locked(org):  # noqa: ANN001
            return False

        w.service.byo_entitlement_check = locked
        w.ts.send = (503, {"success": False})
        fx = await _otp_with_dispatcher(w)
        await _guest_code(fx)
        assert len(fx.sms_provider.sent) == 1

    async def test_master_can_turn_the_fallback_back_on(self) -> None:
        w = _ts_world()
        await _setup(w, fallback=False)
        view, _ = await w.service.put_provider(
            ORG_A,
            "sms",
            MASTER,
            provider_type=None,
            config={},
            enabled=None,
            fallback_to_platform_default=True,
        )
        # Not a credential change: stays verified and in use.
        assert view["status"] == "verified" and view["effective"] is True
        assert view["fallback_to_platform_default"] is True
        w.ts.send = (503, {"success": False})
        fx = await _otp_with_dispatcher(w)
        await _guest_code(fx)
        assert len(fx.sms_provider.sent) == 1
