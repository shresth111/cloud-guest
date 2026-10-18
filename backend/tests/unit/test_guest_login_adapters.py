"""Login-code provider registry and adapters (app.domains.guest_messaging).

* the registry: every adapter declares its fields (the dashboard renders its
  form from them), secrets are typed as such, keys are unique per channel;
* config validation and masking: a secret is write-only, never in a view,
  and an omitted secret keeps the stored one;
* the Custom HTTP adapter: placeholder templating (JSON- and form-escaped),
  success parsing (2xx / JSON path / regex), message-id paths, and the SSRF
  guard (https only, port 443, private/loopback/link-local/CGNAT refused by
  literal and by DNS answer, no redirects);
* one mocked request/response per named vendor adapter, asserting the exact
  URL, auth and body its public docs describe, plus the documented failure
  shape for several.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, unquote

import httpx
import pytest

from app.domains.guest_messaging.adapters import (
    KALEYRA_DOMAINS,
    REGISTRY,
    meta_auth_template_payload,
    parse_json_path,
    render_sms,
)
from app.domains.guest_messaging.http_guard import (
    UrlNotAllowedError,
    check_url_shape,
    vet_host,
)
from app.domains.guest_messaging.registry import (
    KIND_SECRET,
    AdapterContext,
    AdapterSpec,
    ConfigError,
    FieldSpec,
    OtpMessage,
    ProviderSendError,
    Registry,
    build_display,
    normalize_config,
    scrub,
)

PHONE = "+919876543210"
CODE = "482913"
MESSAGE = OtpMessage(PHONE, CODE, f"Your Wyfy Guest verification code is {CODE}.")
PUBLIC = "93.184.216.34"


def _public(host: str, port: int) -> list[str]:
    return [PUBLIC]


class Recorder:
    """httpx.MockTransport handler that records the request and answers."""

    def __init__(self, status: int = 200, body: Any = None, text: str | None = None):
        self.status = status
        self.body = body
        self.text = text
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.text is not None:
            return httpx.Response(self.status, text=self.text)
        return httpx.Response(
            self.status, json=self.body if self.body is not None else {}
        )

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


def _adapter(channel: str, key: str, config: dict[str, Any], recorder: Recorder):
    spec = REGISTRY.get(channel, key)
    assert spec is not None
    normalized = normalize_config(spec, config)
    ctx = AdapterContext(transport=httpx.MockTransport(recorder), resolver=_public)
    return spec.factory(normalized, ctx)


def _form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


# ============================================================================
# Registry
# ============================================================================


class TestRegistry:
    def test_every_requested_vendor_or_the_custom_adapter_is_present(self) -> None:
        whatsapp = {s.key for s in REGISTRY.for_channel("whatsapp")}
        sms = {s.key for s in REGISTRY.for_channel("sms")}
        assert {"meta_cloud", "dialog360", "gupshup", "interakt", "aisensy", "wati",
                "twilio", "custom_http"} <= whatsapp  # fmt: skip
        assert {"ping4sms", "msg91", "exotel", "twilio", "kaleyra", "fast2sms",
                "twofactor", "custom_http"} <= sms  # fmt: skip

    def test_every_named_adapter_cites_its_public_docs(self) -> None:
        for spec in REGISTRY.specs.values():
            if spec.key != "custom_http":
                assert spec.docs_url.startswith("https://"), spec.key
                assert spec.docs_url in (spec.factory.__doc__ or "") or (
                    spec.docs_url.split("?")[0] in (spec.factory.__doc__ or "")
                ), f"{spec.key}: docstring must cite {spec.docs_url}"

    def test_every_adapter_declares_at_least_one_secret(self) -> None:
        for spec in REGISTRY.specs.values():
            if spec.key == "custom_http":
                assert any(f.kind == "headers" for f in spec.fields)
            else:
                assert spec.secret_fields, spec.key

    def test_schema_is_what_the_form_renders_from(self) -> None:
        schema = REGISTRY.schema()
        meta = next(s for s in schema["whatsapp"] if s["key"] == "meta_cloud")
        names = [f["name"] for f in meta["fields"]]
        assert names == [
            "phone_number_id",
            "waba_id",
            "access_token",
            "template_name",
            "template_language",
        ]
        token = next(f for f in meta["fields"] if f["name"] == "access_token")
        assert token["kind"] == KIND_SECRET and token["required"] is True

    def test_duplicate_registration_is_refused(self) -> None:
        registry = Registry()
        spec = AdapterSpec("x", "sms", "X", "https://x", (FieldSpec("a", "A"),), dict)
        registry.register(spec)
        with pytest.raises(ValueError):
            registry.register(spec)
        with pytest.raises(ValueError):
            registry.register(
                AdapterSpec("y", "fax", "Y", "", (FieldSpec("a", "A"),), dict)
            )


# ============================================================================
# Config validation, write-only secrets, masking
# ============================================================================

META_CONFIG = {
    "phone_number_id": "1234567890",
    "waba_id": "9876543210",
    "access_token": "EAAG-secret-token-value-0001",
    "template_name": "wifi_login_code",
}


class TestConfig:
    def test_required_unknown_and_pattern_errors_are_named(self) -> None:
        spec = REGISTRY.get("whatsapp", "meta_cloud")
        with pytest.raises(ConfigError) as caught:
            normalize_config(
                spec, {"phone_number_id": "12ab", "surprise": "x", "waba_id": "1"}
            )
        assert caught.value.fields["phone_number_id"] == "digits only"
        assert caught.value.fields["surprise"] == "unknown field for this provider"
        assert caught.value.fields["access_token"] == "required"

    def test_defaults_fill_in(self) -> None:
        spec = REGISTRY.get("whatsapp", "meta_cloud")
        assert normalize_config(spec, META_CONFIG)["template_language"] == "en"

    def test_an_omitted_secret_keeps_the_stored_one(self) -> None:
        spec = REGISTRY.get("whatsapp", "meta_cloud")
        stored = normalize_config(spec, META_CONFIG)
        again = normalize_config(
            spec, {**META_CONFIG, "access_token": ""}, stored=stored
        )
        assert again["access_token"] == META_CONFIG["access_token"]

    def test_display_never_contains_a_secret(self) -> None:
        spec = REGISTRY.get("whatsapp", "meta_cloud")
        display = build_display(spec, normalize_config(spec, META_CONFIG))
        assert display["access_token"] == {"set": True, "hint": "…0001"}
        assert "EAAG-secret" not in json.dumps(display)
        assert display["phone_number_id"] == "1234567890"

    def test_short_secret_gets_no_characters_in_its_hint(self) -> None:
        spec = REGISTRY.get("sms", "twofactor")
        display = build_display(spec, {"api_key": "short"})
        assert display["api_key"] == {"set": True, "hint": "…"}

    def test_sms_template_must_have_a_code_slot(self) -> None:
        spec = REGISTRY.get("sms", "ping4sms")
        base = {
            "api_key": "k" * 20,
            "sender_id": "CAFEWF",
            "dlt_template_id": "1107000000000001",
            "message_template": "Welcome to the cafe",
        }
        with pytest.raises(ConfigError) as caught:
            normalize_config(spec, base)
        assert "message_template" in caught.value.fields
        ok = normalize_config(
            spec, {**base, "message_template": "{#var#} is your code"}
        )
        assert render_sms(ok["message_template"], CODE) == f"{CODE} is your code"

    def test_scrub_removes_configured_values(self) -> None:
        text = scrub("bad key EAAG-secret-token-value-0001 for 1234567890", META_CONFIG)
        assert "EAAG" not in text and "1234567890" not in text


# ============================================================================
# Custom HTTP adapter
# ============================================================================

CUSTOM = {
    "url": "https://api.vendor.example/v1/otp?to={phone_digits}",
    "method": "POST",
    "headers": [
        {"name": "X-Api-Key", "value": "vendor-secret-key-9999", "secret": True},
        {"name": "X-Client", "value": "wyfy", "secret": False},
    ],
    "content_type": "json",
    "body_template": '{"phone": "{phone_e164}", "otp": "{otp}", "text": "{message}"}',
    "message_template": 'Code "{otp}" & welcome',
    "success_mode": "json_path",
    "success_json_path": "$.data[0].status",
    "success_value": "queued",
    "message_id_path": "data.0.id",
}


class TestCustomHttpTemplating:
    def test_json_body_is_escaped_and_parses(self) -> None:
        recorder = Recorder(body={"data": [{"status": "queued", "id": "m-1"}]})
        adapter = _adapter("sms", "custom_http", CUSTOM, recorder)
        request = adapter.build_request(MESSAGE)
        body = json.loads(request["content"])
        assert body == {
            "phone": PHONE,
            "otp": CODE,
            "text": f'Code "{CODE}" & welcome',
        }
        assert request["url"] == "https://api.vendor.example/v1/otp?to=919876543210"
        assert request["headers"]["X-Api-Key"] == "vendor-secret-key-9999"

    def test_form_body_is_url_encoded(self) -> None:
        config = {
            **CUSTOM,
            "content_type": "form",
            "body_template": "to={phone_e164}&msg={message}",
        }
        adapter = _adapter("sms", "custom_http", config, Recorder())
        request = adapter.build_request(MESSAGE)
        assert request["content"] == (
            "to=%2B919876543210&msg=" + "Code%20%22482913%22%20%26%20welcome"
        )

    def test_unknown_placeholder_and_bad_json_are_refused_on_save(self) -> None:
        spec = REGISTRY.get("whatsapp", "custom_http")
        with pytest.raises(ConfigError) as caught:
            normalize_config(spec, {**CUSTOM, "body_template": '{"x": "{pin}"}'})
        assert "unknown placeholder {pin}" in caught.value.fields["body_template"]
        with pytest.raises(ConfigError) as caught:
            normalize_config(spec, {**CUSTOM, "body_template": '{"x": {otp}'})
        assert "not valid JSON" in caught.value.fields["body_template"]

    def test_the_request_must_carry_the_code(self) -> None:
        spec = REGISTRY.get("whatsapp", "custom_http")
        with pytest.raises(ConfigError) as caught:
            normalize_config(
                spec,
                {"url": "https://api.vendor.example/send", "body_template": "{}"},
            )
        assert "{otp}" in caught.value.fields["body_template"]

    def test_json_path_parser(self) -> None:
        assert parse_json_path("$.data[0].status") == ["data", 0, "status"]
        assert parse_json_path("data.0.id") == ["data", 0, "id"]
        with pytest.raises(ValueError):
            parse_json_path("data..id")


class TestCustomHttpSuccess:
    async def test_json_path_success_and_message_id(self) -> None:
        recorder = Recorder(body={"data": [{"status": "QUEUED", "id": "m-77"}]})
        adapter = _adapter("sms", "custom_http", CUSTOM, recorder)
        result = await adapter.send_otp(MESSAGE)
        assert result.message_id == "m-77"
        sent = recorder.last
        assert sent.method == "POST"
        assert sent.headers["x-api-key"] == "vendor-secret-key-9999"
        assert json.loads(sent.content)["otp"] == CODE

    async def test_json_path_mismatch_is_a_failure(self) -> None:
        recorder = Recorder(body={"data": [{"status": "rejected"}]})
        adapter = _adapter("sms", "custom_http", CUSTOM, recorder)
        with pytest.raises(ProviderSendError) as caught:
            await adapter.send_otp(MESSAGE)
        assert caught.value.code == "provider_rejected"

    async def test_regex_success(self) -> None:
        config = {**CUSTOM, "success_mode": "regex", "success_regex": r"^OK \d+"}
        ok = _adapter("sms", "custom_http", config, Recorder(text="OK 12345"))
        assert (await ok.send_otp(MESSAGE)).provider == "custom_http"
        bad = _adapter("sms", "custom_http", config, Recorder(text="ERR 7"))
        with pytest.raises(ProviderSendError):
            await bad.send_otp(MESSAGE)

    async def test_any_2xx_mode_and_http_errors(self) -> None:
        config = {**CUSTOM, "success_mode": "status_2xx"}
        assert await _adapter("sms", "custom_http", config, Recorder(204)).send_otp(
            MESSAGE
        )
        with pytest.raises(ProviderSendError) as caught:
            await _adapter("sms", "custom_http", config, Recorder(401)).send_otp(
                MESSAGE
            )
        assert caught.value.auth is True
        with pytest.raises(ProviderSendError) as caught:
            await _adapter("sms", "custom_http", config, Recorder(500)).send_otp(
                MESSAGE
            )
        assert caught.value.code == "provider_rejected"

    async def test_a_redirect_is_never_followed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

        spec = REGISTRY.get("sms", "custom_http")
        adapter = spec.factory(
            normalize_config(spec, {**CUSTOM, "success_mode": "status_2xx"}),
            AdapterContext(transport=httpx.MockTransport(handler), resolver=_public),
        )
        with pytest.raises(ProviderSendError) as caught:
            await adapter.send_otp(MESSAGE)
        assert caught.value.code == "redirect_refused"

    def test_secret_header_is_write_only(self) -> None:
        spec = REGISTRY.get("sms", "custom_http")
        stored = normalize_config(spec, CUSTOM)
        display = build_display(spec, stored)
        assert "vendor-secret-key-9999" not in json.dumps(display)
        assert display["headers"][0] == {
            "name": "X-Api-Key",
            "secret": True,
            "set": True,
            "hint": "…9999",
        }
        assert display["headers"][1] == {
            "name": "X-Client",
            "secret": False,
            "value": "wyfy",
        }
        resubmitted = {
            **CUSTOM,
            "headers": [
                {"name": "X-Api-Key", "secret": True},
                {"name": "X-Client", "value": "wyfy2", "secret": False},
            ],
        }
        again = normalize_config(spec, resubmitted, stored=stored)
        assert again["headers"][0]["value"] == "vendor-secret-key-9999"
        assert again["headers"][1]["value"] == "wyfy2"


class TestSsrfGuard:
    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("http://api.vendor.example/send", "https"),
            ("https://api.vendor.example:8443/send", "port 443"),
            ("https://user:pw@api.vendor.example/send", "username"),
            ("https://localhost/send", "internal"),
            ("https://metadata.internal/send", "internal"),
            ("ftp://x.example/", "https"),
        ],
    )
    def test_url_shape(self, url: str, reason: str) -> None:
        with pytest.raises(UrlNotAllowedError) as caught:
            check_url_shape(url)
        assert reason in caught.value.reason

    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.3.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fd00:ec2::254",
            "0.0.0.0",
        ],
    )
    def test_internal_literals_are_refused(self, address: str) -> None:
        with pytest.raises(UrlNotAllowedError):
            vet_host(address, 443)

    def test_a_name_resolving_inside_is_refused_even_if_mixed(self) -> None:
        with pytest.raises(UrlNotAllowedError):
            vet_host("rebind.example", 443, resolver=lambda h, p: [PUBLIC, "10.1.2.3"])
        assert vet_host("ok.example", 443, resolver=_public) == PUBLIC

    async def test_send_refuses_a_private_dns_answer_before_any_request(self) -> None:
        recorder = Recorder()
        spec = REGISTRY.get("sms", "custom_http")
        adapter = spec.factory(
            normalize_config(spec, CUSTOM),
            AdapterContext(
                transport=httpx.MockTransport(recorder),
                resolver=lambda h, p: ["169.254.169.254"],
            ),
        )
        with pytest.raises(ProviderSendError) as caught:
            await adapter.send_otp(MESSAGE)
        assert caught.value.code == "url_not_allowed"
        assert recorder.requests == []

    def test_save_refuses_http_and_private_literals(self) -> None:
        spec = REGISTRY.get("sms", "custom_http")
        with pytest.raises(ConfigError) as caught:
            normalize_config(spec, {**CUSTOM, "url": "http://10.0.0.1/x?o={otp}"})
        assert "https" in caught.value.fields["url"]

    async def test_the_transport_pins_the_vetted_address(self, monkeypatch) -> None:
        """The real transport resolves on connect and dials the vetted IP,
        so a second DNS answer cannot rebind it to an internal address."""
        from app.domains.guest_messaging import http_guard

        dialed: list[str] = []

        class _Inner:
            async def connect_tcp(self, host, port, **kwargs):  # noqa: ANN001
                dialed.append(host)
                raise httpx.ConnectError("stop here")

            async def sleep(self, seconds):  # noqa: ANN001
                return None

        backend = http_guard._GuardedBackend(_Inner(), lambda h, p: PUBLIC)
        with pytest.raises(httpx.ConnectError):
            await backend.connect_tcp("api.vendor.example", 443)
        assert dialed == [PUBLIC]
        refusing = http_guard._GuardedBackend(
            _Inner(),
            lambda h, p: vet_host(h, p, resolver=lambda *_: ["10.0.0.9"]),
        )
        with pytest.raises(UrlNotAllowedError):
            await refusing.connect_tcp("api.vendor.example", 443)


# ============================================================================
# Named adapters: one mocked request/response each
# ============================================================================


class TestMetaCloud:
    def test_authentication_template_payload_shape(self) -> None:
        assert meta_auth_template_payload(
            PHONE, CODE, template_name="wifi_login_code", language="en_US"
        ) == {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": "919876543210",
            "type": "template",
            "template": {
                "name": "wifi_login_code",
                "language": {"code": "en_US"},
                "components": [
                    {"type": "body", "parameters": [{"type": "text", "text": CODE}]},
                    {
                        "type": "button",
                        "sub_type": "url",
                        "index": "0",
                        "parameters": [{"type": "text", "text": CODE}],
                    },
                ],
            },
        }

    async def test_send(self) -> None:
        recorder = Recorder(body={"messages": [{"id": "wamid.ABC"}]})
        adapter = _adapter("whatsapp", "meta_cloud", META_CONFIG, recorder)
        result = await adapter.send_otp(MESSAGE)
        assert result.message_id == "wamid.ABC"
        sent = recorder.last
        assert str(sent.url) == "https://graph.facebook.com/v21.0/1234567890/messages"
        assert sent.headers["authorization"] == "Bearer EAAG-secret-token-value-0001"
        assert json.loads(sent.content)["template"]["components"][1]["index"] == "0"

    async def test_expired_token_is_an_auth_error(self) -> None:
        recorder = Recorder(400, {"error": {"code": 190, "message": "expired"}})
        adapter = _adapter("whatsapp", "meta_cloud", META_CONFIG, recorder)
        with pytest.raises(ProviderSendError) as caught:
            await adapter.send_otp(MESSAGE)
        assert caught.value.auth is True

    async def test_preflight_requires_an_approved_authentication_template(self) -> None:
        marketing = Recorder(
            body={
                "data": [
                    {
                        "name": "wifi_login_code",
                        "language": "en",
                        "status": "APPROVED",
                        "category": "MARKETING",
                    }
                ]
            }
        )
        adapter = _adapter("whatsapp", "meta_cloud", META_CONFIG, marketing)
        with pytest.raises(ProviderSendError) as caught:
            await adapter.preflight()
        assert caught.value.code == "template_wrong_category"
        assert marketing.last.url.params["name"] == "wifi_login_code"
        good = Recorder(
            body={
                "data": [
                    {
                        "name": "wifi_login_code",
                        "language": "en",
                        "status": "APPROVED",
                        "category": "AUTHENTICATION",
                    }
                ]
            }
        )
        assert await _adapter("whatsapp", "meta_cloud", META_CONFIG, good).preflight()


async def test_dialog360() -> None:
    recorder = Recorder(body={"messages": [{"id": "wamid.360"}]})
    adapter = _adapter(
        "whatsapp",
        "dialog360",
        {"api_key": "d360-key-000000001", "template_name": "wifi_login_code"},
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "wamid.360"
    assert str(recorder.last.url) == "https://waba-v2.360dialog.io/messages"
    assert recorder.last.headers["d360-api-key"] == "d360-key-000000001"
    assert json.loads(recorder.last.content)["template"]["name"] == "wifi_login_code"


async def test_gupshup() -> None:
    recorder = Recorder(body={"status": "submitted", "messageId": "gs-1"})
    adapter = _adapter(
        "whatsapp",
        "gupshup",
        {
            "api_key": "gupshup-key-00000001",
            "source_number": "917834811114",
            "template_id": "c6aecef6-bcb0-4fb1-8100-28c094e3bc6b",
        },
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "gs-1"
    sent = recorder.last
    assert str(sent.url) == "https://api.gupshup.io/wa/api/v1/template/msg"
    assert sent.headers["apikey"] == "gupshup-key-00000001"
    form = _form(sent)
    assert form["source"] == "917834811114"
    assert form["destination"] == "919876543210"
    assert json.loads(form["template"]) == {
        "id": "c6aecef6-bcb0-4fb1-8100-28c094e3bc6b",
        "params": [CODE],
    }
    rejected = _adapter(
        "whatsapp",
        "gupshup",
        {
            "api_key": "gupshup-key-00000001",
            "source_number": "917834811114",
            "template_id": "t-1",
        },
        Recorder(body={"status": "error", "message": "Invalid template"}),
    )
    with pytest.raises(ProviderSendError):
        await rejected.send_otp(MESSAGE)


async def test_interakt() -> None:
    recorder = Recorder(body={"result": True, "message": "ok", "id": "ik-9"})
    adapter = _adapter(
        "whatsapp",
        "interakt",
        {"api_key": "aW50ZXJha3Qta2V5", "template_name": "wifi_login_code"},
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "ik-9"
    sent = recorder.last
    assert str(sent.url) == "https://api.interakt.ai/v1/public/message/"
    assert sent.headers["authorization"] == "Basic aW50ZXJha3Qta2V5"
    assert json.loads(sent.content) == {
        "countryCode": "+91",
        "phoneNumber": "9876543210",
        "type": "Template",
        "template": {
            "name": "wifi_login_code",
            "languageCode": "en",
            "bodyValues": [CODE],
            "buttonValues": {"0": [CODE]},
        },
    }
    with pytest.raises(ProviderSendError) as caught:
        await adapter.send_otp(OtpMessage("+447700900123", CODE, ""))
    assert caught.value.code == "number_not_supported"


async def test_aisensy() -> None:
    recorder = Recorder(body={"success": "true"})
    adapter = _adapter(
        "whatsapp",
        "aisensy",
        {"api_key": "aisensy-key-000001", "campaign_name": "wifi_otp"},
        recorder,
    )
    await adapter.send_otp(MESSAGE)
    assert str(recorder.last.url) == "https://backend.aisensy.com/campaign/t1/api/v2"
    assert json.loads(recorder.last.content) == {
        "apiKey": "aisensy-key-000001",
        "campaignName": "wifi_otp",
        "destination": PHONE,
        "userName": "Guest",
        "templateParams": [CODE],
    }


async def test_wati() -> None:
    recorder = Recorder(body={"result": True})
    adapter = _adapter(
        "whatsapp",
        "wati",
        {
            "api_endpoint": "https://live-mt-server.wati.io/123456",
            "access_token": "Bearer wati-token-0000001",
            "template_name": "wifi_login_code",
        },
        recorder,
    )
    await adapter.send_otp(MESSAGE)
    sent = recorder.last
    assert sent.url.path == "/123456/api/v1/sendTemplateMessage"
    assert sent.url.params["whatsappNumber"] == "919876543210"
    assert sent.headers["authorization"] == "Bearer wati-token-0000001"
    assert sent.headers["content-type"] == "application/json-patch+json"
    assert json.loads(sent.content) == {
        "template_name": "wifi_login_code",
        "broadcast_name": "wifi_login",
        "parameters": [{"name": "1", "value": CODE}],
    }
    failing = _adapter(
        "whatsapp",
        "wati",
        {
            "api_endpoint": "https://live-mt-server.wati.io/123456",
            "access_token": "wati-token-0000001",
            "template_name": "wifi_login_code",
        },
        Recorder(body={"result": False, "info": "Template not found"}),
    )
    with pytest.raises(ProviderSendError):
        await failing.send_otp(MESSAGE)
    spec = REGISTRY.get("whatsapp", "wati")
    with pytest.raises(ConfigError):
        normalize_config(
            spec,
            {
                "api_endpoint": "https://evil.example/123",
                "access_token": "t" * 20,
                "template_name": "x",
            },
        )


async def test_twilio_whatsapp() -> None:
    sid = "AC" + "0" * 32
    recorder = Recorder(201, {"sid": "SM123"})
    adapter = _adapter(
        "whatsapp",
        "twilio",
        {
            "account_sid": sid,
            "auth_token": "twilio-token-000001",
            "from_number": "+14155238886",
            "content_sid": "HX" + "a" * 32,
        },
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "SM123"
    form = _form(recorder.last)
    assert form["From"] == "whatsapp:+14155238886"
    assert form["To"] == f"whatsapp:{PHONE}"
    assert json.loads(form["ContentVariables"]) == {"1": CODE}
    assert recorder.last.headers["authorization"].startswith("Basic ")


SMS_TEXT = "{otp} is your Wi-Fi login code for Cafe. Valid 5 min."


async def test_ping4sms() -> None:
    recorder = Recorder(text="5512345")
    adapter = _adapter(
        "sms",
        "ping4sms",
        {
            "api_key": "p4s-key-0000000001",
            "sender_id": "CAFEWF",
            "dlt_entity_id": "1101000000000001",
            "dlt_template_id": "1107000000000001",
            "message_template": SMS_TEXT,
        },
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "5512345"
    params = recorder.last.url.params
    assert recorder.last.url.host == "site.ping4sms.com"
    assert params["route"] == "4"
    assert params["number"] == "919876543210"
    assert params["sms"] == SMS_TEXT.replace("{otp}", CODE)
    assert params["templateid"] == "1107000000000001"
    assert params["entityid"] == "1101000000000001"
    bad = _adapter(
        "sms",
        "ping4sms",
        {
            "api_key": "p4s-key-0000000001",
            "sender_id": "CAFEWF",
            "dlt_template_id": "1107000000000001",
            "message_template": SMS_TEXT,
        },
        Recorder(text="101"),
    )
    with pytest.raises(ProviderSendError) as caught:
        await bad.send_otp(MESSAGE)
    assert caught.value.auth is True


async def test_msg91() -> None:
    recorder = Recorder(body={"type": "success", "message": "5762846b4f8d285d378b4567"})
    adapter = _adapter(
        "sms",
        "msg91",
        {
            "auth_key": "msg91-auth-0000001",
            "flow_id": "64f0abc123",
            "sender_id": "CAFEWF",
        },
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "5762846b4f8d285d378b4567"
    assert str(recorder.last.url) == "https://api.msg91.com/api/v5/flow/"
    assert recorder.last.headers["authkey"] == "msg91-auth-0000001"
    assert json.loads(recorder.last.content) == {
        "flow_id": "64f0abc123",
        "sender": "CAFEWF",
        "recipients": [{"mobiles": "919876543210", "VAR1": CODE}],
    }
    failing = _adapter(
        "sms",
        "msg91",
        {"auth_key": "msg91-auth-0000001", "flow_id": "64f0abc123"},
        Recorder(body={"type": "error", "message": "Invalid authkey"}),
    )
    with pytest.raises(ProviderSendError) as caught:
        await failing.send_otp(MESSAGE)
    assert caught.value.auth is True


async def test_exotel() -> None:
    recorder = Recorder(body={"SMSMessage": {"Sid": "ex-sid-1"}})
    adapter = _adapter(
        "sms",
        "exotel",
        {
            "api_key": "exotel-key-0000001",
            "api_token": "exotel-token-000001",
            "account_sid": "cafe1",
            "sender_id": "CAFEWF",
            "dlt_template_id": "1107000000000001",
            "message_template": SMS_TEXT,
        },
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "ex-sid-1"
    assert (
        str(recorder.last.url)
        == "https://api.in.exotel.com/v1/Accounts/cafe1/Sms/send.json"
    )
    form = _form(recorder.last)
    assert form["SmsType"] == "transactional"
    assert form["DltTemplateId"] == "1107000000000001"
    assert form["Body"] == SMS_TEXT.replace("{otp}", CODE)


async def test_twilio_sms() -> None:
    recorder = Recorder(201, {"sid": "SM9"})
    adapter = _adapter(
        "sms",
        "twilio",
        {
            "account_sid": "AC" + "1" * 32,
            "auth_token": "twilio-token-000001",
            "from_number": "+14155550100",
            "message_template": SMS_TEXT,
        },
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "SM9"
    assert _form(recorder.last)["Body"] == SMS_TEXT.replace("{otp}", CODE)


async def test_kaleyra() -> None:
    recorder = Recorder(body={"id": "kl-1", "data": [{"message_id": "kl-1:1"}]})
    adapter = _adapter(
        "sms",
        "kaleyra",
        {
            "api_key": "kaleyra-key-000001",
            "sid": "HXIN1234",
            "sender_id": "KLRHXA",
            "dlt_template_id": "1107000000000001",
            "message_template": SMS_TEXT,
        },
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "kl-1"
    assert (
        str(recorder.last.url)
        == f"https://{KALEYRA_DOMAINS['in']}/v1/HXIN1234/messages"
    )
    assert recorder.last.headers["api-key"] == "kaleyra-key-000001"
    form = _form(recorder.last)
    assert form["type"] == "OTP" and form["to"] == PHONE
    assert form["template_id"] == "1107000000000001"
    error = _adapter(
        "sms",
        "kaleyra",
        {
            "api_key": "kaleyra-key-000001",
            "sid": "HXIN1234",
            "sender_id": "KLRHXA",
            "message_template": SMS_TEXT,
        },
        Recorder(body={"code": "E404", "message": "x", "error": {}}),
    )
    with pytest.raises(ProviderSendError):
        await error.send_otp(MESSAGE)


async def test_fast2sms() -> None:
    recorder = Recorder(
        body={"return": True, "request_id": "lwdtp7cjyqxvfe9", "message": ["sent"]}
    )
    adapter = _adapter(
        "sms",
        "fast2sms",
        {
            "api_key": "f2s-key-0000000001",
            "sender_id": "FSTSMS",
            "message_id": "111111",
        },
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "lwdtp7cjyqxvfe9"
    assert str(recorder.last.url) == "https://www.fast2sms.com/dev/bulkV2"
    assert recorder.last.headers["authorization"] == "f2s-key-0000000001"
    assert json.loads(recorder.last.content) == {
        "route": "dlt",
        "sender_id": "FSTSMS",
        "message": "111111",
        "variables_values": CODE,
        "numbers": "9876543210",
    }


async def test_twofactor() -> None:
    recorder = Recorder(body={"Status": "Success", "Details": "sess-1"})
    adapter = _adapter(
        "sms",
        "twofactor",
        {"api_key": "2f-key-00000000001", "template_name": "OTP1"},
        recorder,
    )
    assert (await adapter.send_otp(MESSAGE)).message_id == "sess-1"
    assert recorder.last.method == "GET"
    assert unquote(recorder.last.url.raw_path.decode()) == (
        f"/API/V1/2f-key-00000000001/SMS/{PHONE}/{CODE}/OTP1"
    )
    bad = _adapter(
        "sms",
        "twofactor",
        {"api_key": "2f-key-00000000001"},
        Recorder(body={"Status": "Error", "Details": "Invalid API Key"}),
    )
    with pytest.raises(ProviderSendError) as caught:
        await bad.send_otp(MESSAGE)
    assert caught.value.auth is True
