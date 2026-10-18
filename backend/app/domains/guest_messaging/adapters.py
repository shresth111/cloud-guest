"""Vendor adapters for guest login codes, and the registry that lists them.

Rules every adapter here follows:

* the endpoint, auth and payload come from the vendor's PUBLIC API docs,
  cited in the class docstring. A vendor whose send API could not be
  verified from public docs is NOT given an adapter; venues on it use
  :class:`CustomHttpOtpAdapter` (today: MSG91 WhatsApp, Textlocal);
* success is what the vendor documents as success, never "no exception";
  anything else raises :class:`~.registry.ProviderSendError`, and the
  caller (``OtpService``) then sends the code through the platform default
  so a guest's login never waits on a venue's vendor;
* no redirects are followed, proxy env vars are ignored, timeouts are short;
* secrets live only in the decrypted ``config`` handed to the factory and
  are never logged. Vendor error text is scrubbed by the service before it
  is stored or returned.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .http_guard import (
    TIMEOUT,
    UrlNotAllowedError,
    check_url_shape,
    guarded_client,
    system_resolver,
    vet_host,
)
from .registry import (
    KIND_BOOLEAN,
    KIND_HEADERS,
    KIND_SECRET,
    KIND_SELECT,
    KIND_TEXTAREA,
    AdapterContext,
    AdapterSpec,
    FieldSpec,
    OtpMessage,
    ProviderSendError,
    Registry,
    SendResult,
)

MAX_RESPONSE_BYTES = 64 * 1024
DIGITS = r"\d{1,30}"
SENDER_ID = r"[A-Za-z0-9]{3,11}|\+?\d{6,15}"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _client(ctx: AdapterContext) -> httpx.AsyncClient:
    """For fixed, vendor-owned hosts. Customer-supplied URLs go through
    :func:`.http_guard.guarded_client` instead."""
    return httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        transport=ctx.transport,
    )


async def _send(
    client: httpx.AsyncClient, provider: str, method: str, url: str, **kwargs: Any
) -> httpx.Response:
    try:
        async with client:
            response = await client.request(method, url, **kwargs)
    except UrlNotAllowedError as exc:
        raise ProviderSendError("url_not_allowed", exc.reason) from exc
    except httpx.TimeoutException as exc:
        raise ProviderSendError("provider_timeout", f"{provider} timed out") from exc
    except httpx.HTTPError as exc:
        raise ProviderSendError(
            "provider_unreachable", f"{provider}: {type(exc).__name__}"
        ) from exc
    if 300 <= response.status_code < 400:
        raise ProviderSendError(
            "redirect_refused", f"{provider} answered a redirect; not followed"
        )
    if response.status_code in (401, 403):
        raise ProviderSendError(
            "provider_auth_failed",
            f"{provider} HTTP {response.status_code}: {_text(response)[:200]}",
            auth=True,
        )
    if response.status_code >= 400:
        raise ProviderSendError(
            "provider_rejected",
            f"{provider} HTTP {response.status_code}: {_text(response)[:300]}",
        )
    return response


def _text(response: httpx.Response) -> str:
    return response.content[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")


def _json(response: httpx.Response) -> Any:
    try:
        return json.loads(_text(response))
    except ValueError:
        return None


_CODE_SLOT = re.compile(r"\{otp\}|\{#var#\}", re.IGNORECASE)


def render_sms(template: str, code: str) -> str:
    """The venue's DLT-approved text with the code in its slot. The slot is
    ``{otp}`` or, as DLT portals write it, the first ``{#var#}``."""
    return _CODE_SLOT.sub(code, template, count=1)


def _validate_sms_template(config: dict[str, Any]) -> dict[str, str]:
    template = config.get("message_template")
    if template and not _CODE_SLOT.search(template):
        return {
            "message_template": "must contain {otp} (or {#var#}) where the code goes"
        }
    return {}


MESSAGE_TEMPLATE = FieldSpec(
    "message_template",
    "Approved message text",
    kind=KIND_TEXTAREA,
    help=(
        "The exact text of your DLT-approved OTP template, with {otp} (or "
        "{#var#}) where the code goes. Carriers drop any other text."
    ),
    placeholder="{otp} is your Wi-Fi login code for Cafe Name. Valid for 5 minutes.",
    max_length=1000,
)
DLT_ENTITY = FieldSpec(
    "dlt_entity_id",
    "DLT entity id",
    required=False,
    pattern=DIGITS,
    pattern_message="digits only",
    help="Your principal entity id on the DLT portal.",
)
DLT_TEMPLATE = FieldSpec(
    "dlt_template_id",
    "DLT template id",
    pattern=DIGITS,
    pattern_message="digits only",
    help="The DLT id of the OTP template above.",
)
SENDER = FieldSpec(
    "sender_id",
    "Sender id (DLT header)",
    pattern=SENDER_ID,
    pattern_message="3-11 letters/digits, or a phone number",
    placeholder="CAFEWF",
)


# ---------------------------------------------------------------------------
# WhatsApp: Meta Cloud API (direct) and 360dialog (same payload)
# ---------------------------------------------------------------------------

META_GRAPH_BASE = "https://graph.facebook.com/v21.0"
_META_AUTH_CODES = {190, 102, 10, 200}


def meta_auth_template_payload(
    phone_e164: str, code: str, *, template_name: str, language: str
) -> dict[str, Any]:
    """The send body for an AUTHENTICATION template with a copy-code button.

    The code goes twice: as the body's ``{{1}}`` and as the parameter of
    button 0, which Meta stores as a ``url`` button once an ``otp`` button is
    approved. (developers.facebook.com/docs/whatsapp/business-management-api
    /authentication-templates/copy-code-button-authentication-templates)"""
    return {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": phone_e164.lstrip("+"),
        "type": "template",
        "template": {
            "name": template_name,
            "language": {"code": language},
            "components": [
                {"type": "body", "parameters": [{"type": "text", "text": code}]},
                {
                    "type": "button",
                    "sub_type": "url",
                    "index": "0",
                    "parameters": [{"type": "text", "text": code}],
                },
            ],
        },
    }


def _meta_error(provider: str, response: httpx.Response) -> ProviderSendError:
    body = _json(response) or {}
    error = body.get("error") if isinstance(body, dict) else None
    error = error if isinstance(error, dict) else {}
    try:
        code = int(error.get("code") or 0)
    except (TypeError, ValueError):
        code = 0
    message = str(error.get("message") or _text(response)[:300])
    if code in _META_AUTH_CODES or response.status_code in (401, 403):
        return ProviderSendError(
            "provider_auth_failed", f"{provider} {code}: {message}", auth=True
        )
    return ProviderSendError("provider_rejected", f"{provider} {code}: {message}")


async def _meta_style_send(
    ctx: AdapterContext,
    provider: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
) -> SendResult:
    try:
        async with _client(ctx) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.TimeoutException as exc:
        raise ProviderSendError("provider_timeout", f"{provider} timed out") from exc
    except httpx.HTTPError as exc:
        raise ProviderSendError(
            "provider_unreachable", f"{provider}: {type(exc).__name__}"
        ) from exc
    if response.status_code >= 300:
        raise _meta_error(provider, response)
    messages = (_json(response) or {}).get("messages") or []
    message_id = (
        messages[0].get("id") if messages and isinstance(messages[0], dict) else None
    )
    if not message_id:
        raise ProviderSendError(
            "provider_rejected", f"{provider} returned no message id"
        )
    return SendResult(provider=provider, message_id=str(message_id))


class MetaCloudOtpAdapter:
    """WhatsApp Cloud API, direct (no BSP). ``POST /{phone_number_id}/messages``
    with an AUTHENTICATION template and copy-code button.

    Docs: https://developers.facebook.com/docs/whatsapp/business-management-api/authentication-templates/copy-code-button-authentication-templates
    and https://developers.facebook.com/docs/whatsapp/cloud-api/reference/messages
    """

    provider = "meta_cloud"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.config['access_token']}"}

    async def send_otp(self, message: OtpMessage) -> SendResult:
        return await _meta_style_send(
            self.ctx,
            self.provider,
            f"{META_GRAPH_BASE}/{self.config['phone_number_id']}/messages",
            self._headers(),
            meta_auth_template_payload(
                message.phone_e164,
                message.code,
                template_name=self.config["template_name"],
                language=self.config.get("template_language") or "en",
            ),
        )

    async def preflight(self) -> list[str]:
        """Before the first code: the template must exist in this WABA,
        be APPROVED and be an AUTHENTICATION template
        (``GET /{waba_id}/message_templates?name=``)."""
        try:
            async with _client(self.ctx) as client:
                response = await client.get(
                    f"{META_GRAPH_BASE}/{self.config['waba_id']}/message_templates",
                    params={
                        "name": self.config["template_name"],
                        "fields": "name,language,status,category",
                    },
                    headers=self._headers(),
                )
        except httpx.HTTPError as exc:
            raise ProviderSendError(
                "provider_unreachable", f"meta_cloud: {type(exc).__name__}"
            ) from exc
        if response.status_code >= 300:
            raise _meta_error(self.provider, response)
        language = self.config.get("template_language") or "en"
        rows = [
            t
            for t in (_json(response) or {}).get("data") or []
            if isinstance(t, dict) and t.get("name") == self.config["template_name"]
        ]
        match = next((t for t in rows if t.get("language") == language), None)
        if match is None:
            raise ProviderSendError(
                "template_not_found",
                f"No template '{self.config['template_name']}' in language "
                f"'{language}' in this WhatsApp Business Account",
            )
        if str(match.get("category", "")).upper() != "AUTHENTICATION":
            raise ProviderSendError(
                "template_wrong_category",
                "The template must be in the AUTHENTICATION category "
                f"(it is {match.get('category')})",
            )
        if str(match.get("status", "")).upper() != "APPROVED":
            raise ProviderSendError(
                "template_not_approved",
                f"The template is {match.get('status')}, not APPROVED",
            )
        return ["Template is an approved AUTHENTICATION template"]


class Dialog360OtpAdapter:
    """360dialog (WhatsApp BSP on the Cloud API). Same body as Meta's,
    sent to ``https://waba-v2.360dialog.io/messages`` with ``D360-API-KEY``.

    Docs: https://docs.360dialog.com/docs/messaging-api/api-reference/messages
    and https://docs.360dialog.com/partner/messaging/template-messages/authentication-templates
    """

    provider = "dialog360"
    URL = "https://waba-v2.360dialog.io/messages"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        return await _meta_style_send(
            self.ctx,
            self.provider,
            self.URL,
            {"D360-API-KEY": self.config["api_key"]},
            meta_auth_template_payload(
                message.phone_e164,
                message.code,
                template_name=self.config["template_name"],
                language=self.config.get("template_language") or "en",
            ),
        )


# ---------------------------------------------------------------------------
# WhatsApp: BSPs with their own send APIs
# ---------------------------------------------------------------------------


class GupshupOtpAdapter:
    """Gupshup template message: ``POST https://api.gupshup.io/wa/api/v1/template/msg``,
    form-encoded, ``apikey`` header; ``template={"id": ..., "params": [code]}``.
    Success is ``{"status": "submitted", "messageId": ...}``.

    Docs: https://docs.gupshup.io/docs/template-messages
    """

    provider = "gupshup"
    URL = "https://api.gupshup.io/wa/api/v1/template/msg"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        response = await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            self.URL,
            headers={"apikey": self.config["api_key"]},
            data={
                "source": self.config["source_number"],
                "destination": message.phone_digits,
                "template": json.dumps(
                    {"id": self.config["template_id"], "params": [message.code]}
                ),
            },
        )
        body = _json(response) or {}
        if str(body.get("status", "")).lower() != "submitted":
            raise ProviderSendError("provider_rejected", f"gupshup: {str(body)[:300]}")
        return SendResult(self.provider, str(body.get("messageId") or "") or None)


class InteraktOtpAdapter:
    """Interakt: ``POST https://api.interakt.ai/v1/public/message/``,
    ``Authorization: Basic <API key>`` (the key from Developer Settings, sent
    as given), JSON with ``countryCode`` + ``phoneNumber`` (no country code)
    and ``template {name, languageCode, bodyValues, buttonValues}``. Success
    is ``{"result": true, "id": ...}``.

    The copy-code button of an authentication template is a URL-type button
    on Meta's side; Interakt documents ``buttonValues`` (keyed by button
    index) for exactly that, so the code is sent as ``buttonValues["0"]``.

    Docs: https://interakt.shop/resource-center/how-to-send-whatsapp-templates-using-apis-webhooks
    """

    provider = "interakt"
    URL = "https://api.interakt.ai/v1/public/message/"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        country = self.config.get("country_code") or "+91"
        if not message.phone_e164.startswith(country):
            raise ProviderSendError(
                "number_not_supported",
                f"interakt is set up for {country} numbers only",
            )
        template: dict[str, Any] = {
            "name": self.config["template_name"],
            "languageCode": self.config.get("template_language") or "en",
            "bodyValues": [message.code],
        }
        if self.config.get("copy_code_button", True):
            template["buttonValues"] = {"0": [message.code]}
        response = await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            self.URL,
            headers={"Authorization": f"Basic {self.config['api_key']}"},
            json={
                "countryCode": country,
                "phoneNumber": message.phone_e164[len(country) :],
                "type": "Template",
                "template": template,
            },
        )
        body = _json(response) or {}
        if body.get("result") is not True:
            raise ProviderSendError("provider_rejected", f"interakt: {str(body)[:300]}")
        return SendResult(self.provider, str(body.get("id") or "") or None)


class AiSensyOtpAdapter:
    """AiSensy API campaign: ``POST https://backend.aisensy.com/campaign/t1/api/v2``
    with ``apiKey``, ``campaignName`` (a Live API campaign on the venue's
    approved template), ``destination`` (+country code), ``userName`` and
    ``templateParams``. AiSensy documents HTTP 200 as success and no message
    id, so none is recorded.

    Docs: https://aisensy.com/tutorials/api-reference-docs
    """

    provider = "aisensy"
    URL = "https://backend.aisensy.com/campaign/t1/api/v2"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            self.URL,
            json={
                "apiKey": self.config["api_key"],
                "campaignName": self.config["campaign_name"],
                "destination": message.phone_e164,
                "userName": "Guest",
                "templateParams": [message.code],
            },
        )
        return SendResult(self.provider, None)


def _validate_wati(config: dict[str, Any]) -> dict[str, str]:
    endpoint = config.get("api_endpoint", "")
    try:
        host = check_url_shape(endpoint)
    except UrlNotAllowedError as exc:
        return {"api_endpoint": exc.reason}
    if not (host == "wati.io" or host.endswith(".wati.io")):
        return {"api_endpoint": "must be your WATI API endpoint (a *.wati.io address)"}
    return {}


class WatiOtpAdapter:
    """WATI: ``POST {API endpoint}/api/v1/sendTemplateMessage?whatsappNumber=<digits>``,
    ``Authorization: Bearer <token>``, body ``{template_name, broadcast_name,
    parameters: [{name, value}]}``. The API endpoint is per account
    (``https://live-mt-server.wati.io/<tenant>``) and is still sent through
    the SSRF guard. A ``"result": false`` body is a failure.

    Docs: https://support.wati.io/en/articles/11463104-how-to-send-whatsapp-messages-via-wati-using-make-com-formerly-integromat
    and https://support.wati.io/en/articles/11463224-how-to-send-otp-on-whatsapp-using-wati-api
    """

    provider = "wati"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        endpoint = self.config["api_endpoint"].rstrip("/")
        url = f"{endpoint}/api/v1/sendTemplateMessage"
        await _vet(url, self.ctx)
        token = self.config["access_token"]
        if token.lower().startswith("bearer "):
            token = token[7:]
        response = await _send(
            guarded_client(
                settings=self.ctx.settings,
                resolver=self.ctx.resolver or system_resolver,
                transport=self.ctx.transport,
            ),
            self.provider,
            "POST",
            url,
            params={"whatsappNumber": message.phone_digits},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json-patch+json",
            },
            content=json.dumps(
                {
                    "template_name": self.config["template_name"],
                    "broadcast_name": self.config.get("broadcast_name") or "wifi_login",
                    "parameters": [
                        {
                            "name": self.config.get("parameter_name") or "1",
                            "value": message.code,
                        }
                    ],
                }
            ),
        )
        body = _json(response)
        if isinstance(body, dict) and body.get("result") is False:
            raise ProviderSendError(
                "provider_rejected", f"wati: {str(body.get('info') or body)[:300]}"
            )
        return SendResult(self.provider, None)


class TwilioWhatsAppOtpAdapter:
    """Twilio WhatsApp: the Messages resource with ``From/To: whatsapp:+...``,
    ``ContentSid`` (an approved authentication Content Template) and
    ``ContentVariables``. Success returns the message ``sid``.

    Docs: https://www.twilio.com/docs/whatsapp/api and https://www.twilio.com/docs/content
    """

    provider = "twilio"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        cfg = self.config
        response = await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            f"https://api.twilio.com/2010-04-01/Accounts/{cfg['account_sid']}/Messages.json",
            auth=(cfg["account_sid"], cfg["auth_token"]),
            data={
                "From": f"whatsapp:{cfg['from_number']}",
                "To": f"whatsapp:{message.phone_e164}",
                "ContentSid": cfg["content_sid"],
                "ContentVariables": json.dumps(
                    {cfg.get("content_variable_key") or "1": message.code}
                ),
            },
        )
        return _twilio_result(self.provider, response)


def _twilio_result(provider: str, response: httpx.Response) -> SendResult:
    body = _json(response) or {}
    sid = body.get("sid") if isinstance(body, dict) else None
    if not sid:
        raise ProviderSendError("provider_rejected", f"{provider} returned no sid")
    return SendResult(provider, str(sid))


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------


class Ping4SmsOtpAdapter:
    """Ping4SMS: ``GET https://site.ping4sms.com/api/smsapi?key=&route=&sender=
    &number=&sms=&templateid=``. A numeric body is a message id unless it is
    one of the documented error codes 101-110.

    Docs: https://site.ping4sms.com/api/smsapi (the account's API page)
    """

    provider = "ping4sms"
    URL = "https://site.ping4sms.com/api/smsapi"
    ERRORS = {
        101: "Invalid user",
        102: "Invalid sender ID",
        103: "Invalid contact(s)",
        104: "Invalid route",
        105: "Invalid message",
        106: "Spam blocked",
        107: "Promotional block",
        108: "Low credits in the specified route",
        109: "Promotional route is only active 9am-8:45pm",
        110: "Invalid DLT Template ID",
    }

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        cfg = self.config
        params = {
            "key": cfg["api_key"],
            "route": cfg.get("route") or "4",
            "sender": cfg["sender_id"],
            "number": message.phone_digits,
            "sms": render_sms(cfg["message_template"], message.code),
            "templateid": cfg["dlt_template_id"],
        }
        if cfg.get("dlt_entity_id"):
            params["entityid"] = cfg["dlt_entity_id"]
        response = await _send(
            _client(self.ctx), self.provider, "GET", self.URL, params=params
        )
        text = _text(response).strip()
        if text.isdigit() and int(text) in self.ERRORS:
            code = int(text)
            raise ProviderSendError(
                "provider_auth_failed" if code == 101 else "provider_rejected",
                f"ping4sms {code}: {self.ERRORS[code]}",
                auth=code == 101,
            )
        if not text.isdigit():
            raise ProviderSendError("provider_rejected", f"ping4sms: {text[:200]}")
        return SendResult(self.provider, text)


class Msg91OtpAdapter:
    """MSG91 Flow: ``POST https://api.msg91.com/api/v5/flow/``, ``authkey``
    header, ``{flow_id, sender, recipients: [{mobiles, <VAR>: code}]}``. The
    DLT template, header and text live in the flow on MSG91's side. Success
    is ``{"type": "success", "message": <request id>}``.

    Docs: https://api.msg91.com/apidoc/textsms/send-sms-flow.php
    """

    provider = "msg91"
    URL = "https://api.msg91.com/api/v5/flow/"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        cfg = self.config
        payload: dict[str, Any] = {
            "flow_id": cfg["flow_id"],
            "recipients": [
                {
                    "mobiles": message.phone_digits,
                    cfg.get("otp_variable") or "VAR1": message.code,
                }
            ],
        }
        if cfg.get("sender_id"):
            payload["sender"] = cfg["sender_id"]
        response = await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            self.URL,
            headers={"authkey": cfg["auth_key"]},
            json=payload,
        )
        body = _json(response) or {}
        if str(body.get("type", "")).lower() != "success":
            message_text = str(body.get("message") or body)[:300]
            raise ProviderSendError(
                "provider_auth_failed"
                if "auth" in message_text.lower()
                else "provider_rejected",
                f"msg91: {message_text}",
                auth="auth" in message_text.lower(),
            )
        return SendResult(self.provider, str(body.get("message") or "") or None)


class ExotelOtpAdapter:
    """Exotel SMS: ``POST https://{subdomain}/v1/Accounts/{sid}/Sms/send.json``,
    Basic auth (API key, token), ``From/To/Body/DltEntityId/DltTemplateId``,
    ``SmsType=transactional``. Success returns ``SMSMessage.Sid``.

    Docs: https://developer.exotel.com/api/sms
    """

    provider = "exotel"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        cfg = self.config
        data = {
            "From": cfg["sender_id"],
            "To": message.phone_e164,
            "Body": render_sms(cfg["message_template"], message.code),
            "DltTemplateId": cfg["dlt_template_id"],
            "SmsType": "transactional",
        }
        if cfg.get("dlt_entity_id"):
            data["DltEntityId"] = cfg["dlt_entity_id"]
        response = await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            f"https://{cfg['subdomain']}/v1/Accounts/{cfg['account_sid']}/Sms/send.json",
            auth=(cfg["api_key"], cfg["api_token"]),
            data=data,
        )
        body = _json(response) or {}
        sid = (
            (body.get("SMSMessage") or {}).get("Sid")
            if isinstance(body, dict)
            else None
        )
        if not sid:
            raise ProviderSendError(
                "provider_rejected", "exotel returned no message Sid"
            )
        return SendResult(self.provider, str(sid))


class TwilioSmsOtpAdapter:
    """Twilio SMS: ``POST /2010-04-01/Accounts/{sid}/Messages.json`` with
    ``From/To/Body``. Success returns the message ``sid``.

    Docs: https://www.twilio.com/docs/sms/api
    """

    provider = "twilio"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        cfg = self.config
        response = await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            f"https://api.twilio.com/2010-04-01/Accounts/{cfg['account_sid']}/Messages.json",
            auth=(cfg["account_sid"], cfg["auth_token"]),
            data={
                "From": cfg["from_number"],
                "To": message.phone_e164,
                "Body": render_sms(cfg["message_template"], message.code),
            },
        )
        return _twilio_result(self.provider, response)


KALEYRA_DOMAINS = {
    "in": "api.in.kaleyra.io",
    "sg": "api.kaleyra.io",
    "eu": "api.eu.kaleyra.io",
}


class KaleyraOtpAdapter:
    """Kaleyra: ``POST https://<pod>/v1/<SID>/messages`` form-encoded,
    ``api-key`` header, ``to/type=OTP/sender/body/template_id`` (template id
    required for Indian traffic). Success returns an ``id``; errors carry a
    ``code`` and ``error``.

    Docs: https://developers.kaleyra.io/docs/send-otp-sms
    """

    provider = "kaleyra"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        cfg = self.config
        data = {
            "to": message.phone_e164,
            "type": "OTP",
            "sender": cfg["sender_id"],
            "body": render_sms(cfg["message_template"], message.code),
        }
        if cfg.get("dlt_template_id"):
            data["template_id"] = cfg["dlt_template_id"]
        response = await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            f"https://{KALEYRA_DOMAINS[cfg['region']]}/v1/{cfg['sid']}/messages",
            headers={"api-key": cfg["api_key"]},
            data=data,
        )
        body = _json(response) or {}
        if not isinstance(body, dict) or not body.get("id") or body.get("code"):
            raise ProviderSendError("provider_rejected", f"kaleyra: {str(body)[:300]}")
        return SendResult(self.provider, str(body["id"]))


class Fast2SmsOtpAdapter:
    """Fast2SMS DLT route: ``POST https://www.fast2sms.com/dev/bulkV2``,
    ``authorization: <API key>``, JSON ``{route: "dlt", sender_id, message:
    <DLT message id registered in Fast2SMS>, variables_values, numbers}``.
    Success is ``{"return": true, "request_id": ...}``.

    Docs: https://www.fast2sms.com/help/?p=17046 and https://docs.fast2sms.com/
    """

    provider = "fast2sms"
    URL = "https://www.fast2sms.com/dev/bulkV2"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        cfg = self.config
        response = await _send(
            _client(self.ctx),
            self.provider,
            "POST",
            self.URL,
            headers={"authorization": cfg["api_key"]},
            json={
                "route": "dlt",
                "sender_id": cfg["sender_id"],
                "message": cfg["message_id"],
                "variables_values": render_sms(
                    cfg.get("variables_values") or "{otp}", message.code
                ),
                "numbers": message.phone_10,
            },
        )
        body = _json(response) or {}
        if body.get("return") is not True:
            raise ProviderSendError("provider_rejected", f"fast2sms: {str(body)[:300]}")
        return SendResult(self.provider, str(body.get("request_id") or "") or None)


class TwoFactorOtpAdapter:
    """2Factor custom-OTP send: ``GET https://2factor.in/API/V1/{api_key}/SMS/
    {+phone}/{otp}/{template name}`` (template optional; the account default
    is used without it). Success is ``{"Status": "Success", "Details":
    <session id>}``; errors are ``{"Status": "Error", "Details": ...}``.

    Docs: https://documenter.getpostman.com/view/301893/TWDamFGh
    ("Send OTP ( Manual Generation )") and https://2factor.in/API/DOCS/SMS_OTP.html
    """

    provider = "twofactor"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    async def send_otp(self, message: OtpMessage) -> SendResult:
        cfg = self.config
        url = (
            f"https://2factor.in/API/V1/{quote(cfg['api_key'], safe='')}/SMS/"
            f"{quote(message.phone_e164, safe='')}/{quote(message.code, safe='')}"
        )
        if cfg.get("template_name"):
            url += "/" + quote(cfg["template_name"], safe="")
        response = await _send(_client(self.ctx), self.provider, "GET", url)
        body = _json(response) or {}
        if str(body.get("Status", "")).lower() != "success":
            details = str(body.get("Details") or body)[:300]
            raise ProviderSendError(
                "provider_auth_failed"
                if "api key" in details.lower()
                else "provider_rejected",
                f"2factor: {details}",
                auth="api key" in details.lower(),
            )
        return SendResult(self.provider, str(body.get("Details") or "") or None)


# ---------------------------------------------------------------------------
# Custom HTTP API: any vendor not listed above
# ---------------------------------------------------------------------------

PLACEHOLDERS = (
    "phone_e164",
    "phone_digits",
    "phone_10",
    "otp",
    "message",
    "template_name",
)
_PLACEHOLDER = re.compile(r"\{([a-z0-9_]+)\}")


def _values(message: OtpMessage, config: dict[str, Any]) -> dict[str, str]:
    return {
        "phone_e164": message.phone_e164,
        "phone_digits": message.phone_digits,
        "phone_10": message.phone_10,
        "otp": message.code,
        "message": render_sms(config["message_template"], message.code)
        if config.get("message_template")
        else message.text,
        "template_name": config.get("template_name") or "",
    }


def render_template(template: str, values: dict[str, str], escape) -> str:  # noqa: ANN001
    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise KeyError(name)
        return escape(values[name])

    return _PLACEHOLDER.sub(_sub, template)


def _json_escape(value: str) -> str:
    return json.dumps(value)[1:-1]


def _form_escape(value: str) -> str:
    return quote(value, safe="")


def _unknown_placeholders(text: str | None) -> list[str]:
    return sorted(
        {n for n in _PLACEHOLDER.findall(text or "") if n not in PLACEHOLDERS}
    )


_PATH_PART = re.compile(r"^([A-Za-z0-9_\-]+)?((?:\[\d+\])*)$")


def parse_json_path(path: str) -> list[str | int]:
    """``$.data[0].status`` / ``data.0.status`` -> ``["data", 0, "status"]``."""
    raw = path.strip()
    if raw.startswith("$"):
        raw = raw[1:].lstrip(".")
    if not raw:
        raise ValueError("empty path")
    out: list[str | int] = []
    for part in raw.split("."):
        match = _PATH_PART.match(part)
        if not match or (not match.group(1) and not match.group(2)):
            raise ValueError(f"bad path segment {part!r}")
        name, indexes = match.group(1), match.group(2)
        if name is not None:
            out.append(int(name) if name.isdigit() else name)
        out.extend(int(i) for i in re.findall(r"\[(\d+)\]", indexes))
    return out


def json_path_get(document: Any, path: list[str | int]) -> Any:
    current = document
    for step in path:
        if isinstance(step, int) and isinstance(current, list):
            if step >= len(current):
                return None
            current = current[step]
        elif isinstance(current, dict):
            current = current.get(str(step))
        else:
            return None
    return current


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


SAMPLE = OtpMessage("+919876543210", "123456", "Your code is 123456")


def _validate_custom(config: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    try:
        check_url_shape(config.get("url", ""))
    except UrlNotAllowedError as exc:
        errors["url"] = exc.reason
    for name in ("url", "body_template", "message_template"):
        unknown = _unknown_placeholders(config.get(name))
        if unknown:
            errors[name] = (
                "unknown placeholder "
                + ", ".join("{" + u + "}" for u in unknown)
                + "; use "
                + ", ".join("{" + p + "}" for p in PLACEHOLDERS)
            )
    for header in config.get("headers") or []:
        if _unknown_placeholders(header.get("value")):
            errors["headers"] = f"unknown placeholder in '{header['name']}'"
    body = config.get("body_template")
    content_type = config.get("content_type") or "json"
    if config.get("method") == "GET" and body:
        errors["body_template"] = "a GET request has no body; put values in the URL"
    if body and content_type == "json" and "body_template" not in errors:
        try:
            json.loads(render_template(body, _values(SAMPLE, config), _json_escape))
        except (ValueError, KeyError):
            errors["body_template"] = (
                "is not valid JSON once the placeholders are filled"
            )
    mode = config.get("success_mode") or "status_2xx"
    if mode == "json_path":
        if not config.get("success_json_path"):
            errors["success_json_path"] = "required for this success check"
        if config.get("success_value") in (None, ""):
            errors["success_value"] = "required for this success check"
    if mode == "regex":
        pattern = config.get("success_regex") or ""
        if not pattern:
            errors["success_regex"] = "required for this success check"
        elif len(pattern) > 200:
            errors["success_regex"] = "keep it under 200 characters"
        else:
            try:
                re.compile(pattern)
            except re.error:
                errors["success_regex"] = "is not a valid regular expression"
    for name in ("success_json_path", "message_id_path"):
        if config.get(name):
            try:
                parse_json_path(config[name])
            except ValueError:
                errors[name] = "use a path like data.0.id or $.status"
    carried = (
        (config.get("url") or "")
        + (body or "")
        + "".join(h.get("value", "") for h in config.get("headers") or [])
    )
    if "{otp}" not in carried and "{message}" not in carried:
        errors.setdefault(
            "body_template", "the request must carry {otp} or {message} somewhere"
        )
    return errors


async def _vet(url: str, ctx: AdapterContext) -> None:
    """Check the URL and its DNS answer before the request (the transport
    checks again on connect, against rebinding)."""
    try:
        host = check_url_shape(url)
        await asyncio.to_thread(
            vet_host,
            host,
            urlsplit(url).port or 443,
            resolver=ctx.resolver or system_resolver,
            settings=ctx.settings,
        )
    except UrlNotAllowedError as exc:
        raise ProviderSendError("url_not_allowed", exc.reason) from exc


class CustomHttpOtpAdapter:
    """Any HTTPS API the venue already has. The owner enters the URL and
    method, headers (secret values encrypted and write-only), a body
    template with ``{phone_e164} {phone_digits} {phone_10} {otp} {message}
    {template_name}``, and how success looks: any 2xx, a JSON path equal to a
    value, or a regex on the body; plus an optional message-id JSON path.

    Every request goes through :mod:`.http_guard`: https only, port 443, DNS
    resolved and every address checked (private, loopback, link-local, CGNAT
    refused) on each connect, no redirects, short timeouts.
    """

    provider = "custom_http"

    def __init__(self, config: dict[str, Any], ctx: AdapterContext) -> None:
        self.config = config
        self.ctx = ctx

    def build_request(self, message: OtpMessage) -> dict[str, Any]:
        cfg = self.config
        values = _values(message, cfg)
        url = render_template(cfg["url"], values, _form_escape)
        headers = {
            h["name"]: render_template(h["value"], values, lambda v: v)
            for h in cfg.get("headers") or []
        }
        request: dict[str, Any] = {
            "method": cfg.get("method") or "POST",
            "url": url,
            "headers": headers,
        }
        body = cfg.get("body_template")
        content_type = cfg.get("content_type") or "json"
        if body:
            if content_type == "json":
                request["content"] = render_template(body, values, _json_escape)
                headers.setdefault("Content-Type", "application/json")
            elif content_type == "form":
                request["content"] = render_template(body, values, _form_escape)
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                request["content"] = render_template(body, values, lambda v: v)
                headers.setdefault("Content-Type", "text/plain")
        return request

    def parse(self, response: httpx.Response) -> SendResult:
        cfg = self.config
        mode = cfg.get("success_mode") or "status_2xx"
        text = _text(response)
        document = _json(response)
        if mode == "json_path":
            actual = json_path_get(document, parse_json_path(cfg["success_json_path"]))
            if _as_text(actual).lower() != str(cfg["success_value"]).lower():
                raise ProviderSendError(
                    "provider_rejected",
                    f"custom_http: {cfg['success_json_path']} was "
                    f"{_as_text(actual)[:80]!r}, expected {cfg['success_value']!r}",
                )
        elif mode == "regex" and not re.search(cfg["success_regex"], text[:8192]):
            raise ProviderSendError(
                "provider_rejected",
                f"custom_http: success pattern not found in {text[:200]!r}",
            )
        message_id = None
        if cfg.get("message_id_path"):
            found = json_path_get(document, parse_json_path(cfg["message_id_path"]))
            message_id = _as_text(found)[:100] or None
        return SendResult(self.provider, message_id)

    async def send_otp(self, message: OtpMessage) -> SendResult:
        request = self.build_request(message)
        await _vet(request["url"], self.ctx)
        response = await _send(
            guarded_client(
                settings=self.ctx.settings,
                resolver=self.ctx.resolver or system_resolver,
                transport=self.ctx.transport,
            ),
            self.provider,
            request.pop("method"),
            request.pop("url"),
            **request,
        )
        return self.parse(response)


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

REGISTRY = Registry()

_TEMPLATE_NAME = FieldSpec(
    "template_name",
    "Template name",
    help="Your APPROVED authentication template (with a copy-code button).",
    placeholder="wifi_login_code",
    pattern=r"[a-z0-9_]{1,512}",
    pattern_message="lowercase letters, digits and underscores",
)
_TEMPLATE_LANGUAGE = FieldSpec(
    "template_language",
    "Template language",
    default="en",
    pattern=r"[a-z]{2,3}(_[A-Z]{2})?",
    pattern_message="a language code like en or en_US",
)

REGISTRY.register(
    AdapterSpec(
        key="meta_cloud",
        channel="whatsapp",
        display_name="WhatsApp Cloud API (Meta, direct)",
        docs_url="https://developers.facebook.com/docs/whatsapp/business-management-api/authentication-templates/copy-code-button-authentication-templates",
        fields=(
            FieldSpec(
                "phone_number_id",
                "Phone number id",
                pattern=DIGITS,
                pattern_message="digits only",
                help="WhatsApp Manager > API Setup.",
            ),  # noqa: E501
            FieldSpec(
                "waba_id",
                "WhatsApp Business Account id",
                pattern=DIGITS,
                pattern_message="digits only",
            ),  # noqa: E501
            FieldSpec(
                "access_token",
                "Access token",
                kind=KIND_SECRET,
                help="A System User token with whatsapp_business_messaging.",
            ),  # noqa: E501
            _TEMPLATE_NAME,
            _TEMPLATE_LANGUAGE,
        ),
        factory=MetaCloudOtpAdapter,
        sender_field="phone_number_id",
        notes="Needs an APPROVED template in the AUTHENTICATION category with a copy-code button.",  # noqa: E501
    )
)
REGISTRY.register(
    AdapterSpec(
        key="dialog360",
        channel="whatsapp",
        display_name="360dialog",
        docs_url="https://docs.360dialog.com/docs/messaging-api/api-reference/messages",
        fields=(
            FieldSpec("api_key", "API key (D360-API-KEY)", kind=KIND_SECRET),
            _TEMPLATE_NAME,
            _TEMPLATE_LANGUAGE,
        ),
        factory=Dialog360OtpAdapter,
        sender_field="template_name",
        notes="Needs an APPROVED AUTHENTICATION template with a copy-code button.",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="gupshup",
        channel="whatsapp",
        display_name="Gupshup",
        docs_url="https://docs.gupshup.io/docs/template-messages",
        fields=(
            FieldSpec("api_key", "API key", kind=KIND_SECRET),
            FieldSpec(
                "source_number",
                "Your WhatsApp number",
                pattern=r"\d{8,15}",
                pattern_message="digits with country code, no +",
                placeholder="919876543210",
            ),  # noqa: E501
            FieldSpec(
                "template_id",
                "Template id",
                help="The Gupshup id of your approved OTP template.",
                pattern=r"[A-Za-z0-9-]{1,100}",
                pattern_message="letters, digits and dashes",
            ),  # noqa: E501
        ),
        factory=GupshupOtpAdapter,
        sender_field="source_number",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="interakt",
        channel="whatsapp",
        display_name="Interakt",
        docs_url="https://interakt.shop/resource-center/how-to-send-whatsapp-templates-using-apis-webhooks",
        fields=(
            FieldSpec(
                "api_key",
                "API key",
                kind=KIND_SECRET,
                help="Developer Settings in Interakt.",
            ),  # noqa: E501
            _TEMPLATE_NAME,
            _TEMPLATE_LANGUAGE,
            FieldSpec(
                "country_code",
                "Country code",
                default="+91",
                pattern=r"\+\d{1,4}",
                pattern_message="like +91",
            ),  # noqa: E501
            FieldSpec(
                "copy_code_button",
                "Template has a copy-code button",
                kind=KIND_BOOLEAN,
                required=False,
                default=True,
            ),  # noqa: E501
        ),
        factory=InteraktOtpAdapter,
        sender_field="template_name",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="aisensy",
        channel="whatsapp",
        display_name="AiSensy",
        docs_url="https://aisensy.com/tutorials/api-reference-docs",
        fields=(
            FieldSpec("api_key", "API key", kind=KIND_SECRET),
            FieldSpec(
                "campaign_name",
                "API campaign name",
                help=(
                    "A Live API campaign on your approved OTP template; "
                    "the code fills its first variable."
                ),
            ),  # noqa: E501
        ),
        factory=AiSensyOtpAdapter,
        sender_field="campaign_name",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="wati",
        channel="whatsapp",
        display_name="WATI",
        docs_url="https://support.wati.io/en/articles/11463104-how-to-send-whatsapp-messages-via-wati-using-make-com-formerly-integromat",
        fields=(
            FieldSpec(
                "api_endpoint",
                "API endpoint",
                help="From WATI > API Docs, e.g. https://live-mt-server.wati.io/123456",
                placeholder="https://live-mt-server.wati.io/123456",
            ),  # noqa: E501
            FieldSpec("access_token", "Access token", kind=KIND_SECRET),
            _TEMPLATE_NAME,
            FieldSpec(
                "broadcast_name", "Broadcast name", required=False, default="wifi_login"
            ),  # noqa: E501
            FieldSpec(
                "parameter_name",
                "Code parameter name",
                required=False,
                default="1",
                help="The template variable the code fills.",
            ),  # noqa: E501
        ),
        factory=WatiOtpAdapter,
        validate=_validate_wati,
        sender_field="template_name",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="twilio",
        channel="whatsapp",
        display_name="Twilio WhatsApp",
        docs_url="https://www.twilio.com/docs/whatsapp/api",
        fields=(
            FieldSpec(
                "account_sid",
                "Account SID",
                pattern=r"AC[0-9a-fA-F]{32}",
                pattern_message="starts with AC",
            ),  # noqa: E501
            FieldSpec("auth_token", "Auth token", kind=KIND_SECRET),
            FieldSpec(
                "from_number",
                "WhatsApp sender",
                pattern=r"\+\d{8,15}",
                pattern_message="like +919876543210",
            ),  # noqa: E501
            FieldSpec(
                "content_sid",
                "Content template SID",
                pattern=r"HX[0-9a-fA-F]{32}",
                pattern_message="starts with HX",
            ),  # noqa: E501
            FieldSpec(
                "content_variable_key", "Code variable", required=False, default="1"
            ),
        ),
        factory=TwilioWhatsAppOtpAdapter,
        sender_field="from_number",
    )
)

REGISTRY.register(
    AdapterSpec(
        key="ping4sms",
        channel="sms",
        display_name="Ping4SMS",
        docs_url="https://site.ping4sms.com/api/smsapi",
        fields=(
            FieldSpec("api_key", "API key", kind=KIND_SECRET),
            FieldSpec(
                "route",
                "Route",
                default="4",
                options=("2", "4"),
                kind=KIND_SELECT,
                help="4 = Trans OTP, 2 = Transactional.",
            ),  # noqa: E501
            SENDER,
            DLT_ENTITY,
            DLT_TEMPLATE,
            MESSAGE_TEMPLATE,
        ),
        factory=Ping4SmsOtpAdapter,
        validate=_validate_sms_template,
        sender_field="sender_id",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="msg91",
        channel="sms",
        display_name="MSG91",
        docs_url="https://api.msg91.com/apidoc/textsms/send-sms-flow.php",
        fields=(
            FieldSpec("auth_key", "Auth key", kind=KIND_SECRET),
            FieldSpec(
                "flow_id",
                "Flow / template id",
                help="The MSG91 flow that holds your DLT OTP template.",
                pattern=r"[A-Za-z0-9]{1,64}",
                pattern_message="letters and digits",
            ),  # noqa: E501
            FieldSpec(
                "sender_id",
                "Sender id (if the flow uses FromAPI)",
                required=False,
                pattern=SENDER_ID,
                pattern_message="3-11 letters/digits",
            ),  # noqa: E501
            FieldSpec(
                "otp_variable",
                "Code variable in the flow",
                required=False,
                default="VAR1",
                pattern=r"[A-Za-z0-9_]{1,30}",
                pattern_message="letters, digits, _",
            ),  # noqa: E501
        ),
        factory=Msg91OtpAdapter,
        sender_field="flow_id",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="exotel",
        channel="sms",
        display_name="Exotel",
        docs_url="https://developer.exotel.com/api/sms",
        fields=(
            FieldSpec("api_key", "API key", kind=KIND_SECRET),
            FieldSpec("api_token", "API token", kind=KIND_SECRET),
            FieldSpec(
                "account_sid",
                "Account SID",
                pattern=r"[A-Za-z0-9_-]{1,64}",
                pattern_message="letters, digits, - and _",
            ),  # noqa: E501
            FieldSpec(
                "subdomain",
                "Region",
                kind=KIND_SELECT,
                options=("api.exotel.com", "api.in.exotel.com"),
                default="api.in.exotel.com",
            ),  # noqa: E501
            SENDER,
            DLT_ENTITY,
            DLT_TEMPLATE,
            MESSAGE_TEMPLATE,
        ),
        factory=ExotelOtpAdapter,
        validate=_validate_sms_template,
        sender_field="sender_id",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="twilio",
        channel="sms",
        display_name="Twilio SMS",
        docs_url="https://www.twilio.com/docs/sms/api",
        fields=(
            FieldSpec(
                "account_sid",
                "Account SID",
                pattern=r"AC[0-9a-fA-F]{32}",
                pattern_message="starts with AC",
            ),  # noqa: E501
            FieldSpec("auth_token", "Auth token", kind=KIND_SECRET),
            FieldSpec(
                "from_number",
                "From (number or sender id)",
                pattern=SENDER_ID,
                pattern_message="a number like +14155550100 or a sender id",
            ),  # noqa: E501
            MESSAGE_TEMPLATE,
        ),
        factory=TwilioSmsOtpAdapter,
        validate=_validate_sms_template,
        sender_field="from_number",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="kaleyra",
        channel="sms",
        display_name="Kaleyra",
        docs_url="https://developers.kaleyra.io/docs/send-otp-sms",
        fields=(
            FieldSpec("api_key", "API key", kind=KIND_SECRET),
            FieldSpec(
                "sid",
                "SID",
                pattern=r"[A-Za-z0-9]{1,64}",
                pattern_message="letters and digits",
            ),  # noqa: E501
            FieldSpec(
                "region",
                "Region",
                kind=KIND_SELECT,
                options=tuple(KALEYRA_DOMAINS),
                default="in",
            ),  # noqa: E501
            SENDER,
            FieldSpec(
                "dlt_template_id",
                "DLT template id",
                required=False,
                pattern=DIGITS,
                pattern_message="digits only",
                help="Required for Indian numbers.",
            ),  # noqa: E501
            MESSAGE_TEMPLATE,
        ),
        factory=KaleyraOtpAdapter,
        validate=_validate_sms_template,
        sender_field="sender_id",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="fast2sms",
        channel="sms",
        display_name="Fast2SMS",
        docs_url="https://www.fast2sms.com/help/?p=17046",
        fields=(
            FieldSpec("api_key", "API key", kind=KIND_SECRET),
            SENDER,
            FieldSpec(
                "message_id",
                "DLT message id in Fast2SMS",
                pattern=DIGITS,
                pattern_message="digits only",
                help="The id Fast2SMS shows for your approved OTP template.",
            ),  # noqa: E501
            FieldSpec(
                "variables_values",
                "Variable values",
                required=False,
                default="{otp}",
                help=(
                    "Values for the template's {#var#} slots, separated by |. "
                    "Use {otp} for the code."
                ),
            ),  # noqa: E501
        ),
        factory=Fast2SmsOtpAdapter,
        sender_field="sender_id",
        notes="Indian numbers only.",
    )
)
REGISTRY.register(
    AdapterSpec(
        key="twofactor",
        channel="sms",
        display_name="2Factor",
        docs_url="https://documenter.getpostman.com/view/301893/TWDamFGh",
        fields=(
            FieldSpec("api_key", "API key", kind=KIND_SECRET),
            FieldSpec(
                "template_name",
                "OTP template name",
                required=False,
                help="Leave empty to use your account's default OTP template.",
                pattern=r"[A-Za-z0-9_ -]{1,60}",
                pattern_message="letters, digits, spaces, - and _",
            ),  # noqa: E501
        ),
        factory=TwoFactorOtpAdapter,
        sender_field="template_name",
    )
)

_CUSTOM_FIELDS = (
    FieldSpec(
        "url",
        "URL",
        help="https only. Placeholders allowed, e.g. https://api.vendor.com/send?to={phone_digits}",
        placeholder="https://api.vendor.com/v1/otp",
    ),  # noqa: E501
    FieldSpec(
        "method",
        "Method",
        kind=KIND_SELECT,
        options=("POST", "GET", "PUT"),
        default="POST",
    ),  # noqa: E501
    FieldSpec(
        "headers",
        "Headers",
        kind=KIND_HEADERS,
        required=False,
        help="Mark API keys as secret: they are encrypted and never shown again.",
    ),  # noqa: E501
    FieldSpec(
        "content_type",
        "Body format",
        kind=KIND_SELECT,
        options=("json", "form", "text"),
        default="json",
    ),  # noqa: E501
    FieldSpec(
        "body_template",
        "Body",
        kind=KIND_TEXTAREA,
        required=False,
        max_length=4000,
        help=(
            "Placeholders: {phone_e164} {phone_digits} {phone_10} {otp} "
            "{message} {template_name}."
        ),
        placeholder='{"to": "{phone_e164}", "otp": "{otp}"}',
    ),  # noqa: E501
    FieldSpec(
        "message_template",
        "Message text",
        kind=KIND_TEXTAREA,
        required=False,
        max_length=1000,
        help="What {message} becomes. For SMS, your DLT-approved text with {otp}.",
    ),  # noqa: E501
    FieldSpec(
        "template_name",
        "Template name",
        required=False,
        help="What {template_name} becomes.",
    ),  # noqa: E501
    FieldSpec(
        "success_mode",
        "Success means",
        kind=KIND_SELECT,
        options=("status_2xx", "json_path", "regex"),
        default="status_2xx",
    ),  # noqa: E501
    FieldSpec(
        "success_json_path",
        "JSON path",
        required=False,
        placeholder="status or data.0.status",
    ),  # noqa: E501
    FieldSpec("success_value", "Equals", required=False, placeholder="success"),
    FieldSpec("success_regex", "Body matches (regex)", required=False, max_length=200),
    FieldSpec(
        "message_id_path",
        "Message id JSON path",
        required=False,
        placeholder="data.0.id",
    ),  # noqa: E501
)
for _channel in ("whatsapp", "sms"):
    REGISTRY.register(
        AdapterSpec(
            key="custom_http",
            channel=_channel,
            display_name="Custom HTTP API",
            docs_url="",
            fields=_CUSTOM_FIELDS,
            factory=CustomHttpOtpAdapter,
            validate=(
                (lambda c: {**_validate_custom(c), **_validate_sms_template(c)})
                if _channel == "sms"
                else _validate_custom
            ),
            sender_field="url",
            notes="For any vendor not listed. https only; private and internal addresses are refused.",  # noqa: E501
        )
    )


def build_adapter(
    channel: str, provider_type: str, config: dict[str, Any], ctx: AdapterContext
):
    spec = REGISTRY.get(channel, provider_type)
    if spec is None:
        raise ValueError(f"unsupported {channel} provider {provider_type!r}")
    return spec.factory(config, ctx)


__all__ = [
    "REGISTRY",
    "CustomHttpOtpAdapter",
    "MetaCloudOtpAdapter",
    "build_adapter",
    "json_path_get",
    "meta_auth_template_payload",
    "parse_json_path",
    "render_sms",
    "render_template",
]
