"""Marketing message senders -- contract §7.

These sit *alongside* the OTP providers in ``app.domains.otp.service``, never
in place of them, and read only the ``marketing_*`` settings block. Code
review rule from the spec (§10, "OTP collateral damage"): this module must
never call ``get_configured_sms_provider``, ``get_configured_whatsapp_provider``
or ``get_configured_email_provider`` -- each of those resolves the OTP
sender and, for email, silently falls back to the DEFAULT mailbox.

## No fake success

Every sender returns a :class:`ProviderResult` only after the provider has
answered 2xx; any other outcome raises :class:`SendError`, classified as
permanent or transient so the worker knows whether to retry. There is no
"logging" sender here: a marketing channel whose setting is ``logging`` or
``unconfigured`` resolves to *no sender at all*
(:func:`resolve_channel_status` reports why), and nothing is ever recorded
as submitted without a provider response.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

import httpx

from app.core.config import Settings
from app.domains.otp.service import (
    MailIdentity,
    SesEmailProvider,
    SmtpEmailProvider,
    resolve_smtp_identity,
)

from .constants import Channel, ChannelMode

_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    message_id: str | None


class SendError(Exception):
    """A provider refused or failed a send. ``permanent`` = do not retry
    (and, for an invalid address, suppress it); otherwise transient."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        permanent: bool,
        suppress_reason: str | None = None,
    ) -> None:
        self.code = code
        self.message = message[:500]
        self.permanent = permanent
        self.suppress_reason = suppress_reason
        super().__init__(f"{code}: {message}")


def _classify_http_error(provider: str, exc: Exception) -> SendError:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        body = exc.response.text[:300]
        if code == 429 or code >= 500:
            return SendError(f"{provider}_http_{code}", body, permanent=False)
        return SendError("provider_rejected", f"HTTP {code}: {body}", permanent=True)
    if isinstance(exc, httpx.TimeoutException | httpx.TransportError):
        return SendError(
            "provider_timeout", str(exc) or "transport error", permanent=False
        )
    return SendError("provider_error", str(exc), permanent=False)


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


class MarketingSmsSender(Protocol):
    provider: str

    async def send(
        self, phone_e164: str, body: str, *, dlt_template_id: str
    ) -> ProviderResult: ...


class MarketingWhatsAppSender(Protocol):
    provider: str

    async def send_template(
        self, phone_e164: str, *, content_sid: str, variables: dict[str, str]
    ) -> ProviderResult: ...


class MarketingEmailSender(Protocol):
    provider: str

    async def send(
        self,
        email: str,
        *,
        subject: str,
        html_body: str,
        from_name: str,
        headers: dict[str, str],
    ) -> ProviderResult: ...


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------


class Ping4SmsMarketingSender:
    """Ping4SMS with a per-message DLT template id and the promotional
    route/header (never the OTP route ``ping4sms_route``)."""

    provider = "ping4sms"
    _URL = "https://site.ping4sms.com/api/smsapi"
    _ERROR_CODES = {
        101: ("invalid_user", False),
        102: ("invalid_sender", False),
        103: ("invalid_number", True),
        104: ("invalid_route", False),
        105: ("invalid_message", False),
        106: ("spam_blocked", False),
        107: ("promotional_block", False),
        108: ("low_credits", False),
        109: ("promotional_window_closed", False),
        110: ("invalid_dlt_template", False),
    }

    def __init__(
        self, *, api_key: str, route: str, sender_id: str, entity_id: str
    ) -> None:
        self.api_key = api_key
        self.route = route
        self.sender_id = sender_id
        self.entity_id = entity_id

    async def send(
        self, phone_e164: str, body: str, *, dlt_template_id: str
    ) -> ProviderResult:
        params = {
            "key": self.api_key,
            "route": self.route,
            "sender": self.sender_id,
            "number": phone_e164.lstrip("+"),
            "sms": body,
            "templateid": dlt_template_id,
        }
        if self.entity_id:
            params["entityid"] = self.entity_id
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.get(self._URL, params=params)
                response.raise_for_status()
        except Exception as exc:  # noqa: BLE001 - classified below
            raise _classify_http_error(self.provider, exc) from exc
        text = response.text.strip()
        if text.isdigit():
            code = int(text)
            if code in self._ERROR_CODES:
                name, bad_number = self._ERROR_CODES[code]
                # Account/config errors are permanent for this message too
                # (retrying cannot fix a wrong route), but only a bad number
                # is suppressed.
                raise SendError(
                    name,
                    f"ping4sms error {code}",
                    permanent=True,
                    suppress_reason="invalid_number" if bad_number else None,
                )
            return ProviderResult(provider=self.provider, message_id=text)
        raise SendError("provider_rejected", f"ping4sms: {text[:200]}", permanent=True)


class ExotelSmsMarketingSender:
    """Exotel with a per-message DLT template id, the account credentials
    shared with OTP, and the marketing sender (never ``exotel_from_number``)."""

    provider = "exotel"

    def __init__(
        self,
        *,
        api_key: str,
        api_token: str,
        account_sid: str,
        subdomain: str,
        from_number: str,
        entity_id: str,
    ) -> None:
        self.api_key = api_key
        self.api_token = api_token
        self.account_sid = account_sid
        self.subdomain = subdomain
        self.from_number = from_number
        self.entity_id = entity_id

    async def send(
        self, phone_e164: str, body: str, *, dlt_template_id: str
    ) -> ProviderResult:
        url = f"https://{self.subdomain}/v1/Accounts/{self.account_sid}/Sms/send.json"
        data = {
            "From": self.from_number,
            "To": phone_e164,
            "Body": body,
            "DltTemplateId": dlt_template_id,
            "SmsType": "promotional",
        }
        if self.entity_id:
            data["DltEntityId"] = self.entity_id
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    url, auth=(self.api_key, self.api_token), data=data
                )
                response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            raise _classify_http_error(self.provider, exc) from exc
        try:
            payload = response.json()
            sid = payload.get("SMSMessage", {}).get("Sid")
        except (ValueError, AttributeError):
            sid = None
        if not sid:
            raise SendError(
                "provider_rejected", "exotel returned no message Sid", permanent=False
            )
        return ProviderResult(provider=self.provider, message_id=str(sid))


# ---------------------------------------------------------------------------
# WhatsApp
# ---------------------------------------------------------------------------


class TwilioWhatsAppMarketingSender:
    """Twilio Content API send of a Meta-approved MARKETING template:
    ``ContentSid`` + ``ContentVariables`` built from the template's
    ``whatsapp_variable_order``. Returns the Twilio message ``SM...`` sid."""

    provider = "twilio"
    _URL = "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    # Twilio error codes that mean "this number cannot receive WhatsApp".
    _BAD_NUMBER_CODES = {21211, 21614, 63003, 63024}

    def __init__(self, *, account_sid: str, auth_token: str, from_number: str) -> None:
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number

    async def send_template(
        self, phone_e164: str, *, content_sid: str, variables: dict[str, str]
    ) -> ProviderResult:
        data = {
            "From": f"whatsapp:{self.from_number}",
            "To": f"whatsapp:{phone_e164}",
            "ContentSid": content_sid,
            "ContentVariables": json.dumps(variables),
        }
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    self._URL.format(sid=self.account_sid),
                    auth=(self.account_sid, self.auth_token),
                    data=data,
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            error = _classify_http_error(self.provider, exc)
            try:
                twilio_code = int(exc.response.json().get("code") or 0)
            except (ValueError, AttributeError):
                twilio_code = 0
            if twilio_code in self._BAD_NUMBER_CODES:
                error.suppress_reason = "invalid_number"
                error.permanent = True
            raise error from exc
        except Exception as exc:  # noqa: BLE001
            raise _classify_http_error(self.provider, exc) from exc
        sid = (response.json() or {}).get("sid")
        if not sid:
            raise SendError(
                "provider_rejected", "twilio returned no message sid", permanent=False
            )
        return ProviderResult(provider=self.provider, message_id=str(sid))


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


class ProviderBackedEmailSender:
    """Wraps the existing SES/SMTP providers (with the additive ``headers``
    and ``from_name`` parameters). Only ever built from the MARKETING
    identity / ``marketing_email_*`` settings."""

    def __init__(
        self, provider_name: str, provider: SesEmailProvider | SmtpEmailProvider
    ) -> None:
        self.provider = provider_name
        self._provider = provider

    async def send(
        self,
        email: str,
        *,
        subject: str,
        html_body: str,
        from_name: str,
        headers: dict[str, str],
    ) -> ProviderResult:
        try:
            message_id = await self._provider.send(
                email, subject, html_body, headers=headers, from_name=from_name
            )
        except Exception as exc:  # noqa: BLE001
            text = str(exc)
            # smtplib.SMTPRecipientsRefused / SES MessageRejected are
            # hard rejects; everything else is retried.
            name = type(exc).__name__
            if name in {"SMTPRecipientsRefused", "MessageRejected"}:
                raise SendError(
                    "hard_bounce", text, permanent=True, suppress_reason="hard_bounce"
                ) from exc
            raise SendError("provider_error", text or name, permanent=False) from exc
        return ProviderResult(provider=self.provider, message_id=message_id)


# ---------------------------------------------------------------------------
# Resolution + channel status
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChannelStatus:
    channel: Channel
    configured: bool
    provider: str | None
    mode: ChannelMode
    reason: str | None
    requires_dlt_template_id: bool = False
    custom_templates_supported: bool = True

    def as_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "channel": self.channel.value,
            "configured": self.configured,
            "provider": self.provider,
            "mode": self.mode.value,
            "reason": self.reason,
        }
        if self.channel is Channel.SMS:
            data["requires_dlt_template_id"] = True
        data["custom_templates_supported"] = self.custom_templates_supported
        return data


@dataclass(frozen=True)
class MarketingSenders:
    sms: MarketingSmsSender | None
    whatsapp: MarketingWhatsAppSender | None
    email: MarketingEmailSender | None
    statuses: dict[Channel, ChannelStatus]

    def status(self, channel: Channel) -> ChannelStatus:
        return self.statuses[channel]


def _unconfigured(
    channel: Channel, provider: str | None, reason: str, *, logging_mode: bool = False
) -> ChannelStatus:
    return ChannelStatus(
        channel=channel,
        configured=False,
        provider=provider,
        mode=ChannelMode.LOGGING if logging_mode else ChannelMode.UNCONFIGURED,
        reason=reason,
        requires_dlt_template_id=channel is Channel.SMS,
        custom_templates_supported=channel is not Channel.WHATSAPP,
    )


def _live(channel: Channel, provider: str) -> ChannelStatus:
    return ChannelStatus(
        channel=channel,
        configured=True,
        provider=provider,
        mode=ChannelMode.LIVE,
        reason=None,
        requires_dlt_template_id=channel is Channel.SMS,
        custom_templates_supported=channel is not Channel.WHATSAPP,
    )


def _resolve_sms(settings: Settings) -> tuple[MarketingSmsSender | None, ChannelStatus]:
    choice = (settings.marketing_sms_provider or "unconfigured").lower()
    channel = Channel.SMS
    if choice == "logging":
        return None, _unconfigured(
            channel,
            None,
            "SMS provider is in logging mode; no messages would be delivered.",
            logging_mode=True,
        )
    if choice in ("", "unconfigured"):
        return None, _unconfigured(
            channel,
            None,
            "Marketing SMS is not set up (promotional DLT header required).",
        )
    sender_id = settings.marketing_sms_sender_id
    if not sender_id:
        return None, _unconfigured(
            channel, choice, "No promotional SMS header configured."
        )
    if choice == "ping4sms":
        if sender_id == settings.ping4sms_sender_id:
            return None, _unconfigured(
                channel, choice, "Marketing SMS header must not be the OTP header."
            )
        if not settings.ping4sms_api_key or not settings.marketing_ping4sms_route:
            return None, _unconfigured(
                channel, choice, "Ping4SMS key or promotional route is missing."
            )
        if settings.marketing_ping4sms_route == settings.ping4sms_route:
            return None, _unconfigured(
                channel,
                choice,
                "Marketing SMS must not use the OTP (transactional) route.",
            )
        return (
            Ping4SmsMarketingSender(
                api_key=settings.ping4sms_api_key,
                route=settings.marketing_ping4sms_route,
                sender_id=sender_id,
                entity_id=settings.marketing_dlt_entity_id,
            ),
            _live(channel, choice),
        )
    if choice == "exotel":
        if sender_id == settings.exotel_from_number:
            return None, _unconfigured(
                channel, choice, "Marketing SMS sender must not be the OTP sender."
            )
        if not (
            settings.exotel_api_key
            and settings.exotel_api_token
            and settings.exotel_account_sid
        ):
            return None, _unconfigured(
                channel, choice, "Exotel account credentials missing."
            )
        return (
            ExotelSmsMarketingSender(
                api_key=settings.exotel_api_key,
                api_token=settings.exotel_api_token,
                account_sid=settings.exotel_account_sid,
                subdomain=settings.exotel_subdomain,
                from_number=sender_id,
                entity_id=settings.marketing_dlt_entity_id,
            ),
            _live(channel, choice),
        )
    return None, _unconfigured(
        channel, choice, f"Unsupported marketing SMS provider '{choice}'."
    )


def _resolve_whatsapp(
    settings: Settings,
) -> tuple[MarketingWhatsAppSender | None, ChannelStatus]:
    choice = (settings.marketing_whatsapp_provider or "unconfigured").lower()
    channel = Channel.WHATSAPP
    if choice == "logging":
        return None, _unconfigured(
            channel,
            None,
            "WhatsApp provider is in logging mode; no messages would be delivered.",
            logging_mode=True,
        )
    if choice in ("", "unconfigured"):
        return None, _unconfigured(
            channel, None, "Marketing WhatsApp sender is not set up."
        )
    if choice != "twilio":
        return None, _unconfigured(
            channel, choice, f"Unsupported marketing WhatsApp provider '{choice}'."
        )
    number = settings.marketing_whatsapp_from_number
    if not number:
        return None, _unconfigured(
            channel, choice, "No marketing WhatsApp sender number."
        )
    if number == settings.whatsapp_twilio_from_number:
        return None, _unconfigured(
            channel, choice, "Marketing WhatsApp sender must not be the OTP number."
        )
    if not settings.twilio_account_sid or not settings.twilio_auth_token:
        return None, _unconfigured(
            channel, choice, "Twilio account credentials missing."
        )
    return (
        TwilioWhatsAppMarketingSender(
            account_sid=settings.twilio_account_sid,
            auth_token=settings.twilio_auth_token,
            from_number=number,
        ),
        _live(channel, choice),
    )


def _resolve_email(
    settings: Settings,
) -> tuple[MarketingEmailSender | None, ChannelStatus]:
    choice = (settings.marketing_email_provider or "unconfigured").lower()
    channel = Channel.EMAIL
    if choice == "logging":
        return None, _unconfigured(
            channel,
            None,
            "Email provider is in logging mode; no messages would be delivered.",
            logging_mode=True,
        )
    if choice in ("", "unconfigured"):
        return None, _unconfigured(
            channel, None, "Marketing email identity is not set up."
        )
    if choice == "ses":
        if not (
            settings.ses_access_key_id
            and settings.ses_secret_access_key
            and settings.marketing_email_from_address
        ):
            return None, _unconfigured(
                channel, choice, "SES credentials or marketing From address missing."
            )
        if settings.marketing_email_from_address in {
            settings.ses_from_address,
            settings.smtp_from_address,
            settings.admin_smtp_from_address,
            settings.admin_smtp_username,
        }:
            return None, _unconfigured(
                channel, choice, "Marketing mail must not use the OTP/admin mailbox."
            )
        return (
            ProviderBackedEmailSender(
                "ses",
                SesEmailProvider(
                    access_key_id=settings.ses_access_key_id,
                    secret_access_key=settings.ses_secret_access_key,
                    region_name=settings.ses_region,
                    from_address=settings.marketing_email_from_address,
                ),
            ),
            _live(channel, choice),
        )
    if choice == "smtp":
        # Resolved directly -- never via get_configured_email_provider, which
        # falls back to the DEFAULT mailbox.
        identity = resolve_smtp_identity(settings, MailIdentity.MARKETING)
        if identity is None:
            return None, _unconfigured(
                channel, choice, "marketing_smtp_* is missing or inconsistent."
            )
        forbidden = {
            settings.smtp_username,
            settings.admin_smtp_username,
            settings.smtp_from_address,
            settings.admin_smtp_from_address,
        } - {""}
        if identity.from_address in forbidden or identity.username in forbidden:
            return None, _unconfigured(
                channel, choice, "Marketing mail must not use the OTP/admin mailbox."
            )
        return (
            ProviderBackedEmailSender("smtp", SmtpEmailProvider(identity)),
            _live(channel, choice),
        )
    return None, _unconfigured(
        channel, choice, f"Unsupported marketing email provider '{choice}'."
    )


def resolve_marketing_senders(settings: Settings) -> MarketingSenders:
    sms, sms_status = _resolve_sms(settings)
    whatsapp, whatsapp_status = _resolve_whatsapp(settings)
    email, email_status = _resolve_email(settings)
    return MarketingSenders(
        sms=sms,
        whatsapp=whatsapp,
        email=email,
        statuses={
            Channel.SMS: sms_status,
            Channel.WHATSAPP: whatsapp_status,
            Channel.EMAIL: email_status,
        },
    )
