"""Bring-your-own marketing providers (spec §12).

A venue organization may plug in its own SMS, WhatsApp or email account per
channel. This module holds the pieces that do not depend on the database:

* the per-type config spec (required/optional/secret fields) and validation;
* masking: the ``display`` stub, which is the ONLY thing any API returns --
  non-secret fields verbatim plus ``{"set": bool, "hint": "…a1b2"}`` per
  secret (no characters at all for a secret shorter than 12);
* scrubbing provider error text of any echoed credential;
* encryption of the whole config (Fernet under ``router_encryption_key``),
  refused outside a developer machine while that key is the public default;
* the SMTP SSRF guard -- the host is customer supplied and our server
  connects to it, so every connect resolves the host and refuses loopback,
  private, link-local (incl. 169.254.169.254), CGNAT, multicast, reserved
  and configured VPC ranges, then connects to the vetted IP (no second DNS
  lookup to rebind);
* the own-provider sender adapters and the verify checks.

Secrets are decrypted only inside :func:`build_own_senders` / :func:`verify`
and never logged, never put in a Celery argument, never returned.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import smtplib
import socket
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.config import Settings, get_settings

from .constants import Channel
from .senders import ProviderResult, SendError, _classify_http_error

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10.0
SMTP_ALLOWED_PORTS = (25, 465, 587, 2525)
EXOTEL_SUBDOMAINS = ("api.exotel.com", "api.in.exotel.com")
META_GRAPH_BASE = "https://graph.facebook.com/v21.0"
HINT_MIN_LENGTH = 12

# ---------------------------------------------------------------------------
# Config specs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderSpec:
    channel: Channel
    provider_type: str
    display_name: str
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()
    secrets: tuple[str, ...] = ()
    sender_field: str | None = None

    @property
    def fields(self) -> tuple[str, ...]:
        return self.required + self.optional


PROVIDER_SPECS: dict[tuple[Channel, str], ProviderSpec] = {
    (Channel.SMS, "ping4sms"): ProviderSpec(
        Channel.SMS,
        "ping4sms",
        "Ping4SMS",
        required=("api_key", "route", "sender_id", "dlt_entity_id"),
        secrets=("api_key",),
        sender_field="sender_id",
    ),
    (Channel.SMS, "exotel"): ProviderSpec(
        Channel.SMS,
        "exotel",
        "Exotel",
        required=(
            "api_key",
            "api_token",
            "account_sid",
            "subdomain",
            "sender_id",
            "dlt_entity_id",
        ),
        secrets=("api_key", "api_token"),
        sender_field="sender_id",
    ),
    (Channel.EMAIL, "smtp"): ProviderSpec(
        Channel.EMAIL,
        "smtp",
        "SMTP",
        required=("host", "port", "username", "password", "from_address"),
        optional=("use_tls", "from_name", "reply_to"),
        secrets=("password",),
        sender_field="from_address",
    ),
    (Channel.EMAIL, "ses"): ProviderSpec(
        Channel.EMAIL,
        "ses",
        "Amazon SES",
        required=("access_key_id", "secret_access_key", "region", "from_address"),
        optional=("from_name", "configuration_set"),
        secrets=("access_key_id", "secret_access_key"),
        sender_field="from_address",
    ),
    (Channel.WHATSAPP, "meta_cloud"): ProviderSpec(
        Channel.WHATSAPP,
        "meta_cloud",
        "WhatsApp Cloud API",
        required=("phone_number_id", "waba_id", "access_token"),
        secrets=("access_token",),
        sender_field="display_phone_number",
    ),
}

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DIGITS = re.compile(r"^\d+$")
_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_SENDER_ID = re.compile(r"^[A-Za-z0-9]{3,11}$|^\+?\d{6,15}$")


class ProviderConfigError(ValueError):
    def __init__(self, fields: dict[str, str]) -> None:
        self.fields = fields
        super().__init__("; ".join(f"{k}: {v}" for k, v in fields.items()))


def spec_for(channel: Channel, provider_type: str) -> ProviderSpec | None:
    return PROVIDER_SPECS.get((channel, provider_type))


def normalize_config(spec: ProviderSpec, config: dict[str, Any]) -> dict[str, Any]:
    """Validate a *complete* config for ``spec``; returns the normalized dict
    or raises :class:`ProviderConfigError` naming every bad field."""
    errors: dict[str, str] = {}
    unknown = sorted(set(config) - set(spec.fields))
    for name in unknown:
        errors[name] = "unknown field for this provider"
    out: dict[str, Any] = {}
    for name in spec.fields:
        value = config.get(name)
        if isinstance(value, str):
            value = value.strip()
        if value in (None, ""):
            if name in spec.required:
                errors[name] = "required"
            continue
        out[name] = value
    _check = errors.setdefault
    if spec.provider_type == "smtp":
        try:
            port = int(out.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        if port not in SMTP_ALLOWED_PORTS:
            _check("port", "must be one of 25,465,587,2525")
        else:
            out["port"] = port
        if "use_tls" in out and not isinstance(out["use_tls"], bool):
            _check("use_tls", "must be true or false")
        out.setdefault("use_tls", True)
        host = str(out.get("host", ""))
        if host and (len(host) > 253 or not re.match(r"^[A-Za-z0-9.-]+$", host)):
            _check("host", "must be a hostname")
        for key in ("from_address", "reply_to"):
            if key in out and not _EMAIL.match(str(out[key])):
                _check(key, "must be an email address")
    if spec.provider_type == "ses":
        if "from_address" in out and not _EMAIL.match(str(out["from_address"])):
            _check("from_address", "must be an email address")
        if "region" in out and not _REGION.match(str(out["region"])):
            _check("region", "must be an AWS region, e.g. ap-south-1")
    if spec.provider_type in ("ping4sms", "exotel"):
        if "sender_id" in out and not _SENDER_ID.match(str(out["sender_id"])):
            _check("sender_id", "must be a DLT header (3-11 letters/digits)")
        if "dlt_entity_id" in out and not _DIGITS.match(str(out["dlt_entity_id"])):
            _check("dlt_entity_id", "must be digits")
    if (
        spec.provider_type == "exotel"
        and "subdomain" in out
        and out["subdomain"] not in EXOTEL_SUBDOMAINS
    ):
        _check("subdomain", "must be api.exotel.com or api.in.exotel.com")
    if spec.provider_type == "meta_cloud":
        for key in ("phone_number_id", "waba_id"):
            if key in out and not _DIGITS.match(str(out[key])):
                _check(key, "must be digits")
    for name in spec.fields:
        if name in out and not isinstance(out[name], bool | int | str):
            _check(name, "must be a string")
        if isinstance(out.get(name), str) and len(out[name]) > 2048:
            _check(name, "too long")
    if errors:
        raise ProviderConfigError(errors)
    return out


# ---------------------------------------------------------------------------
# Masking + scrubbing
# ---------------------------------------------------------------------------


def secret_hint(value: str | None) -> str:
    if not value or len(value) < HINT_MIN_LENGTH:
        return "…"
    return "…" + value[-4:]


def build_display(spec: ProviderSpec, config: dict[str, Any]) -> dict[str, Any]:
    display: dict[str, Any] = {}
    for name in spec.fields:
        if name in spec.secrets:
            value = config.get(name)
            display[name] = {"set": bool(value), "hint": secret_hint(value)}
        elif name in config:
            display[name] = config[name]
    return display


def scrub(message: str | None, config: dict[str, Any]) -> str | None:
    """Remove every configured value that could be a credential from a
    provider message (some providers echo the key back in errors)."""
    if message is None:
        return None
    text = str(message)
    for value in config.values():
        if isinstance(value, str) and len(value) >= 4:
            text = text.replace(value, "***")
    return text[:500]


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


class ProviderEncryptionUnavailableError(Exception):
    """Refusing to encrypt customer credentials under the public default
    ``router_encryption_key`` outside a developer machine."""


def uses_public_router_key(settings: Settings) -> bool:
    from app.core.config import INSECURE_LOCAL_DEV_FERNET_KEY

    return (
        not settings.is_local_environment
        and settings.router_encryption_key == INSECURE_LOCAL_DEV_FERNET_KEY
    )


def encrypt_config(config: dict[str, Any], *, settings: Settings | None = None) -> str:
    from app.domains.router.crypto import encrypt_secret

    app_settings = settings or get_settings()
    if uses_public_router_key(app_settings):
        logger.critical(
            "marketing_provider_secrets_refused_public_key",
            extra={
                "env_var": "CLOUDGUEST_ROUTER_ENCRYPTION_KEY",
                "environment": app_settings.environment,
            },
        )
        raise ProviderEncryptionUnavailableError()
    return encrypt_secret(json.dumps(config, sort_keys=True), settings=app_settings)


def decrypt_config(
    ciphertext: str, *, settings: Settings | None = None
) -> dict[str, Any]:
    from app.domains.router.crypto import decrypt_secret

    return json.loads(decrypt_secret(ciphertext, settings=settings))


def assert_provider_key_safe(settings: Settings) -> bool:
    """Startup check (called from the app lifespan). Returns False and logs
    CRITICAL when own-provider credentials could not be stored safely. Not a
    crash: an unrelated key must not take guest WiFi login down; writes are
    refused instead (``encrypt_config``)."""
    if uses_public_router_key(settings):
        logger.critical(
            "marketing_provider_encryption_key_is_public_default",
            extra={
                "env_var": "CLOUDGUEST_ROUTER_ENCRYPTION_KEY",
                "environment": settings.environment,
            },
        )
        return False
    return True


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_ALWAYS_BLOCKED = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    _CGNAT,
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("fd00:ec2::/32"),
)


class SmtpHostNotAllowedError(Exception):
    def __init__(self, host: str, reason: str) -> None:
        self.host = host
        self.reason = reason
        super().__init__(f"{host}: {reason}")


def _extra_blocked(settings: Settings | None) -> list[ipaddress._BaseNetwork]:
    raw = getattr(settings or get_settings(), "marketing_smtp_blocked_cidrs", "") or ""
    networks = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                networks.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
    return networks


def ip_is_blocked(ip: str, *, settings: Settings | None = None) -> bool:
    address = ipaddress.ip_address(ip)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return True
    return any(
        address in network
        for network in (*_ALWAYS_BLOCKED, *_extra_blocked(settings))
        if network.version == address.version
    )


Resolver = Callable[[str, int], list[str]]


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


def vet_smtp_host(
    host: str,
    port: int,
    *,
    resolver: Resolver = system_resolver,
    settings: Settings | None = None,
) -> str:
    """Resolve ``host`` and return the first address, refusing the host if
    ANY resolved address is internal (a mixed answer is a rebinding tell)."""
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            addresses = resolver(host, port)
        except OSError as exc:
            raise SmtpHostNotAllowedError(host, "does not resolve") from exc
    if not addresses:
        raise SmtpHostNotAllowedError(host, "does not resolve")
    for address in addresses:
        if ip_is_blocked(address, settings=settings):
            raise SmtpHostNotAllowedError(host, "resolves to a non-public address")
    return addresses[0]


class _GuardedSMTPMixin:
    """Connects to the vetted IP (resolved and checked on THIS connect),
    while TLS still verifies the certificate against the hostname."""

    _vet: Callable[[str, int], str]

    def _get_socket(self, host, port, timeout):  # noqa: ANN001
        ip = self._vet(host, port)
        sock = socket.create_connection((ip, port), timeout, self.source_address)
        if isinstance(self, smtplib.SMTP_SSL):
            return self.context.wrap_socket(sock, server_hostname=host)
        return sock


class GuardedSMTP(_GuardedSMTPMixin, smtplib.SMTP):
    def __init__(self, *args, vet, **kwargs) -> None:  # noqa: ANN001
        self._vet = vet
        super().__init__(*args, **kwargs)

    def starttls(self, *args, **kwargs):  # noqa: ANN001
        return super().starttls(*args, context=ssl.create_default_context())


class GuardedSMTP_SSL(_GuardedSMTPMixin, smtplib.SMTP_SSL):  # noqa: N801
    def __init__(self, *args, vet, **kwargs) -> None:  # noqa: ANN001
        self._vet = vet
        super().__init__(*args, context=ssl.create_default_context(), **kwargs)


# ---------------------------------------------------------------------------
# Own-provider senders
# ---------------------------------------------------------------------------


def _email_message(
    *,
    from_address: str,
    from_name: str | None,
    to: str,
    subject: str,
    html_body: str,
    headers: dict[str, str],
    reply_to: str | None,
):
    from email.message import EmailMessage
    from email.utils import formataddr, make_msgid

    from app.domains.otp.service import html_to_plain_text

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = (
        formataddr((from_name, from_address)) if from_name else from_address
    )
    message["To"] = to
    message["Message-ID"] = make_msgid(domain=from_address.rpartition("@")[2] or None)
    if reply_to:
        headers = {**headers, "Reply-To": reply_to}
    for name, value in headers.items():
        message[name] = value
    message.set_content(html_to_plain_text(html_body))
    message.add_alternative(html_body, subtype="html")
    return message


class GuardedSmtpEmailSender:
    """A venue's own SMTP server, connected through the SSRF guard."""

    provider = "smtp"

    def __init__(
        self, config: dict[str, Any], *, vet: Callable[[str, int], str]
    ) -> None:
        self._config = config
        self._vet = vet

    def _connect(self):
        cfg = self._config
        port = int(cfg["port"])
        cls = GuardedSMTP_SSL if port == 465 else GuardedSMTP
        smtp = cls(cfg["host"], port, timeout=_TIMEOUT_SECONDS, vet=self._vet)
        if port != 465 and cfg.get("use_tls", True):
            smtp.starttls()
        smtp.login(cfg["username"], cfg["password"])
        return smtp

    def check_sync(self) -> None:
        with self._connect():
            pass

    def _send_sync(self, email, subject, html_body, from_name, headers) -> str:  # noqa: ANN001
        cfg = self._config
        message = _email_message(
            from_address=cfg["from_address"],
            from_name=cfg.get("from_name") or from_name,
            to=email,
            subject=subject,
            html_body=html_body,
            headers=headers,
            reply_to=cfg.get("reply_to"),
        )
        with self._connect() as smtp:
            smtp.send_message(message)
        return message["Message-ID"]

    async def send(
        self, email, *, subject, html_body, from_name, headers
    ) -> ProviderResult:  # noqa: ANN001
        try:
            message_id = await asyncio.to_thread(
                self._send_sync, email, subject, html_body, from_name, headers
            )
        except SmtpHostNotAllowedError as exc:
            raise SendError(
                "smtp_host_not_allowed", str(exc), permanent=True, auth=True
            ) from exc
        except smtplib.SMTPAuthenticationError as exc:
            raise SendError(
                "provider_auth_failed", str(exc), permanent=True, auth=True
            ) from exc
        except smtplib.SMTPRecipientsRefused as exc:
            raise SendError(
                "hard_bounce", str(exc), permanent=True, suppress_reason="hard_bounce"
            ) from exc
        except (OSError, smtplib.SMTPException) as exc:
            raise SendError(
                "provider_error", str(exc) or type(exc).__name__, permanent=False
            ) from exc
        return ProviderResult(provider=self.provider, message_id=message_id)


class ByoSesEmailSender:
    """A venue's own SES account (SESv2, per-row credentials)."""

    provider = "ses"

    def __init__(self, config: dict[str, Any], *, client_factory=None) -> None:  # noqa: ANN001
        self._config = config
        self._client_factory = client_factory

    def client(self):
        if self._client_factory is not None:
            return self._client_factory(self._config)
        import boto3

        return boto3.client(
            "sesv2",
            aws_access_key_id=self._config["access_key_id"],
            aws_secret_access_key=self._config["secret_access_key"],
            region_name=self._config["region"],
        )

    def _send_sync(self, email, subject, html_body, from_name, headers) -> str | None:  # noqa: ANN001
        cfg = self._config
        message = _email_message(
            from_address=cfg["from_address"],
            from_name=cfg.get("from_name") or from_name,
            to=email,
            subject=subject,
            html_body=html_body,
            headers=headers,
            reply_to=None,
        )
        kwargs: dict[str, Any] = {
            "FromEmailAddress": cfg["from_address"],
            "Destination": {"ToAddresses": [email]},
            "Content": {"Raw": {"Data": message.as_bytes()}},
        }
        if cfg.get("configuration_set"):
            kwargs["ConfigurationSetName"] = cfg["configuration_set"]
        response = self.client().send_email(**kwargs)
        return response.get("MessageId")

    async def send(
        self, email, *, subject, html_body, from_name, headers
    ) -> ProviderResult:  # noqa: ANN001
        from .senders import is_email_auth_error

        try:
            message_id = await asyncio.to_thread(
                self._send_sync, email, subject, html_body, from_name, headers
            )
        except Exception as exc:  # noqa: BLE001
            if is_email_auth_error(exc):
                raise SendError(
                    "provider_auth_failed", str(exc), permanent=True, auth=True
                ) from exc
            code = ((getattr(exc, "response", None) or {}).get("Error") or {}).get(
                "Code"
            )
            if code == "MessageRejected":
                raise SendError(
                    "hard_bounce",
                    str(exc),
                    permanent=True,
                    suppress_reason="hard_bounce",
                ) from exc
            raise SendError(
                "provider_error", str(exc) or type(exc).__name__, permanent=False
            ) from exc
        if not message_id:
            raise SendError(
                "provider_rejected", "SES returned no MessageId", permanent=False
            )
        return ProviderResult(provider=self.provider, message_id=message_id)


class MetaCloudWhatsAppSender:
    """WhatsApp Cloud API (Graph ``POST /{phone_number_id}/messages``, type
    ``template``). Templates are addressed by name + language from the
    venue's own WABA; parameters are positional ``{{1}}..{{n}}``."""

    provider = "meta_cloud"
    _AUTH_CODES = {190, 102, 10, 200}
    _BAD_NUMBER_CODES = {131026, 131030}

    def __init__(
        self,
        config: dict[str, Any],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=_TIMEOUT_SECONDS,
            transport=self._transport,
            headers={"Authorization": f"Bearer {self._config['access_token']}"},
        )

    def _error(self, response: httpx.Response) -> SendError:
        try:
            error = response.json().get("error") or {}
        except ValueError:
            error = {}
        code = int(error.get("code") or 0)
        message = str(error.get("message") or response.text[:300])
        if code in self._AUTH_CODES or response.status_code in (401, 403):
            return SendError(
                "provider_auth_failed",
                f"Meta {code}: {message}",
                permanent=True,
                auth=True,
            )
        if code in self._BAD_NUMBER_CODES:
            return SendError(
                "invalid_number",
                f"Meta {code}: {message}",
                permanent=True,
                suppress_reason="invalid_number",
            )
        if (
            response.status_code == 429
            or response.status_code >= 500
            or code in (4, 80007, 130429, 131048, 131056)
        ):
            return SendError(
                f"meta_http_{response.status_code}",
                f"Meta {code}: {message}",
                permanent=False,
            )
        return SendError("provider_rejected", f"Meta {code}: {message}", permanent=True)

    async def get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            async with self._client() as client:
                response = await client.get(
                    path if path.startswith("http") else f"{META_GRAPH_BASE}/{path}",
                    params=params,
                )
        except httpx.HTTPError as exc:
            raise _classify_http_error(self.provider, exc) from exc
        if response.status_code >= 400:
            raise self._error(response)
        return response.json()

    async def send_waba_template(
        self,
        phone_e164: str,
        *,
        template_name: str,
        language: str,
        parameters: list[str],
    ) -> ProviderResult:
        payload: dict[str, Any] = {
            "messaging_product": "whatsapp",
            "to": phone_e164.lstrip("+"),
            "type": "template",
            "template": {"name": template_name, "language": {"code": language}},
        }
        if parameters:
            payload["template"]["components"] = [
                {
                    "type": "body",
                    "parameters": [{"type": "text", "text": p} for p in parameters],
                }
            ]
        try:
            async with self._client() as client:
                response = await client.post(
                    f"{META_GRAPH_BASE}/{self._config['phone_number_id']}/messages",
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise _classify_http_error(self.provider, exc) from exc
        if response.status_code >= 400:
            raise self._error(response)
        messages = (response.json() or {}).get("messages") or []
        message_id = messages[0].get("id") if messages else None
        if not message_id:
            raise SendError(
                "provider_rejected", "Meta returned no message id", permanent=False
            )
        return ProviderResult(provider=self.provider, message_id=message_id)

    async def list_templates(self) -> list[dict[str, Any]]:
        """Every template in the WABA (``GET /{waba_id}/message_templates``,
        following ``paging.next``)."""
        out: list[dict[str, Any]] = []
        url: str | None = f"{self._config['waba_id']}/message_templates"
        params: dict[str, Any] | None = {
            "fields": "name,language,status,category,components,parameter_format",
            "limit": 100,
        }
        for _ in range(50):  # hard page cap
            if url is None:
                break
            page = await self.get(url, params)
            out.extend(page.get("data") or [])
            url = ((page.get("paging") or {}).get("next")) or None
            params = None
        return out


@dataclass
class OwnSenders:
    """The adapter for one own-provider row, typed per channel."""

    provider_type: str
    sms: Any | None = None
    email: Any | None = None
    whatsapp: MetaCloudWhatsAppSender | None = None
    # Removes this row's configured values from provider error text before
    # anything is stored or returned.
    scrubber: Callable[[str | None], str | None] = lambda message: message


def build_own_senders(
    provider_type: str,
    config: dict[str, Any],
    *,
    settings: Settings | None = None,
    resolver: Resolver = system_resolver,
) -> OwnSenders:
    from .senders import ExotelSmsMarketingSender, Ping4SmsMarketingSender

    if provider_type == "ping4sms":
        return OwnSenders(
            provider_type,
            sms=Ping4SmsMarketingSender(
                api_key=config["api_key"],
                route=config["route"],
                sender_id=config["sender_id"],
                entity_id=config["dlt_entity_id"],
            ),
        )
    if provider_type == "exotel":
        return OwnSenders(
            provider_type,
            sms=ExotelSmsMarketingSender(
                api_key=config["api_key"],
                api_token=config["api_token"],
                account_sid=config["account_sid"],
                subdomain=config["subdomain"],
                from_number=config["sender_id"],
                entity_id=config["dlt_entity_id"],
            ),
        )
    if provider_type == "smtp":
        return OwnSenders(
            provider_type,
            email=GuardedSmtpEmailSender(
                config,
                vet=lambda host, port: vet_smtp_host(
                    host, port, resolver=resolver, settings=settings
                ),
            ),
        )
    if provider_type == "ses":
        return OwnSenders(provider_type, email=ByoSesEmailSender(config))
    if provider_type == "meta_cloud":
        return OwnSenders(provider_type, whatsapp=MetaCloudWhatsAppSender(config))
    raise ValueError(f"unsupported provider type {provider_type!r}")


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


@dataclass
class VerifyCheck:
    name: str
    ok: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


@dataclass
class VerifyResult:
    checks: list[VerifyCheck] = field(default_factory=list)
    display_phone_number: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(check.ok for check in self.checks)

    def first_error(self) -> str | None:
        return next((c.detail for c in self.checks if not c.ok), None)


TestSend = Callable[[], Awaitable[ProviderResult]]


async def _test_send_check(test_send: TestSend | None) -> VerifyCheck:
    if test_send is None:
        return VerifyCheck("test_send", True, "Skipped (no test recipient given).")
    try:
        result = await test_send()
    except SendError as exc:
        return VerifyCheck("test_send", False, f"{exc.code}: {exc.message}")
    return VerifyCheck(
        "test_send",
        True,
        f"Accepted by provider (id {result.message_id}). Check the device; "
        "acceptance is not delivery.",
    )


async def verify_provider(
    provider_type: str,
    config: dict[str, Any],
    senders: OwnSenders,
    *,
    test_send: TestSend | None,
) -> VerifyResult:
    """Real calls against the venue's provider. Every detail string is
    scrubbed of configured values before it is returned or stored."""
    result = VerifyResult()
    if provider_type in ("ping4sms", "exotel"):
        # Neither provider documents an account/balance API we can rely on,
        # so the credential check IS the test send (a DLT template to the
        # owner's phone): a wrong key fails it with an auth error.
        send = await _test_send_check(test_send)
        result.checks.append(
            VerifyCheck(
                "credentials",
                send.ok,
                "Accepted the API credentials" if send.ok else send.detail,
            )
        )
        result.checks.append(send)
    elif provider_type == "smtp":
        try:
            await asyncio.to_thread(senders.email.check_sync)
            result.checks.append(
                VerifyCheck("credentials", True, "Connected, TLS and AUTH succeeded")
            )
            result.checks.append(await _test_send_check(test_send))
        except SmtpHostNotAllowedError as exc:
            result.checks.append(
                VerifyCheck(
                    "credentials", False, f"smtp_host_not_allowed: {exc.reason}"
                )
            )
        except smtplib.SMTPAuthenticationError:
            result.checks.append(
                VerifyCheck(
                    "credentials",
                    False,
                    "The SMTP server rejected the username or password",
                )
            )
        except (OSError, smtplib.SMTPException) as exc:
            result.checks.append(
                VerifyCheck(
                    "credentials",
                    False,
                    f"Could not connect: {type(exc).__name__}: {exc}",
                )
            )
    elif provider_type == "ses":
        try:
            client = senders.email.client()
            await asyncio.to_thread(client.get_account)
            identity_ok = await asyncio.to_thread(
                _ses_identity_verified, client, config["from_address"]
            )
            result.checks.append(
                VerifyCheck("credentials", True, "SES account reachable")
            )
            result.checks.append(
                VerifyCheck(
                    "from_identity",
                    identity_ok,
                    "From address is a verified identity"
                    if identity_ok
                    else "From address (or its domain) is not a verified SES identity",
                )
            )
            if identity_ok:
                result.checks.append(await _test_send_check(test_send))
        except Exception as exc:  # noqa: BLE001
            result.checks.append(
                VerifyCheck("credentials", False, f"{type(exc).__name__}: {exc}")
            )
    elif provider_type == "meta_cloud":
        try:
            phone = await senders.whatsapp.get(
                config["phone_number_id"],
                {"fields": "display_phone_number,verified_name,quality_rating"},
            )
            await senders.whatsapp.get(config["waba_id"], {"fields": "id,name"})
            result.display_phone_number = phone.get("display_phone_number")
            result.checks.append(
                VerifyCheck(
                    "credentials",
                    True,
                    f"Number {phone.get('display_phone_number')} "
                    f"({phone.get('verified_name')}), "
                    f"quality {phone.get('quality_rating')}",
                )
            )
            result.checks.append(await _test_send_check(test_send))
        except SendError as exc:
            result.checks.append(VerifyCheck("credentials", False, exc.message))
    for check in result.checks:
        check.detail = scrub(check.detail, config) or ""
    return result


def _ses_identity_verified(client, from_address: str) -> bool:  # noqa: ANN001
    for identity in (from_address, from_address.rpartition("@")[2]):
        try:
            response = client.get_email_identity(EmailIdentity=identity)
        except Exception:  # noqa: BLE001 - NotFoundException etc.
            continue
        if response.get("VerifiedForSendingStatus"):
            return True
    return False


# ---------------------------------------------------------------------------
# WABA template helpers (BE-11b)
# ---------------------------------------------------------------------------

_POSITIONAL = re.compile(r"\{\{(\d+)\}\}")


def waba_template_body(template: dict[str, Any]) -> tuple[str | None, str | None]:
    """(body text, reason it cannot be synced). Only positional-parameter
    templates whose variables are all in the BODY and whose header, if any,
    is static text can be sent by this platform."""
    if (template.get("parameter_format") or "POSITIONAL").upper() != "POSITIONAL":
        return None, "named parameters are not supported"
    body: str | None = None
    for component in template.get("components") or []:
        kind = (component.get("type") or "").upper()
        if kind == "BODY":
            body = component.get("text") or ""
        elif kind == "HEADER":
            if (component.get("format") or "TEXT").upper() != "TEXT":
                return None, "media headers are not supported"
            if _POSITIONAL.search(component.get("text") or ""):
                return None, "header variables are not supported"
        elif kind == "BUTTONS":
            for button in component.get("buttons") or []:
                if _POSITIONAL.search(button.get("url") or "") or _POSITIONAL.search(
                    button.get("text") or ""
                ):
                    return None, "button variables are not supported"
    if body is None:
        return None, "template has no body"
    return body, None


def placeholder_count(body: str | None) -> int:
    if not body:
        return 0
    return len(set(_POSITIONAL.findall(body)))


__all__ = [
    "OwnSenders",
    "PROVIDER_SPECS",
    "ProviderConfigError",
    "ProviderEncryptionUnavailableError",
    "ProviderSpec",
    "SmtpHostNotAllowedError",
    "VerifyResult",
    "build_display",
    "build_own_senders",
    "decrypt_config",
    "encrypt_config",
    "ip_is_blocked",
    "normalize_config",
    "scrub",
    "secret_hint",
    "spec_for",
    "verify_provider",
    "vet_smtp_host",
]
