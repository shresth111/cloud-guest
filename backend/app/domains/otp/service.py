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
import functools
import hashlib
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from redis.asyncio import Redis

from app.core.config import Settings
from app.core.email_layout import (
    callout,
    code_block,
    esc,
    heading,
    html_to_plain_text,
    paragraph,
    render_email,
)
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


def _render_otp_email(*, intro: str, code: str, minutes: int) -> str:
    """The one-purpose OTP email: deliberately terse and urgent -- no
    onboarding warmth, no secondary content, just the code, what it's for,
    and how long it's valid. See ``app.core.email_layout``'s module
    docstring for the shared shell this composes into."""
    plural = "s" if minutes != 1 else ""
    content = (
        heading("Your verification code")
        + paragraph(esc(intro))
        + code_block(code)
        + callout(
            f"This code expires in <strong>{minutes} minute{plural}</strong>. "
            "Never share it with anyone -- Wyfy Guest will never ask you for it.",
            tone="warning",
        )
    )
    return render_email(
        preheader=f"Your Wyfy Guest verification code is {code}.",
        content_html=content,
        accent="#d97706",
    )


# ============================================================================
# Provider interfaces (composition point for a future real SMS/email
# integration -- see module docstring)
# ============================================================================


class SmsProviderProtocol(Protocol):
    async def send(self, phone_number: str, message: str) -> None: ...


@dataclasses.dataclass(frozen=True, slots=True)
class EmailAttachment:
    """A single file attachment for ``EmailProviderProtocol.send`` -- e.g.
    a generated invoice PDF (``app.domains.billing.router``'s
    ``generate_and_send_invoice`` endpoint attaches one this way). Optional
    on every implementation below -- every pre-existing caller (OTP,
    ``app.domains.notification``, ``app.domains.monitoring``) keeps sending
    plain text-only mail by simply omitting it; this is a purely additive,
    backward-compatible parameter."""

    filename: str
    content: bytes
    content_type: str = "application/octet-stream"


class EmailProviderProtocol(Protocol):
    async def send(
        self,
        email: str,
        subject: str,
        body: str,
        *,
        attachment: EmailAttachment | None = None,
    ) -> None: ...


class WhatsAppProviderProtocol(Protocol):
    """Deliberately takes both the raw ``code`` and the already-composed
    ``message`` -- unlike ``SmsProviderProtocol``'s plain ``message``-only
    shape, a real WhatsApp send needs the bare code on its own (to
    substitute into an approved Content Template's ``{{1}}`` placeholder;
    see ``TwilioWhatsAppProvider``'s docstring for why a freeform message
    body can't be sent the way SMS's can). ``message`` is still passed
    through so ``LoggingWhatsAppProvider`` (and any future provider that
    genuinely can send free text, e.g. within an already-open 24-hour
    session window) has it available without recomposing it itself."""

    async def send(self, phone_number: str, *, code: str, message: str) -> None: ...


class LoggingSmsProvider:
    """Honest interim SMS provider -- logs the would-be-sent message
    instead of calling a real carrier/gateway API. See module docstring.

    Logs the full ``message`` (which is how a real OTP code actually
    reaches an operator while no real SMS_DELIVERY_PROVIDER is configured
    yet -- see ``Settings.sms_delivery_provider``'s own docstring: this
    provider IS the intended fallback visibility mechanism, not a
    stand-in that happens to also work for that). Previously logged only
    ``message_length``, which meant nobody -- not even an operator with
    full log/DB access -- could ever read a code back once generated (the
    DB only ever stores ``hash_otp_code(code)``, one-way, same as a
    password); that made "logging mode" silently unusable as an actual
    fallback rather than the honest one its own docstring claims to be.

    The logged field is named ``sms_message``, not ``message`` --
    ``logging.Logger.makeRecord`` hard-rejects an ``extra`` key literally
    named ``message`` (and ``asctime``) with a ``KeyError``, since
    ``LogRecord`` assigns its own ``message`` attribute during formatting;
    passing that key crashed this call (and therefore every ``send``,
    i.e. every SMS OTP dispatch through this provider) the moment the
    root logger's level actually let an INFO record through, which is
    exactly production's configured level."""

    async def send(self, phone_number: str, message: str) -> None:
        logger.info(
            "otp_sms_would_send",
            extra={"phone_number": phone_number, "sms_message": message},
        )


class LoggingEmailProvider:
    """Honest interim email provider -- logs the would-be-sent message
    instead of calling a real transactional-email API. See module
    docstring, and ``LoggingSmsProvider``'s own docstring for why the full
    ``body`` (not just its length) is logged."""

    async def send(
        self,
        email: str,
        subject: str,
        body: str,
        *,
        attachment: EmailAttachment | None = None,
    ) -> None:
        logger.info(
            "otp_email_would_send",
            extra={
                "email": email,
                "subject": subject,
                "body": body,
                "attachment_filename": attachment.filename if attachment else None,
            },
        )


class LoggingWhatsAppProvider:
    """Honest interim WhatsApp provider -- logs the would-be-sent message
    instead of calling a real WhatsApp Business API. Same posture as
    ``LoggingSmsProvider``/``LoggingEmailProvider`` above (including
    logging the full message/code, not just a length -- see
    ``LoggingSmsProvider``'s own docstring for why), and the default for a
    fresh checkout (``Settings.whatsapp_delivery_provider == 'logging'``).

    The logged field is named ``whatsapp_message``, not ``message`` --
    see ``LoggingSmsProvider``'s own docstring for why the bare key
    ``message`` in ``extra`` crashes ``logging.Logger.makeRecord`` with a
    ``KeyError`` (this provider had the identical bug)."""

    async def send(self, phone_number: str, *, code: str, message: str) -> None:
        logger.info(
            "otp_whatsapp_would_send",
            extra={
                "phone_number": phone_number,
                "code": code,
                "whatsapp_message": message,
            },
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


class WhatsAppProviderNotConfiguredError(Exception):
    """Same as :class:`EmailProviderNotConfiguredError`, for
    ``Settings.whatsapp_delivery_provider``."""


class MailIdentityMismatchError(Exception):
    """Raised when a :class:`SmtpIdentity` would be built with a ``From``
    address belonging to a different account than the one its credentials
    authenticate as.

    This is not a theoretical guard. This platform has twice shipped a
    configuration that authenticated as one Zoho mailbox while claiming to
    send as another; Zoho answers that with ``553 Sender is not allowed to
    relay emails``, which reads at a glance like a credential problem and
    costs an evening to find. An identity is a username, a password and a
    From address *together* -- so the only way to build one is through this
    class, and this class refuses to hold a mismatched pair."""


class MailIdentity(StrEnum):
    """Which real mailbox a given outgoing message is sent from.

    Outgoing mail on this platform is split across two mailboxes on
    purpose. To answer "which mailbox does flow X come from?":

    * flows sent directly by a service (guest OTP, quotations,
      channel-partner welcome) name their identity at the point where
      their ``EmailProviderProtocol`` is built -- grep for
      ``get_configured_email_provider(`` and read the ``identity=``
      argument;
    * flows that go through the ``app.domains.notification`` outbox
      (password reset, new-location welcome, demo-request notification)
      are routed by event type in
      ``app.domains.notification.constants.MAIL_IDENTITY_BY_EVENT_TYPE``.

    Members:

    ``DEFAULT``
        The general ``Settings.smtp_*`` block. ``sales@wyfyguest.com`` in
        production, which is where quotations, channel-partner welcomes and
        demo-request notifications should come from -- and also, unchanged,
        every other sender in this codebase that never asked for a specific
        identity (monitoring alerts, user invites, voucher exports,
        subscription reminders).

    ``ADMIN``
        The ``Settings.admin_smtp_*`` block. ``admin@wyfyguest.com`` in
        production: guest OTP, password reset, new-location welcome. Falls
        back to ``DEFAULT`` -- loudly, see
        :func:`get_configured_email_provider` -- when that block is not
        configured, so an unconfigured second mailbox degrades to exactly
        today's behavior rather than failing.

    Note there is no ``INVOICE`` member: invoice mail has its own
    long-standing ``Settings.invoice_smtp_*`` block and its own selection
    function in ``app.domains.billing.router``. It resolves through the
    same :class:`SmtpIdentity` value object, so it gets the same
    From/credentials guarantee, but it is not part of this routing table
    and nothing here changes it.
    """

    DEFAULT = "default"
    ADMIN = "admin"


@dataclasses.dataclass(frozen=True, slots=True)
class SmtpIdentity:
    """One complete SMTP sending identity: the server to connect to, the
    account the connection authenticates as, and the address it sends as --
    inseparable, by construction.

    ``SmtpEmailProvider`` takes one of these and nothing else, so there is
    no code path anywhere that can hand a provider a ``from_address`` from
    one mailbox and a ``username``/``password`` from another: the two are
    not separate arguments to begin with. See
    :class:`MailIdentityMismatchError` for the production failures this
    exists to make unrepresentable.

    Build one with :meth:`from_settings_block`, never field-by-field from
    scattered settings reads.
    """

    host: str
    port: int
    username: str
    password: str
    use_tls: bool
    from_address: str
    label: str = "smtp"

    def __post_init__(self) -> None:
        if not self.host:
            raise MailIdentityMismatchError(
                f"{self.label}: host is empty -- an identity with no server "
                "cannot send."
            )
        if self.username and self.from_address != self.username:
            raise MailIdentityMismatchError(
                f"{self.label}: refusing to send as {self.from_address!r} "
                f"while authenticating as {self.username!r}. A From address "
                "must belong to the account whose credentials are used; "
                "Zoho rejects the mismatch with '553 Sender is not allowed "
                "to relay emails'. Configure both halves of one mailbox, or "
                "leave the From empty to default to the username."
            )
        if not self.from_address:
            raise MailIdentityMismatchError(
                f"{self.label}: no From address and no username to derive "
                "one from."
            )

    @classmethod
    def from_settings_block(
        cls,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        use_tls: bool,
        from_address: str,
        label: str,
    ) -> SmtpIdentity:
        """Builds an identity from the six fields of **one**
        ``Settings`` ``*_smtp_*`` block.

        Every caller passes all six from the same block -- that is the
        whole point, and why this is a classmethod on the value object
        rather than six keyword arguments spread across each call site. An
        empty ``from_address`` defaults to ``username``: an account sends
        as itself unless deliberately told otherwise.
        """
        return cls(
            host=host,
            port=port,
            username=username,
            password=password,
            use_tls=use_tls,
            from_address=from_address or username,
            label=label,
        )


def smtp_host_setting_for(settings: Settings, identity: MailIdentity) -> str:
    """The ``*_smtp_host`` setting backing ``identity`` -- the one field
    that answers "was this mailbox configured at all?", as distinct from
    "was it configured correctly?"."""
    if identity is MailIdentity.ADMIN:
        return settings.admin_smtp_host
    return settings.smtp_host


def resolve_smtp_identity(
    settings: Settings, identity: MailIdentity
) -> SmtpIdentity | None:
    """The one place that maps a :class:`MailIdentity` onto its
    ``Settings`` block. Returns ``None`` when that identity is not usable
    -- either no server is configured for it, or its settings describe a
    mailbox that cannot legally send as itself. The caller decides what
    falling back means.

    Each branch reads six fields from a single block and nothing else, so
    a cross-mailbox mixture is not expressible here either.

    A :class:`MailIdentityMismatchError` is caught and turned into
    ``None``+ERROR rather than propagating: a hand-edited ``.env`` that
    pairs ``admin@``'s username with ``sales@``'s From must not take down
    guest OTP with a 500. Unusable means unusable; ADMIN then degrades to
    the DEFAULT mailbox (which works) and DEFAULT raises
    ``EmailProviderNotConfiguredError`` exactly as an empty ``smtp_host``
    already does. Either way the misconfiguration is logged at ERROR with
    the offending block named, and no mail is ever sent from a mailbox we
    did not authenticate as.
    """
    try:
        if identity is MailIdentity.ADMIN:
            if not settings.admin_smtp_host:
                return None
            return SmtpIdentity.from_settings_block(
                host=settings.admin_smtp_host,
                port=settings.admin_smtp_port,
                username=settings.admin_smtp_username,
                password=settings.admin_smtp_password,
                use_tls=settings.admin_smtp_use_tls,
                from_address=settings.admin_smtp_from_address,
                label="admin_smtp",
            )
        if not settings.smtp_host:
            return None
        return SmtpIdentity.from_settings_block(
            host=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            use_tls=settings.smtp_use_tls,
            from_address=settings.smtp_from_address,
            label="smtp",
        )
    except MailIdentityMismatchError as exc:
        logger.error(
            "email_identity_invalid",
            extra={"identity": identity.value, "error": str(exc)},
        )
        return None


class SmtpEmailProvider:
    """Real ``EmailProviderProtocol`` implementation: sends via any
    standard SMTP server (SendGrid, Mailgun, Postmark, AWS SES's own SMTP
    interface, or a plain relay) using stdlib ``smtplib``/``email`` --
    zero new dependencies. ``smtplib`` is synchronous; ``send`` bridges it
    through ``asyncio.to_thread``, the same sync-in-async bridge
    ``app.core.storage.S3ObjectStorage`` uses for boto3.

    Takes exactly one argument -- a :class:`SmtpIdentity` -- deliberately.
    It used to take ``host``/``port``/``username``/``password``/``use_tls``/
    ``from_address`` as six independent keyword arguments, which made
    "authenticate as A, send as B" a one-line typo away at every call site.

    ``body`` is expected to be the real, branded HTML every caller now
    builds via ``app.core.email_layout.render_email`` (see that module's
    docstring). ``set_content``/``add_alternative`` below composes a real
    ``multipart/alternative`` message -- a derived plain-text part (via
    ``html_to_plain_text``) plus the HTML part -- so a client that prefers
    or requires plain text (and any scanner/preview that strips HTML)
    still gets a readable message, not a raw tag soup."""

    def __init__(self, identity: SmtpIdentity) -> None:
        self.identity = identity

    # Read-only passthroughs. They exist so this class still reads like a
    # plain SMTP client at the point of use (``self.host``, ``self.port``)
    # while the only *writable* representation of "who am I sending as" is
    # the single frozen identity above -- there is no setter, and no
    # constructor argument, that can move `from_address` away from the
    # credentials it was validated against.
    @property
    def host(self) -> str:
        return self.identity.host

    @property
    def port(self) -> int:
        return self.identity.port

    @property
    def username(self) -> str:
        return self.identity.username

    @property
    def password(self) -> str:
        return self.identity.password

    @property
    def use_tls(self) -> bool:
        return self.identity.use_tls

    @property
    def from_address(self) -> str:
        return self.identity.from_address

    def _send_sync(
        self,
        email: str,
        subject: str,
        body: str,
        *,
        attachment: EmailAttachment | None = None,
    ) -> None:
        import smtplib
        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.from_address
        message["To"] = email
        message.set_content(html_to_plain_text(body))
        message.add_alternative(body, subtype="html")
        if attachment is not None:
            maintype, _, subtype = attachment.content_type.partition("/")
            message.add_attachment(
                attachment.content,
                maintype=maintype or "application",
                subtype=subtype or "octet-stream",
                filename=attachment.filename,
            )

        smtp_class = smtplib.SMTP_SSL if self.port == 465 else smtplib.SMTP
        with smtp_class(self.host, self.port, timeout=10) as smtp:
            if self.use_tls and self.port != 465:
                smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(message)

    async def send(
        self,
        email: str,
        subject: str,
        body: str,
        *,
        attachment: EmailAttachment | None = None,
    ) -> None:
        await asyncio.to_thread(
            self._send_sync, email, subject, body, attachment=attachment
        )


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

    def _send_sync(
        self,
        email: str,
        subject: str,
        body: str,
        *,
        attachment: EmailAttachment | None = None,
    ) -> None:
        if attachment is None:
            self._client.send_email(
                Source=self.from_address,
                Destination={"ToAddresses": [email]},
                Message={
                    "Subject": {"Data": subject},
                    "Body": {
                        "Html": {"Data": body},
                        "Text": {"Data": html_to_plain_text(body)},
                    },
                },
            )
            return

        # An attachment needs a real MIME multipart body -- SES's plain
        # ``send_email`` API has no attachment field at all, so this branch
        # composes the identical stdlib ``EmailMessage`` :class:`SmtpEmailProvider`
        # builds above (including its own HTML + derived-plain-text
        # ``multipart/alternative`` pair) and ships it via SES's raw-message
        # API instead.
        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.from_address
        message["To"] = email
        message.set_content(html_to_plain_text(body))
        message.add_alternative(body, subtype="html")
        maintype, _, subtype = attachment.content_type.partition("/")
        message.add_attachment(
            attachment.content,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=attachment.filename,
        )
        self._client.send_raw_email(
            Source=self.from_address,
            Destinations=[email],
            RawMessage={"Data": message.as_bytes()},
        )

    async def send(
        self,
        email: str,
        subject: str,
        body: str,
        *,
        attachment: EmailAttachment | None = None,
    ) -> None:
        await asyncio.to_thread(
            self._send_sync, email, subject, body, attachment=attachment
        )


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


class TwilioWhatsAppProvider:
    """Real ``WhatsAppProviderProtocol`` implementation via Twilio's
    WhatsApp Business API -- the *same* Messages API endpoint and Account
    SID/Auth Token :class:`TwilioSmsProvider` above already uses
    (https://www.twilio.com/docs/whatsapp/api: "WhatsApp messages ... use
    the same Messages resource as SMS", just a ``whatsapp:`` prefix on
    ``From``/``To``) -- a natural, low-effort extension of the existing
    Twilio integration, not a second provider account with its own
    credential set.

    **The one real constraint that makes this genuinely different from a
    plain SMS send, not just a prefix swap:** WhatsApp Business API
    requires every *business-initiated* message to use a pre-approved
    Content Template (https://www.twilio.com/docs/content) unless it falls
    inside a 24-hour customer-service session window opened by the *guest*
    messaging this WhatsApp number first. An OTP send is never that --
    the guest has never messaged this number before; this is always the
    first, business-initiated contact -- so sending a freeform ``Body``
    the way :class:`TwilioSmsProvider` does would be silently rejected by
    WhatsApp. This provider therefore sends via Twilio's Content API
    fields, ``ContentSid`` (the Twilio-Console-registered SID of a
    Meta-approved template, e.g. one reading "Your CloudGuest code is
    {{1}}") and ``ContentVariables`` (a JSON object substituting the real
    OTP code into that template's ``{{1}}`` placeholder), instead of
    ``Body``. A real deployment must create that template in the Twilio
    Console and get it approved by Meta *before* any send here can
    succeed -- ``get_configured_whatsapp_provider`` below raises a clear,
    honest error if ``whatsapp_twilio_content_sid`` is left unset rather
    than silently attempting (and failing) a freeform send."""

    _API_URL_TEMPLATE = (
        "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    )
    _TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        *,
        account_sid: str,
        auth_token: str,
        from_number: str,
        content_sid: str,
        content_variable_key: str = "1",
    ) -> None:
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number
        self.content_sid = content_sid
        self.content_variable_key = content_variable_key

    async def send(self, phone_number: str, *, code: str, message: str) -> None:
        import httpx

        url = self._API_URL_TEMPLATE.format(sid=self.account_sid)
        data = {
            "From": f"whatsapp:{self.from_number}",
            "To": f"whatsapp:{phone_number}",
            "ContentSid": self.content_sid,
            "ContentVariables": json.dumps({self.content_variable_key: code}),
        }
        async with httpx.AsyncClient(timeout=self._TIMEOUT_SECONDS) as client:
            response = await client.post(
                url, auth=(self.account_sid, self.auth_token), data=data
            )
            response.raise_for_status()


class ExotelSmsProvider:
    """Real ``SmsProviderProtocol`` implementation: a plain
    ``httpx.AsyncClient`` POST to Exotel's documented SMS API
    (https://developer.exotel.com/api/sms), HTTP Basic auth with
    ``api_key``/``api_token`` per Exotel's own convention (mirrors
    :class:`TwilioSmsProvider`'s identical "real, documented third-party
    API" bar).

    ``dlt_entity_id``/``dlt_template_id`` are TRAI DLT compliance fields,
    mandatory for any transactional SMS to an Indian number -- when set,
    they're forwarded as-is; the caller (``OtpService``) is responsible
    for composing ``message`` to match the DLT-approved template's exact
    text, since carriers silently drop a body that doesn't match."""

    _TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        *,
        api_key: str,
        api_token: str,
        account_sid: str,
        from_number: str,
        subdomain: str,
        dlt_entity_id: str = "",
        dlt_template_id: str = "",
    ) -> None:
        self.api_key = api_key
        self.api_token = api_token
        self.account_sid = account_sid
        self.from_number = from_number
        self.subdomain = subdomain
        self.dlt_entity_id = dlt_entity_id
        self.dlt_template_id = dlt_template_id

    async def send(self, phone_number: str, message: str) -> None:
        import httpx

        url = f"https://{self.subdomain}/v1/Accounts/{self.account_sid}/Sms/send"
        data = {"From": self.from_number, "To": phone_number, "Body": message}
        if self.dlt_entity_id:
            data["DltEntityId"] = self.dlt_entity_id
        if self.dlt_template_id:
            data["DltTemplateId"] = self.dlt_template_id
        async with httpx.AsyncClient(timeout=self._TIMEOUT_SECONDS) as client:
            response = await client.post(
                url, auth=(self.api_key, self.api_token), data=data
            )
            response.raise_for_status()


@functools.lru_cache(maxsize=32)
def warn_email_identity_fallback(
    requested_identity: str, email_delivery_provider: str, reason: str
) -> None:
    """Logs, at WARNING, that a named mail identity was asked for and could
    not be honoured, so its mail is going out from the ``DEFAULT`` mailbox
    instead.

    Memoized on purpose. Provider selection happens per request (it is a
    FastAPI dependency), and a guest-OTP-per-warning firehose is how a
    warning stops being read -- which is the exact failure mode that let
    ``535 Authentication Failed`` run unnoticed for days here. One WARNING
    per distinct (identity, provider, reason) per process: loud on the
    first send after every restart, silent thereafter.

    ``warn_email_identity_fallback.cache_clear()`` re-arms it (tests do
    this; nothing in production needs to).
    """
    logger.warning(
        "email_identity_fallback",
        extra={
            "requested_identity": requested_identity,
            "fallback_identity": MailIdentity.DEFAULT.value,
            "email_delivery_provider": email_delivery_provider,
            "reason": reason,
        },
    )


def get_configured_email_provider(
    settings: Settings, *, identity: MailIdentity = MailIdentity.DEFAULT
) -> EmailProviderProtocol:
    """Selects the real ``EmailProviderProtocol`` implementation
    ``Settings.email_delivery_provider`` names, or :class:`LoggingEmailProvider`
    if unset/``"logging"``. Shared by this domain's own ``dependencies.py``,
    ``app.domains.monitoring``'s ``NotificationService`` wiring, and
    ``app.domains.notification`` -- one place to add a new provider, not
    three copies of the same selection logic.

    ``identity`` names which mailbox the caller sends as (see
    :class:`MailIdentity`). It defaults to ``DEFAULT``, so every call site
    that does not care keeps behaving exactly as it did before this
    parameter existed.

    ``MailIdentity.ADMIN`` resolves to its own ``admin_smtp_*`` mailbox
    only when two things are true: ``email_delivery_provider`` is
    ``'smtp'`` (a checkout in ``'logging'`` mode must not start sending
    real mail just because a second mailbox happens to be configured, and
    ``'ses'`` has no per-message credentials for a second identity to use),
    and ``admin_smtp_host`` is set. Otherwise it falls back to the
    ``DEFAULT`` identity and logs ``email_identity_fallback`` at WARNING --
    the fallback is today's working behavior, so it must degrade quietly
    for the guest and loudly for us. Silent is what let ``535
    Authentication Failed`` run unnoticed for days.
    """
    provider = settings.email_delivery_provider.lower()

    if identity is not MailIdentity.DEFAULT:
        named = (
            resolve_smtp_identity(settings, identity) if provider == "smtp" else None
        )
        if named is not None:
            return SmtpEmailProvider(named)
        if provider != "smtp":
            reason = f"email_delivery_provider={provider!r} is not 'smtp'"
        elif not smtp_host_setting_for(settings, identity):
            reason = f"{identity.value}_smtp_host is empty"
        else:
            # The block exists but does not describe a mailbox that can
            # send as itself. `resolve_smtp_identity` has already logged
            # `email_identity_invalid` with the specific fault; don't
            # restate it here and risk the two drifting apart.
            reason = (
                f"{identity.value}_smtp_* is configured but unusable -- see "
                "the preceding email_identity_invalid log line"
            )
        warn_email_identity_fallback(identity.value, provider, reason)

    if provider == "smtp":
        default_identity = resolve_smtp_identity(settings, MailIdentity.DEFAULT)
        if default_identity is None:
            raise EmailProviderNotConfiguredError(
                "email_delivery_provider='smtp' but smtp_host is empty, or "
                "smtp_from_address belongs to a different account than "
                "smtp_username (see the preceding email_identity_invalid "
                "log line for which)."
            )
        return SmtpEmailProvider(default_identity)
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


def get_configured_email_providers_by_identity(
    settings: Settings,
) -> dict[MailIdentity, EmailProviderProtocol]:
    """One built provider per :class:`MailIdentity`, for callers that route
    between mailboxes at send time rather than picking one up front --
    ``app.domains.notification``'s outbox dispatch is the only such caller
    today (see its ``constants.MAIL_IDENTITY_BY_EVENT_TYPE``).

    Every entry goes through :func:`get_configured_email_provider`, so an
    unconfigured identity has already fallen back to ``DEFAULT`` and logged
    it by the time it lands in this dict -- callers never see a hole and
    never have to implement fallback a second time.
    """
    return {
        member: get_configured_email_provider(settings, identity=member)
        for member in MailIdentity
    }


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
    if provider == "exotel":
        if (
            not settings.exotel_api_key
            or not settings.exotel_api_token
            or not settings.exotel_account_sid
            or not settings.exotel_from_number
        ):
            raise SmsProviderNotConfiguredError(
                "sms_delivery_provider='exotel' but exotel_api_key/"
                "exotel_api_token/exotel_account_sid/exotel_from_number is empty."
            )
        return ExotelSmsProvider(
            api_key=settings.exotel_api_key,
            api_token=settings.exotel_api_token,
            account_sid=settings.exotel_account_sid,
            from_number=settings.exotel_from_number,
            subdomain=settings.exotel_subdomain,
            dlt_entity_id=settings.exotel_dlt_entity_id,
            dlt_template_id=settings.exotel_dlt_template_id,
        )
    return LoggingSmsProvider()


def get_configured_whatsapp_provider(settings: Settings) -> WhatsAppProviderProtocol:
    """Same selection contract as :func:`get_configured_sms_provider`, for
    ``Settings.whatsapp_delivery_provider``. Deliberately reuses
    ``settings.twilio_account_sid``/``twilio_auth_token`` -- the exact same
    Twilio account SMS already authenticates with -- rather than a second
    set of Twilio credentials; see :class:`TwilioWhatsAppProvider`'s own
    docstring for why WhatsApp is the same Twilio account, just a
    different sender/message shape."""
    provider = settings.whatsapp_delivery_provider.lower()
    if provider == "twilio":
        if (
            not settings.twilio_account_sid
            or not settings.twilio_auth_token
            or not settings.whatsapp_twilio_from_number
            or not settings.whatsapp_twilio_content_sid
        ):
            raise WhatsAppProviderNotConfiguredError(
                "whatsapp_delivery_provider='twilio' but twilio_account_sid/"
                "twilio_auth_token/whatsapp_twilio_from_number/"
                "whatsapp_twilio_content_sid is empty."
            )
        return TwilioWhatsAppProvider(
            account_sid=settings.twilio_account_sid,
            auth_token=settings.twilio_auth_token,
            from_number=settings.whatsapp_twilio_from_number,
            content_sid=settings.whatsapp_twilio_content_sid,
            content_variable_key=settings.whatsapp_twilio_content_variable_key,
        )
    return LoggingWhatsAppProvider()


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
        whatsapp_provider: WhatsAppProviderProtocol | None = None,
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
        self.whatsapp_provider: WhatsAppProviderProtocol = (
            whatsapp_provider or LoggingWhatsAppProvider()
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

        await self._dispatch(otp_request, code=code, channel=channel, purpose=purpose)

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
        self,
        otp_request: OtpRequest,
        *,
        code: str,
        channel: OtpChannel,
        purpose: OtpPurpose = OtpPurpose.GUEST_LOGIN,
    ) -> None:
        minutes = max(self.expiry_seconds // 60, 1)
        if purpose == OtpPurpose.ACCOUNT_DATA_MASKING:
            subject = "Your Wyfy Guest data-masking verification code"
            message = (
                f"Your Wyfy Guest verification code to change your dashboard's "
                f"guest-data masking setting is {code}. It expires in "
                f"{minutes} minute(s). Ignore this if you didn't request it."
            )
            intro = (
                "Use this code to change your dashboard's guest-data masking "
                "setting. Ignore this message if you didn't request it."
            )
        else:
            subject = "Your Wyfy Guest verification code"
            message = (
                f"Your Wyfy Guest verification code is {code}. "
                f"It expires in {minutes} minute(s)."
            )
            intro = "Use this code to finish signing in."
        if channel == OtpChannel.SMS:
            await self.sms_provider.send(otp_request.identifier, message)
        elif channel == OtpChannel.WHATSAPP:
            await self.whatsapp_provider.send(
                otp_request.identifier, code=code, message=message
            )
        else:
            email_html = _render_otp_email(
                intro=intro, code=code, minutes=minutes
            )
            await self.email_provider.send(
                otp_request.identifier, subject, email_html
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
    "EmailAttachment",
    "EmailProviderProtocol",
    "WhatsAppProviderProtocol",
    "LoggingSmsProvider",
    "LoggingEmailProvider",
    "LoggingWhatsAppProvider",
    "SmtpEmailProvider",
    "SmtpIdentity",
    "MailIdentity",
    "MailIdentityMismatchError",
    "resolve_smtp_identity",
    "SesEmailProvider",
    "TwilioSmsProvider",
    "TwilioWhatsAppProvider",
    "ExotelSmsProvider",
    "EmailProviderNotConfiguredError",
    "SmsProviderNotConfiguredError",
    "WhatsAppProviderNotConfiguredError",
    "get_configured_email_provider",
    "get_configured_email_providers_by_identity",
    "warn_email_identity_fallback",
    "get_configured_sms_provider",
    "get_configured_whatsapp_provider",
    "AuditLogWriter",
    "OtpRateLimiter",
    "generate_numeric_code",
    "hash_otp_code",
]
