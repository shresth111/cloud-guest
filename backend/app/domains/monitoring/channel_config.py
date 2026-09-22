"""What a ``NotificationChannel``'s decrypted config is allowed to become
before it leaves this process -- for an API response, a log line or an audit
payload.

## Why this module exists

``NotificationChannel.config_encrypted`` holds, depending on
``channel_type``, a Slack/Teams/Discord incoming-webhook URL, a generic
webhook URL plus an optional auth header value, or a destination email
address / phone number. The first three are **bearer-equivalent**: anyone
holding the URL can post into that channel, which is why the column is
Fernet-encrypted at rest and why ``schemas.NotificationChannelResponse``
has never carried a decrypted ``config``.

That was the right call and this module does not relax it. But "return
nothing at all" has a cost the console has been paying: the list endpoint
returns a name, a type and an ``is_active`` flag, and *nothing an operator
can use to tell two Slack channels apart, or to tell a channel that was
configured from one whose credential was never filled in*. The honest
answer to "is this channel actually configured, and where does it point?"
is not the secret -- it is a redaction that answers the question and
nothing more.

This codebase has already shipped the failure this module is written
against: a venue-facing endpoint returned plaintext WiFi passwords in a
*list* response, because the list serializer was written by reaching for
the model rather than by deciding field by field what a reader is entitled
to. So the rule here is inverted. :class:`ChannelConfigSummary` is an
allowlist -- a fixed set of fields, every one of which is safe by
construction -- and the raw config dict never reaches a caller. Adding a
field to it is a deliberate act with a reason next to it.

## Fingerprints, and why only some values get one

:attr:`ChannelConfigSummary.fingerprint` is a truncated SHA-256 of the
secret material. It answers "is the webhook URL on this channel the same
one as on that channel / the same one it was last week?" without revealing
it -- the question an operator actually has when a channel silently stops
delivering, and the one the Omada shared-secret incident was eventually
resolved by asking.

A fingerprint is only safe for **high-entropy** material. A Slack webhook
URL carries ~100 bits of random path; hashing it reveals nothing. An email
address or a phone number does not: an Indian mobile number is ten digits
behind a handful of prefixes, so a published hash of one is recovered by
brute force in seconds, and publishing it would turn a redaction into a
disclosure. So email and phone channels get **no fingerprint at all** --
they get a partial mask instead, which reveals strictly less than the
domain or country code an operator needs in order to recognise the
destination.

## Nothing here is logged by its caller

Every field on the summary is safe to log, and the raw ``config`` mapping
is never returned, stringified or attached to an exception by this module.
``summarize_channel_config`` takes the decrypted mapping and gives back
only the summary, so a caller that holds a summary cannot accidentally
serialize a secret it no longer has.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from .constants import NotificationChannelType

__all__ = [
    "ChannelConfigSummary",
    "CHANNEL_REQUIREMENTS",
    "fingerprint_secret",
    "mask_email",
    "mask_phone",
    "mask_url",
    "summarize_channel_config",
]


#: How many hex characters of the SHA-256 digest a fingerprint carries.
#: Twelve is enough that two different webhook URLs colliding is not a
#: practical concern for a fleet of tens of channels, and short enough to
#: read off a screen and compare by eye, which is the entire purpose.
FINGERPRINT_HEX_LENGTH = 12


def fingerprint_secret(value: str) -> str:
    """A short, stable, non-reversible identifier for one high-entropy
    secret. See the module docstring for why this must never be applied to
    an email address or a phone number."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:FINGERPRINT_HEX_LENGTH]


def mask_email(value: str) -> str:
    """``operations@example.com`` -> ``op•••@example.com``.

    The domain is kept in full and the local part is reduced to its first
    two characters. An operator recognises their own ops mailbox from the
    domain; nobody can reconstruct the address from two characters, and
    the address is a destination rather than a credential, so this is a
    privacy redaction rather than a secret one.
    """
    local, separator, domain = value.partition("@")
    if not separator:
        # Not an address shape at all. Fail towards revealing less.
        return "•" * 8
    kept = local[:2]
    return f"{kept}•••@{domain}"


def mask_phone(value: str) -> str:
    """``+919876543210`` -> ``+91•••••3210``.

    Last four digits only, which is the convention every bank and courier
    in this market already uses, so an operator reads it without being
    taught. Leading ``+`` and the first three characters are kept because
    a country code is not identifying on its own.
    """
    if len(value) <= 6:
        return "•" * len(value)
    return f"{value[:3]}•••••{value[-4:]}"


def mask_url(value: str) -> str:
    """``https://hooks.slack.com/services/T0/B0/XXXX`` ->
    ``https://hooks.slack.com/…``.

    **The path is the secret.** For Slack, Teams and Discord the host is a
    fixed, public, well-known hostname and every bit of the credential
    lives in the path, so this keeps scheme and host -- which tell an
    operator it is a Slack webhook and not a Discord one -- and discards
    everything after, including the query string. No path segment is ever
    partially revealed: a first segment that looks harmless on
    ``hooks.slack.com`` is a customer identifier on somebody's generic
    webhook host.
    """
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return "•" * 8
    has_more = bool(parts.path.strip("/") or parts.query or parts.fragment)
    return f"{parts.scheme}://{parts.netloc}/…" if has_more else (
        f"{parts.scheme}://{parts.netloc}"
    )


#: What an operator must supply, per channel type, before a channel of that
#: type can deliver anything -- in the words the console shows them. This is
#: the honest answer to "why did my test fail?" for the two channel types
#: whose answer is not "your URL is wrong" but "this deployment has no
#: provider configured at all".
#:
#: WHATSAPP's entry is the one that matters most and is the one most often
#: got wrong. ``app.domains.otp.service.TwilioWhatsAppProvider`` is real and
#: does work -- but it sends a Meta-approved **Content Template** with a
#: variable substituted into it, not free text, because the WhatsApp
#: Business API rejects freeform business-initiated messages outside a
#: 24-hour customer-service window. The template Wyfy Guest has approved
#: today is the OTP one: its body is a one-time code. An ops alert is not a
#: one-time code, so there is no approved template this message fits, and
#: no amount of backend work creates one -- that is a Meta review, measured
#: in days, against copy that does not exist yet. See
#: ``backend/docs/hindi-transactional-messaging-followup.md`` §4.1, which
#: reached the same conclusion from the other direction.
CHANNEL_REQUIREMENTS: dict[NotificationChannelType, tuple[str, ...]] = {
    NotificationChannelType.EMAIL: (
        "Settings.email_delivery_provider must be 'smtp' or 'ses'. While it "
        "is 'logging' (the default) a test will report success and no mail "
        "will leave this deployment.",
    ),
    NotificationChannelType.SMS: (
        "Settings.sms_delivery_provider must be 'twilio' or 'exotel'. While "
        "it is 'logging' (the default) a test will report success and no SMS "
        "will be sent.",
        "Exotel (the India path) additionally requires the message body to "
        "match a TRAI DLT-registered template or carriers drop it silently.",
    ),
    NotificationChannelType.WHATSAPP: (
        "A WhatsApp Business API account and a WhatsApp-enabled sender "
        "number (Settings.whatsapp_twilio_from_number).",
        "A Meta-approved Content Template whose body is an operational "
        "alert. The only template approved today is the one-time-code "
        "template used for guest OTP; an alert cannot be sent through it. "
        "Until such a template exists and its SID is configured, this "
        "channel type logs and does not deliver.",
    ),
    NotificationChannelType.SLACK: (),
    NotificationChannelType.TEAMS: (),
    NotificationChannelType.DISCORD: (),
    NotificationChannelType.WEBHOOK: (),
}


@dataclass(frozen=True, slots=True)
class ChannelConfigSummary:
    """Everything an API response is allowed to say about one channel's
    credentials. An allowlist, not a filter -- see the module docstring.

    :param configured: whether the config carries the field this channel
        type needs in order to deliver. False means the channel exists but
        points nowhere, which is the state the console previously rendered
        identically to a working one.
    :param target: a masked, human-recognisable destination. Safe to log.
    :param fingerprint: a truncated SHA-256 of the secret material, or
        ``None`` for channel types whose config is too low-entropy to hash
        safely (email, SMS, WhatsApp). Never a prefix of the secret itself.
    :param has_secret: whether this channel holds bearer-equivalent
        material at all. Drives the console's "replace credential" affordance
        without saying anything about the value.
    :param auth_header_name: a generic webhook's custom auth header *name*
        (``X-Api-Key``), which is not a secret and is the half an operator
        needs in order to check it against the receiving system. The
        corresponding value is never represented here in any form -- not
        masked, not fingerprinted, not by length.
    :param requirements: :data:`CHANNEL_REQUIREMENTS` for this type.
    """

    configured: bool
    target: str
    fingerprint: str | None
    has_secret: bool
    auth_header_name: str | None
    requirements: tuple[str, ...]


def _string(config: dict[str, object], key: str) -> str:
    value = config.get(key)
    return value if isinstance(value, str) else ""


def summarize_channel_config(
    channel_type: NotificationChannelType | str, config: dict[str, object]
) -> ChannelConfigSummary:
    """Reduce one decrypted channel config to the fields a caller outside
    this process may see.

    ``channel_type`` is accepted as a plain ``str`` as well as the enum
    because ``NotificationChannel.channel_type`` is a persisted string
    column: a row written before a member existed (or after one was
    removed) must summarise to *something* redacted rather than raise
    inside a list serializer and take the whole page down.
    """
    try:
        kind = NotificationChannelType(channel_type)
    except ValueError:
        return ChannelConfigSummary(
            configured=False,
            target="unknown channel type",
            fingerprint=None,
            has_secret=False,
            auth_header_name=None,
            requirements=(),
        )

    requirements = CHANNEL_REQUIREMENTS.get(kind, ())

    if kind is NotificationChannelType.EMAIL:
        email = _string(config, "email")
        return ChannelConfigSummary(
            configured=bool(email),
            target=mask_email(email) if email else "not configured",
            # Deliberately no fingerprint -- see the module docstring.
            fingerprint=None,
            has_secret=False,
            auth_header_name=None,
            requirements=requirements,
        )

    if kind in (NotificationChannelType.SMS, NotificationChannelType.WHATSAPP):
        phone = _string(config, "phone_number")
        return ChannelConfigSummary(
            configured=bool(phone),
            target=mask_phone(phone) if phone else "not configured",
            fingerprint=None,
            has_secret=False,
            auth_header_name=None,
            requirements=requirements,
        )

    if kind in (
        NotificationChannelType.SLACK,
        NotificationChannelType.TEAMS,
        NotificationChannelType.DISCORD,
    ):
        url = _string(config, "webhook_url")
        return ChannelConfigSummary(
            configured=bool(url),
            target=mask_url(url) if url else "not configured",
            fingerprint=fingerprint_secret(url) if url else None,
            has_secret=bool(url),
            auth_header_name=None,
            requirements=requirements,
        )

    url = _string(config, "url")
    header_name = _string(config, "auth_header_name")
    header_value = _string(config, "auth_header_value")
    # The URL is fingerprinted together with the auth header value, so
    # rotating either one changes the fingerprint. An operator comparing
    # "did this change?" means the credential as a whole, not one half.
    material = f"{url}\n{header_value}"
    return ChannelConfigSummary(
        configured=bool(url),
        target=mask_url(url) if url else "not configured",
        fingerprint=fingerprint_secret(material) if url else None,
        has_secret=bool(header_value),
        auth_header_name=header_name or None,
        requirements=requirements,
    )
