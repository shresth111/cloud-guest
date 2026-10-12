"""The outbound half of ``NotificationChannelType.SLACK``: a real POST to a
Slack incoming-webhook URL, and the selector that decides whether there is
one at all.

## Why this is not ``app.domains.monitoring.service.SlackNotifier``

That class exists, is real, and is left exactly as it is. It is not
reusable here for two independent reasons:

* Its ``send`` signature is ``send(*, alert: Alert, config: dict)`` -- it
  renders an ``Alert`` and reads its webhook out of a per-organization
  ``NotificationChannel.config_encrypted``. An onboarding notice is not an
  alert and its webhook is not per-organization.
* Importing it would pull ``app.domains.monitoring.service`` (a ~4,300
  line module that imports the alert/incident/SLA/heartbeat graph) into
  the notification dispatch sweep, which today imports none of it.

What is *not* duplicated is the part worth sharing: the payload shape.
Slack's documented incoming-webhook contract is a JSON object with a
top-level ``text`` field, and that is what both send. Fifteen lines of
``httpx`` with the same timeout constant is the cheaper half of that
trade.

## The webhook is a bearer credential

Anyone holding the URL can post to the channel, so it is treated like the
SMTP passwords next to it in ``Settings``:

* read from ``Settings.slack_onboarding_webhook_url``
  (``CLOUDGUEST_SLACK_ONBOARDING_WEBHOOK_URL``), which in production comes
  from the ``cloudguest/prod/mail`` Secrets Manager secret via
  ``deploy/remote-deploy.sh``'s ``materialise_slack_env`` (that script's
  ``SLACK_SECRET_ID`` comment explains why it shares the mail secret);
* never committed, never written to any database column (a Slack outbox
  row's ``recipient`` is the constant label
  ``SLACK_ONBOARDING_RECIPIENT``), and
* **never logged.** ``_redact`` below is what enforces the last one: a
  failure logs the host and the number of path characters, which is
  enough to tell "wrong workspace" from "revoked webhook" and is not
  enough to post anything.

## Unset is inert, not broken

``get_configured_slack_sender`` returns ``None`` when no webhook is
configured, and every caller treats ``None`` as "do not enqueue". Nothing
is written, nothing is posted, and nothing raises -- see
``onboarding_slack.py``. ``UnconfiguredSlackSender`` covers only the
narrow case where a row was enqueued while a webhook existed and the
webhook was removed before the sweep drained it: that row fails honestly
(``RETRYING`` -> ``FAILED``, with a message saying why) rather than being
marked ``SENT`` for a message nobody received.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit

import httpx
from fastapi import status

from app.common.exceptions import CloudGuestError
from app.core.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class SlackDeliveryError(CloudGuestError):
    """A real Slack webhook POST failed. Raised out of ``send`` and caught
    by ``NotificationService._attempt_delivery``'s existing blanket
    handler, which turns it into ``RETRYING``/``FAILED`` exactly as it
    already does for an SMTP failure -- the sweep never crashes on one."""

    def __init__(self, message: str) -> None:
        super().__init__(
            f"Slack webhook delivery failed: {message}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class SlackWebhookNotConfiguredError(CloudGuestError):
    def __init__(self) -> None:
        super().__init__(
            "No Slack webhook is configured "
            "(CLOUDGUEST_SLACK_ONBOARDING_WEBHOOK_URL is empty)",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class SlackSenderProtocol(Protocol):
    """The whole surface the dispatch sweep needs. Narrow and duck-typed so
    a test substitutes a list-appending fake, exactly as
    ``tests/unit/test_notification.py`` already does for email/SMS."""

    async def send(self, text: str) -> None: ...


def _redact(webhook_url: str) -> str:
    """A safely loggable description of a webhook URL: its host, and how
    many characters of path it had. Never the path itself -- the path *is*
    the credential."""
    try:
        parts = urlsplit(webhook_url)
    except ValueError:
        return "<unparseable webhook url>"
    return f"{parts.hostname or '<no host>'} (path len {len(parts.path)})"


class HttpxSlackWebhookSender:
    """The real sender. One POST, one bounded timeout, no retry of its own
    -- retry is the outbox's job (``Settings
    .notification_retry_backoff_seconds``), and duplicating it here would
    multiply the two together."""

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout_seconds: float,
        client_factory: Callable[[], httpx.AsyncClient] = httpx.AsyncClient,
    ) -> None:
        self.webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds
        # The one seam this class has. Production never passes it; tests
        # pass a factory returning a client on an `httpx.MockTransport`,
        # which is how the payload, the URL and the error handling are
        # asserted against a recorded transport instead of a real Slack
        # workspace. Injecting the factory rather than a client keeps
        # "one client per send, closed after" true either way.
        self.client_factory = client_factory

    async def send(self, text: str) -> None:
        try:
            async with self.client_factory() as client:
                response = await client.post(
                    self.webhook_url,
                    json={"text": text},
                    timeout=self.timeout_seconds,
                )
        except httpx.HTTPError as exc:
            # `exc` can carry the request URL, so it is summarised rather
            # than interpolated: `type(exc).__name__` plus the redacted
            # host says which failure it was without printing the secret.
            logger.warning(
                "slack_webhook_post_failed",
                extra={
                    "error_type": type(exc).__name__,
                    "webhook": _redact(self.webhook_url),
                },
            )
            # `from None`, not `from exc`: an httpx error's repr can carry
            # the full request URL, and a chained traceback is a log line.
            # The cause is already summarised in the log above by type.
            raise SlackDeliveryError(
                f"HTTP request failed ({type(exc).__name__})"
            ) from None
        if response.status_code >= 400:
            # Slack answers a bad webhook with a short plain-text body
            # ("invalid_token", "no_service") that is worth keeping; it is
            # bounded because an intercepting proxy may answer with an
            # arbitrarily large error page.
            raise SlackDeliveryError(
                f"HTTP {response.status_code}: {response.text[:200]}"
            )


class UnconfiguredSlackSender:
    """Raises rather than pretending. See this module's docstring for the
    one situation that reaches it. Deliberately NOT the codebase's
    ``LoggingEmailProvider``-style no-op: a no-op here would mark the row
    ``SENT``, which is a claim that a message was delivered."""

    async def send(self, text: str) -> None:
        raise SlackWebhookNotConfiguredError()


def get_configured_slack_sender(settings: Settings) -> SlackSenderProtocol | None:
    """The real sender, or ``None`` when no webhook is configured.

    ``None`` is the signal the whole feature hangs off: it means "Slack is
    not set up here", and every caller's response to it is to do nothing
    at all. It is not an error and is not logged at warning level -- an
    unconfigured deployment is the expected default, including every local
    checkout and every test run.
    """
    webhook_url = settings.slack_onboarding_webhook_url.strip()
    if not webhook_url:
        return None
    return HttpxSlackWebhookSender(
        webhook_url, timeout_seconds=settings.slack_webhook_timeout_seconds
    )


__all__ = [
    "SlackDeliveryError",
    "SlackWebhookNotConfiguredError",
    "SlackSenderProtocol",
    "HttpxSlackWebhookSender",
    "UnconfiguredSlackSender",
    "get_configured_slack_sender",
]
