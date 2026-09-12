"""One place that answers "can this deployment send an alert email?", for
both the Celery sweep and the request path.

## Why this module exists

``app.domains.otp.service.get_configured_email_provider`` raises
``EmailProviderNotConfiguredError`` when ``email_delivery_provider`` is
``smtp``/``ses`` but the matching settings are incomplete -- most easily by
leaving ``smtp_from_address`` at its ``noreply@cloudguest.local`` default
while authenticating as a real mailbox, which ``SmtpIdentity`` flatly
refuses.

It raises at **construction** time, and both callers construct eagerly:

* ``tasks._run_alert_rule_evaluation_sweep_async`` built the service graph
  before evaluating a single rule, so one wrong mail setting took down alert
  evaluation for every channel type on the platform -- Slack, webhooks and
  SMS included, none of which involve email at all.
* ``dependencies.get_notification_service`` is a FastAPI dependency, so the
  same setting would 500 every monitoring endpoint that touches it --
  including the alerts screen an operator would go to in order to find out
  why they were not being alerted.

Both are now routed through ``resolve_email_provider`` below.

## Why the failure is carried rather than swallowed

The obvious "fix" -- pass ``None`` and let ``NotificationService`` fall back
to ``LoggingEmailProvider`` -- is the worst available option. That provider
returns success, so ``dispatch_notification`` writes
``notification_logs.status = 'sent'`` with a ``response_summary`` reading
"queued to ... via EmailProviderProtocol", for a mail that never left the
box. It is indistinguishable from a real delivery in the database and
through the API, which is precisely how "alerting works" can be believed for
months while nothing arrives.

So the misconfiguration is carried to the point of use instead. Everything
that is not email keeps working, and every email attempt records a
``FAILED`` row carrying the original configuration error -- the diagnostic
an operator actually needs, in the place they will actually look.
"""

from __future__ import annotations

from app.core.config import Settings
from app.core.logging import get_logger
from app.domains.otp.service import (
    EmailProviderNotConfiguredError,
    EmailProviderProtocol,
    get_configured_email_provider,
)

from .service import NotificationDeliveryError

logger = get_logger(__name__)


class UnconfiguredEmailProvider:
    """Fails loudly on every send, carrying the original configuration
    error -- see this module's docstring for why this rather than a silent
    fallback to log-only."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    async def send(
        self,
        email: str,
        subject: str,
        body: str,
        *,
        attachment: object | None = None,
    ) -> None:
        raise NotificationDeliveryError(
            f"Email is not deliverable with the current configuration: {self.reason}"
        )


def resolve_email_provider(settings: Settings) -> EmailProviderProtocol:
    """``get_configured_email_provider``, except that a misconfiguration can
    no longer abort whatever was being constructed around it."""
    try:
        return get_configured_email_provider(settings)
    except EmailProviderNotConfiguredError as exc:
        logger.error(
            "alert_email_provider_unconfigured",
            extra={
                "email_delivery_provider": settings.email_delivery_provider,
                "error": str(exc),
            },
        )
        return UnconfiguredEmailProvider(str(exc))


__all__ = ["UnconfiguredEmailProvider", "resolve_email_provider"]
