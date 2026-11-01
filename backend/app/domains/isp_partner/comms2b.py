"""COMMS-2b helpers: the ISP's email senders (gateway choice on a manual
invoice email), sending through the ISP's own SMTP/SES with the invoice PDF
attached, email templates applied to existing email sends, and the rendered
WhatsApp parameters kept per sent message.

Nothing here changes a default: with no own email sender there is one
sender (the platform outbox) and no choice is offered; with no enabled email
template (or ``ISP_COMMS_HUB_ENABLED`` off) the existing text is sent
unchanged.
"""

from __future__ import annotations

import html
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import select

from .comms_logic import EVENTS, render

PLATFORM = "platform"
OWN = "own"


# ---------------------------------------------------------------------------
# email senders
# ---------------------------------------------------------------------------


async def own_email_row(session: Any, isp_org_id: uuid.UUID) -> Any | None:
    """The ISP organization's own email sender, only when it is usable:
    enabled and verified, SMTP or SES."""
    from app.domains.marketing.models import OrgMarketingProvider as P

    row = (
        await session.execute(
            select(P).where(
                P.organization_id == isp_org_id,
                P.channel == "email",
                P.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if (
        row is None
        or not row.enabled
        or row.status != "verified"
        or row.provider_type not in ("smtp", "ses")
    ):
        return None
    return row


async def email_senders(session: Any, isp_org_id: uuid.UUID) -> dict:
    senders = [{"key": PLATFORM, "label": "Wyfy Guest mail (default)"}]
    row = await own_email_row(session, isp_org_id)
    if row is not None:
        addr = (row.display or {}).get("from_address")
        senders.append(
            {
                "key": OWN,
                "label": f"Your {row.provider_type.upper()} sender"
                + (f" ({addr})" if addr else ""),
                "provider_type": row.provider_type,
            }
        )
    return {"senders": senders, "choice_available": len(senders) > 1}


def _with_attachment(message: Any, content: bytes, filename: str) -> Any:
    message.add_attachment(
        content, maintype="application", subtype="pdf", filename=filename
    )
    return message


def own_sender_with_attachment(row: Any, content: bytes, filename: str) -> Any:
    """The ISP's own sender (the marketing adapters, unchanged) with the PDF
    attached to every message it builds. Error mapping is the adapters' own."""
    from app.domains.marketing.providers import (
        ByoSesEmailSender,
        GuardedSmtpEmailSender,
        _email_message,
        decrypt_config,
        system_resolver,
        vet_smtp_host,
    )

    config = decrypt_config(row.config_encrypted)

    def build(cfg: dict, email, subject, html_body, from_name, headers, reply_to):  # noqa: ANN001, PLR0913
        return _with_attachment(
            _email_message(
                from_address=cfg["from_address"],
                from_name=cfg.get("from_name") or from_name,
                to=email,
                subject=subject,
                html_body=html_body,
                headers=headers,
                reply_to=reply_to,
            ),
            content,
            filename,
        )

    if row.provider_type == "smtp":

        class _Smtp(GuardedSmtpEmailSender):
            def _send_sync(self, email, subject, html_body, from_name, headers):  # noqa: ANN001
                cfg = self._config
                message = build(
                    cfg,
                    email,
                    subject,
                    html_body,
                    from_name,
                    headers,
                    cfg.get("reply_to"),
                )
                with self._connect() as smtp:
                    smtp.send_message(message)
                return message["Message-ID"]

        return _Smtp(
            config,
            vet=lambda host, port: vet_smtp_host(host, port, resolver=system_resolver),
        )

    class _Ses(ByoSesEmailSender):
        def _send_sync(self, email, subject, html_body, from_name, headers):  # noqa: ANN001
            cfg = self._config
            message = build(cfg, email, subject, html_body, from_name, headers, None)
            kwargs: dict[str, Any] = {
                "FromEmailAddress": cfg["from_address"],
                "Destination": {"ToAddresses": [email]},
                "Content": {"Raw": {"Data": message.as_bytes()}},
            }
            if cfg.get("configuration_set"):
                kwargs["ConfigurationSetName"] = cfg["configuration_set"]
            return self.client().send_email(**kwargs).get("MessageId")

    return _Ses(config)


# ---------------------------------------------------------------------------
# email templates on existing sends
# ---------------------------------------------------------------------------


async def email_template(
    session: Any,
    isp_org_id: uuid.UUID,
    event: str,
    values: dict[str, str] | Callable[[], Awaitable[dict[str, str]]],
) -> tuple[str, str] | None:
    """(subject, html body) from the ISP's ENABLED email template for
    ``event``; None (caller keeps its existing text) when the COMMS hub is
    off or no enabled template with a subject and body exists."""
    from .comms_models import IspMessageTemplate as T
    from .comms_router import get_comms_settings

    if not get_comms_settings().comms_hub_enabled:
        return None
    t = (
        await session.execute(
            select(T).where(
                T.isp_organization_id == isp_org_id,
                T.event == event,
                T.channel == "email",
                T.enabled.is_(True),
                T.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if t is None or not t.email_subject or not t.email_body:
        return None
    if callable(values):  # built only when a template will use it (pay link)
        values = await values()
    subject = render(t.email_subject, values).replace("\r", " ").replace("\n", " ")
    safe = {k: html.escape(str(v)) for k, v in values.items()}
    paragraphs = [p for p in html.escape(t.email_body).split("\n\n") if p.strip()]
    body = "".join(
        f"<p>{render(p, safe).replace(chr(10), '<br>')}</p>" for p in paragraphs
    )
    return subject[:200], body


# ---------------------------------------------------------------------------
# rendered WhatsApp parameters
# ---------------------------------------------------------------------------

#: JAZE-4 trigger -> COMMS-2 event (whose ``vars`` name the positions).
TRIGGER_EVENT = {
    spec["trigger"]: event for event, spec in EVENTS.items() if spec["trigger"]
}


def parameter_rows(trigger: str, params: list[str]) -> list[dict[str, Any]]:
    names = EVENTS.get(TRIGGER_EVENT.get(trigger, ""), {}).get("vars", [])
    return [
        {
            "position": i + 1,
            "variable": names[i] if i < len(names) else None,
            "value": str(p)[:200],
        }
        for i, p in enumerate(params)
    ]


async def contents_for(
    session: Any, isp_org_id: uuid.UUID, log_ids: list[uuid.UUID]
) -> dict[uuid.UUID, Any]:
    from .comms2b_models import IspMessageContent as M

    if not log_ids:
        return {}
    return {
        r.message_log_id: r
        for r in (
            await session.execute(
                select(M).where(
                    M.isp_organization_id == isp_org_id,
                    M.message_log_id.in_(log_ids),
                    M.is_deleted.is_(False),
                )
            )
        ).scalars()
    }


__all__ = [
    "OWN",
    "PLATFORM",
    "TRIGGER_EVENT",
    "contents_for",
    "email_senders",
    "email_template",
    "own_email_row",
    "own_sender_with_attachment",
    "parameter_rows",
]
