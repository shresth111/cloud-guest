"""JAZE-4 J9 + J14: automated WhatsApp (the ISP's own Meta sender), the
public pay-link page, Telegram router/AP alerts, and the outbound message log.

WhatsApp
--------
Sent ONLY through the ISP organization's own verified ``meta_cloud`` provider
(the ISP-level sender in ``twins_marketing``) -- never Wyfy's -- with the
ISP's own approved templates, mapped per trigger in
``isp_automation_settings.whatsapp_templates``. Positional parameters:

* ``pre_expiry``: {{1}} name, {{2}} expiry date, {{3}} plan name
* ``unpaid``:     {{1}} name, {{2}} invoice no., {{3}} balance, {{4}} pay link
* ``receipt``:    {{1}} name, {{2}} receipt no., {{3}} amount, {{4}} date
* ``renewal``:    {{1}} name, {{2}} invoice no., {{3}} valid until

Recipients must have opted in (subscriber ``reminder_opt_in.whatsapp``, or the
customer's billing contact ``whatsapp_opt_in``), and nobody marked
``exclude_from_reminders`` is messaged. Each message has a dedupe key, so a
repeated sweep sends nothing twice; events older than the moment automation
was switched on are never messaged (no backfill).

The sweeps piggy-back on the existing ISP Celery tasks (``tasks.py``), so no
beat entry is added: receipts/renewals ride the 120 s retry task, pre-expiry
and unpaid reminders the daily billing run.

Telegram
--------
Each sweep reads router status (and derived AP status) for the ISP's
customers, debounces by ``telegram_debounce_minutes`` and sends one batched
message per ISP. A device seen for the first time is recorded silently.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import func, select

from app.core.logging import get_logger

from .billing_models import IspInvoice, IspPayment
from .billing_service import balance_of
from .exceptions import IspError
from .finance_config import get_finance_settings
from .finance_models import (
    IspAlertDeviceState,
    IspAutomationSettings,
    IspBillingContact,
    IspMessageLog,
    IspPayLink,
)

logger = get_logger(__name__)

TRIGGERS = ("pre_expiry", "unpaid", "receipt", "renewal")
PAY_LINK_TTL = timedelta(days=30)
TELEGRAM_API = "https://api.telegram.org"
_IST = ZoneInfo("Asia/Kolkata")


class IspAutomationError(IspError):
    code = "ISP_AUTOMATION_ERROR"
    status_code_default = 422
    default_message = "Automation is not set up"


def mask_phone(phone: str | None) -> str:
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    if len(digits) < 4:
        return "••••"
    return f"••••••{digits[-4:]}"


def mask_email(email: str | None) -> str:
    if not email or "@" not in email:
        return "••••"
    local, domain = email.split("@", 1)
    return f"{local[:1]}•••@{domain}"


def e164_in(phone: str | None) -> str | None:
    """Indian numbers to +91XXXXXXXXXX; anything already +E.164 is kept."""
    raw = (phone or "").strip()
    if raw.startswith("+"):
        digits = "+" + "".join(ch for ch in raw[1:] if ch.isdigit())
        return digits if 8 <= len(digits) <= 16 else None
    digits = "".join(ch for ch in raw if ch.isdigit())
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    if len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return f"+91{digits}" if len(digits) == 10 and digits[0] in "6789" else None


def _rs(paise: int) -> str:
    return f"Rs {paise / 100:,.2f}"


async def automation_settings(
    session: Any, isp_org_id: uuid.UUID
) -> IspAutomationSettings | None:  # noqa: E501
    return (
        await session.execute(
            select(IspAutomationSettings).where(
                IspAutomationSettings.isp_organization_id == isp_org_id,
                IspAutomationSettings.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


def settings_view(row: IspAutomationSettings | None) -> dict:
    return {
        "whatsapp_enabled": bool(row and row.whatsapp_enabled),
        "whatsapp_enabled_at": row.whatsapp_enabled_at.isoformat()
        if row and row.whatsapp_enabled_at
        else None,  # noqa: E501
        "whatsapp_templates": (row.whatsapp_templates if row else {}) or {},
        "pre_expiry_days": row.pre_expiry_days if row else 2,
        "unpaid_reminder_after_days": row.unpaid_reminder_after_days if row else 1,
        "telegram_enabled": bool(row and row.telegram_enabled),
        "telegram_bot_token": {
            "set": bool(row and row.telegram_bot_token_encrypted),
            "hint": row.telegram_bot_token_hint if row else None,
        },  # noqa: E501
        "telegram_chat_id": row.telegram_chat_id if row else None,
        "telegram_debounce_minutes": row.telegram_debounce_minutes if row else 3,
        "telegram_include_aps": bool(row.telegram_include_aps) if row else True,
        "triggers": list(TRIGGERS),
        "flags": {
            "whatsapp": get_finance_settings().whatsapp_automation_enabled,
            "telegram": get_finance_settings().telegram_alerts_enabled,
        },
    }


async def put_settings(session: Any, isp: Any, data: dict) -> dict:
    from app.domains.marketing.providers import encrypt_config

    row = await automation_settings(session, isp.isp_org_id)
    if row is None:
        row = IspAutomationSettings(
            isp_organization_id=isp.isp_org_id, created_by=isp.user_id
        )
        session.add(row)
    if "whatsapp_templates" in data and data["whatsapp_templates"] is not None:
        clean: dict[str, dict] = {}
        for trig, spec in data["whatsapp_templates"].items():
            if trig not in TRIGGERS:
                raise IspAutomationError(
                    f"Unknown trigger {trig}", field="whatsapp_templates"
                )
            if spec and spec.get("template_name"):
                clean[trig] = {
                    "template_name": str(spec["template_name"])[:512],
                    "language": str(spec.get("language") or "en")[:15],
                }
        row.whatsapp_templates = clean
    if data.get("whatsapp_enabled") is True and not row.whatsapp_enabled:
        row.whatsapp_enabled_at = datetime.now(UTC)
    if "telegram_bot_token" in data:
        token = (data.pop("telegram_bot_token") or "").strip()
        if token:
            row.telegram_bot_token_encrypted = encrypt_config({"bot_token": token})
            row.telegram_bot_token_hint = f"…{token[-4:]}"
        else:
            row.telegram_bot_token_encrypted = None
            row.telegram_bot_token_hint = None
    for k in (
        "whatsapp_enabled",
        "pre_expiry_days",
        "unpaid_reminder_after_days",
        "telegram_enabled",
        "telegram_chat_id",
        "telegram_debounce_minutes",
        "telegram_include_aps",
    ):
        if k in data and data[k] is not None:
            setattr(row, k, data[k])
    if row.telegram_enabled and not (
        row.telegram_bot_token_encrypted and row.telegram_chat_id
    ):
        raise IspAutomationError(
            "Telegram needs a bot token and a chat id", field="telegram_enabled"
        )  # noqa: E501
    row.updated_by = isp.user_id
    await session.flush()
    return settings_view(row)


# ---------------------------------------------------------------------------
# message log
# ---------------------------------------------------------------------------


async def _already(session: Any, isp_org_id: uuid.UUID, dedupe_key: str) -> bool:
    return (
        await session.execute(
            select(IspMessageLog.id).where(
                IspMessageLog.isp_organization_id == isp_org_id,
                IspMessageLog.dedupe_key == dedupe_key,
            )
        )
    ).first() is not None


def log_row(isp_org_id: uuid.UUID, **kw: Any) -> IspMessageLog:
    kw["summary"] = (kw.get("summary") or "")[:300]
    if kw.get("error"):
        kw["error"] = str(kw["error"])[:300]
    return IspMessageLog(isp_organization_id=isp_org_id, **kw)


async def list_log(
    session: Any,
    isp: Any,
    *,
    channel: str | None,
    trigger: str | None,
    status: str | None,
    page: int,
    page_size: int,
) -> tuple[list[dict], int]:
    from app.domains.notification.models import NotificationDelivery

    children = await isp.child_ids()
    q = select(IspMessageLog).where(IspMessageLog.isp_organization_id == isp.isp_org_id)
    if isp.confined_customer_ids is not None:
        # A confined role sees only its customers' rows (never ISP-wide alerts).
        q = q.where(
            IspMessageLog.customer_organization_id.in_(children or [uuid.uuid4()])
        )
    for col, val in (
        (IspMessageLog.channel, channel),
        (IspMessageLog.trigger, trigger),
        (IspMessageLog.status, status),
    ):  # noqa: E501
        if val:
            q = q.where(col == val)
    total = (
        await session.execute(select(func.count()).select_from(q.subquery()))
    ).scalar_one()
    rows = (
        (
            await session.execute(
                q.order_by(IspMessageLog.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)  # noqa: E501
            )
        )
        .scalars()
        .all()
    )
    delivery_ids = [
        r.notification_delivery_id for r in rows if r.notification_delivery_id
    ]
    deliveries: dict = {}
    if delivery_ids:
        for d in (
            await session.execute(
                select(NotificationDelivery.id, NotificationDelivery.status).where(
                    NotificationDelivery.id.in_(delivery_ids)
                )
            )
        ).all():
            deliveries[d[0]] = d[1]
    items = []
    for r in rows:
        status_now = r.status
        if r.notification_delivery_id in deliveries:
            st = str(deliveries[r.notification_delivery_id]).lower()
            status_now = {"sent": "sent", "failed": "failed"}.get(st, "queued")
        items.append(
            {
                "id": str(r.id),
                "created_at": r.created_at.isoformat(),
                "channel": r.channel,
                "trigger": r.trigger,
                "recipient": r.recipient_masked,
                "summary": r.summary,
                "status": status_now,
                "error": r.error,
                "isp_customer_id": str(r.customer_organization_id)
                if r.customer_organization_id
                else None,  # noqa: E501
                "subscriber_id": str(r.subscriber_id) if r.subscriber_id else None,
                "invoice_id": str(r.invoice_id) if r.invoice_id else None,
            }
        )
    return items, int(total)


# ---------------------------------------------------------------------------
# pay links
# ---------------------------------------------------------------------------


async def pay_link_for(
    session: Any, isp_org_id: uuid.UUID, invoice_id: uuid.UUID
) -> str:
    now = datetime.now(UTC)
    row = (
        await session.execute(
            select(IspPayLink)
            .where(
                IspPayLink.isp_organization_id == isp_org_id,
                IspPayLink.invoice_id == invoice_id,
                IspPayLink.expires_at > now + timedelta(days=3),
            )
            .order_by(IspPayLink.expires_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None:
        row = IspPayLink(
            isp_organization_id=isp_org_id,
            invoice_id=invoice_id,
            token=secrets.token_urlsafe(9)[:12],
            expires_at=now + PAY_LINK_TTL,
        )
        session.add(row)
        await session.flush()
    base = get_finance_settings().pay_link_base_url.rstrip("/")
    return f"{base}/partner/pay/{row.token}"


async def public_pay_view(session: Any, token: str) -> dict | None:
    """What the public pay page shows: the ISP, the invoice number, amounts,
    and how to pay (UPI intent, bank details). No customer PII beyond the
    first name, and nothing at all for an expired or unknown token."""
    from app.domains.organization.models import Organization

    from .billing_models import IspBillingSettings
    from .billing_pdf import upi_uri
    from .finance_models import IspInvoiceTemplate
    from .models import IspPartnerProfile

    if not token or len(token) > 16:
        return None
    row = (
        await session.execute(select(IspPayLink).where(IspPayLink.token == token))
    ).scalar_one_or_none()  # noqa: E501
    if row is None or row.expires_at <= datetime.now(UTC) or row.is_deleted:
        return None
    inv = await session.get(IspInvoice, row.invoice_id)
    profile = (
        await session.execute(
            select(IspPartnerProfile).where(
                IspPartnerProfile.organization_id == row.isp_organization_id
            )  # noqa: E501
        )
    ).scalar_one_or_none()
    if inv is None or inv.is_deleted or profile is None or profile.status != "active":
        return None
    org = await session.get(Organization, row.isp_organization_id)
    billing = (
        await session.execute(
            select(IspBillingSettings).where(
                IspBillingSettings.isp_organization_id == row.isp_organization_id
            )  # noqa: E501
        )
    ).scalar_one_or_none()
    tpl = (
        await session.execute(
            select(IspInvoiceTemplate).where(
                IspInvoiceTemplate.isp_organization_id == row.isp_organization_id,
                IspInvoiceTemplate.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    row.open_count += 1
    balance = balance_of(inv)
    payee = (billing.payee_name if billing else None) or (org.name if org else "")
    upi = None
    if billing and billing.upi_vpa and balance > 0:
        upi = upi_uri(billing.upi_vpa, payee, balance, inv.number)
    first = (inv.bill_to_name or "").split(" ")[0]
    return {
        "isp_name": org.name if org else "",
        "support_phone": profile.support_phone,
        "support_email": profile.support_email,
        "invoice_number": inv.number,
        "invoice_date": inv.issue_date.isoformat(),
        "due_date": inv.due_date.isoformat(),
        "bill_to_first_name": first,
        "total_paise": inv.total_paise,
        "balance_paise": balance,
        "status": "paid" if balance == 0 else inv.status,
        "upi_uri": upi,
        "upi_vpa": billing.upi_vpa if billing else None,
        "payee_name": payee,
        "bank": (
            {
                "name": tpl.bank_name,
                "account_name": tpl.bank_account_name,
                "account_number": tpl.bank_account_number,
                "ifsc": tpl.bank_ifsc,
            }
            if tpl and tpl.show_bank_details and tpl.bank_account_number
            else None
        ),
        "online_payment": False,
        "note": "Pay by UPI or bank transfer. Your ISP marks the invoice paid when the money arrives.",  # noqa: E501
    }


# ---------------------------------------------------------------------------
# WhatsApp
# ---------------------------------------------------------------------------


async def _whatsapp_sender(session: Any, isp_org_id: uuid.UUID) -> Any | None:
    from app.domains.marketing.models import OrgMarketingProvider
    from app.domains.marketing.providers import MetaCloudWhatsAppSender, decrypt_config

    row = (
        await session.execute(
            select(OrgMarketingProvider).where(
                OrgMarketingProvider.organization_id == isp_org_id,
                OrgMarketingProvider.channel == "whatsapp",
                OrgMarketingProvider.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if (
        row is None
        or row.provider_type != "meta_cloud"
        or row.status != "verified"
        or not row.enabled
    ):  # noqa: E501
        return None
    return MetaCloudWhatsAppSender(decrypt_config(row.config_encrypted))


class _WhatsappRun:
    def __init__(
        self,
        session: Any,
        isp_org_id: uuid.UUID,
        settings: IspAutomationSettings,
        sender: Any,
    ) -> None:  # noqa: E501
        self.session = session
        self.isp_org_id = isp_org_id
        self.settings = settings
        self.sender = sender
        self.sent = 0
        self.skipped = 0
        self.failed = 0

    async def send(
        self,
        trigger: str,
        phone: str | None,
        params: list[str],
        *,
        dedupe_key: str,
        summary: str,
        customer_id: uuid.UUID | None = None,
        subscriber_id: uuid.UUID | None = None,
        invoice_id: uuid.UUID | None = None,
        payment_id: uuid.UUID | None = None,
    ) -> None:
        from app.domains.marketing.senders import SendError

        if await _already(self.session, self.isp_org_id, dedupe_key):
            return
        tpl = (self.settings.whatsapp_templates or {}).get(trigger)
        to = e164_in(phone)
        base = dict(
            channel="whatsapp",
            trigger=trigger,
            recipient_masked=mask_phone(phone),
            customer_organization_id=customer_id,
            subscriber_id=subscriber_id,
            invoice_id=invoice_id,
            payment_id=payment_id,
            summary=summary,
            dedupe_key=dedupe_key,
        )
        if not tpl or to is None:
            # Recorded once so the log explains why nothing went out.
            self.session.add(
                log_row(
                    self.isp_org_id,
                    status="skipped",
                    error="no template mapped for this trigger"
                    if not tpl
                    else "no valid mobile number",  # noqa: E501
                    **base,
                )
            )
            self.skipped += 1
            return
        try:
            result = await self.sender.send_waba_template(
                to,
                template_name=tpl["template_name"],
                language=tpl.get("language") or "en",
                parameters=[str(p)[:200] for p in params],
            )
            self.session.add(
                log_row(
                    self.isp_org_id,
                    status="sent",
                    provider_message_id=result.message_id,
                    **base,
                )  # noqa: E501
            )
            self.sent += 1
        except SendError as exc:
            # A transient failure keeps no dedupe key, so the next sweep retries.
            keep = base | ({"dedupe_key": None} if not exc.permanent else {})
            self.session.add(
                log_row(self.isp_org_id, status="failed", error=str(exc), **keep)
            )
            self.failed += 1
        await self.session.flush()


def _sub_name(sub: Any) -> str:
    return (
        " ".join(p for p in (sub.first_name, sub.last_name) if p)
        or sub.display_name
        or "Customer"
    )


async def _contact_flags(session: Any, isp_org_id: uuid.UUID) -> dict:
    rows = (
        (
            await session.execute(
                select(IspBillingContact).where(
                    IspBillingContact.isp_organization_id == isp_org_id,
                    IspBillingContact.is_deleted.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    return {(r.subject_kind, r.subject_id): r for r in rows}


def _may_message(flags: dict, kind: str, subject: Any) -> bool:
    c = flags.get((kind, subject.id))
    if c is not None and c.exclude_from_reminders:
        return False
    if kind == "subscriber":
        return bool((subject.reminder_opt_in or {}).get("whatsapp"))
    return bool(c and c.whatsapp_opt_in)


async def _recipient(session: Any, inv: IspInvoice) -> tuple[str, Any] | None:
    from app.domains.organization.models import Organization

    from .plans_models import IspSubscriber

    if inv.bill_to_kind == "subscriber" and inv.subscriber_id:
        sub = await session.get(IspSubscriber, inv.subscriber_id)
        return ("subscriber", sub) if sub is not None else None
    org = await session.get(Organization, inv.customer_organization_id)
    return ("customer", org) if org is not None else None


def _phone(kind: str, subject: Any) -> str | None:
    return (
        subject.phone
        if kind == "subscriber"
        else getattr(subject, "contact_phone", None)
    )


def _name(kind: str, subject: Any) -> str:
    return _sub_name(subject) if kind == "subscriber" else subject.name


async def run_whatsapp_events(session: Any, isp_org_id: uuid.UUID) -> dict:
    """Receipts and renewal confirmations (near real time: 120 s task)."""
    cfg = get_finance_settings()
    st = await automation_settings(session, isp_org_id)
    if not (
        cfg.whatsapp_automation_enabled
        and st
        and st.whatsapp_enabled
        and st.whatsapp_enabled_at
    ):  # noqa: E501
        return {"skipped": "off"}
    sender = await _whatsapp_sender(session, isp_org_id)
    if sender is None:
        return {"skipped": "no verified WhatsApp sender"}
    run = _WhatsappRun(session, isp_org_id, st, sender)
    flags = await _contact_flags(session, isp_org_id)
    since = max(st.whatsapp_enabled_at, datetime.now(UTC) - timedelta(days=1))
    pays = (
        (
            await session.execute(
                select(IspPayment).where(
                    IspPayment.isp_organization_id == isp_org_id,
                    IspPayment.status == "confirmed",
                    IspPayment.created_at >= since,
                    IspPayment.mode != "prepaid_coupon",
                )
            )
        )
        .scalars()
        .all()
    )
    from app.domains.organization.models import Organization

    from .plans_models import IspSubscriber

    for p in pays:
        if p.subscriber_id:
            kind, subj = "subscriber", await session.get(IspSubscriber, p.subscriber_id)
        else:
            kind, subj = (
                "customer",
                await session.get(Organization, p.customer_organization_id),
            )
        if subj is None or not _may_message(flags, kind, subj):
            continue
        await run.send(
            "receipt",
            _phone(kind, subj),
            [
                _name(kind, subj),
                p.receipt_number,
                _rs(p.amount_paise),
                p.received_at.date().strftime("%d-%b-%Y"),
            ],  # noqa: E501
            dedupe_key=f"receipt:{p.id}",
            summary=f"Receipt {p.receipt_number} {_rs(p.amount_paise)}",
            customer_id=p.customer_organization_id,
            subscriber_id=p.subscriber_id,
            payment_id=p.id,
        )
    renewals = (
        (
            await session.execute(
                select(IspInvoice).where(
                    IspInvoice.isp_organization_id == isp_org_id,
                    IspInvoice.doc_type == "invoice",
                    IspInvoice.invoice_kind.in_(("recharge", "renewal")),
                    IspInvoice.status != "cancelled",
                    IspInvoice.created_at >= since,
                )
            )
        )
        .scalars()
        .all()
    )
    for inv in renewals:
        rec = await _recipient(session, inv)
        if rec is None or not _may_message(flags, *rec):
            continue
        kind, subj = rec
        until = getattr(subj, "valid_until", None) if kind == "subscriber" else None
        await run.send(
            "renewal",
            _phone(kind, subj),
            [
                _name(kind, subj),
                inv.number,
                (
                    until.date().strftime("%d-%b-%Y")
                    if until
                    else (
                        inv.period_end.strftime("%d-%b-%Y") if inv.period_end else "-"
                    )
                ),
            ],  # noqa: E501
            dedupe_key=f"renewal:{inv.id}",
            summary=f"Renewal {inv.number}",
            customer_id=inv.customer_organization_id,
            subscriber_id=inv.subscriber_id,
            invoice_id=inv.id,
        )
    return {"sent": run.sent, "skipped": run.skipped, "failed": run.failed}


async def run_whatsapp_daily(session: Any, isp_org_id: uuid.UUID, today: date) -> dict:
    """Pre-expiry reminders and unpaid-invoice reminders (daily run)."""
    from .plans_models import IspPackage, IspSubscriber

    cfg = get_finance_settings()
    st = await automation_settings(session, isp_org_id)
    if not (
        cfg.whatsapp_automation_enabled
        and st
        and st.whatsapp_enabled
        and st.whatsapp_enabled_at
    ):  # noqa: E501
        return {"skipped": "off"}
    sender = await _whatsapp_sender(session, isp_org_id)
    if sender is None:
        return {"skipped": "no verified WhatsApp sender"}
    run = _WhatsappRun(session, isp_org_id, st, sender)
    flags = await _contact_flags(session, isp_org_id)
    target = today + timedelta(days=st.pre_expiry_days)
    start = datetime.combine(target, datetime.min.time(), tzinfo=UTC) - timedelta(
        hours=5, minutes=30
    )  # noqa: E501
    subs = (
        (
            await session.execute(
                select(IspSubscriber).where(
                    IspSubscriber.isp_organization_id == isp_org_id,
                    IspSubscriber.is_deleted.is_(False),
                    IspSubscriber.status == "active",
                    IspSubscriber.valid_until >= start,
                    IspSubscriber.valid_until < start + timedelta(days=1),
                )
            )
        )
        .scalars()
        .all()
    )
    for s in subs:
        if not _may_message(flags, "subscriber", s):
            continue
        pkg = await session.get(IspPackage, s.package_id) if s.package_id else None
        await run.send(
            "pre_expiry",
            s.phone,
            [
                _sub_name(s),
                target.strftime("%d-%b-%Y"),
                pkg.name if pkg else "your plan",
            ],
            dedupe_key=f"pre_expiry:{s.id}:{target.isoformat()}",
            summary=f"Expires {target.isoformat()}",
            customer_id=s.customer_organization_id,
            subscriber_id=s.id,
        )
    cutoff = today - timedelta(days=st.unpaid_reminder_after_days)
    week = today.isocalendar()
    invs = (
        (
            await session.execute(
                select(IspInvoice).where(
                    IspInvoice.isp_organization_id == isp_org_id,
                    IspInvoice.doc_type == "invoice",
                    IspInvoice.status.in_(("issued", "partially_paid")),
                    IspInvoice.due_date <= cutoff,
                    IspInvoice.is_deleted.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    for inv in invs:
        bal = balance_of(inv)
        if bal <= 0:
            continue
        rec = await _recipient(session, inv)
        if rec is None or not _may_message(flags, *rec):
            continue
        kind, subj = rec
        link = await pay_link_for(session, isp_org_id, inv.id)
        await run.send(
            "unpaid",
            _phone(kind, subj),
            [_name(kind, subj), inv.number, _rs(bal), link],
            dedupe_key=f"unpaid:{inv.id}:{week[0]}-{week[1]}",
            summary=f"Unpaid {inv.number} {_rs(bal)}",
            customer_id=inv.customer_organization_id,
            subscriber_id=inv.subscriber_id,
            invoice_id=inv.id,
        )
    return {"sent": run.sent, "skipped": run.skipped, "failed": run.failed}


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------


async def telegram_send(
    token: str, chat_id: str, text: str, *, transport: Any = None
) -> str | None:  # noqa: E501
    """Returns None on success, else a short error (never the token)."""
    try:
        async with httpx.AsyncClient(timeout=10, transport=transport) as client:
            r = await client.post(
                f"{TELEGRAM_API}/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text[:4000],
                    "disable_web_page_preview": True,
                },  # noqa: E501
            )
        if r.status_code == 200 and (r.json() or {}).get("ok"):
            return None
        try:
            desc = (r.json() or {}).get("description") or ""
        except ValueError:
            desc = ""
        return f"telegram {r.status_code}: {desc}"[:200]
    except httpx.HTTPError as exc:
        return f"telegram unreachable: {type(exc).__name__}"


def _token(st: IspAutomationSettings) -> str | None:
    from app.domains.marketing.providers import decrypt_config

    if not st.telegram_bot_token_encrypted:
        return None
    return decrypt_config(st.telegram_bot_token_encrypted).get("bot_token")


async def telegram_test(session: Any, isp: Any) -> dict:
    st = await automation_settings(session, isp.isp_org_id)
    token = _token(st) if st else None
    if not token or not st.telegram_chat_id:
        raise IspAutomationError("Save a bot token and a chat id first")
    err = await telegram_send(
        token,
        st.telegram_chat_id,
        f"Test alert from {isp.organization.name} (Wyfy ISP console).",
    )  # noqa: E501
    session.add(
        log_row(
            isp.isp_org_id,
            channel="telegram",
            trigger="test",
            recipient_masked=f"chat …{str(st.telegram_chat_id)[-4:]}",
            summary="Test message",
            status="failed" if err else "sent",
            error=err,
        )
    )
    await session.flush()
    return {"ok": err is None, "error": err}


async def _device_statuses(
    session: Any, child_ids: list[uuid.UUID], include_aps: bool
) -> list[tuple[str, uuid.UUID, str, str, uuid.UUID]]:  # noqa: E501
    """(kind, id, name, up|down, customer org id); unknown/pending skipped."""
    from app.domains.router.models import Router

    out: list = []
    if not child_ids:
        return out
    routers = (
        (
            await session.execute(
                select(Router).where(
                    Router.organization_id.in_(child_ids),
                    Router.is_deleted.is_(False),
                    Router.status.in_(("online", "offline")),
                )
            )
        )
        .scalars()
        .all()
    )
    for r in routers:
        out.append(
            (
                "router",
                r.id,
                r.name,
                "up" if r.status == "online" else "down",
                r.organization_id,
            )
        )  # noqa: E501
    if include_aps:
        try:
            from app.domains.location.repository import (
                LocationCodeCounterRepository,
                LocationRepository,
            )
            from app.domains.location.service import LocationService
            from app.domains.monitored_hardware.repository import (
                MonitoredHardwareRepository,
            )
            from app.domains.monitored_hardware.service import MonitoredHardwareService
            from app.domains.organization.repository import OrganizationRepository
            from app.domains.organization.service import OrganizationService
            from app.domains.router.repository import RouterRepository
            from app.domains.router.service import RouterService

            org_service = OrganizationService(OrganizationRepository(session))
            loc = LocationService(
                LocationRepository(session),
                org_service,
                location_code_counter=LocationCodeCounterRepository(session),
            )
            mh = MonitoredHardwareService(
                MonitoredHardwareRepository(session),
                loc,
                RouterService(RouterRepository(session), loc, org_service),  # noqa: E501
            )
            for cid in child_ids:
                for d in await mh.list_all_devices_with_status(organization_id=cid):
                    st = str(getattr(d.status, "value", d.status))
                    if st in ("up", "down"):
                        out.append(("ap", d.device.id, d.device.name, st, cid))
        except Exception:  # noqa: BLE001 -- AP status is best effort
            logger.warning("isp_telegram_ap_status_unavailable")
    return out


async def run_telegram(
    session: Any,
    isp_org_id: uuid.UUID,
    child_ids: list[uuid.UUID],
    *,
    now: datetime | None = None,
    transport: Any = None,
) -> dict:  # noqa: E501
    cfg = get_finance_settings()
    st = await automation_settings(session, isp_org_id)
    if not (cfg.telegram_alerts_enabled and st and st.telegram_enabled):
        return {"skipped": "off"}
    token = _token(st)
    if not token or not st.telegram_chat_id:
        return {"skipped": "not configured"}
    now = now or datetime.now(UTC)
    debounce = timedelta(minutes=max(0, st.telegram_debounce_minutes))
    states = {
        (s.device_kind, s.device_id): s
        for s in (
            await session.execute(
                select(IspAlertDeviceState).where(
                    IspAlertDeviceState.isp_organization_id == isp_org_id
                )  # noqa: E501
            )
        ).scalars()
    }
    lines: list[str] = []
    to_mark: list[IspAlertDeviceState] = []
    for kind, did, name, status, _cid in await _device_statuses(
        session, child_ids, st.telegram_include_aps
    ):  # noqa: E501
        s = states.get((kind, did))
        if s is None:
            session.add(
                IspAlertDeviceState(
                    isp_organization_id=isp_org_id,
                    device_kind=kind,
                    device_id=did,
                    observed_status=status,
                    observed_since=now,
                    notified_status=status,
                    notified_at=now,
                )
            )
            continue
        if s.observed_status != status:
            s.observed_status = status
            s.observed_since = now
        if (
            s.notified_status != s.observed_status
            and now - s.observed_since >= debounce
        ):
            label = "Router" if kind == "router" else "AP"
            mark = "DOWN" if s.observed_status == "down" else "UP"
            since = s.observed_since.astimezone(_IST).strftime("%H:%M")
            dot = "🔴" if mark == "DOWN" else "🟢"
            lines.append(f"{dot} {label} {name}: {mark} since {since} IST")
            to_mark.append(s)
    sent = 0
    if lines:
        err = await telegram_send(
            token, st.telegram_chat_id, "\n".join(lines), transport=transport
        )  # noqa: E501
        session.add(
            log_row(
                isp_org_id,
                channel="telegram",
                trigger="device_alert",
                recipient_masked=f"chat …{str(st.telegram_chat_id)[-4:]}",
                summary="; ".join(lines)[:300],
                status="failed" if err else "sent",
                error=err,
            )
        )
        if err is None:
            for s in to_mark:
                s.notified_status = s.observed_status
                s.notified_at = now
            sent = len(lines)
    await session.flush()
    return {"alerts": sent, "pending": len(lines) - sent}


__all__ = [
    "IspAutomationError",
    "TRIGGERS",
    "e164_in",
    "list_log",
    "mask_email",
    "mask_phone",
    "pay_link_for",
    "public_pay_view",
    "put_settings",
    "run_telegram",
    "run_whatsapp_daily",
    "run_whatsapp_events",
    "settings_view",
    "telegram_send",
    "telegram_test",
]
