"""COMMS-2 routes (ADDENDUM_06). ``ISP_COMMS_HUB_ENABLED`` (default OFF):
every route answers 404 ``ISP_COMMS_HUB_DISABLED`` while off.

* ``GET /isp/comms/logs`` (+ ``/export.csv``): one log over WhatsApp, email
  and Telegram (JAZE-4 ``isp_message_log``) with the delivery lifecycle,
  filters (channel, status, event, phone, email, plain-date range) and the
  caller's customer scope (ZONE-1 narrows it). Status ``delivered`` / ``read``
  only ever comes from a Meta receipt.
* ``GET|PUT /isp/comms/webhook`` + ``POST .../rotate``: the ISP's Meta webhook
  (path token, verify token, app secret). ``GET|POST
  /isp/public/comms/whatsapp/{path_token}``: Meta's subscribe check and the
  signed status callbacks (``X-Hub-Signature-256``; unsigned -> 403).
* ``GET /isp/comms/templates``, ``PUT /isp/comms/templates/{event}/{channel}``,
  ``POST .../preview``: the per-event template library. A WhatsApp template
  must be APPROVED in the ISP's own WABA (checked live) and take exactly the
  event's variables; enabling one writes JAZE-4's automation mapping for the
  wired trigger (no free text is ever sent). Pay links in previews use the
  existing JAZE-4 pay-link URL scheme.
"""

from __future__ import annotations

import csv
import io
import json
import secrets
import uuid
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from typing import Any, Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from . import comms_logic as logic
from .comms_models import IspCommsWebhook, IspMessageReceipt, IspMessageTemplate
from .constants import ISP_BILLING_EXPORT, ISP_BILLING_MANAGE
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError, _err
from .finance_models import IspMessageLog
from .http import ok

IST = ZoneInfo("Asia/Kolkata")


class IspCommsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    comms_hub_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_comms_settings() -> IspCommsSettings:
    return IspCommsSettings()


IspCommsDisabledError = _err(
    "IspCommsDisabledError", "ISP_COMMS_HUB_DISABLED", 404, "Not Found"
)
IspWaTemplateNotApprovedError = _err(
    "IspWaTemplateNotApprovedError",
    "ISP_WA_TEMPLATE_NOT_APPROVED",
    422,
    "That WhatsApp template is not approved in your WhatsApp Business account",
)
IspWaSenderMissingError = _err(
    "IspWaSenderMissingError",
    "ISP_WA_SENDER_NOT_CONNECTED",
    409,
    "Connect and verify your WhatsApp Business sender first",
)
IspWebhookRejectedError = _err(
    "IspWebhookRejectedError", "ISP_WEBHOOK_REJECTED", 403, "Forbidden"
)


async def RequireCommsEnabled() -> None:
    if not get_comms_settings().comms_hub_enabled:
        raise IspCommsDisabledError()


comms_router = APIRouter(tags=["ISP Partner: communication hub"])
comms_public_router = APIRouter(tags=["ISP Partner: Meta webhook"])
_ON = [Depends(RequireCommsEnabled)]


def _ist(v: datetime | None) -> str | None:
    if v is None:
        return None
    a = v if v.tzinfo else v.replace(tzinfo=UTC)
    return a.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------


class _LogQuery(BaseModel):
    channel: str | None = None
    status: str | None = None
    event: str | None = None
    phone: str | None = None
    email: str | None = None
    date_from: date | None = None
    date_to: date | None = None


def _log_query(
    channel: Literal["email", "whatsapp", "telegram"] | None = None,
    status: Literal["queued", "sent", "delivered", "read", "failed", "skipped"]
    | None = None,
    event: str | None = Query(default=None, max_length=16),
    phone: str | None = Query(default=None, max_length=20),
    email: str | None = Query(default=None, max_length=255),
    date_from: date | None = None,
    date_to: date | None = None,
) -> _LogQuery:
    if date_from and date_to and date_to < date_from:
        raise IspBadRequestError("date_to is before date_from")
    return _LogQuery(
        channel=channel,
        status=status,
        event=event,
        phone=phone,
        email=email,
        date_from=date_from,
        date_to=date_to,
    )


async def _contact_subjects(
    db: AsyncSession, isp: IspContext, phone: str | None, email: str | None
) -> tuple[set[uuid.UUID], set[uuid.UUID]]:
    """Subscribers and customers whose phone / email matches."""
    from app.domains.organization.models import Organization

    from .plans_models import IspSubscriber

    subs: set[uuid.UUID] = set()
    custs: set[uuid.UUID] = set()
    children = await isp.child_ids()
    digits = "".join(c for c in (phone or "") if c.isdigit())[-10:]
    if digits:
        subs |= set(
            (
                await db.execute(
                    select(IspSubscriber.id).where(
                        IspSubscriber.isp_organization_id == isp.isp_org_id,
                        IspSubscriber.phone.like(f"%{digits}"),
                    )
                )
            ).scalars()
        )
        if children:
            custs |= set(
                (
                    await db.execute(
                        select(Organization.id).where(
                            Organization.id.in_(children),
                            Organization.contact_phone.like(f"%{digits}"),
                        )
                    )
                ).scalars()
            )
    if email:
        e = email.strip().lower()
        subs |= set(
            (
                await db.execute(
                    select(IspSubscriber.id).where(
                        IspSubscriber.isp_organization_id == isp.isp_org_id,
                        func.lower(IspSubscriber.email) == e,
                    )
                )
            ).scalars()
        )
        if children:
            custs |= set(
                (
                    await db.execute(
                        select(Organization.id).where(
                            Organization.id.in_(children),
                            func.lower(Organization.contact_email) == e,
                        )
                    )
                ).scalars()
            )
    return subs, custs


async def _log_rows(
    db: AsyncSession, isp: IspContext, q: _LogQuery, *, limit: int | None = None
) -> list[dict[str, Any]]:
    children = await isp.child_ids()
    s = select(IspMessageLog).where(IspMessageLog.isp_organization_id == isp.isp_org_id)
    if isp.confined_customer_ids is not None:
        # Confined (or zone-scoped): only its customers' rows, never ISP-wide alerts.
        s = s.where(
            IspMessageLog.customer_organization_id.in_(children or [uuid.UUID(int=0)])
        )
    if q.channel:
        s = s.where(IspMessageLog.channel == q.channel)
    if q.event:
        s = s.where(IspMessageLog.trigger == q.event)
    if q.date_from:
        s = s.where(
            IspMessageLog.created_at
            >= datetime.combine(q.date_from, datetime.min.time(), tzinfo=IST)
        )
    if q.date_to:
        s = s.where(
            IspMessageLog.created_at
            < datetime.combine(
                q.date_to + timedelta(days=1), datetime.min.time(), tzinfo=IST
            )
        )
    if q.phone or q.email:
        subs, custs = await _contact_subjects(db, isp, q.phone, q.email)
        conds = []
        if subs:
            conds.append(IspMessageLog.subscriber_id.in_(subs))
        if custs:
            conds.append(
                (IspMessageLog.customer_organization_id.in_(custs))
                & IspMessageLog.subscriber_id.is_(None)
            )
        if not conds:
            return []
        s = s.where(or_(*conds))
    s = s.order_by(IspMessageLog.created_at.desc())
    if limit:
        s = s.limit(limit)
    rows = list((await db.execute(s)).scalars())
    pmids = [r.provider_message_id for r in rows if r.provider_message_id]
    receipts: dict[str, list[dict[str, Any]]] = {}
    if pmids:
        for r in (
            await db.execute(
                select(IspMessageReceipt)
                .where(
                    IspMessageReceipt.isp_organization_id == isp.isp_org_id,
                    IspMessageReceipt.provider_message_id.in_(pmids),
                )
                .order_by(IspMessageReceipt.occurred_at)
            )
        ).scalars():
            receipts.setdefault(r.provider_message_id, []).append(
                {
                    "status": r.status,
                    "occurred_at": r.occurred_at,
                    "error_code": r.error_code,
                    "error_title": r.error_title,
                }
            )
    order = {"sent": 1, "delivered": 2, "read": 3, "failed": 4}
    for lst in receipts.values():
        lst.sort(key=lambda x: (x["occurred_at"], order.get(x["status"], 9)))
    from .comms2b import contents_for

    # COMMS-2b: the template + parameters actually sent, when recorded.
    contents = await contents_for(db, isp.isp_org_id, [r.id for r in rows])
    out = []
    for r in rows:
        rs = receipts.get(r.provider_message_id or "", [])
        sent = contents.get(r.id)
        life = logic.lifecycle(r.status, rs)
        if q.status and life["status"] != q.status:
            continue
        out.append(
            {
                "id": str(r.id),
                "at_ist": _ist(r.created_at),
                "channel": r.channel,
                "event": r.trigger,
                "recipient": r.recipient_masked,
                "content": _content(sent) if sent is not None else r.summary,
                "summary": r.summary,
                "template_name": sent.template_name if sent is not None else None,
                "parameters": list(sent.parameters) if sent is not None else None,
                "status": life["status"],
                "status_at_ist": _ist(life["status_at"]),
                "error": life["receipt_error"] or r.error,
                "provider_message_id": r.provider_message_id,
                "receipts": [
                    {
                        "status": x["status"],
                        "at_ist": _ist(x["occurred_at"]),
                        "error_code": x["error_code"],
                        "error_title": x["error_title"],
                    }
                    for x in rs
                ],
                "isp_customer_id": str(r.customer_organization_id)
                if r.customer_organization_id
                else None,
                "subscriber_id": str(r.subscriber_id) if r.subscriber_id else None,
                "invoice_id": str(r.invoice_id) if r.invoice_id else None,
            }
        )
    return out


def _content(sent: Any) -> str:
    vals = " | ".join(
        f"{p.get('variable') or p.get('position')}: {p.get('value')}"
        for p in (sent.parameters or [])
    )
    return f"{sent.template_name} · {vals}" if vals else str(sent.template_name)


# RBAC-FIX (founder 2026-11-01): logs and templates carry recipient
# phone/email and content -> owner/admin/billing (isp_billing.export).
@comms_router.get("/comms/logs", dependencies=_ON + isp_guards(ISP_BILLING_EXPORT))
async def comms_logs(
    request: Request,
    q: _LogQuery = Depends(_log_query),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    rows = await _log_rows(db, isp, q, limit=5000)
    total = len(rows)
    items = rows[(page - 1) * page_size : page * page_size]
    return ok(
        request,
        {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, -(-total // page_size)),
            "status_note": (
                "Delivered and read come only from WhatsApp delivery receipts. "
                "Email and Telegram stop at sent."
            ),
        },
        "Message log",
    )


_CSV = (
    "Time (IST)",
    "Channel",
    "Event",
    "Recipient",
    "Content",
    "Status",
    "Status time (IST)",
    "Error",
    "Provider message id",
)


@comms_router.get(
    "/comms/logs/export.csv", dependencies=_ON + isp_guards(ISP_BILLING_EXPORT)
)
async def comms_logs_csv(
    q: _LogQuery = Depends(_log_query),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    from app.domains.ipdr.formatting import csv_safe

    rows = await _log_rows(db, isp, q, limit=50000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV)
    for r in rows:
        w.writerow(
            [
                csv_safe("" if v is None else v)
                for v in (
                    r["at_ist"],
                    r["channel"],
                    r["event"],
                    r["recipient"],
                    r["content"],
                    r["status"],
                    r["status_at_ist"],
                    r["error"],
                    r["provider_message_id"],
                )
            ]
        )
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return Response(
        content=buf.getvalue().encode(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="messages-{stamp}.csv"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Meta webhook
# ---------------------------------------------------------------------------


class WebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    #: The Meta app secret that signs webhook POSTs. Empty = keep the current one.
    app_secret: str | None = Field(default=None, max_length=128)


def _callback_path(token: str) -> str:
    return f"/api/v1/isp/public/comms/whatsapp/{token}"


async def _webhook(db: AsyncSession, isp_org_id: uuid.UUID) -> IspCommsWebhook | None:
    return (
        await db.execute(
            select(IspCommsWebhook).where(
                IspCommsWebhook.isp_organization_id == isp_org_id,
                IspCommsWebhook.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


def _webhook_view(w: IspCommsWebhook | None) -> dict[str, Any]:
    if w is None:
        return {"configured": False}
    return {
        "configured": True,
        "callback_path": _callback_path(w.path_token),
        "verify_token": w.verify_token,
        "app_secret_set": bool(w.app_secret_encrypted),
        "last_received_ist": _ist(w.last_received_at),
        "rejected_count": w.rejected_count,
    }


@comms_router.get("/comms/webhook", dependencies=_ON + isp_guards(ISP_BILLING_MANAGE))
async def get_webhook(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(request, _webhook_view(await _webhook(db, isp.isp_org_id)), "Webhook")


@comms_router.put("/comms/webhook", dependencies=_ON + isp_guards(ISP_BILLING_MANAGE))
async def put_webhook(
    request: Request,
    body: WebhookRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.domains.marketing.providers import encrypt_config

    w = await _webhook(db, isp.isp_org_id)
    if w is None:
        w = IspCommsWebhook(
            isp_organization_id=isp.isp_org_id,
            path_token=secrets.token_urlsafe(32),
            verify_token=secrets.token_urlsafe(24),
            created_by=isp.user_id,
        )
        db.add(w)
    if body.app_secret:
        w.app_secret_encrypted = encrypt_config({"app_secret": body.app_secret})
    w.updated_by = isp.user_id
    await db.flush()
    view = _webhook_view(w)
    await db.commit()
    return ok(request, view, "Webhook saved")


@comms_router.post(
    "/comms/webhook/rotate", dependencies=_ON + isp_guards(ISP_BILLING_MANAGE)
)
async def rotate_webhook(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    w = await _webhook(db, isp.isp_org_id)
    if w is None:
        raise IspBadRequestError("Set up the webhook first")
    w.path_token = secrets.token_urlsafe(32)
    w.verify_token = secrets.token_urlsafe(24)
    w.updated_by = isp.user_id
    await db.flush()
    view = _webhook_view(w)
    await db.commit()
    return ok(request, view, "Webhook rotated")


async def _webhook_by_token(db: AsyncSession, token: str) -> IspCommsWebhook | None:
    if not token or len(token) > 64:
        return None
    return (
        await db.execute(
            select(IspCommsWebhook).where(
                IspCommsWebhook.path_token == token,
                IspCommsWebhook.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


@comms_public_router.get("/public/comms/whatsapp/{path_token}", dependencies=_ON)
async def meta_verify(
    path_token: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> PlainTextResponse:
    """Meta's subscribe handshake: echo ``hub.challenge`` when the verify
    token matches."""
    w = await _webhook_by_token(db, path_token)
    p = request.query_params
    if (
        w is None
        or p.get("hub.mode") != "subscribe"
        or not secrets.compare_digest(p.get("hub.verify_token") or "", w.verify_token)
    ):
        raise IspWebhookRejectedError()
    return PlainTextResponse(p.get("hub.challenge") or "")


@comms_public_router.post("/public/comms/whatsapp/{path_token}", dependencies=_ON)
async def meta_statuses(
    path_token: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Signed WhatsApp status callbacks -> receipts. Only messages this ISP
    sent (by provider message id) are recorded; nothing else is touched."""
    from app.domains.marketing.providers import decrypt_config

    w = await _webhook_by_token(db, path_token)
    raw = await request.body()
    secret = ""
    if w is not None and w.app_secret_encrypted:
        secret = str(decrypt_config(w.app_secret_encrypted).get("app_secret") or "")
    if w is None or not logic.signature_ok(
        secret, raw, request.headers.get("X-Hub-Signature-256")
    ):
        if w is not None:
            w.rejected_count = (w.rejected_count or 0) + 1
            await db.commit()
        raise IspWebhookRejectedError()
    try:
        payload = json.loads(raw.decode() or "{}")
    except ValueError as exc:
        raise IspBadRequestError("Body is not JSON") from exc
    updates = logic.parse_statuses(payload)
    known = {}
    if updates:
        known = dict(
            (
                await db.execute(
                    select(IspMessageLog.provider_message_id, IspMessageLog.id).where(
                        IspMessageLog.isp_organization_id == w.isp_organization_id,
                        IspMessageLog.provider_message_id.in_(
                            [u["provider_message_id"] for u in updates]
                        ),
                    )
                )
            ).all()
        )
    stored = 0
    for u in updates:
        log_id = known.get(u["provider_message_id"])
        if log_id is None:
            continue  # not a message this ISP sent: ignored
        exists = (
            await db.execute(
                select(IspMessageReceipt.id).where(
                    IspMessageReceipt.isp_organization_id == w.isp_organization_id,
                    IspMessageReceipt.provider_message_id == u["provider_message_id"],
                    IspMessageReceipt.status == u["status"],
                )
            )
        ).first()
        if exists:
            continue
        db.add(
            IspMessageReceipt(
                isp_organization_id=w.isp_organization_id, message_log_id=log_id, **u
            )
        )
        stored += 1
    w.last_received_at = datetime.now(UTC)
    await db.commit()
    return {"received": len(updates), "stored": stored}


# ---------------------------------------------------------------------------
# template library
# ---------------------------------------------------------------------------


class TemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    enabled: bool = False
    email_subject: str | None = Field(default=None, max_length=200)
    email_body: str | None = Field(default=None, max_length=10000)
    wa_template_name: str | None = Field(
        default=None, max_length=512, pattern=r"^[a-z0-9_]*$"
    )
    wa_language: str | None = Field(
        default=None, max_length=15, pattern=r"^[A-Za-z_]*$"
    )


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email_subject: str | None = Field(default=None, max_length=200)
    email_body: str | None = Field(default=None, max_length=10000)


def _tpl_view(event: str, channel: str, t: IspMessageTemplate | None) -> dict[str, Any]:
    e = logic.EVENTS[event]
    return {
        "event": event,
        "label": e["label"],
        "channel": channel,
        "variables": e["vars"],
        "wired": e["trigger"] is not None,
        "automation_trigger": e["trigger"],
        "enabled": bool(t and t.enabled),
        "email_subject": t.email_subject if t else None,
        "email_body": t.email_body if t else None,
        "wa_template_name": t.wa_template_name if t else None,
        "wa_language": t.wa_language if t else None,
        "wa_approval_status": t.wa_approval_status if t else None,
        "wa_checked_ist": _ist(t.wa_checked_at) if t else None,
    }


async def _templates(db: AsyncSession, isp_org_id: uuid.UUID) -> dict[tuple, Any]:
    return {
        (t.event, t.channel): t
        for t in (
            await db.execute(
                select(IspMessageTemplate).where(
                    IspMessageTemplate.isp_organization_id == isp_org_id,
                    IspMessageTemplate.is_deleted.is_(False),
                )
            )
        ).scalars()
    }


@comms_router.get("/comms/templates", dependencies=_ON + isp_guards(ISP_BILLING_EXPORT))
async def list_templates(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    have = await _templates(db, isp.isp_org_id)
    items = [
        _tpl_view(ev, ch, have.get((ev, ch)))
        for ev in logic.EVENTS
        for ch in ("whatsapp", "email")
    ]
    return ok(
        request,
        {
            "items": items,
            "rules": (
                "WhatsApp messages use approved templates from your own WhatsApp "
                "Business account only; free text is never sent. Variables are "
                "filled in the order listed."
            ),
        },
        "Templates",
    )


def _check(event: str, channel: str) -> None:
    if event not in logic.EVENTS:
        raise IspBadRequestError("Unknown event", field="event")
    if channel not in ("email", "whatsapp"):
        raise IspBadRequestError("Channel is email or whatsapp", field="channel")


@comms_router.put(
    "/comms/templates/{event}/{channel}",
    dependencies=_ON + isp_guards(ISP_BILLING_MANAGE),
)
async def put_template(
    request: Request,
    event: str,
    channel: str,
    body: TemplateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .automation import _whatsapp_sender, automation_settings
    from .finance_models import IspAutomationSettings

    _check(event, channel)
    spec = logic.EVENTS[event]
    t = (await _templates(db, isp.isp_org_id)).get((event, channel))
    if t is None:
        t = IspMessageTemplate(
            isp_organization_id=isp.isp_org_id,
            event=event,
            channel=channel,
            created_by=isp.user_id,
        )
        db.add(t)
    if channel == "email":
        for field in ("email_subject", "email_body"):
            bad = logic.unknown_placeholders(getattr(body, field), event)
            if bad:
                raise IspBadRequestError(
                    f"Unknown variable(s): {', '.join(bad)}", field=field
                )
        if body.enabled and not (body.email_subject and body.email_body):
            raise IspBadRequestError(
                "An enabled email template needs a subject and body"
            )
        t.email_subject, t.email_body = body.email_subject, body.email_body
    else:
        name, lang = body.wa_template_name or "", body.wa_language or "en"
        if body.enabled and not name:
            raise IspBadRequestError(
                "Pick an approved template", field="wa_template_name"
            )
        if name:
            sender = await _whatsapp_sender(db, isp.isp_org_id)
            if sender is None:
                raise IspWaSenderMissingError()
            status, params = logic.find_approved(
                await sender.list_templates(), name, lang
            )
            t.wa_approval_status, t.wa_body_params = status, params
            t.wa_checked_at = datetime.now(UTC)
            if status != "APPROVED":
                raise IspWaTemplateNotApprovedError(status=status)
            if params is not None and params != len(spec["vars"]):
                raise IspBadRequestError(
                    f"This event fills {len(spec['vars'])} variables "
                    f"({', '.join(spec['vars'])}); the template takes {params}",
                    field="wa_template_name",
                )
        t.wa_template_name, t.wa_language = name or None, lang if name else None
        # JAZE-4 automation sends by its own mapping: keep it in step.
        trig = spec["trigger"]
        if trig is not None:
            row = await automation_settings(db, isp.isp_org_id)
            if row is None:
                row = IspAutomationSettings(
                    isp_organization_id=isp.isp_org_id, created_by=isp.user_id
                )
                db.add(row)
            mapping = dict(row.whatsapp_templates or {})
            if body.enabled and name:
                mapping[trig] = {"template_name": name[:512], "language": lang[:15]}
            else:
                mapping.pop(trig, None)
            row.whatsapp_templates = mapping
    t.enabled = body.enabled
    t.updated_by = isp.user_id
    await db.flush()
    view = _tpl_view(event, channel, t)
    await db.commit()
    return ok(request, view, "Template saved")


@comms_router.post(
    "/comms/templates/{event}/{channel}/preview",
    dependencies=_ON + isp_guards(ISP_BILLING_EXPORT),
)
async def preview_template(
    request: Request,
    event: str,
    channel: str,
    body: PreviewRequest | None = None,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .finance_config import get_finance_settings

    _check(event, channel)
    base = get_finance_settings().pay_link_base_url.rstrip("/")
    # The JAZE-4 pay-link scheme; the sample token is never a real one.
    values = logic.sample_values(event, f"{base}/partner/pay/SAMPLE-TOKEN")
    t = (await _templates(db, isp.isp_org_id)).get((event, channel))
    if channel == "email":
        subject = (body.email_subject if body and body.email_subject else None) or (
            t.email_subject if t else ""
        )
        text = (body.email_body if body and body.email_body else None) or (
            t.email_body if t else ""
        )
        return ok(
            request,
            {
                "channel": "email",
                "subject": logic.render(subject, values),
                "body": logic.render(text, values),
                "unknown_variables": logic.unknown_placeholders(
                    f"{subject} {text}", event
                ),
            },
            "Preview",
        )
    return ok(
        request,
        {
            "channel": "whatsapp",
            "template_name": t.wa_template_name if t else None,
            "language": t.wa_language if t else None,
            "parameters": [
                {"position": i + 1, "variable": v, "sample": values[v]}
                for i, v in enumerate(logic.EVENTS[event]["vars"])
            ],
            "note": "Meta renders the approved template text with these parameters.",
        },
        "Preview",
    )


__all__ = ["comms_public_router", "comms_router", "get_comms_settings"]
