"""J16 announcements: an ISP tells its customers something (planned
maintenance, a new plan, a holiday). Channels:

* **email**, through the existing notification outbox (``enqueue``, called
  unchanged), to each customer's ``contact_email``;
* **WhatsApp share**: a prefilled ``wa.me`` link per customer with a phone.
  The operator sends it from their own WhatsApp; nothing is sent by us
  (the same rule the invoice reminders follow). SMS is not offered.

Recipients are resolved at send time from the customers the SENDER can see
(confinement applies), so a confined user can never announce to a customer
outside their list. Sending is one-shot: a sent announcement is read-only.
"""

from __future__ import annotations

import html
import re
import urllib.parse
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from app.domains.notification.constants import NotificationChannelType

from .apps_common import (
    IspAppsEventType,
    IspAppsInvalidError,
    IspAppsNotFoundError,
    org_names,
    user_names,
)
from .apps_models import IspAnnouncement, IspAnnouncementRecipient
from .scoping import IspScope

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _now() -> datetime:
    return datetime.now(UTC)


def _future(v: Any) -> Any:
    """APPS-2: a schedule must be in the future (None = send by hand)."""
    if v is None:
        return None
    if v <= _now():
        raise IspAppsInvalidError("Pick a time in the future to schedule it")
    return v


def whatsapp_link(phone: str | None, text: str) -> str | None:
    """``wa.me`` wants digits only with the country code; a bare 10-digit
    Indian mobile gets ``91`` in front."""
    if not phone:
        return None
    digits = re.sub(r"\D", "", phone)
    if len(digits) == 10:
        digits = "91" + digits
    if len(digits) < 11:
        return None
    return f"https://wa.me/{digits}?text={urllib.parse.quote(text)}"


def share_text(isp_name: str, title: str, body: str) -> str:
    return f"{isp_name}: {title}\n\n{body}"


def email_html(isp_name: str, title: str, body: str) -> str:
    paras = "".join(
        f"<p>{html.escape(p).replace(chr(10), '<br>')}</p>"
        for p in body.split("\n\n")
        if p.strip()
    )
    return (
        f'<div style="font-family:Arial,sans-serif;max-width:560px">'
        f"<h2>{html.escape(title)}</h2>{paras}"
        f'<p style="color:#666">— {html.escape(isp_name)}</p></div>'
    )


class AnnouncementService:
    def __init__(self, session: Any, notifications: Any | None = None) -> None:
        self.session = session
        self.notifications = notifications

    async def _get(self, isp: Any, announcement_id: uuid.UUID) -> IspAnnouncement:
        a = await self.session.get(IspAnnouncement, announcement_id)
        if a is None or a.is_deleted or a.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Announcement not found")
        return a

    async def _check_customers(self, isp: Any, ids: list[uuid.UUID]) -> list[str]:
        for cid in ids:
            await IspScope.assert_customer(isp, cid)
        return [str(c) for c in ids]

    async def create(self, isp: Any, data: dict) -> dict:
        audience = data.get("audience") or "all"
        ids = data.get("customer_ids") or []
        if audience == "selected" and not ids:
            raise IspAppsInvalidError("Pick at least one customer")
        a = IspAnnouncement(
            isp_organization_id=isp.isp_org_id,
            title=data["title"],
            body=data["body"],
            audience=audience,
            customer_ids=await self._check_customers(isp, ids)
            if audience == "selected"
            else [],
            send_email=data.get("send_email", True),
            status="draft",
            scheduled_at=_future(data.get("scheduled_at")),
        )
        self.session.add(a)
        await self.session.flush()
        return await self.detail(isp, a.id)

    async def update(self, isp: Any, announcement_id: uuid.UUID, data: dict) -> dict:
        a = await self._get(isp, announcement_id)
        if a.status != "draft":
            raise IspAppsInvalidError("A sent announcement cannot be edited")
        for k in ("title", "body", "audience", "send_email"):
            if k in data:
                setattr(a, k, data[k])
        if "scheduled_at" in data:  # APPS-2: None clears the schedule
            a.scheduled_at = _future(data["scheduled_at"])
        if "customer_ids" in data:
            a.customer_ids = await self._check_customers(
                isp, data["customer_ids"] or []
            )
        if a.audience == "selected" and not a.customer_ids:
            raise IspAppsInvalidError("Pick at least one customer")
        await self.session.flush()
        return await self.detail(isp, a.id)

    async def delete(self, isp: Any, announcement_id: uuid.UUID) -> None:
        a = await self._get(isp, announcement_id)
        if a.status != "draft":
            raise IspAppsInvalidError("A sent announcement cannot be deleted")
        a.is_deleted = True
        a.deleted_at = _now()
        await self.session.flush()

    async def _targets(self, isp: Any, a: Any) -> list[uuid.UUID]:
        visible = await isp.child_ids()
        if a.audience == "all":
            return visible
        wanted = {uuid.UUID(c) for c in a.customer_ids}
        return [c for c in visible if c in wanted]

    async def send(self, isp: Any, announcement_id: uuid.UUID) -> dict:
        from app.domains.organization.models import Organization

        a = await self._get(isp, announcement_id)
        if a.status != "draft":
            raise IspAppsInvalidError("This announcement was already sent")
        targets = await self._targets(isp, a)
        if not targets:
            raise IspAppsInvalidError("No customer to send to")
        isp_name = isp.organization.name
        orgs = (
            (
                await self.session.execute(
                    select(Organization).where(Organization.id.in_(targets))
                )
            )
            .scalars()
            .all()
        )
        for o in orgs:
            email = (o.contact_email or "").strip() or None
            status = "skipped"
            delivery_id = None
            if (
                a.send_email
                and email
                and _EMAIL_RE.match(email)
                and self.notifications is not None
            ):
                try:
                    d = await self.notifications.enqueue(
                        event_type=IspAppsEventType.ANNOUNCEMENT,
                        channel=NotificationChannelType.EMAIL,
                        recipient=email,
                        subject=f"{isp_name}: {a.title}",
                        body=email_html(isp_name, a.title, a.body),
                        organization_id=isp.isp_org_id,
                    )
                    delivery_id = getattr(d, "id", None)
                    status = "queued"
                except Exception:  # noqa: BLE001 -- one bad address must not stop the rest
                    status = "failed"
            self.session.add(
                IspAnnouncementRecipient(
                    announcement_id=a.id,
                    customer_organization_id=o.id,
                    email=email,
                    phone=o.contact_phone,
                    email_status=status,
                    delivery_id=delivery_id,
                )
            )
        a.status = "sent"
        a.sent_at = _now()
        a.sent_by_user_id = isp.user_id
        await self.session.flush()
        return await self.detail(isp, a.id)

    async def list(
        self, isp: Any, *, page: int, page_size: int
    ) -> tuple[list[dict], int]:
        conds = [
            IspAnnouncement.isp_organization_id == isp.isp_org_id,
            IspAnnouncement.is_deleted.is_(False),
        ]
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(IspAnnouncement).where(*conds)
                )
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    select(IspAnnouncement)
                    .where(*conds)
                    .order_by(IspAnnouncement.created_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        visible = await self._visible_ids(isp)
        return [self._view(r, visible) for r in rows], total

    @staticmethod
    async def _visible_ids(isp: Any) -> set[str] | None:
        """None for an unconfined caller; else the customer ids (as stored,
        str) they cover. SCOPE-FIX: a confined caller never sees the id of a
        customer outside their list in ``customer_ids``."""
        if isp.confined_customer_ids is None:
            return None
        return {str(c) for c in await isp.child_ids()}

    def _view(self, r: Any, visible: set[str] | None = None) -> dict:
        ids = r.customer_ids
        if visible is not None and ids:
            ids = [c for c in ids if str(c) in visible]
        return {
            "id": r.id,
            "title": r.title,
            "body": r.body,
            "audience": r.audience,
            "customer_ids": ids,
            "send_email": r.send_email,
            "status": r.status,
            "sent_at": r.sent_at,
            "scheduled_at": r.scheduled_at,
            "created_at": r.created_at,
        }

    async def detail(self, isp: Any, announcement_id: uuid.UUID) -> dict:
        a = await self._get(isp, announcement_id)
        view = self._view(a, await self._visible_ids(isp))
        visible = set(await isp.child_ids())
        recipients = (
            (
                await self.session.execute(
                    select(IspAnnouncementRecipient).where(
                        IspAnnouncementRecipient.announcement_id == a.id
                    )
                )
            )
            .scalars()
            .all()
        )
        names = await org_names(
            self.session, {r.customer_organization_id for r in recipients}
        )
        text = share_text(isp.organization.name, a.title, a.body)
        # a confined viewer only sees the recipients they cover
        view["recipients"] = [
            {
                "isp_customer_id": r.customer_organization_id,
                "customer_name": names.get(r.customer_organization_id),
                "email": r.email,
                "email_status": r.email_status,
                "whatsapp_link": whatsapp_link(r.phone, text),
            }
            for r in recipients
            if r.customer_organization_id in visible
        ]
        view["sent_by"] = (await user_names(self.session, {a.sent_by_user_id})).get(
            a.sent_by_user_id
        )
        return view
