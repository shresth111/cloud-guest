"""AUDIT-LOG: one ISP-wide page of who did what, when, from which IP.

Read-only over rows that already exist:

* ``audit_log_entries`` written by every lane (and by the customer-dashboard
  code the venue twins call): rows whose actor is one of this ISP's staff, or
  whose organization is this ISP or one of its customers (the same scope the
  per-customer Staff Activity uses). Under a zone switch only rows of the
  zone's customers are shown.
* ``login_attempts`` of this ISP's staff (sign-ins, with the IP the auth code
  recorded).

IP: a sign-in row carries the auth code's IP; an action row carries
``event_metadata.ip`` when it was written during an ``/isp`` request after
``ISP_AUDIT_LOG_ENABLED`` was switched on (``audit_ip.py``). Older rows show
"not recorded".
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import String, and_, cast, false, func, or_, select

from app.domains.auth.models import LoginAttempt, User
from app.domains.organization.models import Organization
from app.domains.rbac.models import AuditLogEntry

from .exceptions import IspBadRequestError
from .scoping import IspScope

#: metadata keys never shown (bookkeeping, not facts)
_HIDDEN = {"console", "isp_organization_id", "ip"}
MAX_EXPORT = 50_000


def _iso(v: Any) -> Any:
    return v.isoformat() if v is not None and hasattr(v, "isoformat") else v


def action_label(action: str) -> str:
    a = action.removeprefix("isp_").replace("_", " ").strip()
    return a[:1].upper() + a[1:] if a else action


def _detail(meta: dict | None) -> dict:
    out = {}
    for k, v in (meta or {}).items():
        if k in _HIDDEN:
            continue
        s = v if isinstance(v, int | float | bool) or v is None else str(v)
        out[k] = s[:200] if isinstance(s, str) else s
        if len(out) >= 20:
            break
    return out


class IspAuditLogService:
    def __init__(self, *, session: Any, audit: Any = None) -> None:
        self.session = session
        self.audit = audit

    async def _staff(self, isp: Any) -> dict[uuid.UUID, str]:
        return {
            a.user_id: r.slug
            for a, r in await isp.repository.isp_role_assignments(isp.isp_org_id)
        }

    def _bounds(self, isp: Any, since: date | None, until: date | None) -> tuple:
        tz = ZoneInfo(isp.organization.timezone or "Asia/Kolkata")
        if since and until and until < since:
            raise IspBadRequestError(
                "The end date is before the start",
                field="until",
                reason="ISP_DATE_RANGE_ORDER",
            )
        lo = datetime.combine(since, time.min, tzinfo=tz) if since else None
        hi = (
            datetime.combine(until + timedelta(days=1), time.min, tzinfo=tz)
            if until
            else None
        )
        return lo, hi

    async def _action_query(
        self,
        isp: Any,
        staff: dict,
        *,
        isp_user_id: uuid.UUID | None,
        isp_customer_id: uuid.UUID | None,
        action: str | None,
        entity_type: str | None,
        search: str | None,
        lo: datetime | None,
        hi: datetime | None,
    ) -> Any:
        children = await isp.child_ids()
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            scope = AuditLogEntry.organization_id == isp_customer_id
        elif isp.confined_customer_ids is not None:  # zone switch narrows
            scope = AuditLogEntry.organization_id.in_(children) if children else false()
        else:
            scope = or_(
                AuditLogEntry.actor_user_id.in_(list(staff)) if staff else false(),
                AuditLogEntry.organization_id.in_([isp.isp_org_id, *children]),
            )
        conds: list[Any] = [scope, AuditLogEntry.is_deleted.is_(False)]
        if isp_user_id is not None:
            conds.append(AuditLogEntry.actor_user_id == isp_user_id)
        if action:
            conds.append(AuditLogEntry.action == action)
        if entity_type:
            conds.append(AuditLogEntry.entity_type == entity_type)
        if search:
            like = f"%{search.strip()}%"
            conds.append(
                or_(
                    AuditLogEntry.action.ilike(like),
                    AuditLogEntry.description.ilike(like),
                    cast(AuditLogEntry.event_metadata["ip"].astext, String).ilike(like),
                )
            )
        if lo is not None:
            conds.append(AuditLogEntry.created_at >= lo)
        if hi is not None:
            conds.append(AuditLogEntry.created_at < hi)
        return and_(*conds)

    def _login_cond(
        self,
        isp: Any,
        staff: dict,
        *,
        isp_user_id: uuid.UUID | None,
        search: str | None,
        lo: datetime | None,
        hi: datetime | None,
    ) -> Any:
        ids = [isp_user_id] if isp_user_id else list(staff)
        if not ids or (isp_user_id and isp_user_id not in staff):
            return false()
        conds: list[Any] = [
            LoginAttempt.user_id.in_(ids),
            LoginAttempt.is_deleted.is_(False),
        ]
        if search:
            like = f"%{search.strip()}%"
            conds.append(
                or_(LoginAttempt.ip_address.ilike(like), LoginAttempt.email.ilike(like))
            )
        if lo is not None:
            conds.append(LoginAttempt.created_at >= lo)
        if hi is not None:
            conds.append(LoginAttempt.created_at < hi)
        return and_(*conds)

    async def rows(
        self,
        isp: Any,
        *,
        source: str = "all",
        isp_user_id: uuid.UUID | None = None,
        isp_customer_id: uuid.UUID | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        search: str | None = None,
        since: date | None = None,
        until: date | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[dict], int]:
        staff = await self._staff(isp)
        lo, hi = self._bounds(isp, since, until)
        want_actions = source in ("all", "actions")
        # sign-ins are not tied to a customer or an action filter
        want_logins = source in ("all", "sign_ins") and not (
            isp_customer_id or action or entity_type or isp.confined_customer_ids
        )
        a_cond = (
            await self._action_query(
                isp,
                staff,
                isp_user_id=isp_user_id,
                isp_customer_id=isp_customer_id,
                action=action,
                entity_type=entity_type,
                search=search,
                lo=lo,
                hi=hi,
            )
            if want_actions
            else false()
        )
        l_cond = (
            self._login_cond(
                isp, staff, isp_user_id=isp_user_id, search=search, lo=lo, hi=hi
            )
            if want_logins
            else false()
        )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(AuditLogEntry).where(a_cond)
                )
            ).scalar_one()
        ) + int(
            (
                await self.session.execute(
                    select(func.count()).select_from(LoginAttempt).where(l_cond)
                )
            ).scalar_one()
        )
        # merge the two streams newest-first: fetch offset+limit from each
        n = offset + limit
        acts = (
            (
                await self.session.execute(
                    select(AuditLogEntry)
                    .where(a_cond)
                    .order_by(AuditLogEntry.created_at.desc(), AuditLogEntry.id)
                    .limit(n)
                )
            )
            .scalars()
            .all()
        )
        logins = (
            (
                await self.session.execute(
                    select(LoginAttempt)
                    .where(l_cond)
                    .order_by(LoginAttempt.created_at.desc(), LoginAttempt.id)
                    .limit(n)
                )
            )
            .scalars()
            .all()
        )
        merged = sorted(
            [("action", a) for a in acts] + [("sign_in", x) for x in logins],
            key=lambda t: t[1].created_at,
            reverse=True,
        )[offset : offset + limit]
        users = {
            u.id: u
            for u in (
                await self.session.execute(
                    select(User).where(
                        User.id.in_(
                            {
                                (r.actor_user_id if k == "action" else r.user_id)
                                for k, r in merged
                            }
                            - {None}
                            or [uuid.UUID(int=0)]
                        )
                    )
                )
            ).scalars()
        }
        orgs = dict(
            (
                await self.session.execute(
                    select(Organization.id, Organization.name).where(
                        Organization.id.in_(
                            {r.organization_id for k, r in merged if k == "action"}
                            - {None}
                            or [uuid.UUID(int=0)]
                        )
                    )
                )
            ).all()
        )
        out = []
        for kind, r in merged:
            uid = r.actor_user_id if kind == "action" else r.user_id
            u = users.get(uid)
            actor = (
                {
                    "isp_user_id": str(uid),
                    "name": (
                        f"{u.first_name or ''} {u.last_name or ''}".strip() or u.email
                    )
                    if u
                    else None,
                    "email": u.email if u else None,
                    "role": staff.get(uid),
                    "is_isp_staff": uid in staff,
                }
                if uid
                else None
            )
            if kind == "action":
                meta = r.event_metadata or {}
                org = r.organization_id
                out.append(
                    {
                        "id": str(r.id),
                        "source": "action",
                        "at": _iso(r.created_at),
                        "action": r.action,
                        "action_label": action_label(r.action),
                        "entity_type": r.entity_type,
                        "entity_id": str(r.entity_id) if r.entity_id else None,
                        "description": r.description,
                        "actor": actor,
                        "customer": {"isp_customer_id": str(org), "name": orgs.get(org)}
                        if org and org != isp.isp_org_id
                        else None,
                        "ip": meta.get("ip"),
                        "ip_recorded": bool(meta.get("ip")),
                        "detail": _detail(meta),
                    }
                )
            else:
                out.append(
                    {
                        "id": str(r.id),
                        "source": "sign_in",
                        "at": _iso(r.created_at),
                        "action": "sign_in" if r.success else "sign_in_failed",
                        "action_label": "Signed in"
                        if r.success
                        else f"Sign-in failed ({r.failure_reason or 'unknown'})",
                        "entity_type": "session",
                        "entity_id": None,
                        "description": (r.user_agent or "")[:200],
                        "actor": actor,
                        "customer": None,
                        "ip": r.ip_address,
                        "ip_recorded": bool(r.ip_address),
                        "detail": {},
                    }
                )
        return out, total

    async def page(self, isp: Any, *, page: int, page_size: int, **f: Any) -> dict:
        items, total = await self.rows(
            isp, offset=(page - 1) * page_size, limit=page_size, **f
        )
        return {"items": items, "total": total, "page": page, "page_size": page_size}

    async def facets(self, isp: Any) -> dict:
        staff = await self._staff(isp)
        cond = await self._action_query(
            isp,
            staff,
            isp_user_id=None,
            isp_customer_id=None,
            action=None,
            entity_type=None,
            search=None,
            lo=None,
            hi=None,
        )
        actions = (
            await self.session.execute(
                select(AuditLogEntry.action, func.count())
                .where(cond)
                .group_by(AuditLogEntry.action)
                .order_by(func.count().desc())
                .limit(300)
            )
        ).all()
        people = (
            await self.session.execute(
                select(User.id, User.first_name, User.last_name, User.email).where(
                    User.id.in_(list(staff) or [uuid.UUID(int=0)])
                )
            )
        ).all()
        return {
            "actions": [
                {"action": a, "label": action_label(a), "count": int(n)}
                for a, n in actions
            ],
            "staff": sorted(
                (
                    {
                        "isp_user_id": str(uid),
                        "name": f"{fn or ''} {ln or ''}".strip() or em,
                        "role": staff.get(uid),
                    }
                    for uid, fn, ln, em in people
                ),
                key=lambda p: p["name"] or "",
            ),
        }

    async def csv(self, isp: Any, **f: Any) -> tuple[str, int]:
        items, total = await self.rows(isp, offset=0, limit=MAX_EXPORT, **f)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "time",
                "who",
                "email",
                "role",
                "what",
                "action",
                "customer",
                "ip",
                "detail",
            ]
        )
        for i in items:
            a = i["actor"] or {}
            w.writerow(
                [
                    i["at"],
                    _safe(a.get("name")),
                    _safe(a.get("email")),
                    a.get("role") or "",
                    _safe(i["action_label"]),
                    i["action"],
                    _safe((i["customer"] or {}).get("name")),
                    i["ip"] or "",
                    _safe(
                        "; ".join(f"{k}={v}" for k, v in (i["detail"] or {}).items())
                    ),
                ]
            )
        if self.audit is not None:
            await self.audit.create_audit_log_entry(
                actor_user_id=isp.user_id,
                action="isp_audit_log_exported",
                entity_type="isp_audit_log",
                entity_id=None,
                description="isp audit log exported",
                event_metadata={
                    "console": "isp",
                    "isp_organization_id": str(isp.isp_org_id),
                    "rows": len(items),
                    "filters": {k: str(v) for k, v in f.items() if v not in (None, "")},
                },
                organization_id=isp.isp_org_id,
                location_id=None,
            )
        return buf.getvalue(), min(total, MAX_EXPORT)


def _safe(v: Any) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


__all__ = ["IspAuditLogService", "action_label"]
