"""SMALL-3: CHURN-RISK win-back save rate.

Behind the CHURN-RISK lane's flag, ``ISP_REVENUE_HUB_ENABLED`` (off: the
routes 404 and the pass does nothing).

* **Record.** The Churn risk tab posts one row per win-back action it
  performs (``offer_renew`` = the renew-at-offer-price flow, ``ticket`` =
  RaiseTicketDialog, ``whatsapp_share`` = the wa.me share). The action itself
  still goes through the existing endpoints; recording is a separate,
  best-effort call. Idempotent per ``idempotency_key`` (per ISP).
* **Saved.** An action is *saved* when its subscriber renews (a subscriber
  invoice of kind ``recharge``, not cancelled; every renew path issues one:
  recharge, 360 renew, DIR-2 bulk, queued renewal) or pays (a ``confirmed``
  payment by the subscriber) after ``acted_at`` and no later than
  ``acted_at + window_days`` (``ISP_WINBACK_SAVE_WINDOW_DAYS``, default 30).
  The earliest such event wins (``saved_via`` renewal | payment). Filled by
  the 120 s pass, one ISP per transaction, idempotent (only rows with
  ``saved_at IS NULL`` are touched; a re-run finds nothing new).
* **Rate.** Over actions taken in the last ``days`` (default 90), per
  subscriber: *saved* = any of its actions saved; *lost* = none saved and
  every window has ended; *pending* = none saved, a window still open.
  ``save_rate = saved / (saved + lost)``, null when nothing is decided yet.
  Per action type the same at action level. Scope: the caller's customers
  (confinement + header zone, customer-granular like the other non-subscriber
  tables, GAP_SWEEP #16).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select

from .winback_models import WINBACK_ACTIONS, IspWinbackAction


class IspWinbackSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_WINBACK_", case_sensitive=False, extra="ignore"
    )

    save_window_days: int = Field(default=30, ge=1, le=180)


@lru_cache(maxsize=1)
def get_winback_settings() -> IspWinbackSettings:
    return IspWinbackSettings()


def _now() -> datetime:
    return datetime.now(UTC)


def rate(saved: int, lost: int) -> float | None:
    decided = saved + lost
    return None if decided == 0 else round(saved / decided, 4)


async def record_action(
    session: Any,
    isp: Any,
    subscriber: Any,
    *,
    action: str,
    reasons: list[str],
    ref_id: uuid.UUID | None,
    idempotency_key: str | None,
    now: datetime | None = None,
) -> tuple[IspWinbackAction, bool]:
    """(row, created). ``subscriber`` is already resolved through IspScope."""
    if idempotency_key:
        prior = (
            await session.execute(
                select(IspWinbackAction).where(
                    IspWinbackAction.isp_organization_id == isp.isp_org_id,
                    IspWinbackAction.idempotency_key == idempotency_key,
                )
            )
        ).scalar_one_or_none()
        if prior is not None:
            return prior, False
    now = now or _now()
    days = get_winback_settings().save_window_days
    row = IspWinbackAction(
        isp_organization_id=isp.isp_org_id,
        customer_organization_id=subscriber.customer_organization_id,
        subscriber_id=subscriber.id,
        action=action,
        reasons=list(dict.fromkeys(reasons)),
        ref_id=ref_id,
        idempotency_key=idempotency_key,
        acted_at=now,
        window_days=days,
        window_ends_at=now + timedelta(days=days),
        created_by=isp.user_id,
    )
    session.add(row)
    await session.flush()
    return row, True


async def _first_save(
    session: Any, isp_org_id: uuid.UUID, a: IspWinbackAction
) -> tuple[datetime, str, uuid.UUID] | None:
    from .billing_models import IspInvoice, IspPayment

    inv = (
        await session.execute(
            select(IspInvoice.created_at, IspInvoice.id)
            .where(
                IspInvoice.isp_organization_id == isp_org_id,
                IspInvoice.subscriber_id == a.subscriber_id,
                IspInvoice.doc_type == "invoice",
                IspInvoice.invoice_kind == "recharge",
                IspInvoice.status != "cancelled",
                IspInvoice.is_deleted.is_(False),
                IspInvoice.created_at > a.acted_at,
                IspInvoice.created_at <= a.window_ends_at,
            )
            .order_by(IspInvoice.created_at)
            .limit(1)
        )
    ).first()
    pay = (
        await session.execute(
            select(IspPayment.created_at, IspPayment.id)
            .where(
                IspPayment.isp_organization_id == isp_org_id,
                IspPayment.subscriber_id == a.subscriber_id,
                IspPayment.status == "confirmed",
                IspPayment.is_deleted.is_(False),
                IspPayment.created_at > a.acted_at,
                IspPayment.created_at <= a.window_ends_at,
            )
            .order_by(IspPayment.created_at)
            .limit(1)
        )
    ).first()
    cands = []
    if inv is not None:
        cands.append((inv[0], "renewal", inv[1]))
    if pay is not None:
        cands.append((pay[0], "payment", pay[1]))
    return min(cands, key=lambda c: c[0]) if cands else None


async def mark_saves_for_isp(
    session: Any, isp_org_id: uuid.UUID, *, now: datetime | None = None
) -> int:
    """Fill ``saved_at`` for this ISP's open actions. Only rows whose window
    has not ended more than a week ago are looked at (the pass runs every
    120 s; a week covers any outage). Idempotent."""
    now = now or _now()
    rows = (
        (
            await session.execute(
                select(IspWinbackAction)
                .where(
                    IspWinbackAction.isp_organization_id == isp_org_id,
                    IspWinbackAction.is_deleted.is_(False),
                    IspWinbackAction.saved_at.is_(None),
                    IspWinbackAction.window_ends_at > now - timedelta(days=7),
                    IspWinbackAction.acted_at <= now,
                )
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    n = 0
    for a in rows:
        hit = await _first_save(session, isp_org_id, a)
        if hit is None:
            continue
        a.saved_at, a.saved_via, a.saved_ref_id = hit
        n += 1
    await session.flush()
    return n


async def run_winback_saves(*, now: datetime | None = None) -> dict[str, int]:
    """120 s pass hook: one ISP per transaction (own session each), flag
    off = no-op."""
    from .revenue_router import get_revenue_settings
    from .tasks import _own_tx

    summary: dict[str, int] = {"isps": 0, "saved": 0}
    if not get_revenue_settings().revenue_hub_enabled:
        return summary
    from app.database.session import SessionLocal

    now = now or _now()
    async with SessionLocal() as session:
        isp_ids = list(
            (
                await session.execute(
                    select(IspWinbackAction.isp_organization_id)
                    .where(
                        IspWinbackAction.saved_at.is_(None),
                        IspWinbackAction.is_deleted.is_(False),
                        IspWinbackAction.window_ends_at > now - timedelta(days=7),
                    )
                    .distinct()
                )
            ).scalars()
        )
    for isp_id in isp_ids:
        summary["isps"] += 1

        async def _one(session: Any, isp_id: uuid.UUID = isp_id) -> int:
            return await mark_saves_for_isp(session, isp_id, now=now)

        summary["saved"] += int(
            await _own_tx("isp_winback_saves", _one, summary, isp=isp_id) or 0
        )
    return summary


async def save_rate(
    session: Any, isp: Any, *, days: int, now: datetime | None = None
) -> dict[str, Any]:
    now = now or _now()
    since = now - timedelta(days=days)
    children = await isp.child_ids()
    rows = (
        await session.execute(
            select(
                IspWinbackAction.subscriber_id,
                IspWinbackAction.action,
                IspWinbackAction.saved_at,
                IspWinbackAction.saved_via,
                IspWinbackAction.window_ends_at,
            ).where(
                IspWinbackAction.isp_organization_id == isp.isp_org_id,
                IspWinbackAction.is_deleted.is_(False),
                IspWinbackAction.acted_at >= since,
                IspWinbackAction.customer_organization_id.in_(children or [None]),
            )
        )
    ).all()
    per_sub: dict[uuid.UUID, dict[str, bool]] = {}
    by_action = {
        a: {"actions": 0, "saved": 0, "lost": 0, "pending": 0} for a in WINBACK_ACTIONS
    }
    via = {"renewal": 0, "payment": 0}
    for sid, action, saved_at, saved_via, ends in rows:
        st = "saved" if saved_at else ("lost" if ends <= now else "pending")
        b = by_action.setdefault(
            action, {"actions": 0, "saved": 0, "lost": 0, "pending": 0}
        )
        b["actions"] += 1
        b[st] += 1
        s = per_sub.setdefault(sid, {"saved": False, "open": False})
        if st == "saved":
            s["saved"] = True
            via[saved_via or "renewal"] = via.get(saved_via or "renewal", 0) + 1
        elif st == "pending":
            s["open"] = True
    saved = sum(1 for s in per_sub.values() if s["saved"])
    pending = sum(1 for s in per_sub.values() if not s["saved"] and s["open"])
    lost = len(per_sub) - saved - pending
    for b in by_action.values():
        b["save_rate"] = rate(b["saved"], b["lost"])
    return {
        "days": days,
        "window_days": get_winback_settings().save_window_days,
        "actions": len(rows),
        "subscribers": len(per_sub),
        "saved": saved,
        "lost": lost,
        "pending": pending,
        "save_rate": rate(saved, lost),
        "saved_via_actions": via,
        "by_action": by_action,
        "definition": (
            "A subscriber counts as saved when, after a win-back action, they "
            "renew or pay within the window. Rate = saved / (saved + lost); "
            "subscribers whose window is still open are pending and not counted."
        ),
    }


__all__ = [
    "get_winback_settings",
    "mark_saves_for_isp",
    "rate",
    "record_action",
    "run_winback_saves",
    "save_rate",
]
