"""REFERRAL-1 service.

Rules (per-ISP ``isp_referral_settings``):

* staff record "A referred B" for two subscribers of this ISP; B must be newer
  than A, created at most ``window_days`` ago, and not referred already; no
  A <-> B loops;
* the referral is **earned** when B's first invoice (the earliest one that is
  not cancelled) is fully paid and is at least ``min_first_invoice_paise``,
  unless A already earned ``max_rewards_per_year`` rewards in the last 365
  days (then **rejected**, with the reason);
* an earned reward is **applied** as an ordinary credit note
  (``IspBillingService.credit_note``, the existing credit path) on A's next
  invoice: the first of A's open invoices issued after the reward was
  earned, for ``min(reward, balance)``. A bill paid on the spot has no
  balance to credit, so the reward waits for the next unpaid one.

The pass (``run_referrals``) rides the existing 120 s ISP task; every step is
idempotent (status moves forward only, one credit note per referral).
Every change is appended to ``history`` and written to the audit log.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select

from app.core.logging import get_logger

from .billing_models import IspInvoice
from .billing_service import IspBillingService, balance_of
from .plans_models import IspSubscriber
from .referrals_config import (
    IspReferralInvalidError,
    IspReferralNotFoundError,
    get_referrals_settings,
)
from .referrals_models import IspReferral, IspReferralSettings

logger = get_logger(__name__)
LIVE = ("pending", "earned", "applied")


def _iso(v: Any) -> Any:
    return v.isoformat() if v is not None and hasattr(v, "isoformat") else v


def label(s: Any) -> str:
    name = " ".join(p for p in (s.first_name, s.last_name) if p).strip()
    return name or s.display_name or s.identifier


class IspReferralsService:
    def __init__(self, *, session: Any, audit: Any = None, clock: Any = None) -> None:
        self.session = session
        self.audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))
        self.billing = IspBillingService(session=session, audit=audit, clock=clock)

    def now(self) -> datetime:
        return self._clock()

    async def _audit(self, isp: Any, action: str, r: IspReferral, **meta: Any) -> None:
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=getattr(isp, "user_id", None),
            action=action,
            entity_type="isp_referral",
            entity_id=r.id,
            description=action.replace("_", " "),
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp.isp_org_id),
                "referrer_subscriber_id": str(r.referrer_subscriber_id),
                "referred_subscriber_id": str(r.referred_subscriber_id),
                **{
                    k: (str(v) if isinstance(v, uuid.UUID) else v)
                    for k, v in meta.items()
                },
            },
            organization_id=r.referrer_customer_id,
            location_id=None,
        )

    def _log(self, r: IspReferral, isp: Any, status: str, detail: str | None) -> None:
        by = getattr(isp, "user_id", None)
        r.history = [
            *(r.history or []),
            {
                "at": self.now().isoformat(),
                "status": status,
                "by": str(by) if by else None,
                "detail": detail,
            },
        ]
        r.status = status

    # -- settings ---------------------------------------------------------
    async def settings_row(self, isp_org_id: uuid.UUID) -> IspReferralSettings | None:
        return (
            await self.session.execute(
                select(IspReferralSettings).where(
                    IspReferralSettings.isp_organization_id == isp_org_id,
                    IspReferralSettings.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    @staticmethod
    def settings_view(row: IspReferralSettings | None) -> dict:
        return {
            "enabled": bool(row and row.enabled),
            "reward_paise": row.reward_paise if row else 0,
            "max_rewards_per_year": row.max_rewards_per_year if row else 12,
            "window_days": row.window_days if row else 30,
            "min_first_invoice_paise": row.min_first_invoice_paise if row else 0,
            "rules": (
                "When the referred subscriber's first invoice is paid, the "
                "referrer gets a credit note for the reward on their next unpaid "
                "invoice (at most that invoice's balance)."
            ),
        }

    async def put_settings(self, isp: Any, data: dict) -> dict:
        row = await self.settings_row(isp.isp_org_id)
        before = self.settings_view(row)
        if row is None:
            row = IspReferralSettings(
                isp_organization_id=isp.isp_org_id, created_by=isp.user_id
            )
            self.session.add(row)
        for k in (
            "enabled",
            "reward_paise",
            "max_rewards_per_year",
            "window_days",
            "min_first_invoice_paise",
        ):
            if data.get(k) is not None:
                setattr(row, k, data[k])
        if row.enabled and not row.reward_paise:
            raise IspReferralInvalidError(
                "Set a reward amount before switching referrals on"
            )
        row.updated_by = isp.user_id
        await self.session.flush()
        after = self.settings_view(row)
        if self.audit is not None:
            await self.audit.create_audit_log_entry(
                actor_user_id=isp.user_id,
                action="isp_referral_settings_updated",
                entity_type="isp_referral",
                entity_id=row.id,
                description="isp referral settings updated",
                event_metadata={
                    "console": "isp",
                    "isp_organization_id": str(isp.isp_org_id),
                    "before": {k: before[k] for k in data if k in before},
                    "after": {k: after[k] for k in data if k in after},
                },
                organization_id=isp.isp_org_id,
                location_id=None,
            )
        return after

    # -- create / read -----------------------------------------------------
    async def create(
        self,
        isp: Any,
        *,
        referrer_subscriber_id: uuid.UUID,
        referred_subscriber_id: uuid.UUID,
        note: str | None,
    ) -> dict:
        a = await self.billing.subscriber_in_scope(isp, referrer_subscriber_id)
        b = await self.billing.subscriber_in_scope(isp, referred_subscriber_id)
        st = await self.settings_row(isp.isp_org_id)
        if st is None or not st.enabled:
            raise IspReferralInvalidError("Referral rewards are off in your settings")
        if a.id == b.id:
            raise IspReferralInvalidError("A subscriber cannot refer themselves")
        if a.created_at >= b.created_at:
            raise IspReferralInvalidError(
                "The referrer must have joined before the new subscriber"
            )
        if b.created_at < self.now() - timedelta(days=st.window_days):
            raise IspReferralInvalidError(
                f"Referrals must be recorded within {st.window_days} days of joining"
            )
        clash = (
            await self.session.execute(
                select(IspReferral.id).where(
                    IspReferral.isp_organization_id == isp.isp_org_id,
                    IspReferral.status.in_(LIVE),
                    IspReferral.is_deleted.is_(False),
                    or_(
                        IspReferral.referred_subscriber_id == b.id,
                        and_(
                            IspReferral.referrer_subscriber_id == b.id,
                            IspReferral.referred_subscriber_id == a.id,
                        ),
                    ),
                )
            )
        ).first()
        if clash is not None:
            raise IspReferralInvalidError("This subscriber was already referred")
        r = IspReferral(
            isp_organization_id=isp.isp_org_id,
            referrer_subscriber_id=a.id,
            referred_subscriber_id=b.id,
            referrer_customer_id=a.customer_organization_id,
            referred_customer_id=b.customer_organization_id,
            status="pending",
            note=note,
            created_by=isp.user_id,
            history=[],
        )
        self._log(r, isp, "pending", "Recorded")
        self.session.add(r)
        await self.session.flush()
        await self._audit(isp, "isp_referral_created", r)
        await self.evaluate(isp, r)
        return (await self.views(isp, [r]))[0]

    async def _visible(self, isp: Any, r: IspReferral) -> bool:
        if r.is_deleted or r.isp_organization_id != isp.isp_org_id:
            return False
        ids = set(await isp.child_ids())
        return r.referrer_customer_id in ids and r.referred_customer_id in ids

    async def referral(self, isp: Any, referral_id: uuid.UUID) -> IspReferral:
        r = await self.session.get(IspReferral, referral_id)
        if r is None or not await self._visible(isp, r):
            raise IspReferralNotFoundError()
        return r

    async def views(self, isp: Any, rows: list) -> list[dict]:
        ids = {r.referrer_subscriber_id for r in rows} | {
            r.referred_subscriber_id for r in rows
        }
        subs = {}
        if ids:
            subs = {
                s.id: s
                for s in (
                    await self.session.execute(
                        select(IspSubscriber).where(IspSubscriber.id.in_(ids))
                    )
                ).scalars()
            }
        inv_ids = {
            x
            for r in rows
            for x in (r.qualifying_invoice_id, r.applied_invoice_id, r.credit_note_id)
            if x
        }
        nums = {}
        if inv_ids:
            nums = dict(
                (
                    await self.session.execute(
                        select(IspInvoice.id, IspInvoice.number).where(
                            IspInvoice.id.in_(inv_ids)
                        )
                    )
                ).all()
            )

        def who(sid: uuid.UUID) -> dict:
            s = subs.get(sid)
            return {
                "subscriber_id": str(sid),
                "label": label(s) if s else None,
                "identifier": s.identifier if s else None,
            }

        return [
            {
                "id": str(r.id),
                "referrer": who(r.referrer_subscriber_id),
                "referred": who(r.referred_subscriber_id),
                "status": r.status,
                "reward_paise": r.reward_paise,
                "qualifying_invoice_number": nums.get(r.qualifying_invoice_id),
                "earned_at": _iso(r.earned_at),
                "applied_invoice_number": nums.get(r.applied_invoice_id),
                "credit_note_number": nums.get(r.credit_note_id),
                "applied_paise": r.applied_paise,
                "applied_at": _iso(r.applied_at),
                "reason": r.reason,
                "note": r.note,
                "history": r.history or [],
                "created_at": _iso(r.created_at),
            }
            for r in rows
        ]

    async def list(
        self,
        isp: Any,
        *,
        status: str | None,
        subscriber_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> dict:
        if subscriber_id:
            await self.billing.subscriber_in_scope(isp, subscriber_id)  # 404
        ids = await isp.child_ids()
        rows: list = []
        if ids:
            q = select(IspReferral).where(
                IspReferral.isp_organization_id == isp.isp_org_id,
                IspReferral.is_deleted.is_(False),
                IspReferral.referrer_customer_id.in_(ids),
                IspReferral.referred_customer_id.in_(ids),
            )
            if status:
                q = q.where(IspReferral.status == status)
            if subscriber_id:
                q = q.where(
                    or_(
                        IspReferral.referrer_subscriber_id == subscriber_id,
                        IspReferral.referred_subscriber_id == subscriber_id,
                    )
                )
            rows = list(
                (await self.session.execute(q.order_by(IspReferral.created_at.desc())))
                .scalars()
                .all()
            )
        start = (page - 1) * page_size
        return {
            "items": await self.views(isp, rows[start : start + page_size]),
            "total": len(rows),
            "page": page,
            "page_size": page_size,
            "summary": {
                s: sum(1 for r in rows if r.status == s)
                for s in ("pending", "earned", "applied", "rejected", "cancelled")
            }
            | {"credited_paise": sum(r.applied_paise or 0 for r in rows)},
        }

    async def cancel(self, isp: Any, referral_id: uuid.UUID, reason: str) -> dict:
        r = await self.referral(isp, referral_id)
        if r.status not in ("pending", "earned"):
            raise IspReferralInvalidError(
                f"A referral that is {r.status} cannot be cancelled"
            )
        r.reason = reason
        self._log(r, isp, "cancelled", reason)
        await self.session.flush()
        await self._audit(isp, "isp_referral_cancelled", r, reason=reason)
        return (await self.views(isp, [r]))[0]

    # -- the pass ------------------------------------------------------------
    async def _first_invoice(self, b_id: uuid.UUID) -> IspInvoice | None:
        return (
            await self.session.execute(
                select(IspInvoice)
                .where(
                    IspInvoice.subscriber_id == b_id,
                    IspInvoice.bill_to_kind == "subscriber",
                    IspInvoice.doc_type == "invoice",
                    IspInvoice.status != "cancelled",
                    IspInvoice.is_deleted.is_(False),
                )
                .order_by(IspInvoice.issue_date, IspInvoice.created_at)
                .limit(1)
            )
        ).scalar_one_or_none()

    async def evaluate(self, isp: Any, r: IspReferral) -> None:
        """Move one referral forward as far as the data allows."""
        st = await self.settings_row(r.isp_organization_id)
        if r.status == "pending":
            inv = await self._first_invoice(r.referred_subscriber_id)
            if inv is None or inv.status != "paid":
                return
            if st is None or not st.enabled or not st.reward_paise:
                return  # rewards off: wait, never reject silently
            r.qualifying_invoice_id = inv.id
            if inv.total_paise < st.min_first_invoice_paise:
                r.reason = "First invoice below the minimum"
                self._log(r, isp, "rejected", r.reason)
                await self._audit(isp, "isp_referral_rejected", r, reason=r.reason)
                return
            n = (
                await self.session.execute(
                    select(func.count()).where(
                        IspReferral.referrer_subscriber_id == r.referrer_subscriber_id,
                        IspReferral.status.in_(("earned", "applied")),
                        IspReferral.earned_at >= self.now() - timedelta(days=365),
                        IspReferral.id != r.id,
                    )
                )
            ).scalar_one()
            if n >= st.max_rewards_per_year:
                r.reason = f"Limit of {st.max_rewards_per_year} rewards a year reached"
                self._log(r, isp, "rejected", r.reason)
                await self._audit(isp, "isp_referral_rejected", r, reason=r.reason)
                return
            r.reward_paise = st.reward_paise
            r.earned_at = self.now()
            self._log(r, isp, "earned", f"First invoice {inv.number} paid")
            await self.session.flush()
            await self._audit(
                isp, "isp_referral_earned", r, reward_paise=r.reward_paise
            )
        if r.status == "earned":
            target = (
                await self.session.execute(
                    select(IspInvoice)
                    .where(
                        IspInvoice.subscriber_id == r.referrer_subscriber_id,
                        IspInvoice.bill_to_kind == "subscriber",
                        IspInvoice.doc_type == "invoice",
                        IspInvoice.status.in_(("issued", "partially_paid")),
                        IspInvoice.created_at >= r.earned_at,
                        IspInvoice.is_deleted.is_(False),
                    )
                    .order_by(IspInvoice.issue_date, IspInvoice.created_at)
                )
            ).scalars()
            inv = next((i for i in target if balance_of(i) > 0), None)
            if inv is None:
                return
            amount = min(int(r.reward_paise or 0), balance_of(inv))
            b = await self.session.get(IspSubscriber, r.referred_subscriber_id)
            note = await self.billing.credit_note(
                isp,
                inv.id,
                amount_paise=amount,
                reason=f"Referral credit: {label(b) if b else 'new subscriber'}",
            )
            r.applied_invoice_id, r.credit_note_id = inv.id, note.id
            r.applied_paise, r.applied_at = amount, self.now()
            self._log(
                r,
                isp,
                "applied",
                f"Credit note {note.number} on {inv.number}"
                + (
                    " (capped at the balance)" if amount < (r.reward_paise or 0) else ""
                ),
            )
            await self.session.flush()
            await self._audit(
                isp,
                "isp_referral_applied",
                r,
                invoice=inv.number,
                credit_note=note.number,
                amount_paise=amount,
            )


async def run_referrals(session: Any) -> dict:
    """Every ISP with a pending or earned referral, each referral in a
    SAVEPOINT. A no-op while ISP_REFERRALS_ENABLED is off."""
    from app.domains.rbac.repository import RBACRepository

    from .repository import IspRepository
    from .tasks import _SystemContext

    out = {"referrals": 0, "errors": 0}
    if not get_referrals_settings().referrals_enabled:
        return out
    rows = (
        (
            await session.execute(
                select(IspReferral)
                .where(
                    IspReferral.status.in_(("pending", "earned")),
                    IspReferral.is_deleted.is_(False),
                )
                .order_by(IspReferral.created_at)
                .limit(1000)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    repo = IspRepository(session)
    ctx: dict = {}
    svc = IspReferralsService(session=session, audit=RBACRepository(session))
    for r in rows:
        try:
            if r.isp_organization_id not in ctx:
                org = await repo.get_organization(r.isp_organization_id)
                prof = await repo.get_profile(r.isp_organization_id)
                ctx[r.isp_organization_id] = (
                    _SystemContext(org, prof, repo)
                    if org is not None and prof is not None
                    else None
                )
            isp = ctx[r.isp_organization_id]
            if isp is None:
                continue
            async with session.begin_nested():
                await svc.evaluate(isp, r)
            out["referrals"] += 1
        except Exception:  # noqa: BLE001 -- one referral never blocks the rest
            out["errors"] += 1
            logger.exception("isp_referral_failed", extra={"referral": str(r.id)})
    return out


__all__ = ["IspReferralsService", "run_referrals"]
