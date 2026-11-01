"""ADDENDUM_05 JAZE-1: Subscriber 360 (J1), onboarding profile (J2),
directory / typeahead / move / per-subscriber ledger (J11) and plan sync
(J19).

Every subscriber lookup goes through ``IspPlansService.subscriber`` (same
ISP + caller confinement, else 404). Network effects reuse existing services
unchanged:

- disconnect -> ``GuestService.disconnect_session`` (RouterOS 8728 kick);
- block / freeze -> ``GuestService.block_guest`` / ``unblock_guest`` on the
  subscriber's guest in the customer org, plus a kick of live sessions;
- renew -> ``IspPlansService.recharge`` (invoice + optional payment +
  validity), with the profile's override price;
- revert -> ``IspBillingService.credit_note`` + restore of the prior
  validity/package recorded on the renewal event;
- plan sync live push -> ``QueueManagementService
  .reapply_active_sessions_for_location`` (the existing "speeds changed,
  re-push connected guests" hook).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from urllib.parse import quote

from sqlalchemy import and_, func, or_, select, true

from .billing_models import IspCustomerServiceState, IspInvoice, IspPayment
from .constants import IspRole
from .dependencies import IspContext
from .exceptions import _err
from .plans_models import IspPackage, IspSpeedGroup, IspSubscriber
from .plans_service import (
    IspNameTakenError,
    IspPlansService,
    _iso,
    billing_balance,
)
from .scoping import IspScope
from .subscriber360_models import IspSubscriberEvent, IspSubscriberProfile
from .subscriber_identity import subscriber_identifier

IspSubscriberBlockedError = _err(
    "IspSubscriberBlockedError",
    "ISP_SUBSCRIBER_BLOCKED",
    409,
    "This subscriber is blocked; unblock first",
)
IspSubscriberFrozenError = _err(
    "IspSubscriberFrozenError",
    "ISP_SUBSCRIBER_FROZEN",
    409,
    "This subscriber is frozen; unfreeze first",
)
IspSubscriberNotBlockedError = _err(
    "IspSubscriberNotBlockedError",
    "ISP_SUBSCRIBER_NOT_BLOCKED",
    409,
    "This subscriber is not blocked",
)
IspSubscriberNotFrozenError = _err(
    "IspSubscriberNotFrozenError",
    "ISP_SUBSCRIBER_NOT_FROZEN",
    409,
    "This subscriber is not frozen",
)
IspFreezeNeedsValidityError = _err(
    "IspFreezeNeedsValidityError",
    "ISP_FREEZE_NEEDS_VALIDITY",
    409,
    "Only a subscriber with validity left can be frozen",
)
IspGraceActiveError = _err(
    "IspGraceActiveError",
    "ISP_GRACE_ACTIVE",
    409,
    "A grace period is already running for this subscriber",
)
IspPermanentBlockOwnerOnlyError = _err(
    "IspPermanentBlockOwnerOnlyError",
    "ISP_PERMANENT_BLOCK_OWNER_ONLY",
    403,
    "Only an ISP owner or admin can lift a permanent block",
)
IspNothingToRevertError = _err(
    "IspNothingToRevertError",
    "ISP_NOTHING_TO_REVERT",
    409,
    "There is no renewal to revert",
)
IspRevertPaidError = _err(
    "IspRevertPaidError",
    "ISP_REVERT_PAID",
    409,
    "That renewal has a payment recorded; void the payment first, then revert",
)
IspMoveSameCustomerError = _err(
    "IspMoveSameCustomerError",
    "ISP_MOVE_SAME_CUSTOMER",
    409,
    "The subscriber is already with that customer",
)
IspProfileInvalidError = _err(
    "IspProfileInvalidError", "ISP_PROFILE_INVALID", 422, "Invalid profile field"
)

_OWNERISH = {IspRole.OWNER.value, IspRole.ADMIN.value}
_PIN_RE = re.compile(r"^[1-9][0-9]{5}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: Directory states (J11). ``suspended`` = the customer's service is cut
#: (ADDENDUM_01); everything else is per subscriber.
DISPLAY_STATES = (
    "active",
    "grace",
    "expired",
    "blocked",
    "permanently_blocked",
    "frozen",
    "suspended",
    "scheduled",
    "disabled",
)

PROFILE_FIELDS = (
    "alt_email",
    "gender",
    "billing_city",
    "billing_pincode",
    "install_same_as_billing",
    "install_address",
    "install_area",
    "install_building",
    "install_city",
    "install_pincode",
    "latitude",
    "longitude",
    "installed_at",
    "user_type",
    "connection_type",
    "ont_serial",
    "stb_serial",
    "override_price_paise",
    "billing_anchor_day",
    "after_due_action",
    "exclude_reminders",
    "activation_at",
    "comments",
)


def _num(v: Any) -> float | None:
    return float(v) if v is not None else None


class IspSubscriber360Service:
    def __init__(
        self,
        *,
        plans: IspPlansService,
        guest_service: Any = None,
        queue_service: Any = None,
        clock: Any = None,
    ) -> None:
        self.plans = plans
        self.session = plans.session
        self.guest_service = guest_service
        self.queue_service = queue_service or plans.queue_service
        self._clock = clock or plans._clock or (lambda: datetime.now(UTC))

    def now(self) -> datetime:
        return self._clock()

    # ------------------------------------------------------------------
    # profile + events
    # ------------------------------------------------------------------
    async def profile(self, s: IspSubscriber) -> IspSubscriberProfile | None:
        return (
            await self.session.execute(
                select(IspSubscriberProfile).where(
                    IspSubscriberProfile.subscriber_id == s.id,
                    IspSubscriberProfile.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def ensure_profile(
        self, isp: IspContext, s: IspSubscriber
    ) -> IspSubscriberProfile:
        p = await self.profile(s)
        if p is None:
            p = IspSubscriberProfile(
                isp_organization_id=isp.isp_org_id,
                subscriber_id=s.id,
                created_by=isp.user_id,
            )
            self.session.add(p)
            await self.session.flush()
        return p

    async def event(
        self,
        isp: IspContext,
        s: IspSubscriber,
        kind: str,
        summary: str | None = None,
        **detail: Any,
    ) -> IspSubscriberEvent:
        e = IspSubscriberEvent(
            isp_organization_id=isp.isp_org_id,
            subscriber_id=s.id,
            kind=kind,
            summary=(summary or "")[:255] or None,
            detail={k: _jsonable(v) for k, v in detail.items()},
            actor_user_id=isp.user_id,
            created_by=isp.user_id,
        )
        self.session.add(e)
        await self.session.flush()
        return e

    @staticmethod
    def validate_profile(data: dict) -> dict:
        """Field rules beyond the request schema; raises 422 with the field."""
        out = {k: v for k, v in data.items() if k in PROFILE_FIELDS}
        for k in ("billing_pincode", "install_pincode"):
            v = out.get(k)
            if v not in (None, "") and not _PIN_RE.match(str(v)):
                raise IspProfileInvalidError("A PIN code is 6 digits", field=k)
        if out.get("alt_email") and not _EMAIL_RE.match(out["alt_email"]):
            raise IspProfileInvalidError("Invalid email", field="alt_email")
        lat, lon = out.get("latitude"), out.get("longitude")
        if lat is not None and not -90 <= float(lat) <= 90:
            raise IspProfileInvalidError("Latitude is -90..90", field="latitude")
        if lon is not None and not -180 <= float(lon) <= 180:
            raise IspProfileInvalidError("Longitude is -180..180", field="longitude")
        for k in ("latitude", "longitude"):
            if out.get(k) is not None:
                out[k] = Decimal(str(round(float(out[k]), 6)))
        if out.get("install_same_as_billing") is True:
            for k in (
                "install_address",
                "install_area",
                "install_building",
                "install_city",
                "install_pincode",
            ):
                out.setdefault(k, None)
        return out

    async def put_profile(
        self, isp: IspContext, subscriber_id: uuid.UUID, data: dict
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        p = await self.ensure_profile(isp, s)
        fields = self.validate_profile(data)
        changed = []
        for k, v in fields.items():
            if getattr(p, k) != v:
                setattr(p, k, v)
                changed.append(k)
        p.updated_by = isp.user_id
        await self.session.flush()
        if changed:
            await self.event(
                isp, s, "profile_updated", "Profile updated", fields=changed
            )
        return self.profile_view(p)

    @staticmethod
    def profile_view(p: IspSubscriberProfile | None) -> dict:
        if p is None:
            return {
                "install_same_as_billing": True,
                "user_type": "home",
                "after_due_action": "suspend",
                "exclude_reminders": False,
            }
        out = {k: getattr(p, k) for k in PROFILE_FIELDS}
        out["latitude"], out["longitude"] = _num(p.latitude), _num(p.longitude)
        for k in ("installed_at", "activation_at"):
            out[k] = _iso(out[k])
        out["maps_url"] = (
            f"https://www.google.com/maps?q={p.latitude},{p.longitude}"
            if p.latitude is not None and p.longitude is not None
            else None
        )
        return out

    # ------------------------------------------------------------------
    # state
    # ------------------------------------------------------------------
    async def _suspended_customers(self, ids: list[uuid.UUID]) -> set[uuid.UUID]:
        if not ids:
            return set()
        rows = await self.session.execute(
            select(IspCustomerServiceState.customer_organization_id).where(
                IspCustomerServiceState.customer_organization_id.in_(ids),
                IspCustomerServiceState.state.in_(("suspended", "suspend_pending")),
                IspCustomerServiceState.is_deleted.is_(False),
            )
        )
        return {r[0] for r in rows.all()}

    def display_state(
        self,
        s: IspSubscriber,
        p: IspSubscriberProfile | None,
        *,
        customer_suspended: bool = False,
    ) -> str:
        now = self.now()
        if p is not None and p.block_kind == "permanent":
            return "permanently_blocked"
        if p is not None and p.block_kind == "temporary":
            return "blocked"
        if p is not None and p.frozen_at is not None:
            return "frozen"
        if customer_suspended:
            return "suspended"
        if p is not None and p.activation_at and p.activation_at > now:
            return "scheduled"
        if s.status == "disabled":
            return "disabled"
        if s.valid_until is not None and s.valid_until <= now:
            return "expired"
        if p is not None and p.grace_until and p.grace_until > now:
            return "grace"
        return "active" if s.status == "active" else s.status

    async def live_sessions(self, s: IspSubscriber) -> list[Any]:
        from app.domains.guest.constants import GuestSessionStatus
        from app.domains.guest.models import GuestSession

        if not s.guest_id:
            return []
        return list(
            (
                await self.session.execute(
                    select(GuestSession).where(
                        GuestSession.guest_id == s.guest_id,
                        GuestSession.organization_id == s.customer_organization_id,
                        GuestSession.status == GuestSessionStatus.ACTIVE.value,
                    )
                )
            )
            .scalars()
            .all()
        )

    async def _live_view(self, sessions: list[Any]) -> list[dict]:
        from app.domains.guest.models import GuestDevice
        from app.domains.location.models import Location
        from app.domains.router.models import Router

        if not sessions:
            return []
        dev_ids = [g.device_id for g in sessions if g.device_id]
        macs = {}
        if dev_ids:
            macs = dict(
                (
                    await self.session.execute(
                        select(GuestDevice.id, GuestDevice.mac_address).where(
                            GuestDevice.id.in_(dev_ids)
                        )
                    )
                ).all()
            )
        rnames = dict(
            (
                await self.session.execute(
                    select(Router.id, Router.name).where(
                        Router.id.in_([g.router_id for g in sessions])
                    )
                )
            ).all()
        )
        lnames = dict(
            (
                await self.session.execute(
                    select(Location.id, Location.name).where(
                        Location.id.in_([g.location_id for g in sessions])
                    )
                )
            ).all()
        )
        now = self.now()
        return [
            {
                "id": str(g.id),
                "started_at": _iso(g.started_at),
                "uptime_seconds": int((now - g.started_at).total_seconds())
                if g.started_at
                else None,
                "last_activity_at": _iso(getattr(g, "last_activity_at", None)),
                "ip_address": g.ip_address,
                "mac_address": macs.get(g.device_id),
                "router_name": rnames.get(g.router_id),
                "location_name": lnames.get(g.location_id),
                "bytes_uploaded": int(g.bytes_uploaded or 0),
                "bytes_downloaded": int(g.bytes_downloaded or 0),
            }
            for g in sessions
        ]

    async def ledger(self, isp: IspContext, subscriber_id: uuid.UUID) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        billing = self.plans._billing()
        invoices = list(
            (
                await self.session.execute(
                    select(IspInvoice)
                    .where(
                        IspInvoice.isp_organization_id == isp.isp_org_id,
                        IspInvoice.subscriber_id == s.id,
                        IspInvoice.is_deleted.is_(False),
                    )
                    .order_by(IspInvoice.issue_date.desc(), IspInvoice.seq.desc())
                )
            )
            .scalars()
            .all()
        )
        payments = list(
            (
                await self.session.execute(
                    select(IspPayment)
                    .where(
                        IspPayment.isp_organization_id == isp.isp_org_id,
                        IspPayment.subscriber_id == s.id,
                        IspPayment.is_deleted.is_(False),
                    )
                    .order_by(IspPayment.received_at.desc())
                )
            )
            .scalars()
            .all()
        )
        live = [
            i for i in invoices if i.doc_type == "invoice" and i.status != "cancelled"
        ]
        due = sum(billing_balance(i) for i in live)
        today = billing.today(isp)
        overdue = sum(
            billing_balance(i) for i in live if i.due_date and i.due_date < today
        )
        billed = sum(
            i.total_paise - i.credit_noted_paise
            for i in invoices
            if i.doc_type == "invoice"
        )
        paid = sum(p.amount_paise for p in payments if p.status == "confirmed")
        subs, packages = await billing.row_extras(invoices)
        return {
            "subscriber_id": str(s.id),
            "billed_paise": billed,
            "paid_paise": paid,
            "due_paise": due,
            "overdue_paise": overdue,
            "status": "unpaid" if due > 0 else "paid",
            "invoices": [
                billing.invoice_row(
                    i, subscriber=subs.get(i.id), package=packages.get(i.id)
                )
                for i in invoices
            ],
            "payments": await billing.payment_rows(isp, payments),
        }

    async def timeline(self, s: IspSubscriber, limit: int = 50) -> list[dict]:
        from app.domains.auth.models import User

        rows = (
            await self.session.execute(
                select(IspSubscriberEvent, User.first_name, User.last_name)
                .outerjoin(User, User.id == IspSubscriberEvent.actor_user_id)
                .where(
                    IspSubscriberEvent.subscriber_id == s.id,
                    IspSubscriberEvent.is_deleted.is_(False),
                )
                .order_by(IspSubscriberEvent.created_at.desc())
                .limit(limit)
            )
        ).all()
        return [
            {
                "id": str(e.id),
                "kind": e.kind,
                "summary": e.summary,
                "detail": e.detail,
                "at": _iso(e.created_at),
                "actor_name": " ".join(x for x in (fn, ln) if x) or None,
            }
            for e, fn, ln in rows
        ]

    async def view_360(self, isp: IspContext, subscriber_id: uuid.UUID) -> dict:
        await self.activate_due(isp)
        base = await self.plans.subscriber_detail(isp, subscriber_id)
        s = await self.plans.subscriber(isp, subscriber_id)
        p = await self.profile(s)
        suspended = s.customer_organization_id in await self._suspended_customers(
            [s.customer_organization_id]
        )
        sessions = await self.live_sessions(s)
        live = await self._live_view(sessions)
        ledger = await self.ledger(isp, s.id)
        state = self.display_state(s, p, customer_suspended=suspended)
        last_renewal = await self._last_renewal(s)
        base.update(
            display_state=state,
            profile=self.profile_view(p),
            hold={
                "block_kind": p.block_kind if p else None,
                "blocked_reason": p.blocked_reason if p else None,
                "blocked_at": _iso(p.blocked_at) if p else None,
                "frozen_at": _iso(p.frozen_at) if p else None,
                "frozen_remaining_seconds": p.frozen_remaining_seconds if p else None,
                "grace_until": _iso(p.grace_until) if p else None,
            },
            online=bool(live),
            live_sessions=live,
            auth={
                # PPPoE lands with Phase 2b (X2); MAC / static IP belong to
                # the JAZE-2 lane and are filled there when present.
                "hotspot": True,
                "pppoe": False,
                "mac_bound": None,
                "static_ip": None,
            },
            billing={
                "due_paise": ledger["due_paise"],
                "overdue_paise": ledger["overdue_paise"],
                "status": ledger["status"],
            },
            can_revert=last_renewal is not None,
            timeline=await self.timeline(s),
        )
        return base

    # ------------------------------------------------------------------
    # actions (J1)
    # ------------------------------------------------------------------
    async def disconnect(
        self,
        isp: IspContext,
        subscriber_id: uuid.UUID,
        *,
        reason: str = "isp_subscriber_disconnect",
        record: bool = True,
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        return await self._kick(isp, s, reason=reason, record=record)

    async def _kick(
        self, isp: IspContext, s: IspSubscriber, *, reason: str, record: bool = True
    ) -> dict:
        sessions = await self.live_sessions(s)
        ended, unconfirmed = 0, 0
        for g in sessions:
            if g.organization_id != s.customer_organization_id:
                continue  # never touch anything outside this customer
            try:
                updated = await self.guest_service.disconnect_session(
                    session_id=g.id,
                    requesting_organization_id=s.customer_organization_id,
                    actor_user_id=isp.user_id,
                    reason=reason,
                )
                ended += 1
                if getattr(updated, "disconnect_enforced", None) is False:
                    unconfirmed += 1
            except Exception:  # noqa: BLE001 -- a router failure is reported, not a 5xx
                unconfirmed += 1
        if record and sessions:
            await self.event(
                isp,
                s,
                "disconnected",
                f"{ended} session(s) ended",
                reason=reason,
                ended=ended,
                unconfirmed=unconfirmed,
            )
        return {"sessions_ended": ended, "unconfirmed": unconfirmed}

    async def _guest_block(self, isp: IspContext, s: IspSubscriber, reason: str):
        if s.guest_id and self.guest_service is not None:
            await self.guest_service.block_guest(
                actor_user_id=isp.user_id,
                guest_id=s.guest_id,
                requesting_organization_id=s.customer_organization_id,
                reason=reason,
            )

    async def _guest_unblock(self, isp: IspContext, s: IspSubscriber):
        if s.guest_id and self.guest_service is not None:
            await self.guest_service.unblock_guest(
                actor_user_id=isp.user_id,
                guest_id=s.guest_id,
                requesting_organization_id=s.customer_organization_id,
            )

    def _status_from_validity(self, s: IspSubscriber) -> str:
        return (
            "active" if not s.valid_until or s.valid_until > self.now() else "expired"
        )

    async def block(
        self,
        isp: IspContext,
        subscriber_id: uuid.UUID,
        *,
        kind: str,
        reason: str | None,
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        p = await self.ensure_profile(isp, s)
        if p.block_kind == "permanent" or (p.block_kind == kind):
            raise IspSubscriberBlockedError()
        if p.block_kind is None and p.frozen_at is None:
            p.status_before_hold = s.status
        p.block_kind, p.blocked_reason, p.blocked_at = kind, reason, self.now()
        s.status = "disabled"
        await self.session.flush()
        await self._guest_block(isp, s, f"isp_block:{kind}")
        kicked = await self._kick(isp, s, reason="isp_subscriber_blocked", record=False)
        await self.event(
            isp,
            s,
            "blocked",
            f"{'Permanently' if kind == 'permanent' else 'Temporarily'} blocked",
            block_kind=kind,
            reason=reason,
            **kicked,
        )
        return kicked

    async def unblock(self, isp: IspContext, subscriber_id: uuid.UUID) -> None:
        s = await self.plans.subscriber(isp, subscriber_id)
        p = await self.ensure_profile(isp, s)
        if p.block_kind is None:
            raise IspSubscriberNotBlockedError()
        if p.block_kind == "permanent" and isp.role_slug not in _OWNERISH:
            raise IspPermanentBlockOwnerOnlyError()
        was = p.block_kind
        p.block_kind = p.blocked_reason = p.blocked_at = None
        if p.frozen_at is None:
            s.status = self._status_from_validity(s)
            p.status_before_hold = None
            await self._guest_unblock(isp, s)
        await self.session.flush()
        await self.event(isp, s, "unblocked", "Block lifted", was=was)

    async def freeze(
        self, isp: IspContext, subscriber_id: uuid.UUID, *, reason: str | None
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        p = await self.ensure_profile(isp, s)
        if p.block_kind:
            raise IspSubscriberBlockedError()
        if p.frozen_at is not None:
            raise IspSubscriberFrozenError()
        now = self.now()
        if s.valid_until is None or s.valid_until <= now or s.status == "disabled":
            raise IspFreezeNeedsValidityError()
        p.frozen_remaining_seconds = int((s.valid_until - now).total_seconds())
        p.frozen_at = now
        p.status_before_hold = s.status
        s.status = "disabled"
        await self.session.flush()
        await self._guest_block(isp, s, "isp_frozen")
        kicked = await self._kick(isp, s, reason="isp_subscriber_frozen", record=False)
        await self.event(
            isp,
            s,
            "frozen",
            "Service frozen; validity paused",
            reason=reason,
            remaining_seconds=p.frozen_remaining_seconds,
            valid_until_before=s.valid_until,
            **kicked,
        )
        return kicked

    async def unfreeze(self, isp: IspContext, subscriber_id: uuid.UUID) -> None:
        s = await self.plans.subscriber(isp, subscriber_id)
        p = await self.ensure_profile(isp, s)
        if p.frozen_at is None:
            raise IspSubscriberNotFrozenError()
        before = s.valid_until
        s.valid_until = self.now() + timedelta(
            seconds=int(p.frozen_remaining_seconds or 0)
        )
        frozen_for = int((self.now() - p.frozen_at).total_seconds())
        p.frozen_at = None
        p.frozen_remaining_seconds = None
        if p.block_kind is None:
            s.status = self._status_from_validity(s)
            p.status_before_hold = None
            await self._guest_unblock(isp, s)
        await self.session.flush()
        await self.event(
            isp,
            s,
            "unfrozen",
            "Service resumed; validity restored",
            valid_until_before=before,
            valid_until=s.valid_until,
            frozen_seconds=frozen_for,
        )

    async def grace(
        self, isp: IspContext, subscriber_id: uuid.UUID, *, hours: int, note: str | None
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        p = await self.ensure_profile(isp, s)
        if p.block_kind:
            raise IspSubscriberBlockedError()
        if p.frozen_at is not None:
            raise IspSubscriberFrozenError()
        now = self.now()
        if p.grace_until and p.grace_until > now:
            raise IspGraceActiveError()
        before = s.valid_until
        start = max(now, s.valid_until) if s.valid_until else now
        s.valid_until = start + timedelta(hours=hours)
        p.grace_until = s.valid_until
        s.status = "active"
        await self.session.flush()
        await self.event(
            isp,
            s,
            "grace",
            f"Grace {hours} h (no payment recorded)",
            hours=hours,
            note=note,
            valid_until_before=before,
            valid_until=s.valid_until,
        )
        return {"valid_until": _iso(s.valid_until), "grace_until": _iso(p.grace_until)}

    async def renew(
        self, isp: IspContext, subscriber_id: uuid.UUID, data: dict
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        p = await self.profile(s)
        if p is not None and p.block_kind:
            raise IspSubscriberBlockedError()
        if p is not None and p.frozen_at is not None:
            raise IspSubscriberFrozenError()
        key = data.get("idempotency_key")
        if key:
            prior = (
                await self.session.execute(
                    select(IspSubscriberEvent).where(
                        IspSubscriberEvent.subscriber_id == s.id,
                        IspSubscriberEvent.kind == "renewed",
                        IspSubscriberEvent.detail["idempotency_key"].astext == key,
                    )
                )
            ).scalar_one_or_none()
        else:
            prior = None
        before = {
            "valid_until_before": s.valid_until,
            "package_id_before": s.package_id,
            "speed_group_id_before": s.speed_group_id,
            "status_before": s.status,
        }
        payload = dict(data)
        payload.setdefault("package_id", s.package_id)
        if p is not None and p.override_price_paise is not None:
            payload["price_override_paise"] = p.override_price_paise
        result = await self.plans.recharge(isp, s.id, payload)
        if prior is None:
            inv = result.get("invoice") or {}
            pay = result.get("payment") or {}
            await self.event(
                isp,
                s,
                "renewed",
                f"Renewed to {result['subscriber']['valid_until']}",
                idempotency_key=key,
                invoice_id=inv.get("id"),
                invoice_number=inv.get("number"),
                payment_id=pay.get("id"),
                override_price_paise=payload.get("price_override_paise"),
                **before,
            )
            if p is not None and p.grace_until:
                p.grace_until = None
                await self.session.flush()
        return result

    async def _last_renewal(self, s: IspSubscriber) -> IspSubscriberEvent | None:
        e = (
            await self.session.execute(
                select(IspSubscriberEvent)
                .where(
                    IspSubscriberEvent.subscriber_id == s.id,
                    IspSubscriberEvent.kind.in_(("renewed", "reverted")),
                    IspSubscriberEvent.is_deleted.is_(False),
                )
                .order_by(IspSubscriberEvent.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if e is None or e.kind != "renewed" or (e.detail or {}).get("reverted"):
            return None
        return e

    async def revert(
        self, isp: IspContext, subscriber_id: uuid.UUID, *, reason: str
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        await self.session.execute(
            select(IspSubscriber.id).where(IspSubscriber.id == s.id).with_for_update()
        )
        e = await self._last_renewal(s)
        if e is None:
            raise IspNothingToRevertError()
        d = dict(e.detail or {})
        billing = self.plans._billing()
        note = None
        if d.get("invoice_id"):
            inv = await billing._invoice(isp, uuid.UUID(d["invoice_id"]))
            if inv.paid_paise > 0:
                raise IspRevertPaidError(invoice=inv.number)
            if billing_balance(inv) > 0 and inv.status != "cancelled":
                note = await billing.credit_note(
                    isp, inv.id, amount_paise=None, reason=f"Revert: {reason}"
                )
        s.valid_until = _parse_dt(d.get("valid_until_before"))
        if d.get("package_id_before"):
            s.package_id = uuid.UUID(d["package_id_before"])
        if d.get("speed_group_id_before"):
            s.speed_group_id = uuid.UUID(d["speed_group_id_before"])
        s.status = (
            d.get("status_before")
            if d.get("status_before") == "disabled"
            else self._status_from_validity(s)
        )
        d["reverted"] = True
        e.detail = d
        await self.session.flush()
        await self.event(
            isp,
            s,
            "reverted",
            f"Renewal {d.get('invoice_number') or ''} reverted".strip(),
            reason=reason,
            renewal_event_id=e.id,
            credit_note_id=note.id if note else None,
            credit_note_number=note.number if note else None,
            valid_until=s.valid_until,
        )
        return {
            "valid_until": _iso(s.valid_until),
            "credit_note_number": note.number if note else None,
            "status": s.status,
        }

    async def add_note(
        self, isp: IspContext, subscriber_id: uuid.UUID, data: dict
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        e = await self.event(
            isp,
            s,
            "ticket" if data.get("ticket_type") else "note",
            (data.get("subject") or data.get("body") or "")[:255],
            ticket_type=data.get("ticket_type"),
            source=data.get("source"),
            body=data.get("body"),
            closed=bool(data.get("close_after_raising")),
        )
        return {"id": str(e.id), "kind": e.kind}

    # ------------------------------------------------------------------
    # onboarding (J2)
    # ------------------------------------------------------------------
    async def next_circuit_id(self, isp: IspContext) -> int:
        """Preview only (nothing is reserved): the id the next subscriber
        gets, from the gap-free per-ISP ``circuit`` series."""
        from .billing_models import IspInvoiceSequence

        v = (
            await self.session.execute(
                select(IspInvoiceSequence.next_value).where(
                    IspInvoiceSequence.isp_organization_id == isp.isp_org_id,
                    IspInvoiceSequence.series == "circuit",
                    IspInvoiceSequence.fy == "----",
                )
            )
        ).scalar_one_or_none()
        return int(v or 1)

    async def onboard(self, isp: IspContext, data: dict) -> dict:
        core_keys = (
            "isp_customer_id",
            "package_id",
            "identifier",
            "display_name",
            "first_name",
            "last_name",
            "phone",
            "email",
            "gstin",
            "address",
            "state_code",
            "zone_id",
            "reminder_opt_in",
        )
        core = {k: data[k] for k in core_keys if k in data}
        profile = self.validate_profile(data.get("profile") or {})
        activation_at = profile.get("activation_at")
        if activation_at and activation_at > self.now():
            core["valid_from"] = activation_at
        if profile.get("exclude_reminders"):
            core["reminder_opt_in"] = {"email": False, "sms": False, "whatsapp": False}
        s = await self.plans.create_subscriber(isp, core)
        if activation_at and activation_at > self.now():
            s.status = "disabled"  # not yet live; activate_due() flips it
        p = IspSubscriberProfile(
            isp_organization_id=isp.isp_org_id,
            subscriber_id=s.id,
            created_by=isp.user_id,
            **profile,
        )
        self.session.add(p)
        await self.session.flush()
        await self.event(
            isp,
            s,
            "created",
            f"Subscriber created (circuit {s.circuit_id})",
            scheduled_activation=activation_at,
        )
        welcome = self.welcome(isp, s) if data.get("welcome_whatsapp") else None
        out = await self.view_360(isp, s.id)
        out["welcome"] = welcome
        return out

    def welcome(self, isp: IspContext, s: IspSubscriber) -> dict | None:
        """A staff-opened WhatsApp share link (no API send; SMS deferred)."""
        phone = re.sub(r"\D", "", s.phone or "")
        if len(phone) == 10:
            phone = "91" + phone
        if len(phone) < 11:
            return None
        name = isp.organization.name
        text = (
            f"Welcome to {name}! Your connection is set up. "
            f"Circuit ID: {s.circuit_id}. Login ID: {s.identifier}."
        )
        return {
            "whatsapp_share_url": f"https://wa.me/{phone}?text={quote(text)}",
            "text": text,
        }

    async def activate_due(self, isp: IspContext) -> int:
        """Lazy scheduled activation: subscribers whose ``activation_at`` has
        passed and who were held only for it go live."""
        now = self.now()
        rows = (
            await self.session.execute(
                select(IspSubscriber, IspSubscriberProfile)
                .join(
                    IspSubscriberProfile,
                    IspSubscriberProfile.subscriber_id == IspSubscriber.id,
                )
                .where(
                    IspSubscriber.isp_organization_id == isp.isp_org_id,
                    IspSubscriber.status == "disabled",
                    IspSubscriberProfile.activation_at.is_not(None),
                    IspSubscriberProfile.activation_at <= now,
                    IspSubscriberProfile.block_kind.is_(None),
                    IspSubscriberProfile.frozen_at.is_(None),
                    IspSubscriberProfile.is_deleted.is_(False),
                    IspSubscriber.is_deleted.is_(False),
                )
            )
        ).all()
        n = 0
        for s, _p in rows:
            created = (
                await self.session.execute(
                    select(IspSubscriberEvent.id).where(
                        IspSubscriberEvent.subscriber_id == s.id,
                        IspSubscriberEvent.kind == "activated",
                    )
                )
            ).first()
            if created:
                continue  # a manual disable after activation stays disabled
            s.status = self._status_from_validity(s)
            await self.event(isp, s, "activated", "Scheduled activation reached")
            n += 1
        if n:
            await self.session.flush()
        return n

    # ------------------------------------------------------------------
    # directory (J11)
    # ------------------------------------------------------------------
    def _state_condition(self, state: str, suspended_ids: set) -> Any:
        P, S = IspSubscriberProfile, IspSubscriber
        now = self.now()
        no_hold = and_(
            or_(P.id.is_(None), and_(P.block_kind.is_(None), P.frozen_at.is_(None)))
        )
        # NOT IN (NULL) is NULL in SQL: with no suspended customer this must
        # be TRUE, not "filter everything".
        not_susp = (
            S.customer_organization_id.not_in(list(suspended_ids))
            if suspended_ids
            else true()
        )
        if state == "permanently_blocked":
            return P.block_kind == "permanent"
        if state == "blocked":
            return P.block_kind == "temporary"
        if state == "frozen":
            return and_(P.frozen_at.is_not(None), P.block_kind.is_(None))
        if state == "suspended":
            return and_(no_hold, S.customer_organization_id.in_(list(suspended_ids)))
        scheduled = and_(P.activation_at.is_not(None), P.activation_at > now)
        if state == "scheduled":
            return and_(no_hold, not_susp, scheduled)
        base = and_(no_hold, not_susp, or_(P.id.is_(None), ~scheduled))
        if state == "disabled":
            return and_(base, S.status == "disabled")
        expired = and_(S.valid_until.is_not(None), S.valid_until <= now)
        if state == "expired":
            return and_(base, S.status != "disabled", expired)
        grace = and_(P.grace_until.is_not(None), P.grace_until > now)
        if state == "grace":
            return and_(base, S.status == "active", ~expired, grace)
        # active
        return and_(base, S.status == "active", ~expired, or_(P.id.is_(None), ~grace))

    async def directory(
        self,
        isp: IspContext,
        *,
        state: str | None,
        search: str | None,
        isp_customer_id: uuid.UUID | None,
        package_id: uuid.UUID | None,
        zone_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> dict:
        await self.plans.sync_subscribers(isp)
        await self.activate_due(isp)
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            ids = [isp_customer_id]
        else:
            ids = await isp.child_ids()
        empty = {
            "items": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "pages": 0,
            "state_counts": dict.fromkeys(DISPLAY_STATES, 0),
            "package_counts": [],
        }
        if not ids:
            return empty
        suspended = await self._suspended_customers(ids)
        S, P = IspSubscriber, IspSubscriberProfile
        base = select(S).outerjoin(
            P, and_(P.subscriber_id == S.id, P.is_deleted.is_(False))
        )
        cond = [
            S.isp_organization_id == isp.isp_org_id,
            S.customer_organization_id.in_(ids),
            S.is_deleted.is_(False),
        ]
        if package_id:
            cond.append(S.package_id == package_id)
        if zone_id:
            cond.append(S.zone_id == zone_id)
        if search and search.strip():
            cond.append(_search_condition(search))
        counts = {}
        for st in DISPLAY_STATES:
            counts[st] = int(
                (
                    await self.session.execute(
                        select(func.count()).select_from(
                            base.where(
                                *cond, self._state_condition(st, suspended)
                            ).subquery()
                        )
                    )
                ).scalar_one()
            )
        q_cond = list(cond)
        if state:
            q_cond.append(self._state_condition(state, suspended))
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(base.where(*q_cond).subquery())
                )
            ).scalar_one()
        )
        rows = list(
            (
                await self.session.execute(
                    base.where(*q_cond)
                    .order_by(S.created_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        views = await self.plans.subscriber_views(isp, rows)
        profiles = {}
        if rows:
            profiles = {
                p.subscriber_id: p
                for p in (
                    await self.session.execute(
                        select(P).where(
                            P.subscriber_id.in_([r.id for r in rows]),
                            P.is_deleted.is_(False),
                        )
                    )
                )
                .scalars()
                .all()
            }
        for v, s in zip(views, rows, strict=True):
            p = profiles.get(s.id)
            v["display_state"] = self.display_state(
                s, p, customer_suspended=s.customer_organization_id in suspended
            )
            v["phone"] = s.phone
            v["user_type"] = p.user_type if p else "home"
            v["override_price_paise"] = p.override_price_paise if p else None
        # per-package active / total (scope: same customers, no state filter)
        now = self.now()
        pk = (
            await self.session.execute(
                select(
                    IspPackage.id,
                    IspPackage.name,
                    func.count(S.id),
                    func.count(S.id).filter(
                        S.status == "active",
                        or_(S.valid_until.is_(None), S.valid_until > now),
                    ),
                )
                .join(S, S.package_id == IspPackage.id)
                .where(
                    S.isp_organization_id == isp.isp_org_id,
                    S.customer_organization_id.in_(ids),
                    S.is_deleted.is_(False),
                )
                .group_by(IspPackage.id, IspPackage.name)
                .order_by(IspPackage.name)
            )
        ).all()
        return {
            "items": views,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
            "state_counts": counts,
            "package_counts": [
                {"package_id": str(i), "name": n, "total": int(t), "active": int(a)}
                for i, n, t, a in pk
            ],
        }

    async def typeahead(self, isp: IspContext, q: str, limit: int = 10) -> list[dict]:
        ids = await isp.child_ids()
        if not ids or len(q.strip()) < 2:
            return []
        from app.domains.organization.models import Organization

        rows = (
            await self.session.execute(
                select(IspSubscriber, Organization.name)
                .join(
                    Organization,
                    Organization.id == IspSubscriber.customer_organization_id,
                )
                .where(
                    IspSubscriber.isp_organization_id == isp.isp_org_id,
                    IspSubscriber.customer_organization_id.in_(ids),
                    IspSubscriber.is_deleted.is_(False),
                    _search_condition(q),
                )
                .order_by(IspSubscriber.circuit_id)
                .limit(limit)
            )
        ).all()
        return [
            {
                "id": str(s.id),
                "circuit_id": s.circuit_id,
                "identifier": subscriber_identifier(s.identifier, s.source),
                "name": " ".join(x for x in (s.first_name, s.last_name) if x)
                or s.display_name,
                "phone": s.phone,
                "customer_name": cname,
                "status": s.status,
            }
            for s, cname in rows
        ]

    async def move(
        self,
        isp: IspContext,
        subscriber_id: uuid.UUID,
        *,
        isp_customer_id: uuid.UUID,
        reason: str | None,
    ) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        target = await IspScope.assert_customer(isp, isp_customer_id)
        if target.id == s.customer_organization_id:
            raise IspMoveSameCustomerError()
        clash = (
            await self.session.execute(
                select(IspSubscriber.id).where(
                    IspSubscriber.customer_organization_id == target.id,
                    IspSubscriber.identifier == s.identifier,
                    IspSubscriber.is_deleted.is_(False),
                )
            )
        ).first()
        if clash:
            raise IspNameTakenError(
                "The target customer already has a subscriber with that login"
            )
        kicked = await self._kick(isp, s, reason="isp_subscriber_moved", record=False)
        if s.package_id:
            pkg = await self.plans.package(isp, s.package_id)
            await self.plans.materialize(isp, pkg, target.id)
        source = s.customer_organization_id
        s.customer_organization_id = target.id
        # The guest record belongs to the old venue's org; the next login at
        # the new venue links a new one (sync_subscribers).
        s.guest_id = None
        await self.session.flush()
        await self.event(
            isp,
            s,
            "moved",
            f"Moved to {target.name}",
            from_customer_id=source,
            to_customer_id=target.id,
            reason=reason,
            **kicked,
        )
        return {
            "isp_customer_id": str(target.id),
            "customer_name": target.name,
            **kicked,
        }

    # ------------------------------------------------------------------
    # plan sync (J19)
    # ------------------------------------------------------------------
    async def _affected(
        self,
        isp: IspContext,
        *,
        package: IspPackage | None,
        group: IspSpeedGroup | None,
    ) -> list[IspSubscriber]:
        ids = await isp.child_ids()
        if not ids:
            return []
        cond = [
            IspSubscriber.isp_organization_id == isp.isp_org_id,
            IspSubscriber.customer_organization_id.in_(ids),
            IspSubscriber.is_deleted.is_(False),
        ]
        if package is not None:
            cond.append(IspSubscriber.package_id == package.id)
        else:
            pkg_ids = select(IspPackage.id).where(IspPackage.speed_group_id == group.id)
            cond.append(
                or_(
                    IspSubscriber.speed_group_id == group.id,
                    IspSubscriber.package_id.in_(pkg_ids),
                )
            )
        return list(
            (await self.session.execute(select(IspSubscriber).where(*cond)))
            .scalars()
            .all()
        )

    async def plan_sync(
        self,
        isp: IspContext,
        *,
        package_id: uuid.UUID | None = None,
        speed_group_id: uuid.UUID | None = None,
        dry_run: bool = True,
        live_push: bool = True,
        kick_online: bool = False,
    ) -> dict:
        package = await self.plans.package(isp, package_id) if package_id else None
        group = await self.plans.group(isp, speed_group_id) if speed_group_id else None
        subs = await self._affected(isp, package=package, group=group)
        pkgs: dict[uuid.UUID, IspPackage] = {}
        for s in subs:
            if s.package_id and s.package_id not in pkgs:
                pkgs[s.package_id] = await self.session.get(IspPackage, s.package_id)
        drift = [
            s
            for s in subs
            if s.package_id
            and pkgs.get(s.package_id)
            and s.speed_group_id != pkgs[s.package_id].speed_group_id
        ]
        online: list[tuple[IspSubscriber, Any]] = []
        for s in subs:
            for g in await self.live_sessions(s):
                online.append((s, g))
        locations = sorted({str(g.location_id) for _, g in online})
        summary = {
            "dry_run": dry_run,
            "subscribers": len(subs),
            "speed_group_changes": len(drift),
            "online_sessions": len(online),
            "locations_with_online": len(locations),
        }
        if dry_run:
            return summary
        for s in drift:
            s.speed_group_id = pkgs[s.package_id].speed_group_id
        # Queue profiles of every package/customer pair follow the group.
        groups = {pkgs[p].speed_group_id for p in pkgs if pkgs.get(p)}
        if group is not None:
            groups.add(group.id)
        for gid in groups:
            g = await self.session.get(IspSpeedGroup, gid)
            if g is not None and g.isp_organization_id == isp.isp_org_id:
                await self.plans._propagate_group(isp, g)
        for s in subs:
            if s.package_id and pkgs.get(s.package_id):
                await self.plans.materialize(
                    isp, pkgs[s.package_id], s.customer_organization_id
                )
        await self.session.flush()
        pushed, push_failed, kicked = 0, 0, 0
        if live_push and self.queue_service is not None and online:
            seen = set()
            for s, g in online:
                key = (g.location_id, s.customer_organization_id)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    r = await self.queue_service.reapply_active_sessions_for_location(
                        location_id=g.location_id,
                        requesting_organization_id=s.customer_organization_id,
                        actor_user_id=isp.user_id,
                    )
                    pushed += int((r or {}).get("reapplied", 0) or 0)
                except Exception:  # noqa: BLE001 -- reported, the DB change stands
                    push_failed += 1
        if kick_online:
            for s in {s.id: s for s, _ in online}.values():
                kicked += (await self._kick(isp, s, reason="isp_plan_sync"))[
                    "sessions_ended"
                ]
        for s in subs:
            await self.event(
                isp,
                s,
                "plan_sync",
                "Plan change applied",
                package_id=package_id,
                speed_group_id=speed_group_id or s.speed_group_id,
            )
        summary.update(
            live_pushed_sessions=pushed,
            live_push_failed_locations=push_failed,
            sessions_kicked=kicked,
        )
        return summary


def _search_condition(q: str) -> Any:
    term = q.strip()
    pattern = f"%{term}%"
    S = IspSubscriber
    terms = [
        S.identifier.ilike(pattern),
        S.display_name.ilike(pattern),
        S.first_name.ilike(pattern),
        S.last_name.ilike(pattern),
        S.phone.ilike(pattern),
        S.email.ilike(pattern),
        func.concat(S.first_name, " ", S.last_name).ilike(pattern),
    ]
    if term.isdigit() and len(term) <= 9:
        terms.append(S.circuit_id == int(term))
    return or_(*terms)


def _parse_dt(v: Any) -> datetime | None:
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        return v
    return datetime.fromisoformat(str(v))


def _jsonable(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, list | tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    return v


__all__ = ["DISPLAY_STATES", "IspSubscriber360Service"]
