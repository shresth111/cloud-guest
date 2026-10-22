"""Suspend cuts internet (ADDENDUM_01 §A, founder Q4 = "internet band hoga").

For every router of the suspended customer:

1. **New logins are refused at once.** ``RadiusService.disable_nas`` on the
   router's NAS row(s): ``authenticate_nas`` then 401s every Access-Request
   (rlm_rest maps 401 to Access-Reject), and the hub's 60 s sync drops the
   client stanza. No FreeRADIUS or guest-domain code is edited.
2. **Live sessions are kicked.** ``GuestService.disconnect_session`` per
   active session (RouterOS 8728; CoA has never worked on this estate). An
   unreachable router leaves the step ``pending``; retries call the
   existing ``issue_live_disconnect`` again.
3. **Optional "Service paused" portal page**, best effort, through
   ``CaptivePortalService``. It is not the security boundary.

Every step records ``prior_state`` so resume restores exactly what suspend
changed (a NAS already disabled before the suspend stays disabled).

Hard rule (§A.9): the only input is an ``IspScope``-resolved customer.
Routers are ``Router.organization_id = customer``; NAS rows are
``organization_id = customer AND router_id IN (those routers)``. Before every
``disable_nas`` / ``activate_nas`` / kick, the owning org is re-checked
(parent = this ISP and an ``isp_customer_profiles`` row); a mismatch raises
``IspScopeViolation`` and aborts the transaction. It must never happen.

TR-069 credentials are NOT touched (ADDENDUM_01 §A.6 overrides PRD §4.3):
cutting them would cut our own management path to the CPEs.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, OperationalError

from app.domains.guest.models import GuestSession, RadiusNasClient
from app.domains.organization.models import Organization
from app.domains.router.models import Router

from .billing_models import IspCustomerServiceState, IspServiceAction
from .constants import (
    AUDIT_ISP_SERVICE_RESUMED,
    AUDIT_ISP_SERVICE_SUSPENDED,
    SERVICE_RETRY_GIVE_UP,
    SERVICE_RETRY_MIN_INTERVAL,
    SUSPEND_REASONS,
)
from .exceptions import (
    IspScopeViolation,
    IspServiceTransitionInProgressError,
    IspSuspendReasonInvalidError,
)
from .models import IspCustomerProfile

logger = logging.getLogger(__name__)

ACTIVE = "active"
SUSPEND_PENDING = "suspend_pending"
SUSPENDED = "suspended"
RESUME_PENDING = "resume_pending"
CUT_STATES = frozenset({SUSPEND_PENDING, SUSPENDED})

SUSPENDED_CONFIG_NAME = "isp-suspended"
SUSPENDED_HEADLINE = "Service paused"


def _now() -> datetime:
    return datetime.now(UTC)


class IspServiceControl:
    def __init__(
        self,
        *,
        session: Any,
        radius_service: Any = None,
        guest_service: Any = None,
        captive_portal_service: Any = None,
        organization_service: Any = None,
        audit: Any = None,
        live_disconnect: Any = None,
        clock: Any = None,
    ) -> None:
        self.session = session
        self.radius_service = radius_service
        self.guest_service = guest_service
        self.captive_portal_service = captive_portal_service
        self.organization_service = organization_service
        self.audit = audit
        #: ``async (session_row) -> bool|None`` -- re-kick for retries.
        self.live_disconnect = live_disconnect
        self._clock = clock or _now

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------
    async def get_state(self, customer_id: uuid.UUID) -> IspCustomerServiceState | None:
        return (
            await self.session.execute(
                select(IspCustomerServiceState).where(
                    IspCustomerServiceState.customer_organization_id == customer_id,
                    IspCustomerServiceState.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def is_cut(self, customer_id: uuid.UUID) -> bool:
        state = await self.get_state(customer_id)
        return state is not None and state.state in CUT_STATES

    async def _steps(self, state: IspCustomerServiceState) -> list[IspServiceAction]:
        rows = await self.session.execute(
            select(IspServiceAction)
            .where(
                IspServiceAction.state_id == state.id,
                IspServiceAction.is_deleted.is_(False),
            )
            .order_by(IspServiceAction.created_at, IspServiceAction.id)
        )
        return list(rows.scalars().all())

    async def view(self, customer: Any, *, now: datetime | None = None) -> dict:
        state = await self.get_state(customer.id)
        if state is None:
            return {
                "isp_customer_id": str(customer.id),
                "state": ACTIVE,
                "reason": None,
                "note": None,
                "requested_by": None,
                "requested_at": None,
                "completed_at": None,
                "routers": [],
                "warnings": [],
                "bypass_entries_not_cut": 0,
            }
        steps = await self._steps(state)
        # The current transition's steps only.
        transition = "suspend" if state.state in CUT_STATES else "resume"
        steps = [s for s in steps if s.transition == transition]
        router_ids = sorted({s.router_id for s in steps if s.router_id}, key=str)
        routers = {}
        if router_ids:
            rows = await self.session.execute(
                select(Router).where(Router.id.in_(router_ids))
            )
            routers = {r.id: r for r in rows.scalars().all()}
        requested_by = None
        if state.requested_by is not None:
            from app.domains.auth.models import User

            user = await self.session.get(User, state.requested_by)
            if user is not None:
                requested_by = {
                    "id": str(user.id),
                    "name": f"{user.first_name} {user.last_name}".strip(),
                }
        out_routers = []
        for rid in router_ids:
            r = routers.get(rid)
            out_routers.append(
                {
                    "isp_router_id": str(rid),
                    "name": r.name if r else None,
                    "online": bool(r and r.status == "online"),
                    "steps": [
                        {
                            "kind": s.kind,
                            "status": s.status,
                            "attempts": s.attempts,
                            "last_error": s.last_error,
                            "detail": s.detail,
                        }
                        for s in steps
                        if s.router_id == rid
                    ],
                }
            )
        return {
            "isp_customer_id": str(customer.id),
            "state": state.state,
            "reason": state.reason,
            "note": state.note,
            "requested_by": requested_by,
            "requested_at": state.requested_at.isoformat()
            if state.requested_at
            else None,
            "completed_at": state.completed_at.isoformat()
            if state.completed_at
            else None,
            "routers": out_routers,
            "warnings": list(state.warnings or []),
            "bypass_entries_not_cut": 0,
        }

    # ------------------------------------------------------------------
    # scope guard (A.9)
    # ------------------------------------------------------------------
    async def _assert_isp_customer(
        self, isp_org_id: uuid.UUID, organization_id: uuid.UUID
    ) -> None:
        org = await self.session.get(Organization, organization_id)
        profile = (
            await self.session.execute(
                select(IspCustomerProfile.id).where(
                    IspCustomerProfile.customer_organization_id == organization_id,
                    IspCustomerProfile.isp_organization_id == isp_org_id,
                    IspCustomerProfile.is_deleted.is_(False),
                )
            )
        ).first()
        if org is None or org.parent_organization_id != isp_org_id or profile is None:
            raise IspScopeViolation(
                organization_id=str(organization_id),
                isp_organization_id=str(isp_org_id),
            )

    async def _routers(self, customer_id: uuid.UUID) -> list[Router]:
        rows = await self.session.execute(
            select(Router)
            .where(Router.organization_id == customer_id, Router.is_deleted.is_(False))
            .order_by(Router.name, Router.id)
        )
        return list(rows.scalars().all())

    async def _nas_rows(
        self, customer_id: uuid.UUID, router_id: uuid.UUID
    ) -> list[Any]:
        rows = await self.session.execute(
            select(RadiusNasClient).where(
                RadiusNasClient.organization_id == customer_id,
                RadiusNasClient.router_id == router_id,
                RadiusNasClient.is_deleted.is_(False),
            )
        )
        return list(rows.scalars().all())

    async def _active_sessions(
        self, customer_id: uuid.UUID, router_id: uuid.UUID
    ) -> list[GuestSession]:
        rows = await self.session.execute(
            select(GuestSession).where(
                GuestSession.organization_id == customer_id,
                GuestSession.router_id == router_id,
                GuestSession.status == "active",
                GuestSession.is_deleted.is_(False),
            )
        )
        return list(rows.scalars().all())

    # ------------------------------------------------------------------
    # locking
    # ------------------------------------------------------------------
    async def _lock_state(
        self, isp_org_id: uuid.UUID, customer_id: uuid.UUID, actor: uuid.UUID
    ) -> IspCustomerServiceState:
        from sqlalchemy.dialects.postgresql import insert

        await self.session.execute(
            insert(IspCustomerServiceState)
            .values(
                id=uuid.uuid4(),
                isp_organization_id=isp_org_id,
                customer_organization_id=customer_id,
                state=ACTIVE,
                requested_by=actor,
                requested_at=self._clock(),
                show_suspended_page=True,
                warnings=[],
                is_deleted=False,
                version=1,
                created_at=self._clock(),
                updated_at=self._clock(),
            )
            .on_conflict_do_nothing(index_elements=["customer_organization_id"])
        )
        try:
            state = (
                await self.session.execute(
                    select(IspCustomerServiceState)
                    .where(
                        IspCustomerServiceState.customer_organization_id == customer_id
                    )
                    .with_for_update(nowait=True)
                    .execution_options(populate_existing=True)
                )
            ).scalar_one()
        except (OperationalError, DBAPIError) as exc:
            if "could not obtain lock" in str(exc) or "LockNotAvailable" in repr(exc):
                raise IspServiceTransitionInProgressError() from exc
            raise
        return state

    async def _step(
        self, state: IspCustomerServiceState, **fields: Any
    ) -> IspServiceAction:
        step = IspServiceAction(state_id=state.id, attempts=0, prior_state={}, **fields)
        self.session.add(step)
        await self.session.flush()
        return step

    async def _cancel_pending(
        self, state: IspCustomerServiceState, transition: str
    ) -> None:
        for step in await self._steps(state):
            if step.transition == transition and step.status == "pending":
                step.status = "cancelled"

    async def _finish(self, state: IspCustomerServiceState, transition: str) -> None:
        steps = [s for s in await self._steps(state) if s.transition == transition]
        pending = [s for s in steps if s.status == "pending"]
        if transition == "suspend":
            state.state = SUSPEND_PENDING if pending else SUSPENDED
        else:
            state.state = RESUME_PENDING if pending else ACTIVE
        state.completed_at = None if pending else self._clock()
        await self.session.flush()

    async def _audit(self, isp_org_id, actor, action, customer, state, **meta) -> None:
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=actor,
            action=action,
            entity_type="organization",
            entity_id=customer.id,
            description=action.replace("_", " "),
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp_org_id),
                "state_id": str(state.id),
                "reason": state.reason,
                **meta,
            },
            organization_id=customer.id,
            location_id=None,
        )

    # ------------------------------------------------------------------
    # suspend
    # ------------------------------------------------------------------
    async def suspend(
        self,
        isp_org_id: uuid.UUID,
        customer: Any,
        *,
        actor: uuid.UUID,
        reason: str,
        note: str | None = None,
        show_suspended_page: bool = True,
        idempotency_key: str | None = None,
        support_line: str | None = None,
        isp_name: str | None = None,
        extra_audit: dict | None = None,
    ) -> dict:
        if reason not in SUSPEND_REASONS:
            raise IspSuspendReasonInvalidError()
        await self._assert_isp_customer(isp_org_id, customer.id)
        state = await self._lock_state(isp_org_id, customer.id, actor)
        if (
            idempotency_key
            and state.idempotency_key == idempotency_key
            and state.idempotent_response
            and state.requested_at
            and self._clock() - state.requested_at < timedelta(hours=24)
        ):
            return state.idempotent_response
        if state.state in CUT_STATES:
            return await self.view(customer)
        if state.state == RESUME_PENDING:
            await self._cancel_pending(state, "resume")
        # A fresh suspend: earlier suspend/resume step rows are history.
        for old in await self._steps(state):
            if old.status != "pending":
                old.is_deleted = True
        state.state = SUSPEND_PENDING
        state.reason = reason
        state.note = note
        state.show_suspended_page = show_suspended_page
        state.requested_by = actor
        state.requested_at = self._clock()
        state.completed_at = None
        state.warnings = []
        state.idempotency_key = idempotency_key
        await self.session.flush()

        if self.organization_service is not None and customer.status == "active":
            await self.organization_service.suspend_organization(
                actor_user_id=actor,
                organization_id=customer.id,
                requesting_organization_id=customer.id,
            )

        kicked = 0
        routers = await self._routers(customer.id)
        for router in routers:
            await self._assert_isp_customer(isp_org_id, router.organization_id)
            nas_rows = await self._nas_rows(customer.id, router.id)
            if not nas_rows:
                await self._step(
                    state,
                    transition="suspend",
                    router_id=router.id,
                    kind="nas_disable",
                    status="skipped",
                    detail="no_nas",
                )
            for nas in nas_rows:
                await self._disable_one(isp_org_id, state, router, nas, actor)
            kicked += await self._kick(isp_org_id, state, customer, router, actor)

        if show_suspended_page:
            await self._portal_pages(
                state, customer, actor, support_line=support_line, isp_name=isp_name
            )

        await self._finish(state, "suspend")
        await self._audit(
            isp_org_id,
            actor,
            AUDIT_ISP_SERVICE_SUSPENDED,
            customer,
            state,
            routers=len(routers),
            sessions_kicked=kicked,
            **(extra_audit or {}),
        )
        response = await self.view(customer)
        state.idempotent_response = response
        await self.session.flush()
        return response

    async def _disable_one(self, isp_org_id, state, router, nas, actor) -> None:
        await self._assert_isp_customer(isp_org_id, nas.organization_id)
        prior = {"nas_status": nas.status}
        if nas.status == "active":
            await self.radius_service.disable_nas(
                nas_id=nas.id,
                requesting_organization_id=nas.organization_id,
                actor_user_id=actor,
                reason=f"isp_suspended:{state.id}",
            )
            detail = "NAS disabled"
        else:
            detail = f"NAS already {nas.status}"
        step = await self._step(
            state,
            transition="suspend",
            router_id=router.id,
            nas_id=nas.id,
            kind="nas_disable",
            status="done",
            detail=detail,
        )
        step.prior_state = prior
        step.attempts = 1

    async def _kick(self, isp_org_id, state, customer, router, actor) -> int:
        sessions = await self._active_sessions(customer.id, router.id)
        unconfirmed: list[str] = []
        ended = 0
        for s in sessions:
            await self._assert_isp_customer(isp_org_id, s.organization_id)
            try:
                updated = await self.guest_service.disconnect_session(
                    session_id=s.id,
                    requesting_organization_id=customer.id,
                    actor_user_id=actor,
                    reason="isp_suspended",
                )
                ended += 1
                if getattr(updated, "disconnect_enforced", None) is False:
                    unconfirmed.append(str(s.id))
            except Exception as exc:  # noqa: BLE001 -- a router failure is a step, not a 5xx
                logger.warning(
                    "isp_suspend_kick_failed", extra={"error": str(exc)[:200]}
                )
                unconfirmed.append(str(s.id))
        step = await self._step(
            state,
            transition="suspend",
            router_id=router.id,
            kind="kick_sessions",
            status="pending" if unconfirmed else "done",
            detail=f"{ended} sessions ended",
        )
        step.attempts = 1
        step.prior_state = {"unconfirmed_session_ids": unconfirmed}
        if unconfirmed:
            step.last_error = "router unreachable"
        return ended

    async def _portal_pages(
        self, state, customer, actor, *, support_line, isp_name
    ) -> None:
        """Best effort; never fails the suspend."""
        if self.captive_portal_service is None:
            return
        from app.domains.captive_portal.models import CaptivePortalConfig
        from app.domains.location.models import Location

        locations = (
            (
                await self.session.execute(
                    select(Location).where(
                        Location.organization_id == customer.id,
                        Location.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        for loc in locations:
            step = await self._step(
                state,
                transition="suspend",
                location_id=loc.id,
                kind="portal_suspended_page",
                status="pending",
            )
            try:
                async with self.session.begin_nested():
                    configs = (
                        (
                            await self.session.execute(
                                select(CaptivePortalConfig).where(
                                    CaptivePortalConfig.organization_id == customer.id,
                                    CaptivePortalConfig.location_id == loc.id,
                                    CaptivePortalConfig.is_deleted.is_(False),
                                )
                            )
                        )
                        .scalars()
                        .all()
                    )
                    paused = next(
                        (c for c in configs if c.name == SUSPENDED_CONFIG_NAME), None
                    )
                    prior_active = [
                        str(c.id) for c in configs if c.is_active and c is not paused
                    ]
                    if paused is None:
                        paused = await self.captive_portal_service.create_config(
                            actor_user_id=actor,
                            requesting_organization_id=customer.id,
                            organization_id=customer.id,
                            location_id=loc.id,
                            name=SUSPENDED_CONFIG_NAME,
                            is_active=False,
                            is_default=False,
                            theme="default",
                            logo_url=None,
                            background_image_url=None,
                            primary_color="#6D28D9",
                            secondary_color="#1E1B4B",
                            default_language="en",
                            supported_languages=["en"],
                            advertisement_banner_url=None,
                            advertisement_banner_link=None,
                            terms_and_conditions_text=None,
                            terms_and_conditions_url=None,
                            privacy_policy_text=None,
                            privacy_policy_url=None,
                            splash_headline=SUSPENDED_HEADLINE,
                            splash_welcome_message=(
                                f"This WiFi is paused. Please contact {isp_name or 'your ISP'}"  # noqa: E501
                                + (f" on {support_line}." if support_line else ".")
                            ),
                            redirect_url=None,
                            otp_sms_enabled=False,
                            otp_email_enabled=True,
                            otp_whatsapp_enabled=False,
                            voucher_enabled=False,
                            username_password_enabled=False,
                            social_login_enabled=False,
                            social_login_providers=[],
                        )
                    for cid in prior_active:
                        await self.captive_portal_service.deactivate_config(
                            actor_user_id=actor,
                            config_id=uuid.UUID(cid),
                            requesting_organization_id=customer.id,
                        )
                    await self.captive_portal_service.activate_config(
                        actor_user_id=actor,
                        config_id=paused.id,
                        requesting_organization_id=customer.id,
                    )
                step.prior_state = {
                    "active_config_ids": prior_active,
                    "paused_config_id": str(paused.id),
                }
                step.status = "done"
            except Exception as exc:  # noqa: BLE001 -- best effort (A.7)
                step.status = "skipped"
                step.last_error = str(exc)[:500]
            step.attempts = 1

    # ------------------------------------------------------------------
    # resume
    # ------------------------------------------------------------------
    async def resume(
        self,
        isp_org_id: uuid.UUID,
        customer: Any,
        *,
        actor: uuid.UUID,
        note: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        await self._assert_isp_customer(isp_org_id, customer.id)
        state = await self._lock_state(isp_org_id, customer.id, actor)
        if state.state in (ACTIVE, RESUME_PENDING):
            return await self.view(customer)
        if state.state == SUSPEND_PENDING:
            await self._cancel_pending(state, "suspend")
        suspend_steps = [
            s for s in await self._steps(state) if s.transition == "suspend"
        ]
        state.state = RESUME_PENDING
        state.note = note or state.note
        state.requested_by = actor
        state.requested_at = self._clock()
        state.completed_at = None
        state.warnings = []
        state.idempotency_key = idempotency_key
        await self.session.flush()

        restored = 0
        for step in suspend_steps:
            if step.kind == "nas_disable" and step.nas_id is not None:
                await self._activate_one(isp_org_id, state, step, actor)
                restored += 1
            elif step.kind == "portal_suspended_page" and step.status == "done":
                await self._restore_portal(state, step, customer, actor)

        if self.organization_service is not None and customer.status == "suspended":
            await self.organization_service.activate_organization(
                actor_user_id=actor,
                organization_id=customer.id,
                requesting_organization_id=customer.id,
            )
        await self._finish(state, "resume")
        await self._audit(
            isp_org_id,
            actor,
            AUDIT_ISP_SERVICE_RESUMED,
            customer,
            state,
            nas_restored=restored,
        )
        response = await self.view(customer)
        state.idempotent_response = response
        await self.session.flush()
        return response

    async def _activate_one(self, isp_org_id, state, suspend_step, actor) -> None:
        nas = await self.session.get(RadiusNasClient, suspend_step.nas_id)
        if nas is None:
            return
        await self._assert_isp_customer(isp_org_id, nas.organization_id)
        was = (suspend_step.prior_state or {}).get("nas_status")
        if was == "active" and nas.status == "disabled":
            await self.radius_service.activate_nas(
                nas_id=nas.id,
                requesting_organization_id=nas.organization_id,
                actor_user_id=actor,
            )
            status, detail = "done", "NAS re-activated"
        else:
            status, detail = "skipped", f"left {nas.status} (was {was} before suspend)"
        step = await self._step(
            state,
            transition="resume",
            router_id=suspend_step.router_id,
            nas_id=nas.id,
            kind="nas_activate",
            status=status,
            detail=detail,
        )
        step.attempts = 1

    async def _restore_portal(self, state, suspend_step, customer, actor) -> None:
        step = await self._step(
            state,
            transition="resume",
            location_id=suspend_step.location_id,
            kind="portal_restore",
            status="pending",
        )
        prior = suspend_step.prior_state or {}
        try:
            async with self.session.begin_nested():
                if prior.get("paused_config_id"):
                    await self.captive_portal_service.deactivate_config(
                        actor_user_id=actor,
                        config_id=uuid.UUID(prior["paused_config_id"]),
                        requesting_organization_id=customer.id,
                    )
                for cid in prior.get("active_config_ids", []):
                    await self.captive_portal_service.activate_config(
                        actor_user_id=actor,
                        config_id=uuid.UUID(cid),
                        requesting_organization_id=customer.id,
                    )
            step.status = "done"
        except Exception as exc:  # noqa: BLE001 -- best effort
            step.status = "skipped"
            step.last_error = str(exc)[:500]
        step.attempts = 1

    # ------------------------------------------------------------------
    # new NAS while cut (A.4)
    # ------------------------------------------------------------------
    async def after_nas_registered(
        self, isp_org_id: uuid.UUID, router: Any, actor: uuid.UUID
    ) -> None:
        """A router added or re-registered while the customer is cut gets
        its NAS disabled at once, so it can never open a hole."""
        state = await self.get_state(router.organization_id)
        if state is None or state.state not in CUT_STATES:
            return
        await self._assert_isp_customer(isp_org_id, router.organization_id)
        for nas in await self._nas_rows(router.organization_id, router.id):
            if nas.status == "active":
                # prior is recorded as active so resume re-activates it
                await self._disable_one(isp_org_id, state, router, nas, actor)

    # ------------------------------------------------------------------
    # retries (lazy, "Retry now", and the E7 sweep)
    # ------------------------------------------------------------------
    async def retry(
        self,
        isp_org_id: uuid.UUID,
        customer_id: uuid.UUID,
        *,
        force: bool = False,
    ) -> bool:
        """Re-run pending kick steps. Returns True if anything ran."""
        state = await self.get_state(customer_id)
        if state is None or state.state not in (SUSPEND_PENDING, RESUME_PENDING):
            return False
        now = self._clock()
        if (
            not force
            and state.last_retry_at
            and now - state.last_retry_at < SERVICE_RETRY_MIN_INTERVAL
        ):
            return False
        if state.isp_organization_id != isp_org_id:
            raise IspScopeViolation(customer=str(customer_id))
        await self._assert_isp_customer(isp_org_id, customer_id)
        state.last_retry_at = now
        warnings: list[str] = list(state.warnings or [])
        for step in await self._steps(state):
            if step.status != "pending" or step.kind != "kick_sessions":
                continue
            router = (
                await self.session.get(Router, step.router_id)
                if step.router_id
                else None
            )
            if router is None or router.organization_id != customer_id:
                raise IspScopeViolation(step=str(step.id))
            await self._assert_isp_customer(isp_org_id, router.organization_id)
            if state.requested_at and now - state.requested_at > SERVICE_RETRY_GIVE_UP:
                step.status = "failed"
                warnings.append(
                    f"Router '{router.name}' unreachable: "
                    f"{len(step.prior_state.get('unconfirmed_session_ids', []))} live "
                    "sessions will end at their session timeout"
                )
                continue
            still: list[str] = []
            for sid in (step.prior_state or {}).get("unconfirmed_session_ids", []):
                row = await self.session.get(GuestSession, uuid.UUID(sid))
                if row is None or row.organization_id != customer_id:
                    raise IspScopeViolation(session=sid)
                result = (
                    await self.live_disconnect(row) if self.live_disconnect else False
                )
                if result is False:
                    still.append(sid)
            step.attempts = (step.attempts or 0) + 1
            step.prior_state = {
                **(step.prior_state or {}),
                "unconfirmed_session_ids": still,
            }
            if not still:
                step.status = "done"
                step.last_error = None
        state.warnings = warnings
        await self._finish(state, "suspend" if state.state in CUT_STATES else "resume")
        return True

    async def pending_customers(
        self, isp_org_id: uuid.UUID | None = None
    ) -> list[tuple]:
        """(isp, customer) pairs with retryable work, for the sweep."""
        q = select(
            IspCustomerServiceState.isp_organization_id,
            IspCustomerServiceState.customer_organization_id,
        ).where(
            IspCustomerServiceState.state.in_([SUSPEND_PENDING, RESUME_PENDING]),
            IspCustomerServiceState.is_deleted.is_(False),
        )
        if isp_org_id is not None:
            q = q.where(IspCustomerServiceState.isp_organization_id == isp_org_id)
        return [tuple(r) for r in (await self.session.execute(q)).all()]
