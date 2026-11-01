"""``/isp`` Subscriber 360 / onboarding / directory / plan sync
(ADDENDUM_05 JAZE-1: J1, J2, J11, J19).

Same guard stack as every ``/isp`` route (``isp_guards``: flag, ISP role,
keys pinned ORGANIZATION on the ISP org). Ids are ``subscriber_id``,
``package_id``, ``speed_group_id``, ``isp_customer_id`` -- none is a
scope-alias name. Every subscriber goes through ``IspPlansService
.subscriber`` (other ISP or outside the caller's confinement -> 404).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.domains.guest.dependencies import get_guest_service
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import get_access_validator
from app.domains.rbac.exceptions import PermissionDeniedError

from .constants import (
    DEFAULT_PAGE_SIZE,
    ISP_SUBSCRIBERS_DISCONNECT,  # RBAC-FIX
    MAX_PAGE_SIZE,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .plans_router import (
    BILLING_EXECUTE,
    INVOICES_CREATE,
    SUBS_READ,
    SUBS_UPDATE,
    RechargePayment,
    SubscriberRequest,
    get_plans_service,
)
from .plans_service import IspPlansService
from .subscriber360_service import DISPLAY_STATES, IspSubscriber360Service

subscriber360_router = APIRouter(tags=["ISP Partner: subscriber 360"])

SUBS_MANAGE = "isp_subscribers.manage"
INVOICES_MANAGE = "isp_invoices.manage"

_STATE_PATTERN = "^(" + "|".join(DISPLAY_STATES) + ")$"


def get_subscriber360_service(
    plans: IspPlansService = Depends(get_plans_service),
    guest_service=Depends(get_guest_service),  # noqa: B008
) -> IspSubscriber360Service:
    return IspSubscriber360Service(plans=plans, guest_service=guest_service)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ProfileBody(_Body):
    alt_email: str | None = Field(default=None, max_length=255)
    gender: str | None = Field(
        default=None, pattern="^(male|female|other|undisclosed)$"
    )
    billing_city: str | None = Field(default=None, max_length=100)
    billing_pincode: str | None = Field(default=None, max_length=10)
    install_same_as_billing: bool | None = None
    install_address: str | None = Field(default=None, max_length=1000)
    install_area: str | None = Field(default=None, max_length=120)
    install_building: str | None = Field(default=None, max_length=120)
    install_city: str | None = Field(default=None, max_length=100)
    install_pincode: str | None = Field(default=None, max_length=10)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    installed_at: datetime | None = None
    user_type: str | None = Field(default=None, pattern="^(home|commercial|sme)$")
    connection_type: str | None = Field(
        default=None, pattern="^(fiber|wireless|ethernet|other)$"
    )
    ont_serial: str | None = Field(default=None, max_length=64)
    stb_serial: str | None = Field(default=None, max_length=64)
    override_price_paise: int | None = Field(default=None, ge=1, le=100_000_000)
    billing_anchor_day: int | None = Field(default=None, ge=1, le=28)
    after_due_action: str | None = Field(
        default=None, pattern="^(suspend|keep_active|disconnect_once)$"
    )
    exclude_reminders: bool | None = None
    activation_at: datetime | None = None
    comments: str | None = Field(default=None, max_length=4000)


class OnboardBody(SubscriberRequest):
    profile: ProfileBody | None = None
    welcome_whatsapp: bool = False


class RenewBody(_Body):
    package_id: uuid.UUID | None = None
    paid_now: bool = False
    payment: RechargePayment | None = None
    po_number: str | None = Field(default=None, max_length=40)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=64)
    # BILL-2: renew for N cycles in one invoice (ISP_BILL2_ENABLED; 1 = as before).
    cycles: int = Field(default=1, ge=1, le=12)


class ReasonBody(_Body):
    reason: str = Field(min_length=3, max_length=255)


class OptionalReasonBody(_Body):
    reason: str | None = Field(default=None, max_length=255)


class BlockBody(_Body):
    kind: str = Field(default="temporary", pattern="^(temporary|permanent)$")
    reason: str | None = Field(default=None, max_length=255)


class GraceBody(_Body):
    hours: int = Field(default=24, ge=1, le=168)
    note: str | None = Field(default=None, max_length=255)


class NoteBody(_Body):
    body: str = Field(min_length=1, max_length=4000)
    subject: str | None = Field(default=None, max_length=200)
    ticket_type: str | None = Field(
        default=None,
        pattern="^(slow_speed|no_connection|frequent_disconnection|billing|other)$",
    )
    source: str | None = Field(
        default=None, pattern="^(phone|whatsapp|walk_in|email|field|other)$"
    )
    close_after_raising: bool = False


class MoveBody(_Body):
    isp_customer_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=255)


class PlanSyncBody(_Body):
    dry_run: bool = True
    live_push: bool = True
    kick_online: bool = False


async def _require(isp: IspContext, av: AccessValidator, key: str) -> None:
    from .router import effective_isp_permissions

    if key not in await effective_isp_permissions(isp, av):
        raise PermissionDeniedError(key, "organization")


# -- read ---------------------------------------------------------------------


@subscriber360_router.get("/subscribers/directory", dependencies=isp_guards(SUBS_READ))
async def subscriber_directory(
    request: Request,
    state: str | None = Query(default=None, pattern=_STATE_PATTERN),
    search: str | None = Query(default=None, max_length=100),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    package_id: uuid.UUID | None = Query(default=None),
    zone_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    data = await svc.directory(
        isp,
        state=state,
        search=search,
        isp_customer_id=isp_customer_id,
        package_id=package_id,
        zone_id=zone_id,
        page=page,
        page_size=page_size,
    )
    return ok(request, data, "Subscribers")


@subscriber360_router.get("/subscribers/typeahead", dependencies=isp_guards(SUBS_READ))
async def subscriber_typeahead(
    request: Request,
    q: str = Query(min_length=2, max_length=100),
    limit: int = Query(default=10, ge=1, le=25),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    return ok(request, await svc.typeahead(isp, q, limit), "Matches")


@subscriber360_router.get(
    "/subscribers/circuit-id/next", dependencies=isp_guards(SUBS_READ)
)
async def next_circuit_id(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    return ok(
        request,
        {"next_circuit_id": await svc.next_circuit_id(isp), "reserved": False},
        "Next free circuit id",
    )


@subscriber360_router.get(
    "/subscribers/{subscriber_id}/360", dependencies=isp_guards(SUBS_READ)
)
async def subscriber_360(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    return ok(request, await svc.view_360(isp, subscriber_id), "Subscriber")


@subscriber360_router.get(
    "/subscribers/{subscriber_id}/ledger", dependencies=isp_guards(SUBS_READ)
)
async def subscriber_ledger(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    return ok(request, await svc.ledger(isp, subscriber_id), "Ledger")


@subscriber360_router.get(
    "/subscribers/{subscriber_id}/profile", dependencies=isp_guards(SUBS_READ)
)
async def get_subscriber_profile(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    s = await svc.plans.subscriber(isp, subscriber_id)
    return ok(request, svc.profile_view(await svc.profile(s)), "Profile")


# -- write (update) -----------------------------------------------------------


@subscriber360_router.put(
    "/subscribers/{subscriber_id}/profile", dependencies=isp_guards(SUBS_UPDATE)
)
async def put_subscriber_profile(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: ProfileBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    data = payload.model_dump(exclude_unset=True)
    return ok(request, await svc.put_profile(isp, subscriber_id, data), "Saved")


@subscriber360_router.post(
    "/subscribers/onboard", status_code=201, dependencies=isp_guards(SUBS_UPDATE)
)
async def onboard_subscriber(
    request: Request,
    payload: OnboardBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    data = payload.model_dump(exclude_unset=True)
    data["profile"] = (
        payload.profile.model_dump(exclude_unset=True) if payload.profile else {}
    )
    return ok(request, await svc.onboard(isp, data), "Subscriber created")


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/disconnect",
    dependencies=isp_guards(ISP_SUBSCRIBERS_DISCONNECT),
)
async def disconnect_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    return ok(request, await svc.disconnect(isp, subscriber_id), "Disconnected")


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/grace", dependencies=isp_guards(SUBS_UPDATE)
)
async def grace_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: GraceBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    r = await svc.grace(isp, subscriber_id, hours=payload.hours, note=payload.note)
    return ok(request, r, "Grace granted")


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/block", dependencies=isp_guards(SUBS_UPDATE)
)
async def block_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: BlockBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    if payload.kind == "permanent":
        await _require(isp, av, SUBS_MANAGE)
    r = await svc.block(isp, subscriber_id, kind=payload.kind, reason=payload.reason)
    return ok(request, r, "Blocked")


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/unblock", dependencies=isp_guards(SUBS_UPDATE)
)
async def unblock_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    await svc.unblock(isp, subscriber_id)
    return ok(request, await svc.view_360(isp, subscriber_id), "Unblocked")


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/freeze", dependencies=isp_guards(SUBS_UPDATE)
)
async def freeze_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: OptionalReasonBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    return ok(
        request, await svc.freeze(isp, subscriber_id, reason=payload.reason), "Frozen"
    )


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/unfreeze", dependencies=isp_guards(SUBS_UPDATE)
)
async def unfreeze_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    await svc.unfreeze(isp, subscriber_id)
    return ok(request, await svc.view_360(isp, subscriber_id), "Unfrozen")


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/notes",
    status_code=201,
    dependencies=isp_guards(SUBS_UPDATE),
)
async def add_subscriber_note(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: NoteBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    return ok(
        request, await svc.add_note(isp, subscriber_id, payload.model_dump()), "Saved"
    )


# -- money --------------------------------------------------------------------


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/renew",
    status_code=201,
    dependencies=isp_guards(INVOICES_CREATE),
)
async def renew_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: RenewBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    """Recharge with the profile's override price; ``paid_now`` also needs
    ``isp_billing.execute`` (same rule as ``/recharge``)."""
    if payload.paid_now:
        await _require(isp, av, BILLING_EXECUTE)
    data = payload.model_dump(exclude_none=True)
    data["payment"] = payload.payment.model_dump() if payload.payment else None
    return ok(request, await svc.renew(isp, subscriber_id, data), "Renewed")


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/revert", dependencies=isp_guards(INVOICES_MANAGE)
)
async def revert_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: ReasonBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    return ok(
        request, await svc.revert(isp, subscriber_id, reason=payload.reason), "Reverted"
    )


# -- manage ---------------------------------------------------------------------


@subscriber360_router.post(
    "/subscribers/{subscriber_id}/move", dependencies=isp_guards(SUBS_MANAGE)
)
async def move_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: MoveBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    r = await svc.move(
        isp,
        subscriber_id,
        isp_customer_id=payload.isp_customer_id,
        reason=payload.reason,
    )
    return ok(request, r, "Moved")


@subscriber360_router.post(
    "/packages/{package_id}/apply-to-subscribers",
    dependencies=isp_guards(SUBS_READ),
)
async def package_plan_sync(
    request: Request,
    package_id: uuid.UUID,
    payload: PlanSyncBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    """Dry run needs read; applying needs ``isp_subscribers.manage``."""
    if not payload.dry_run:
        await _require(isp, av, SUBS_MANAGE)
    r = await svc.plan_sync(isp, package_id=package_id, **payload.model_dump())
    return ok(request, r, "Dry run" if payload.dry_run else "Applied")


@subscriber360_router.post(
    "/speed-groups/{speed_group_id}/apply-to-subscribers",
    dependencies=isp_guards(SUBS_READ),
)
async def group_plan_sync(
    request: Request,
    speed_group_id: uuid.UUID,
    payload: PlanSyncBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    if not payload.dry_run:
        await _require(isp, av, SUBS_MANAGE)
    r = await svc.plan_sync(isp, speed_group_id=speed_group_id, **payload.model_dump())
    return ok(request, r, "Dry run" if payload.dry_run else "Applied")


__all__ = ["subscriber360_router"]
