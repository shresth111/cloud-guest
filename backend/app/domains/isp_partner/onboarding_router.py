"""``/isp/onboarding``: the one-page "Add subscriber" (ONBOARD-1).

A thin orchestrator over the lane services, all called unchanged:

* JAZE-1 ``IspSubscriber360Service.onboard`` -- subscriber + profile (J2);
* JAZE-6 ``IspPppoeService.set_credential`` -- PPPoE login;
* JAZE-2 ``add_mac_binding`` / ``add_ip_binding`` route handlers -- MAC
  binds and static IPs;
* JAZE-3 ``compliance_kyc.upsert_kyc`` / ``assign_caf_number`` -- KYC + CAF;
* ``IspBillingService.issue_subscriber_invoice`` / ``record_payment`` -- the
  first invoice for the period ``create_subscriber`` just opened, and an
  optional same-transaction payment (``recharge`` is not used: it would
  extend the validity a second time).

**One transaction.** Every service above only flushes; the request session
(``get_db_session``) commits once at the end and rolls back on any error.
The JAZE-2 handlers call ``db.commit()`` themselves, so they get
``_FlushOnCommit`` (same session, ``commit`` = ``flush``). A failure in any
step raises ``IspOnboardStepError``: the original status, message and
``data.code`` plus ``data.step``, and nothing is left behind.

Router side effects cannot be rolled back, so the one that exists -- the
static-queue push, behind ``ISP_STATIC_QUEUE_PUSH`` (default OFF) -- runs
last, after every database step succeeded. While the flag is off a
static-queue request is recorded on the subscriber's timeline and nothing
is pushed.

Files (ID/address proofs, photo, signature, signed CAF, installation
report) are step 2: the UI uploads them to the existing JAZE-3 document
endpoint once this call has returned.

Not ``/isp/subscribers/onboard``: that path is JAZE-1's and stays as is.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.exceptions import CloudGuestError
from app.database.session import get_db_session
from app.domains.guest.dependencies import get_guest_service
from app.domains.queue_management.dependencies import get_queue_management_service
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import get_access_validator, get_rbac_repository
from app.domains.rbac.exceptions import PermissionDeniedError

from . import compliance_kyc as kyc_mod
from . import compliance_logic
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .enforcement_router import (
    IpBindingRequest,
    MacRequest,
    add_ip_binding,
    add_mac_binding,
)
from .exceptions import IspBadRequestError, IspError
from .finance_config import get_finance_settings
from .http import ok
from .plans_router import get_plans_service
from .plans_service import IspPlansService, _local_date, billing_balance
from .pppoe_config import get_isp_pppoe_settings
from .pppoe_router import PppoeCredentialBody
from .pppoe_service import IspPppoeService
from .subscriber360_router import OnboardBody
from .subscriber360_service import IspSubscriber360Service

__all__ = ["onboarding_router"]

logger = logging.getLogger(__name__)

onboarding_router = APIRouter(prefix="/onboarding", tags=["ISP Partner: onboarding"])

SUBS_UPDATE = "isp_subscribers.update"
KYC_UPDATE = "isp_partner.update"
INVOICES_CREATE = "isp_invoices.create"
BILLING_EXECUTE = "isp_billing.execute"
IST = ZoneInfo("Asia/Kolkata")
STAFF_PAYMENT_MODES = ("cash", "upi", "bank_transfer")
AUDIT_ONBOARDED = "isp_subscriber_onboarded"
_KYC_KEYS = frozenset(kyc_mod.KYC_FIELDS) | {"id_proof_type", "id_number", "verified"}


class IspOnboardSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    #: ISP_STATIC_QUEUE_PUSH: push a static IP's ``/queue simple`` row to the
    #: router at onboarding. OFF = record the request only.
    static_queue_push: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_onboard_settings() -> IspOnboardSettings:
    return IspOnboardSettings()


class IspOnboardStepError(IspError):
    """One onboarding step failed; the whole transaction is rolled back.
    Keeps the original status, message and ``data`` (so ``data.code`` maps
    to the same UI text as on the lane's own endpoint) and adds ``step``."""

    code = "ISP_ONBOARD_STEP_FAILED"

    def __init__(self, step: str, exc: BaseException) -> None:
        if isinstance(exc, CloudGuestError):
            message, status_code = exc.message, exc.status_code
            data = {**(exc.data or {})}
        elif isinstance(exc, HTTPException):
            message, status_code, data = str(exc.detail), exc.status_code, {}
        elif isinstance(exc, ValidationError | ValueError):
            message = str(exc).splitlines()[0][:255]
            status_code, data = status.HTTP_422_UNPROCESSABLE_ENTITY, {}
        else:
            message = "Unexpected error; nothing was saved"
            status_code, data = status.HTTP_500_INTERNAL_SERVER_ERROR, {}
        data.setdefault("code", self.code)
        CloudGuestError.__init__(
            self, message, status_code=status_code, data={**data, "step": step}
        )


class _FlushOnCommit:
    """The request session with ``commit`` turned into ``flush``: lets a
    route handler that commits run inside the onboarding transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def commit(self) -> None:
        await self._session.flush()

    def __contains__(self, item: object) -> bool:
        return item in self._session

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class StaticIpRow(_Body):
    isp_location_id: uuid.UUID
    pool_id: uuid.UUID
    ip: str | None = Field(default=None, max_length=45)
    mac: str | None = Field(default=None, max_length=32)
    static_queue: bool = False

    @field_validator("mac")
    @classmethod
    def _mac(cls, v: str | None) -> str | None:
        return None if not v else MacRequest(mac=v).mac


class CafChoice(_Body):
    mode: str = Field(pattern="^(auto|number)$")
    number: str | None = Field(default=None, max_length=40)


class OnboardPayment(_Body):
    mode: str = Field(default="cash", max_length=16)
    reference: str | None = Field(default=None, max_length=100)


class BillingChoice(_Body):
    issue_invoice: bool = False
    paid_now: bool = False
    payment: OnboardPayment | None = None


class OnboardingRequest(_Body):
    subscriber: OnboardBody
    pppoe: PppoeCredentialBody | None = None
    static_ips: list[StaticIpRow] = Field(default_factory=list, max_length=4)
    macs: list[str] = Field(default_factory=list, max_length=8)
    kyc: dict[str, Any] | None = None
    caf: CafChoice | None = None
    billing: BillingChoice | None = None

    @field_validator("macs")
    @classmethod
    def _macs(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            mac = MacRequest(mac=raw).mac
            if mac not in out:
                out.append(mac)
        return out

    @field_validator("kyc")
    @classmethod
    def _kyc(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return None
        unknown = sorted(set(v) - _KYC_KEYS)
        if unknown:
            raise ValueError(f"unknown KYC fields: {', '.join(unknown)}")
        return v


def get_subscriber360_service(
    plans: IspPlansService = Depends(get_plans_service),
    guest_service=Depends(get_guest_service),  # noqa: B008
) -> IspSubscriber360Service:
    return IspSubscriber360Service(plans=plans, guest_service=guest_service)


async def _held(isp: IspContext, av: AccessValidator) -> set[str]:
    from .router import effective_isp_permissions

    return set(await effective_isp_permissions(isp, av))


@onboarding_router.get("/options", dependencies=isp_guards(SUBS_UPDATE))
async def onboarding_options(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    """What the form may offer. Sections whose flag is off are hidden."""
    return ok(
        request,
        {
            "next_circuit_id": await svc.next_circuit_id(isp),
            "features": {
                "pppoe": get_isp_pppoe_settings().enabled,
                "static_ip": True,
                "static_queue_push": get_onboard_settings().static_queue_push,
                "kyc": True,
                "invoice_email": get_finance_settings().finance_extras_enabled,
            },
            "kyc": {
                "id_types": list(compliance_logic.ID_TYPES),
                "document_kinds": list(compliance_logic.DOCUMENT_KINDS),
            },
            "payment_modes": list(STAFF_PAYMENT_MODES),
        },
        "Onboarding options",
    )


@onboarding_router.post(
    "", status_code=status.HTTP_201_CREATED, dependencies=isp_guards(SUBS_UPDATE)
)
async def onboard(  # noqa: PLR0912, PLR0913, PLR0915 -- one step per lane
    request: Request,
    payload: OnboardingRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
    av: AccessValidator = Depends(get_access_validator),
    audit=Depends(get_rbac_repository),  # noqa: B008
    queue_service=Depends(get_queue_management_service),  # noqa: B008
) -> dict:
    held = await _held(isp, av)
    for wanted, key in (
        (payload.kyc is not None or payload.caf is not None, KYC_UPDATE),
        (bool(payload.billing and payload.billing.issue_invoice), INVOICES_CREATE),
        (bool(payload.billing and payload.billing.paid_now), BILLING_EXECUTE),
    ):
        if wanted and key not in held:
            raise PermissionDeniedError(key, "organization")
    if payload.pppoe is not None and not get_isp_pppoe_settings().enabled:
        raise IspOnboardStepError(
            "pppoe", IspBadRequestError("PPPoE is not switched on for this platform")
        )
    push = get_onboard_settings().static_queue_push
    steps: dict[str, dict[str, Any]] = {}
    current = "subscriber"

    def done(step: str, detail: str | None = None) -> None:
        steps[step] = {"step": step, "status": "done", "detail": detail}

    try:
        # 1. subscriber + profile (JAZE-1)
        sub_data = payload.subscriber.model_dump(exclude_unset=True)
        sub_data["profile"] = (
            payload.subscriber.profile.model_dump(exclude_unset=True)
            if payload.subscriber.profile
            else {}
        )
        created = await svc.onboard(isp, sub_data)
        sid = uuid.UUID(str(created["id"]))
        s = await svc.plans.subscriber(isp, sid)
        done("subscriber", f"circuit {s.circuit_id}")

        # 2. PPPoE (JAZE-6)
        pppoe_view = None
        if payload.pppoe is not None:
            current = "pppoe"
            pppoe_view = await IspPppoeService(session=db, audit=audit).set_credential(
                isp, sid, payload.pppoe.model_dump(exclude_unset=True)
            )
            done("pppoe", pppoe_view.get("username"))

        tx = _FlushOnCommit(db)

        # 3. MAC binds (JAZE-2)
        macs = []
        if payload.macs:
            current = "mac"
            for mac in payload.macs:
                res = await add_mac_binding(
                    request, sid, MacRequest(mac=mac), isp=isp, db=tx
                )
                macs.append(res["data"])
            done("mac", f"{len(macs)} bound")

        # 4. KYC + CAF (JAZE-3)
        kyc_view, caf_number = None, None
        if payload.kyc is not None or payload.caf is not None:
            current = "kyc"
            kyc = await kyc_mod.upsert_kyc(
                db,
                isp_org_id=isp.isp_org_id,
                subscriber_id=sid,
                body=payload.kyc or {},
                actor=isp.user_id,
            )
            done("kyc")
            if payload.caf is not None:
                current = "caf"
                custom = payload.caf.number if payload.caf.mode == "number" else None
                if payload.caf.mode == "number" and not custom:
                    raise IspBadRequestError("Give the CAF number", field="caf")
                caf_number = await kyc_mod.assign_caf_number(
                    db,
                    isp_org_id=isp.isp_org_id,
                    kyc=kyc,
                    custom=custom,
                    today=datetime.now(IST).date(),
                )
                done("caf", caf_number)
            kyc_view = kyc_mod.kyc_view(kyc, unmasked=False)

        # 5. first invoice + payment
        invoice_row, payment_row = None, None
        billing_req = payload.billing
        if billing_req is not None and billing_req.issue_invoice:
            current = "invoice"
            invoice_row, payment_row, detail = await _first_invoice(
                svc.plans, isp, s, created, billing_req
            )
            if invoice_row is None:
                steps["invoice"] = {
                    "step": "invoice",
                    "status": "skipped",
                    "detail": detail,
                }
            else:
                done("invoice", invoice_row.get("number"))
                if payment_row is not None:
                    done("payment", payment_row.get("receipt_number"))

        # 6. static IPs (JAZE-2) last: the only step that may touch a router
        ips, recorded = [], False
        if payload.static_ips:
            current = "static_ip"
            for row in payload.static_ips:
                res = await add_ip_binding(
                    request,
                    sid,
                    IpBindingRequest(
                        isp_location_id=row.isp_location_id,
                        pool_id=row.pool_id,
                        ip=row.ip or None,
                        mac=row.mac,
                        static_queue=row.static_queue and push,
                    ),
                    isp=isp,
                    db=tx,
                    queue_service=queue_service,
                )
                ips.append(res["data"])
                if row.static_queue and not push:
                    recorded = True
                    await svc.event(
                        isp,
                        s,
                        "note",
                        f"Static queue requested for {res['data']['ip']} "
                        "(recorded; router push is off)",
                        ip=res["data"]["ip"],
                    )
            done("static_ip", ", ".join(x["ip"] for x in ips))

        current = "subscriber"
        await audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=AUDIT_ONBOARDED,
            entity_type="isp_subscriber",
            entity_id=sid,
            description="Subscriber onboarded",
            event_metadata={
                "console": "isp",
                "steps": sorted(k for k, v in steps.items() if v["status"] == "done"),
            },
            organization_id=s.customer_organization_id,
            location_id=None,
        )
        view = await svc.view_360(isp, sid)
        view["welcome"] = created.get("welcome")
        await db.commit()
    except PermissionDeniedError:
        raise
    except IspOnboardStepError:
        raise
    except Exception as exc:  # noqa: BLE001 -- re-raised with the step
        if not isinstance(exc, CloudGuestError | HTTPException | ValueError):
            logger.exception("isp_onboard_step_failed", extra={"step": current})
        raise IspOnboardStepError(current, exc) from exc

    order = (
        "subscriber",
        "pppoe",
        "static_ip",
        "mac",
        "kyc",
        "caf",
        "invoice",
        "payment",
    )
    return ok(
        request,
        {
            "subscriber": view,
            "pppoe": pppoe_view,
            "static_ips": ips,
            "macs": macs,
            "kyc": kyc_view,
            "caf_number": caf_number,
            "invoice": invoice_row,
            "payment": payment_row,
            "static_queue_recorded": recorded,
            "steps": [
                steps.get(k, {"step": k, "status": "skipped", "detail": None})
                for k in order
            ],
        },
        "Subscriber added",
    )


async def _first_invoice(
    plans: IspPlansService,
    isp: IspContext,
    s: Any,
    created: dict,
    req: BillingChoice,
) -> tuple[dict | None, dict | None, str | None]:
    """Bill the period ``create_subscriber`` opened, at the override price
    when the profile has one. A free package gets no invoice (skipped)."""
    from .billing_service import REFERENCE_REQUIRED, IspPaymentReferenceRequiredError

    package = await plans.package(isp, s.package_id)
    override = (created.get("profile") or {}).get("override_price_paise")
    price = override if override is not None else package.price_paise
    if not price or price <= 0:
        return None, None, "free package, nothing to bill"
    pay = req.payment or OnboardPayment()
    if req.paid_now:
        if pay.mode not in STAFF_PAYMENT_MODES:
            raise IspBadRequestError("Pick cash, UPI or bank transfer", field="mode")
        if pay.mode in REFERENCE_REQUIRED and not (pay.reference or "").strip():
            raise IspPaymentReferenceRequiredError()
    tz = isp.organization.timezone or "Asia/Kolkata"
    end = s.valid_until
    start = end - timedelta(days=package.validity_days)
    billing = plans._billing()
    inv = await billing.issue_subscriber_invoice(
        isp,
        s,
        lines=[
            {
                "description": package.name,
                "amount_paise": int(price),
                "price_includes_gst": package.price_includes_gst,
                "period_from": _local_date(start, tz),
                "period_to": _local_date(end, tz),
                "package_id": package.id,
            }
        ],
        invoice_kind="recharge",
        period_start=_local_date(start, tz),
        period_end=_local_date(end, tz),
        description=package.name,
        source_key=f"onboard:{s.id}",
    )
    payment = None
    if req.paid_now and billing_balance(inv) > 0:
        payment = await billing.record_payment(
            isp,
            subscriber_id=s.id,
            invoice_id=inv.id,
            amount_paise=billing_balance(inv),
            mode=pay.mode,
            reference=pay.reference,
            received_at=None,
            idempotency_key=f"onboard:{s.id}",
        )
    subs, packages = await billing.row_extras([inv])
    row = billing.invoice_row(
        inv, subscriber=subs.get(inv.id), package=packages.get(inv.id)
    )
    return row, (billing.payment_row(payment) if payment is not None else None), None
