"""ADDENDUM_04 §2: paid add-ons for ISP customers.

Two layers, both new code that calls the EXISTING add-on machinery:

* **Master** sets, per ISP, which add-ons the ISP may switch on for its
  customers, with an optional cap (``isp_addon_allowances``). Routes:
  ``GET/PUT /platform/isp-partners/{isp_partner_id}/addon-allowances``, pinned
  ``organizations.read`` / ``organizations.manage`` at GLOBAL -- the same keys
  and pin as every other Master ISP route (STATUS D5, ``platform_router``).
* **The ISP** switches an allowed add-on on or off for ONE customer:
  ``PUT /isp/customers/{isp_customer_id}/addons/{feature_key}``
  (``isp_partner.manage``). It calls ``AddonService.set_addon`` -- the same
  method behind ``/platform/organizations/{id}/addons/{key}`` -- so the
  ``OrganizationFeatureOverride`` row, the audit entry, the campaign
  cancellation on lock and the entitlement-cache invalidation are exactly the
  Master panel's, and Master's panel shows the result.

Rules:

* Turning an add-on OFF is always allowed (it can only reduce what a customer
  gets). Turning it ON needs the allowance: not allowed -> 403
  ``ISP_ADDON_NOT_ALLOWED``; at the cap -> 409 ``ISP_ADDON_LIMIT``.
* No allowance rows = ``ISP_PARTNER_ADDON_DEFAULT_ALLOWANCE`` (``none`` until
  founder F1 is answered; ``all`` = every add-on, no cap).
* ``guest_marketing_byo`` is an ordinary allowance row. WHOSE sender a
  customer uses (the ISP-level one or its own) is F3, in ``parity_settings``.
* F1: each allowance row may carry ``price_per_customer_paise`` -- a record
  of the agreed price; nothing bills from it (the ISP pays Wyfy in cash).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.billing.constants import ADDON_FEATURE_KEYS
from app.domains.billing.models import OrganizationFeatureOverride
from app.domains.feature_entitlement.addons import AddonService, AddonView
from app.domains.feature_entitlement.dependencies import get_addon_service
from app.domains.rbac.dependencies import CurrentUser, RequirePermission
from app.domains.rbac.enums import ScopeType

from .addon_models import IspAddonAllowance
from .constants import ISP_PARTNER_MANAGE, ISP_PARTNER_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspError, IspPartnerNotFoundError
from .http import ok
from .models import IspPartnerProfile
from .policy import get_isp_partner_policy
from .scoping import IspScope

__all__ = [
    "IspAddonLimitError",
    "IspAddonNotAllowedError",
    "addon_platform_router",
    "isp_addons_router",
    "resolve_allowances",
]

ADDON_KEYS: tuple[str, ...] = tuple(sorted(k.value for k in ADDON_FEATURE_KEYS))


class IspAddonNotAllowedError(IspError):
    code = "ISP_ADDON_NOT_ALLOWED"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = "This add-on is not enabled for your ISP account. Ask Wyfy."


class IspAddonLimitError(IspError):
    code = "ISP_ADDON_LIMIT"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = (
        "You have switched this add-on on for as many customers as allowed."
    )


class IspAddonUnknownError(IspError):
    code = "ISP_ADDON_UNKNOWN"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "Not an add-on"


def _require_key(feature_key: str) -> str:
    if feature_key not in ADDON_KEYS:
        raise IspAddonUnknownError()
    return feature_key


# ---------------------------------------------------------------------------
# Allowance resolution (pure-ish: rows in, dict out)
# ---------------------------------------------------------------------------


def resolve_allowances(rows: list[Any]) -> dict[str, dict[str, Any]]:
    """``{key: {"allowed": bool, "max_customers": int|None, "source": str}}``.

    With no rows at all the policy default applies to every key; once Master
    has saved any row for this ISP, keys without a row are not allowed.
    """
    policy = get_isp_partner_policy()
    by_key = {r.feature_key: r for r in rows}
    out: dict[str, dict[str, Any]] = {}
    for key in ADDON_KEYS:
        row = by_key.get(key)
        if row is not None:
            out[key] = {
                "allowed": bool(row.enabled),
                "max_customers": row.max_customers,
                "price_per_customer_paise": getattr(
                    row, "price_per_customer_paise", None
                ),
                "source": "master",
            }
        elif not rows and policy.addon_default_allowance == "all":
            out[key] = {
                "allowed": True,
                "max_customers": None,
                "price_per_customer_paise": None,
                "source": "default",
            }
        else:
            out[key] = {
                "allowed": False,
                "max_customers": None,
                "price_per_customer_paise": None,
                "source": "default",
            }
    return out


async def _allowance_rows(db: AsyncSession, isp_org_id: uuid.UUID) -> list[Any]:
    return list(
        (
            await db.execute(
                select(IspAddonAllowance).where(
                    IspAddonAllowance.isp_organization_id == isp_org_id,
                    IspAddonAllowance.is_deleted.is_(False),
                )
            )
        ).scalars()
    )


async def _enabled_count(
    db: AsyncSession, customer_ids: list[uuid.UUID], key: str
) -> int:
    if not customer_ids:
        return 0
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(OrganizationFeatureOverride)
                .where(
                    OrganizationFeatureOverride.organization_id.in_(customer_ids),
                    OrganizationFeatureOverride.feature_key == key,
                    OrganizationFeatureOverride.is_enabled.is_(True),
                    OrganizationFeatureOverride.is_deleted.is_(False),
                )
            )
        ).scalar_one()
    )


def _view(view: AddonView) -> dict[str, Any]:
    return {
        "key": view.key,
        "name": view.name,
        "description": view.description,
        "enabled": view.enabled,
        "source": view.source,
        "blocked_by": view.blocked_by,
    }


# ---------------------------------------------------------------------------
# ISP routes
# ---------------------------------------------------------------------------

isp_addons_router = APIRouter(tags=["ISP Partner: add-ons"])


@isp_addons_router.get("/addons", dependencies=isp_guards(ISP_PARTNER_READ))
async def get_my_addon_allowance(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
):
    """What Wyfy allows this ISP to switch on for its customers."""
    allowances = resolve_allowances(await _allowance_rows(db, isp.isp_org_id))
    children = await isp.repository.child_ids(isp.isp_org_id)
    items = []
    for key, a in allowances.items():
        items.append(
            {
                "key": key,
                **a,
                "enabled_customers": await _enabled_count(db, children, key),
            }
        )
    return ok(request, {"items": items})


@isp_addons_router.get(
    "/customers/{isp_customer_id}/addons", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def list_customer_addons(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    service: AddonService = Depends(get_addon_service),
):
    customer = await IspScope.assert_customer(isp, isp_customer_id)
    allowances = resolve_allowances(await _allowance_rows(db, isp.isp_org_id))
    views = await service.list_addons(customer.id)
    items = [{**_view(v), "allowed": allowances[v.key]["allowed"]} for v in views]
    return ok(request, {"isp_customer_id": str(customer.id), "items": items})


class IspAddonToggleRequest(BaseModel):
    enabled: bool


@isp_addons_router.put(
    "/customers/{isp_customer_id}/addons/{feature_key}",
    dependencies=isp_guards(ISP_PARTNER_MANAGE),
)
async def set_customer_addon(
    request: Request,
    isp_customer_id: uuid.UUID,
    feature_key: str,
    payload: IspAddonToggleRequest,
    isp: IspContext = Depends(RequireIspPartner),
    actor: AuthUser = Depends(CurrentUser),
    db: AsyncSession = Depends(get_db_session),
    service: AddonService = Depends(get_addon_service),
):
    key = _require_key(feature_key)
    customer = await IspScope.assert_customer(isp, isp_customer_id)
    if payload.enabled:
        allowance = resolve_allowances(await _allowance_rows(db, isp.isp_org_id))[key]
        if not allowance["allowed"]:
            raise IspAddonNotAllowedError()
        cap = allowance["max_customers"]
        if cap is not None:
            # All of this ISP's customers, not only the caller's confined set:
            # the cap is the ISP's, whoever switches it on.
            children = await isp.repository.child_ids(isp.isp_org_id)
            others = [c for c in children if c != customer.id]
            if await _enabled_count(db, others, key) >= cap:
                raise IspAddonLimitError()
    view, cancelled = await service.set_addon(
        customer.id,
        key,
        enabled=payload.enabled,
        reason=f"Set by ISP partner {isp.organization.name}",
        actor_user_id=uuid.UUID(str(actor.id)),
    )
    return ok(request, {"addon": _view(view), "cancelled_campaign_count": cancelled})


# ---------------------------------------------------------------------------
# Master routes (GLOBAL-pinned), mounted under /platform/isp-partners
# ---------------------------------------------------------------------------

addon_platform_router = APIRouter(tags=["ISP Partners (Master): add-ons"])


async def _require_isp(db: AsyncSession, isp_partner_id: uuid.UUID) -> None:
    found = (
        await db.execute(
            select(IspPartnerProfile.id).where(
                IspPartnerProfile.organization_id == isp_partner_id,
                IspPartnerProfile.is_deleted.is_(False),
            )
        )
    ).first()
    if found is None:
        raise IspPartnerNotFoundError()


@addon_platform_router.get(
    "/{isp_partner_id}/addon-allowances",
    dependencies=[
        Depends(RequirePermission("organizations.read", scope=ScopeType.GLOBAL))
    ],
)
async def get_isp_addon_allowances(
    request: Request,
    isp_partner_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
):
    await _require_isp(db, isp_partner_id)
    allowances = resolve_allowances(await _allowance_rows(db, isp_partner_id))
    return ok(
        request,
        {
            "isp_partner_id": str(isp_partner_id),
            "default_allowance": get_isp_partner_policy().addon_default_allowance,
            "items": [{"key": k, **v} for k, v in allowances.items()],
        },
    )


class AddonAllowanceItem(BaseModel):
    key: str
    enabled: bool
    max_customers: int | None = Field(default=None, ge=0)
    #: F1: agreed price per customer per month (paise). A record only.
    price_per_customer_paise: int | None = Field(default=None, ge=0)


class AddonAllowanceUpdateRequest(BaseModel):
    items: list[AddonAllowanceItem]


@addon_platform_router.put(
    "/{isp_partner_id}/addon-allowances",
    dependencies=[
        Depends(RequirePermission("organizations.manage", scope=ScopeType.GLOBAL))
    ],
)
async def set_isp_addon_allowances(
    request: Request,
    isp_partner_id: uuid.UUID,
    payload: AddonAllowanceUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    db: AsyncSession = Depends(get_db_session),
):
    """Replace this ISP's allowance rows. Never touches a customer's current
    overrides: lowering an allowance stops NEW switch-ons, it does not lock
    customers who already have the add-on (Master's own panel does that)."""
    await _require_isp(db, isp_partner_id)
    existing = {r.feature_key: r for r in await _allowance_rows(db, isp_partner_id)}
    actor_id = uuid.UUID(str(actor.id))
    for item in payload.items:
        key = _require_key(item.key)
        row = existing.get(key)
        if row is None:
            db.add(
                IspAddonAllowance(
                    isp_organization_id=isp_partner_id,
                    feature_key=key,
                    enabled=item.enabled,
                    max_customers=item.max_customers,
                    price_per_customer_paise=item.price_per_customer_paise,
                    created_by=actor_id,
                    updated_by=actor_id,
                )
            )
        else:
            row.enabled = item.enabled
            row.max_customers = item.max_customers
            row.price_per_customer_paise = item.price_per_customer_paise
            row.updated_by = actor_id
    from app.domains.rbac.models import AuditLogEntry

    db.add(
        AuditLogEntry(
            actor_user_id=actor_id,
            action="isp_addon_allowance_set",
            entity_type="isp_partner",
            entity_id=isp_partner_id,
            organization_id=isp_partner_id,
            description="ISP add-on allowance updated",
            event_metadata={"items": [i.model_dump() for i in payload.items]},
        )
    )
    await db.commit()
    allowances = resolve_allowances(await _allowance_rows(db, isp_partner_id))
    return ok(
        request,
        {
            "isp_partner_id": str(isp_partner_id),
            "items": [{"key": k, **v} for k, v in allowances.items()],
        },
    )
