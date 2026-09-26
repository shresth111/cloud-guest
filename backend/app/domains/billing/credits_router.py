"""Routes for prepaid credits -- contract §13.6 / §13.7.

Two routers, both mounted from ``app/api/v1/router.py``:

* ``customer_router`` (``/marketing/credits``) -- the org's own balance and
  ledger. Lives in the billing domain (the ledger is billing's), so the
  marketing router is untouched. Guards, in order: ``RequireOrganization``,
  ``RequireFeature(GUEST_MARKETING)`` (402 before any permission or data
  work, like every ``/marketing`` route), then a pinned permission:

  - balance: ``marketing.read`` @LOCATION -- location staff see the balance
    so they know whether a send will go through (§13.6);
  - ledger: ``billing.read`` @ORGANIZATION -- financial history follows the
    billing grant, so location-scoped staff get 403 ``permission_denied``.

  The organization is always ``RequireOrganization``'s, never a parameter.

* ``platform_router`` (``/platform/organizations/{organization_id}/credits``)
  -- Master. Every route pins ``scope=ScopeType.GLOBAL``, which is what makes
  taking the organization from the path safe: an organization- or MSP-scoped
  holder of ``billing.manage`` is refused before the handler runs.
  ``enforce_target_organization`` is applied as well, so the handler never
  acts on a path organization that differs from the one the request was
  authorized against, whatever the scope resolver does in future.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.scoping import enforce_target_organization
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .constants import PlanFeatureKey
from .credits_constants import CreditEntryType
from .credits_dependencies import get_credits_service
from .credits_exceptions import CreditsOrganizationNotFoundError
from .credits_schemas import CreditAdjustmentCreate, CreditSettingsUpdate
from .credits_service import AdjustmentRequest, CreditsService
from .dependencies import RequireFeature
from .exceptions import BillingError

customer_router = APIRouter(prefix="/marketing/credits", tags=["Marketing credits"])
platform_router = APIRouter(
    prefix="/platform/organizations", tags=["Platform Marketing credits"]
)


def _rid(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _ok(request: Request, message: str, data: Any) -> dict[str, Any]:
    return build_response(
        success=True, message=message, data=data, request_id=_rid(request)
    )


def _page(items: list[Any], meta: PaginationMeta) -> dict[str, Any]:
    return {
        "items": items,
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


class _InvalidLedgerFilterError(BillingError):
    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            data={"error_code": "validation_error"},
        )


def _ledger_filters(
    entry_type: str | None,
    campaign_id: uuid.UUID | None,
    date_from: date | None,
    date_to: date | None,
    detail: str | None,
    page: int,
    page_size: int,
) -> dict[str, Any]:
    types: list[str] | None = None
    if entry_type:
        types = [part.strip() for part in entry_type.split(",") if part.strip()]
        valid = {member.value for member in CreditEntryType}
        unknown = sorted(set(types) - valid)
        if unknown:
            raise _InvalidLedgerFilterError(f"Unknown entry_type: {', '.join(unknown)}")
    if detail not in (None, "recipients"):
        raise _InvalidLedgerFilterError("detail must be 'recipients' when given")
    if date_from and date_to and date_from > date_to:
        raise _InvalidLedgerFilterError("from must not be after to")
    return {
        "entry_types": types,
        "campaign_id": campaign_id,
        "date_from": date_from,
        "date_to": date_to,
        "detail_recipients": detail == "recipients",
        "page": page,
        "page_size": page_size,
    }


def _customer_guards(permission: str, scope: ScopeType) -> list[Any]:
    return [
        Depends(RequireOrganization),
        Depends(RequireFeature(PlanFeatureKey.GUEST_MARKETING)),
        Depends(RequirePermission(permission, scope=scope)),
    ]


# ============================================================================
# Customer
# ============================================================================


@customer_router.get(
    "",
    response_model=ApiResponse[dict],
    dependencies=_customer_guards("marketing.read", ScopeType.LOCATION),
)
async def get_marketing_credits(
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: CreditsService = Depends(get_credits_service),
):
    return _ok(
        request, "Marketing credits", await service.customer_balance(organization_id)
    )


@customer_router.get(
    "/ledger",
    response_model=ApiResponse[dict],
    dependencies=_customer_guards("billing.read", ScopeType.ORGANIZATION),
)
async def list_marketing_credit_ledger(
    request: Request,
    entry_type: str | None = Query(default=None, max_length=100),
    campaign_id: uuid.UUID | None = Query(default=None),
    date_from: date | None = Query(default=None, alias="from"),
    date_to: date | None = Query(default=None, alias="to"),
    detail: str | None = Query(default=None, max_length=20),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: CreditsService = Depends(get_credits_service),
):
    items, meta = await service.list_ledger(
        organization_id,
        **_ledger_filters(
            entry_type, campaign_id, date_from, date_to, detail, page, page_size
        ),
    )
    return _ok(request, "Credit ledger", _page(items, meta))


# ============================================================================
# Master (platform)
# ============================================================================


async def _target_organization(
    organization_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
) -> uuid.UUID:
    try:
        await enforce_target_organization(
            target_organization_id=organization_id,
            requesting_organization_id=requesting_organization_id,
            organization_service=organization_service,
        )
    except OrganizationNotFoundError as exc:
        raise CreditsOrganizationNotFoundError(organization_id) from exc
    return organization_id


@platform_router.get(
    "/{organization_id}/credits",
    response_model=ApiResponse[dict],
    dependencies=[Depends(RequirePermission("billing.read", scope=ScopeType.GLOBAL))],
)
async def get_organization_credits(
    request: Request,
    organization_id: uuid.UUID = Depends(_target_organization),
    service: CreditsService = Depends(get_credits_service),
):
    return _ok(
        request,
        "Organization credits",
        await service.master_summary(organization_id),
    )


@platform_router.get(
    "/{organization_id}/credits/ledger",
    response_model=ApiResponse[dict],
    dependencies=[Depends(RequirePermission("billing.read", scope=ScopeType.GLOBAL))],
)
async def list_organization_credit_ledger(
    request: Request,
    entry_type: str | None = Query(default=None, max_length=100),
    campaign_id: uuid.UUID | None = Query(default=None),
    date_from: date | None = Query(default=None, alias="from"),
    date_to: date | None = Query(default=None, alias="to"),
    detail: str | None = Query(default=None, max_length=20),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    organization_id: uuid.UUID = Depends(_target_organization),
    service: CreditsService = Depends(get_credits_service),
):
    items, meta = await service.master_ledger(
        organization_id,
        **_ledger_filters(
            entry_type, campaign_id, date_from, date_to, detail, page, page_size
        ),
    )
    return _ok(request, "Credit ledger", _page(items, meta))


@platform_router.post(
    "/{organization_id}/credits/adjustments",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def post_organization_credit_adjustment(
    request: Request,
    body: CreditAdjustmentCreate,
    organization_id: uuid.UUID = Depends(_target_organization),
    user: AuthUser = Depends(CurrentUser),
    service: CreditsService = Depends(get_credits_service),
):
    payload, created = await service.post_adjustment(
        organization_id,
        AdjustmentRequest(
            entry_type=CreditEntryType(body.entry_type),
            amount_minor=body.amount_minor,
            note=body.note,
            reference=body.reference,
            campaign_id=body.campaign_id,
            issue_invoice=body.issue_invoice,
            amount_paid_minor_inr=body.amount_paid_minor_inr,
            idempotency_key=body.idempotency_key,
        ),
        actor_user_id=uuid.UUID(user.id),
    )
    return _ok(
        request,
        "Credits entry recorded" if created else "Credits entry already recorded",
        payload,
    )


@platform_router.put(
    "/{organization_id}/credits/settings",
    response_model=ApiResponse[dict],
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def update_organization_credit_settings(
    request: Request,
    body: CreditSettingsUpdate,
    organization_id: uuid.UUID = Depends(_target_organization),
    user: AuthUser = Depends(CurrentUser),
    service: CreditsService = Depends(get_credits_service),
):
    return _ok(
        request,
        "Credit settings updated",
        await service.update_settings(
            organization_id,
            low_balance_threshold_minor=body.low_balance_threshold_minor,
            actor_user_id=uuid.UUID(user.id),
        ),
    )


__all__ = ["customer_router", "platform_router"]
