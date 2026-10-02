"""Master price-book routes (spec §13.7). Every route pins
``scope=ScopeType.GLOBAL``: reads use ``billing.read``, writes
``billing.manage``. The per-org route takes the organization from the path,
which is safe only because of that pin (an organization-scoped holder of
``billing.manage`` is refused before the handler runs); it additionally runs
``enforce_target_organization`` and 404s an unknown organization. Not
licence-gated: the caller is the platform, not the tenant.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.exceptions import CloudGuestError
from app.common.responses import ApiResponse, build_response
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.scoping import enforce_target_organization
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol

from .credits import PriceBook, PriceRepository
from .schemas import OrgPricesUpdate, PriceBookUpdate

platform_pricing_router = APIRouter(tags=["Platform Marketing pricing"])


class _PricingOrganizationNotFoundError(CloudGuestError):
    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization not found: {organization_id}",
            status_code=status.HTTP_404_NOT_FOUND,
            data={"error_code": "organization_not_found"},
        )


def get_price_book(
    db: AsyncSession = Depends(get_db_session),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> PriceBook:
    return PriceBook(PriceRepository(db), audit_writer=audit_repository)


def _ok(request: Request, message: str, data: Any) -> dict[str, Any]:
    return build_response(
        success=True,
        message=message,
        data=data,
        request_id=str(getattr(request.state, "request_id", "")),
    )


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
        await organization_service.get_organization(organization_id)
    except OrganizationNotFoundError as exc:
        raise _PricingOrganizationNotFoundError(organization_id) from exc
    return organization_id


@platform_pricing_router.get(
    "/platform/marketing/price-book",
    response_model=ApiResponse[dict],
    dependencies=[Depends(RequirePermission("billing.read", scope=ScopeType.GLOBAL))],
)
async def get_marketing_price_book(
    request: Request, price_book: PriceBook = Depends(get_price_book)
):
    return _ok(request, "Marketing price book", await price_book.platform_view())


@platform_pricing_router.put(
    "/platform/marketing/price-book",
    response_model=ApiResponse[dict],
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def update_marketing_price_book(
    request: Request,
    body: PriceBookUpdate,
    user: AuthUser = Depends(CurrentUser),
    price_book: PriceBook = Depends(get_price_book),
):
    """Appends rows effective now. Existing reservations and in-flight
    campaigns keep their snapshot price."""
    return _ok(
        request,
        "Marketing prices updated",
        await price_book.set_platform_prices(
            [(p.channel, p.unit_price_minor) for p in body.prices],
            note=body.note,
            actor_user_id=uuid.UUID(user.id),
        ),
    )


@platform_pricing_router.put(
    "/platform/organizations/{organization_id}/marketing-prices",
    response_model=ApiResponse[dict],
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def update_organization_marketing_prices(
    request: Request,
    body: OrgPricesUpdate,
    organization_id: uuid.UUID = Depends(_target_organization),
    user: AuthUser = Depends(CurrentUser),
    price_book: PriceBook = Depends(get_price_book),
):
    return _ok(
        request,
        "Organization marketing prices updated",
        {
            "prices": await price_book.set_org_prices(
                organization_id,
                [(p.channel, p.unit_price_minor) for p in body.prices],
                note=body.note,
                actor_user_id=uuid.UUID(user.id),
            )
        },
    )


__all__ = ["platform_pricing_router"]
