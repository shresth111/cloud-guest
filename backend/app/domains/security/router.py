"""FastAPI routes for the Security domain: venue security posture and the
capability matrix.

Three read endpoints, no writes. Responses use the project's standard envelope
(``ApiResponse``/``build_response``), matching every other domain's router, and
every endpoint is gated by RBAC's own ``RequirePermission`` against a
``security.*`` permission key seeded by ``app.domains.rbac.seed``
(``PermissionModule.SECURITY``).

## Why nothing here is licence-gated, and what changes when it is

``app/api/v1/router.py``'s licence note is explicit that reads are never gated:
a customer whose plan has lapsed must still be able to sign in and see what
they have. This router is read-only, so it is included without
``_PAID_WRITES`` -- the same treatment ``analytics_router`` and
``dashboard_router`` get.

That holds only for as long as this router has no write endpoint. The first
write added here (deploying a block, isolating a device) must move the
``include_router`` call onto ``_PAID_WRITES``. That is not left to memory:
``tests/unit/test_security.py`` asserts this router is read-only, so adding a
write endpoint fails the suite with the licence decision in the failure
message rather than shipping an ungated write.

## ``/security/overview`` and ``/security/score`` overlap deliberately

``/score`` is the overview's score, extracted for the dashboard's compact
widget, which renders the number and the band without the counters. Both come
from one service call shape, so the widget and the page can never disagree
about the number.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import CurrentOrganization, RequirePermission

from .dependencies import get_security_service
from .schemas import (
    SecurityCapabilityListResponse,
    SecurityOverviewResponse,
    SecurityScoreResponse,
)
from .service import SecurityOverviewService

router = APIRouter(prefix="/security", tags=["Security"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/overview",
    response_model=ApiResponse[SecurityOverviewResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("security.read"))],
)
async def get_security_overview(
    request: Request,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: SecurityOverviewService = Depends(get_security_service),
):
    overview = await service.build_overview(
        requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Security overview retrieved",
        data=overview.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/score",
    response_model=ApiResponse[SecurityScoreResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("security.read"))],
)
async def get_security_score(
    request: Request,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: SecurityOverviewService = Depends(get_security_service),
):
    score = await service.build_score(
        requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Security score retrieved",
        data=score.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/capabilities",
    response_model=ApiResponse[SecurityCapabilityListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("security.read"))],
)
async def list_security_capabilities(
    request: Request,
    service: SecurityOverviewService = Depends(get_security_service),
):
    """What this platform can and cannot enforce.

    Served from the API so the dashboard has exactly one place to learn a
    feature's status. A capability that is not ``available`` must be rendered
    as such, never as an off switch -- the dashboard reads
    ``availability``/``detail`` and does not decide for itself.
    """
    capabilities = service.capabilities()
    return build_response(
        success=True,
        message="Security capabilities retrieved",
        data=capabilities.model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
