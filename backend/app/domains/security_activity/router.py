"""``GET /security/activity`` -- what the venue's protections did.

Mounted under the same ``/security`` prefix as ``app.domains.security``'s
own router, as its own ``APIRouter``: that domain is read-only by
construction (and tested to be), this one owns the collector's table.
Read-only HTTP surface either way -- one GET.
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.location.exceptions import CrossLocationScopeAccessError
from app.domains.rbac.dependencies import (
    CurrentLocation,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.location_scope import (
    CallerLocationScope,
    LocationScope,
    confine_location_filter,
)

from .dependencies import get_security_activity_service
from .schemas import SecurityActivityResponse
from .service import SecurityActivityService

router = APIRouter(prefix="/security", tags=["Security Activity"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/activity",
    response_model=ApiResponse[SecurityActivityResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("security.read"))],
)
async def get_security_activity(
    request: Request,
    window: Literal["24h", "7d"] = Query(default="24h"),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    requesting_location_id: uuid.UUID | None = Depends(CurrentLocation),
    caller_location_scope: LocationScope = Depends(CallerLocationScope),
    service: SecurityActivityService = Depends(get_security_activity_service),
):
    """Per-protection counts for the last 24 hours or 7 days, read off the
    routers' own rule counters (hourly, read-only); device blocks;
    Cloudflare's refused lookups where they can be attributed; and staff
    changes to security settings.

    One organization only (``RequireOrganization``): an all-tenants total is
    not a question this page answers, and ``None`` must never reach the
    queries as "every organization". A caller whose grants cover particular
    sites sees only those sites even when the request names none
    (``confine_location_filter``)."""
    location = confine_location_filter(
        requested_location_id=requesting_location_id,
        caller_location_scope=caller_location_scope,
        error=CrossLocationScopeAccessError(),
    )
    activity = await service.build(
        organization_id=organization_id, location=location, window=window
    )
    return build_response(
        success=True,
        message="Security activity retrieved",
        data=SecurityActivityResponse(**activity).model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
