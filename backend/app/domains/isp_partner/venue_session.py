"""``GET /isp/venue/me/organizations``: the venue's answer to "which org am I in?"

The customer app's pages resolve their organization once through
``GET /me/organizations`` (``services/organization-id.ts``) and then filter and
label everything by it -- ``PortalPage`` drops every config whose
``organization_id`` differs. An ISP user is a member of the ISP org only, so on
the partner host that call names the ISP and the page would show nothing.

While a venue is pinned the shim rewrites the call here. The answer has the
original's shape (``OrganizationMemberResponse``) with one row: the customer
the ``X-Isp-Customer-Id`` header names, resolved through ``IspScope`` (404 for
anything outside the ISP or the caller's confinement). It grants nothing --
every subsequent call still goes through a twin's guards; it only tells the
page which customer it is looking at. ``id``/``user_id`` are the caller's own
ISP membership values so nothing implies a customer membership exists.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request

from .constants import ISP_PARTNER_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspLocationNotFoundError
from .http import ok
from .scoping import IspScope
from .twin_headers import HEADER_CUSTOMER, HEADER_LOCATION
from .twins import _scope_header

__all__ = ["venue_session_router"]

venue_session_router = APIRouter()


@venue_session_router.get(
    "/venue/me/organizations", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def venue_me_organizations(
    request: Request, isp: IspContext = Depends(RequireIspPartner)
) -> dict:
    customer = await IspScope.assert_customer(
        isp, _scope_header(request, HEADER_CUSTOMER)
    )
    # Same rule as every twin (QA-002 leftover): a location header must be a
    # location of this customer.
    if request.headers.get(HEADER_LOCATION):
        location = await IspScope.assert_location(
            isp, _scope_header(request, HEADER_LOCATION)
        )
        if location.organization_id != customer.id:
            raise IspLocationNotFoundError()
    now = datetime.now(UTC).isoformat()
    row = {
        "id": f"isp-venue-{customer.id}",
        "organization_id": str(customer.id),
        "user_id": str(isp.user_id),
        "status": "active",
        "invited_by_user_id": None,
        "invited_at": now,
        "joined_at": None,
        "is_primary_contact": False,
        "created_at": now,
        "updated_at": now,
    }
    return ok(request, [row], "Venue organization")
