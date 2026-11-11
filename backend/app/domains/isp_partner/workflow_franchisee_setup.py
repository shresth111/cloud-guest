"""FR-GENERATE (founder 2026-11-11, "krdo"): a franchisee may Generate the
setup script for a router inside its own zones.

Before this, ``isp-franchisee`` held ``isp_partner.execute`` (so the console
showed Generate) but was not in ``SETUP_SCRIPT_ROLES``, so every setup twin
answered 403 ``ISP_ROLE_ESCALATION``. ``SETUP_SCRIPT_ROLES`` itself is not
changed (it also gates the PPPoE script); instead the setup twins branch on
the franchisee role before their own role check and call
``franchisee_setup_router`` here.

"Inside its zones" is the DECISIONS-1 site rule (``site_zone_for_franchisee``,
the one that decides where a franchisee may ADD a router), applied to the
router's own location:

* the router's customer is one the franchisee scope can see
  (``IspScope.assert_router``: another ISP's router, or a customer outside the
  zones, is already a 404), and
* that customer's profile zone is in the franchisee's subtree, or a router at
  that location (this one included) is linked in ``isp_router_zones`` to a
  zone in the subtree.

A router visible only because a subscriber of the franchisee's zone sits on
the same customer (the shared-site read rule) fails the rule: 404
``ISP_ROUTER_NOT_FOUND``, like any router the caller cannot see.

``GET /isp/routers/{isp_router_id}/setup/access`` lets the console hide
Generate instead of showing a button that would be refused. It answers for
every role (owner/admin/technician: their existing rule, unchanged).

Path ids are ``isp_router_id`` (never ``router_id``: the SCOPE_PARAM_ALIASES
trap).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request

from .constants import ISP_PARTNER_READ, SETUP_SCRIPT_ROLES
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import (
    IspLocationNotFoundError,
    IspRouterNotFoundError,
    IspSetupNotAllowedError,
)
from .http import ok
from .scoping import IspScope
from .workflow_franchisee import FRANCHISEE_SLUG, current_franchisee_scope

__all__ = [
    "franchisee_setup_access_router",
    "franchisee_setup_router",
    "is_franchisee",
]


def is_franchisee(isp: IspContext) -> bool:
    return getattr(isp, "role_slug", None) == FRANCHISEE_SLUG


async def assert_router_in_franchisee_zones(isp: IspContext, router: Any) -> None:
    """404 unless ``router`` (already through ``IspScope.assert_router``) is
    inside the franchisee's zones. No-op for every other role."""
    if not is_franchisee(isp):
        return
    from app.domains.location.models import Location

    from .workflow_franchisee_router import site_zone_for_franchisee

    session = getattr(isp.repository, "session", None)
    scope = current_franchisee_scope(session) if session is not None else None
    if scope is None:  # pragma: no cover - RequireIspPartner always sets it
        raise IspSetupNotAllowedError()
    location = await session.get(Location, router.location_id)
    if location is None or getattr(location, "is_deleted", False):
        raise IspRouterNotFoundError()
    try:
        await site_zone_for_franchisee(session, isp, scope, location)
    except IspLocationNotFoundError:
        raise IspRouterNotFoundError() from None


async def franchisee_setup_router(isp: IspContext, isp_router_id: uuid.UUID) -> Any:
    """The setup twins' target for a franchisee caller (see module doc)."""
    router = await IspScope.assert_router(isp, isp_router_id)
    await assert_router_in_franchisee_zones(isp, router)
    return router


franchisee_setup_access_router = APIRouter(tags=["ISP Partner: router setup"])


@franchisee_setup_access_router.get(
    "/routers/{isp_router_id}/setup/access",
    dependencies=isp_guards(ISP_PARTNER_READ),
)
async def router_setup_access(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
) -> dict:
    """``can_generate``: whether this caller's role may run the setup twins on
    this router. It does not check ``isp_partner.execute`` (the console
    already gates on it). A router the caller cannot see at all is a 404."""
    router = await IspScope.assert_router(isp, isp_router_id)
    if is_franchisee(isp):
        try:
            await assert_router_in_franchisee_zones(isp, router)
            can, reason = True, None
        except IspRouterNotFoundError:
            can, reason = False, "outside_zones"
    elif isp.role_slug in SETUP_SCRIPT_ROLES:
        can, reason = True, None
    else:
        can, reason = False, "role"
    return ok(
        request,
        {"isp_router_id": str(router.id), "can_generate": can, "reason": reason},
        "Router setup access",
    )
