"""QA-021 / ADDENDUM_04 §3 (Portal row): "Support phone on the portal = the
ISP's".

``GET /isp/public/portal-support?location=<uuid>`` is public and
read-only, behind the ``ISP_PARTNER_ENABLED`` flag like every ``/isp`` route.
The query parameter is ``location`` (not ``*_id``): it is not an RBAC scope
parameter, because nothing here is authorized against it, and the name keeps
it out of ``rbac/scope_params.py``, which is not edited.
The guest portal's footer calls it, but only on an ISP portal host (see the
frontend ``src/lib/isp-partner/portal-support.ts``). Other hosts never call it.

- **200** ``{"support_phone", "support_email"}`` when the location belongs to
  an ISP customer whose ISP is active and has at least one of the two set.
  These are the ISP's own published support contacts, meant for guests.
  Nothing else is returned: no names, no ids, no customer data.
- **404** ``ISP_PORTAL_SUPPORT_NOT_FOUND`` for anything else: unknown or
  deleted location, a location of a non-ISP organization, a suspended or
  deleted ISP, or an ISP with no contact set. One body for all of them.
- **429** with ``Retry-After`` after ``IP_LIMIT`` requests per client IP per
  window. The global ``RateLimitMiddleware`` path list is not edited. Fails
  open on a Redis error, like that middleware.

The old ``/captive-portal/resolve`` and portal code are not edited.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import build_response
from app.database.redis import get_redis_client
from app.database.session import get_db_session

from .http import ok, request_id

__all__ = [
    "IP_LIMIT",
    "portal_support_router",
    "support_contact_for_location",
]

logger = logging.getLogger(__name__)

portal_support_router = APIRouter(prefix="/public", tags=["ISP Partner: public"])

#: (max requests, window seconds) per client IP. A portal page load makes one.
IP_LIMIT = (60, 60)
_IP_KEY = "isp_partner:portal_support:ip:{ip}"


async def support_contact_for_location(
    session: AsyncSession, location_id: uuid.UUID
) -> dict | None:
    """The ISP's support contact for a location of one of its customers, or
    None. Three indexed reads: location → customer profile → ISP profile."""
    from app.domains.location.models import Location

    from .models import IspCustomerProfile, IspPartnerProfile

    location = await session.get(Location, location_id)
    if location is None or location.is_deleted:
        return None
    customer = (
        await session.execute(
            select(IspCustomerProfile).where(
                IspCustomerProfile.customer_organization_id == location.organization_id,
                IspCustomerProfile.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if customer is None:
        return None
    isp = (
        await session.execute(
            select(IspPartnerProfile).where(
                IspPartnerProfile.organization_id == customer.isp_organization_id,
                IspPartnerProfile.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if isp is None or isp.status != "active":
        return None
    if not (isp.support_phone or isp.support_email):
        return None
    return {"support_phone": isp.support_phone, "support_email": isp.support_email}


async def _ip_allowed(redis: Redis, client_ip: str) -> tuple[bool, int]:
    cap, window = IP_LIMIT
    key = _IP_KEY.format(ip=client_ip)
    try:
        count = int(await redis.incr(key))
        if count == 1:
            await redis.expire(key, window)
        if count <= cap:
            return True, 0
        ttl = await redis.ttl(key)
        return False, int(ttl) if ttl and ttl > 0 else window
    except Exception:  # noqa: BLE001 -- fail open, like the global middleware
        logger.warning("isp_portal_support_rate_limit_unavailable")
        return True, 0


def _reply(request: Request, code: int, message: str, **extra) -> JSONResponse:
    return JSONResponse(
        status_code=code,
        content=build_response(
            success=False,
            message=message,
            data=extra.pop("data", None),
            request_id=request_id(request),
        ),
        **extra,
    )


@portal_support_router.get("/portal-support")
async def portal_support(
    request: Request,
    location: uuid.UUID = Query(..., description="The portal page's location id"),
    session: AsyncSession = Depends(get_db_session),
    redis: Redis = Depends(get_redis_client),
):
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = await _ip_allowed(redis, client_ip)
    if not allowed:
        return _reply(
            request,
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many requests -- please try again later",
            headers={"Retry-After": str(retry_after)},
        )
    contact = await support_contact_for_location(session, location)
    if contact is None:
        return _reply(
            request,
            status.HTTP_404_NOT_FOUND,
            "No support contact for this location",
            data={"code": "ISP_PORTAL_SUPPORT_NOT_FOUND"},
        )
    response = ok(request, contact, "Support contact")
    return JSONResponse(
        content=response, headers={"Cache-Control": "public, max-age=300"}
    )
