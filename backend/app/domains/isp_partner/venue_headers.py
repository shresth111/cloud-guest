"""The venue header pair for PARITY-2's hand-written venue routes.

``X-Isp-Location-Id`` names the venue; ``X-Isp-Customer-Id``, when sent, must
be that venue's customer. A pair that disagrees is the same 404 a foreign id
gets (QA-002 for the hand routes: ``/isp/venue/alert-rules``, the marketing
``CallerScope``, ``/isp/venue/marketing/credits``).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request

from .dependencies import IspContext
from .exceptions import IspBadRequestError, IspLocationNotFoundError
from .scoping import IspScope
from .twin_headers import HEADER_CUSTOMER, HEADER_LOCATION

__all__ = ["resolve_venue_location"]


def _uuid(request: Request, header: str, *, required: bool) -> uuid.UUID | None:
    raw = request.headers.get(header)
    if not raw:
        if required:
            raise IspBadRequestError(f"{header} is required")
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        raise IspBadRequestError(f"{header} is not a valid id") from None


async def resolve_venue_location(request: Request, isp: IspContext) -> Any:
    location = await IspScope.assert_location(
        isp, _uuid(request, HEADER_LOCATION, required=True)
    )
    customer_id = _uuid(request, HEADER_CUSTOMER, required=False)
    if customer_id is not None:
        await IspScope.assert_customer(isp, customer_id)
        if location.organization_id != customer_id:
            raise IspLocationNotFoundError()
    return location
