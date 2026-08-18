"""TEMP DIAGNOSTIC — remove after incident resolved.

Live incident: a real guest gets stuck on the captive-portal "connecting"
spinner during hotspot login on router WYFY-GUEST. RouterOS's own hotspot
log (``/log print``) shows literally zero evidence of a login POST ever
arriving for that attempt, despite a real, active ``GuestSession`` existing
in this backend's own DB for that exact guest -- meaning
``portal.success.tsx``'s real ``submitHotspotLogin()`` form-post
(cloudguest-foundation) never actually executes ``form.submit()`` for this
specific real-world case. There is no access to the guest's own browser
console/network tab, so cloudguest-foundation's ``sendPortalDiagnosticBeacon``
(``src/lib/portal-diagnostic-beacon.ts``) fires a tiny, best-effort beacon
to this one endpoint at every meaningful decision point in the routing/
hotspot-login flow, to get real ground truth instead of guessing.

Deliberately minimal: no auth (mirrors ``app.domains.guest.router``'s
``guest_router`` posture -- the caller is an anonymous guest device at a
captive portal, no platform-user identity RBAC could ever gate), no new DB
table, no persistence beyond the application log. Read captures with e.g.
``docker compose logs | grep portal_diagnostic_beacon``.

Delete this whole ``app/api/v1/diagnostics/`` package, and the one
``include_router`` line for it in ``app/api/v1/router.py``, once this
incident is resolved and the beacon is no longer needed.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/diagnostics", tags=["Diagnostics (temporary)"])


class PortalDiagnosticBeaconRequest(BaseModel):
    """Mirrors ``sendPortalDiagnosticBeacon``'s payload shape on the
    frontend -- every field but ``event`` is optional since a beacon fired
    early in the flow (e.g. before a session/guestIdentifier exists yet)
    genuinely won't have all of them."""

    event: str
    guest_identifier: str | None = None
    device_mac: str | None = None
    router_id: str | None = None
    organization_id: str | None = None
    location_id: str | None = None
    client_timestamp: str | None = None
    details: dict[str, Any] | None = None


@router.post("/portal-beacon", status_code=status.HTTP_204_NO_CONTENT)
async def portal_diagnostic_beacon(
    request: Request,
    payload: PortalDiagnosticBeaconRequest,
) -> Response:
    # A structured `logger.warning` (not `.info`) so this reliably shows up
    # even at a production log level that filters info-level noise --
    # deliberately loud since this is short-lived incident tooling, not a
    # permanent feature. The literal string "portal_diagnostic_beacon" is
    # the grep anchor called out in this module's own docstring.
    logger.warning(
        "portal_diagnostic_beacon",
        extra={
            "event": payload.event,
            "guest_identifier": payload.guest_identifier,
            "device_mac": payload.device_mac,
            "router_id": payload.router_id,
            "organization_id": payload.organization_id,
            "location_id": payload.location_id,
            "client_timestamp": payload.client_timestamp,
            "details": payload.details,
            "server_received_at": datetime.now(UTC).isoformat(),
            "client_ip": request.client.host if request.client else None,
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
