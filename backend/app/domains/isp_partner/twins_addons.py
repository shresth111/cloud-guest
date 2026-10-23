"""Batch B6 add-on twins (ADDENDUM_04 §3 Network: Traffic Lens).

Traffic Lens on a venue, for the ISP: status, summary, destinations,
per-service destinations, geography and findings. (The destinations CSV export
takes no ``request`` argument, which the twin layer always passes, so it is not
twinned; the partner page exports what it shows.) Every original is
``RequireFeature(TRAFFIC_FLOW)``; each row re-declares it, and ``twin_gates``
evaluates it against the CUSTOMER org -- so the twin answers 402
``feature_not_entitled`` unless the add-on is on for that customer, which an
ISP can only do within Master's allowance (``isp_addons``).

The twins keep the customer path shape
(``/traffic-flow/locations/{id}/<view>``) so the customer's own Traffic Lens
page can be mounted unchanged behind the shim's prefix rewrite. The path id is
``isp_location_id``, resolved through ``IspScope`` and pinned to the header's
customer; the handler's ``header_location_id`` cross-check receives the
HEADER location, so a path naming another venue is refused by the original.

NOT twinned: the per-connection flow records (``/flows``, ``/flows/export``,
``TRAFFIC_FLOW_RECORDS``). They hold per-guest source data; ADDENDUM_04 treats
them like IPDR, and founder F2 (PII for ISP staff) defaults to masked. They
join when F2 is answered.

Key: ``isp_network.read`` (ADDENDUM_04 table).
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime
from datetime import datetime as _dt
from typing import Any as _Any

from fastapi import Depends as _Depends
from fastapi import Query as _Query
from fastapi import Request as _Request
from fastapi import status as _status
from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession

from app.database.session import get_db_session as _get_db_session
from app.domains.billing.constants import PlanFeatureKey
from app.domains.traffic_flow import customer_router as tf_routes
from app.domains.traffic_flow import destinations_customer_router as tf_dest
from app.domains.traffic_flow import findings_customer_router as tf_findings
from app.domains.traffic_flow import (
    flow_records_customer_router as tf_records,
)
from app.domains.traffic_flow import geo_customer_router as tf_geo
from app.domains.traffic_flow.dependencies import get_traffic_flow_customer_service

from .constants import ISP_IPDR_READ, ISP_NETWORK_READ
from .dependencies import IspContext as _IspContext
from .dependencies import RequireIspPartner as _RequireIspPartner
from .exceptions import IspError as _IspError
from .exceptions import IspRouterNotFoundError as _IspRouterNotFoundError
from .scoping import IspScope as _IspScope
from .twin_headers import HEADER_LOCATION as _HEADER_LOCATION
from .twins import Extra, Param, TwinSpec

__all__ = ["ADDON_TWINS"]

_TF = (PlanFeatureKey.TRAFFIC_FLOW,)
_Router = Extra("isp_router_id", "query", "router", "router_id")
_Since = Param("since", "query", datetime | None, None)
_Until = Param("until", "query", datetime | None, None)
_Limit = Param("limit", "query", int | None, None)
#: The customer path's ``{location_id}``, exposed under the ISP name and
#: resolved through ``IspScope`` (same customer as the header, or 404). The
#: handler's own ``header_location_id`` cross-check gets the HEADER location,
#: so a path naming another venue than the one pinned is refused by the
#: original handler itself.
_LocPath = Extra("isp_location_id", "path", "location", "location_id", required=True)
_LOC = {
    "organization_id": ("org",),
    "header_location_id": ("location",),
}
_DEST_FILTERS = (
    _Since,
    _Until,
    Param("address", "query", str | None, None),
    Param("protocol", "query", int | None, None),
    Param("port", "query", int | None, None),
    Param("direction", "query", str | None, None),
    Param("sort", "query", str | None, None),
    Param("order", "query", str | None, None),
)

ADDON_TWINS: tuple[TwinSpec, ...] = (
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/locations/{isp_location_id}/status",
        permission_key=ISP_NETWORK_READ,
        handler=tf_routes.get_venue_traffic_status,
        target="header_location",
        requires_features=_TF,
        extras=(_LocPath,),
        deps={"service": get_traffic_flow_customer_service},
        inject=_LOC,
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/locations/{isp_location_id}/summary",
        permission_key=ISP_NETWORK_READ,
        handler=tf_routes.get_venue_traffic_summary,
        target="header_location",
        requires_features=_TF,
        params=(_Since, _Until, _Limit, Param("series", "query", int | None, None)),
        extras=(_LocPath, _Router),
        deps={"service": get_traffic_flow_customer_service},
        inject=_LOC,
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/locations/{isp_location_id}/destinations",
        permission_key=ISP_NETWORK_READ,
        handler=tf_dest.search_venue_destinations,
        target="header_location",
        requires_features=_TF,
        params=_DEST_FILTERS,
        extras=(_LocPath, _Router),
        deps={"service": tf_dest.get_customer_destination_service},
        inject={**_LOC, "user": ("user",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/locations/{isp_location_id}/services/destinations",
        permission_key=ISP_NETWORK_READ,
        handler=tf_dest.get_venue_service_destinations,
        target="header_location",
        requires_features=_TF,
        params=(
            Param("protocol", "query", int),
            Param("port", "query", int),
            _Since,
            _Until,
            _Limit,
        ),
        extras=(_LocPath, _Router),
        deps={"service": tf_dest.get_customer_destination_service},
        inject={**_LOC, "user": ("user",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/locations/{isp_location_id}/geo",
        permission_key=ISP_NETWORK_READ,
        handler=tf_geo.get_venue_traffic_geo,
        target="header_location",
        requires_features=_TF,
        params=(_Since, _Until, _Limit, Param("networks", "query", int | None, None)),
        extras=(_LocPath, _Router),
        deps={"service": tf_geo.get_customer_geo_service},
        inject=_LOC,
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/locations/{isp_location_id}/findings",
        permission_key=ISP_NETWORK_READ,
        handler=tf_findings.get_venue_traffic_findings,
        target="header_location",
        requires_features=_TF,
        params=(_Since, _Until),
        extras=(_LocPath,),
        deps={"service": tf_findings.get_customer_findings_service},
        inject=_LOC,
    ),
)


# ---------------------------------------------------------------------------
# F2: Traffic Lens flow records (per-connection source data)
# ---------------------------------------------------------------------------
#
# Served only when Master enabled unmasking for this ISP AND the caller is its
# owner/admin (``parity_settings.pii_unmasked_for``); otherwise 403
# ``ISP_PII_MASKED``. Every served page is audited by ``build_twin``
# (``pii_policy``: the path is a PII path). The original's ``_query`` filter
# dependency exposes ``router_id`` -- a scope alias -- so the twin supplies an
# equivalent dict built from ``isp_router_id``, pinned through ``IspScope`` to
# the header location. The CSV export is not twinned (its handler takes no
# ``request``).


class IspPiiMaskedError(_IspError):
    code = "ISP_PII_MASKED"
    status_code_default = _status.HTTP_403_FORBIDDEN
    default_message = (
        "Connection records show guest addresses. Wyfy has not enabled unmasked "
        "records for your account, or your role is not owner/admin."
    )


async def isp_flow_record_query(
    request: _Request,
    isp: _IspContext = _Depends(_RequireIspPartner),
    db: _AsyncSession = _Depends(_get_db_session),
    isp_router_id: _uuid.UUID | None = _Query(default=None),
    since: _dt | None = _Query(default=None),
    until: _dt | None = _Query(default=None),
    address: str | None = _Query(default=None, max_length=64),
    src_address: str | None = _Query(default=None, max_length=64),
    dst_address: str | None = _Query(default=None, max_length=64),
    port: int | None = _Query(default=None, ge=0, le=65535),
    src_port: int | None = _Query(default=None, ge=0, le=65535),
    dst_port: int | None = _Query(default=None, ge=0, le=65535),
    protocol: int | None = _Query(default=None, ge=0, le=255),
    sort: str | None = _Query(default=None, max_length=16),
    order: str | None = _Query(default=None, max_length=8),
) -> dict[str, _Any]:
    from .parity_settings import pii_unmasked_for

    if not await pii_unmasked_for(db, isp):
        raise IspPiiMaskedError()
    router_id = None
    if isp_router_id is not None:
        router = await _IspScope.assert_router(isp, isp_router_id)
        header = request.headers.get(_HEADER_LOCATION)
        if header is None or str(router.location_id) != header:
            raise _IspRouterNotFoundError()
        router_id = router.id
    return {
        "router_id": router_id,
        "since": since,
        "until": until,
        "address": address,
        "src_address": src_address,
        "dst_address": dst_address,
        "port": port,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "sort": sort,
        "order": order,
    }


FLOW_RECORD_TWINS: tuple[TwinSpec, ...] = (
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/locations/{isp_location_id}/flows",
        permission_key=ISP_IPDR_READ,
        handler=tf_records.search_venue_flow_records,
        target="header_location",
        requires_features=(PlanFeatureKey.TRAFFIC_FLOW_RECORDS,),
        extras=(_LocPath,),
        deps={
            "query": isp_flow_record_query,
            "service": tf_records.get_customer_flow_record_service,
        },
        inject={**_LOC, "user": ("user",)},
    ),
)

ADDON_TWINS = ADDON_TWINS + FLOW_RECORD_TWINS
