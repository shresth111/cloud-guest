"""Batch B6 add-on twins (ADDENDUM_04 §3 Network: Traffic Lens).

Traffic Lens on a venue, for the ISP: status, summary, destinations,
per-service destinations, geography and findings. (The destinations CSV export
takes no ``request`` argument, which the twin layer always passes, so it is not
twinned; the partner page exports what it shows.) Every original is
``RequireFeature(TRAFFIC_FLOW)``; each row re-declares it, and ``twin_gates``
evaluates it against the CUSTOMER org -- so the twin answers 402
``feature_not_entitled`` unless the add-on is on for that customer, which an
ISP can only do within Master's allowance (``isp_addons``).

The original paths carry ``{location_id}``. The twins take NO location in the
path: the location is injected from ``X-Isp-Location-Id`` (resolved through
``IspScope``), both as ``location_id`` and as the handler's own
``header_location_id`` cross-check. The partner console calls
``/isp/venue/traffic-flow/<view>``.

NOT twinned: the per-connection flow records (``/flows``, ``/flows/export``,
``TRAFFIC_FLOW_RECORDS``). They hold per-guest source data; ADDENDUM_04 treats
them like IPDR, and founder F2 (PII for ISP staff) defaults to masked. They
join when F2 is answered.

Key: ``isp_network.read`` (ADDENDUM_04 table).
"""

from __future__ import annotations

from datetime import datetime

from app.domains.billing.constants import PlanFeatureKey
from app.domains.traffic_flow import customer_router as tf_routes
from app.domains.traffic_flow import destinations_customer_router as tf_dest
from app.domains.traffic_flow import findings_customer_router as tf_findings
from app.domains.traffic_flow import geo_customer_router as tf_geo
from app.domains.traffic_flow.dependencies import get_traffic_flow_customer_service

from .constants import ISP_NETWORK_READ
from .twins import Extra, Param, TwinSpec

__all__ = ["ADDON_TWINS"]

_TF = (PlanFeatureKey.TRAFFIC_FLOW,)
_Router = Extra("isp_router_id", "query", "router", "router_id")
_Since = Param("since", "query", datetime | None, None)
_Until = Param("until", "query", datetime | None, None)
_Limit = Param("limit", "query", int | None, None)
_LOC = {
    "organization_id": ("org",),
    "location_id": ("location",),
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
        path="/venue/traffic-flow/status",
        permission_key=ISP_NETWORK_READ,
        handler=tf_routes.get_venue_traffic_status,
        target="header_location",
        requires_features=_TF,
        deps={"service": get_traffic_flow_customer_service},
        inject=_LOC,
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/summary",
        permission_key=ISP_NETWORK_READ,
        handler=tf_routes.get_venue_traffic_summary,
        target="header_location",
        requires_features=_TF,
        params=(_Since, _Until, _Limit, Param("series", "query", int | None, None)),
        extras=(_Router,),
        deps={"service": get_traffic_flow_customer_service},
        inject=_LOC,
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/destinations",
        permission_key=ISP_NETWORK_READ,
        handler=tf_dest.search_venue_destinations,
        target="header_location",
        requires_features=_TF,
        params=_DEST_FILTERS,
        extras=(_Router,),
        deps={"service": tf_dest.get_customer_destination_service},
        inject={**_LOC, "user": ("user",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/services/destinations",
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
        extras=(_Router,),
        deps={"service": tf_dest.get_customer_destination_service},
        inject={**_LOC, "user": ("user",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/geo",
        permission_key=ISP_NETWORK_READ,
        handler=tf_geo.get_venue_traffic_geo,
        target="header_location",
        requires_features=_TF,
        params=(_Since, _Until, _Limit, Param("networks", "query", int | None, None)),
        extras=(_Router,),
        deps={"service": tf_geo.get_customer_geo_service},
        inject=_LOC,
    ),
    TwinSpec(
        method="GET",
        path="/venue/traffic-flow/findings",
        permission_key=ISP_NETWORK_READ,
        handler=tf_findings.get_venue_traffic_findings,
        target="header_location",
        requires_features=_TF,
        params=(_Since, _Until),
        deps={"service": tf_findings.get_customer_findings_service},
        inject=_LOC,
    ),
)
