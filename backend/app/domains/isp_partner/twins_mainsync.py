"""MAIN-SYNC: venue twins for what main's customer pages call since integ forked.

The partner console mounts the customer dashboard's own pages unchanged (see
:mod:`app.domains.isp_partner.twins_venue`). Main has since grown those pages:
the Aruba SSID speed tiers and the hybrid speed-control card on Access Rules,
hotspot profiles and router interfaces on Internet Connection, the router's
live DHCP pools on IP Addresses, Terminate on a guest session and the
location-wise SMS usage report. Each call below is the original handler, run
for the resolved customer through the same twin builder, permission keys and
gates as every other venue twin. Nothing here changes a customer route.

Deliberately NOT twinned (fails closed, exactly as it does for a customer):
``POST /locations/{id}/ssid-tiers/instant-on-sync`` requires the GLOBAL
``network_integrations.update`` key (a Master action).
"""

from __future__ import annotations

import inspect
import uuid
from datetime import date

from app.database.session import get_db_session
from app.domains.dhcp import router as dhcp_routes
from app.domains.dhcp.dependencies import get_dhcp_service
from app.domains.dhcp.schemas import DhcpLivePoolUpdateRequest
from app.domains.guest import router as guest_routes
from app.domains.guest import ssid_tier_router as ssid_tier_routes
from app.domains.guest.dependencies import get_guest_service, get_ssid_tier_service
from app.domains.guest.schemas import SessionTerminateRequest
from app.domains.hotspot import router as hotspot_routes
from app.domains.hotspot.dependencies import get_hotspot_service
from app.domains.hotspot.schemas import (
    HotspotProfileCreateRequest,
    HotspotProfileUpdateRequest,
)
from app.domains.location.dependencies import get_location_service
from app.domains.otp import router as otp_routes
from app.domains.otp.dependencies import get_otp_service
from app.domains.queue_management import speed_gateway_router as speed_routes
from app.domains.router import router as router_routes
from app.domains.router.dependencies import get_router_service
from app.domains.vlan import router as vlan_routes
from app.domains.vlan.dependencies import get_vlan_service

from .constants import (
    ISP_ACCESS_EXECUTE,
    ISP_ACCESS_READ,
    ISP_ACCESS_UPDATE,
    ISP_NETWORK_CREATE,
    ISP_NETWORK_DELETE,
    ISP_NETWORK_EXECUTE,
    ISP_NETWORK_READ,
    ISP_NETWORK_UPDATE,
)
from .twin_body import BodyId
from .twins import Extra, Param, TwinSpec

__all__ = ["MAINSYNC_TWINS"]

_Location = Param("isp_location_id", "path", uuid.UUID, forward="location_id")
_RouterPath = Extra("isp_router_id", "path", "router", "router_id", required=True)
_RouterQuery = Extra("isp_router_id", "query", "router", "router_id")
_RouterQueryRequired = Extra(
    "isp_router_id", "query", "router", "router_id", required=True
)
_ProfileId = Param("profile_id", "path", uuid.UUID)
_Page = Param("page", "query", int, 1)
_PageSize = Param("page_size", "query", int, 25)
_org = {"requesting_organization_id": ("org",)}
_org_actor = {"requesting_organization_id": ("org",), "actor": ("user",)}
_hotspot = {"service": get_hotspot_service}


def _body(model):
    return Param("payload", "body", model, inspect.Parameter.empty)


MAINSYNC_TWINS: tuple[TwinSpec, ...] = (
    # -- Access Rules: Aruba SSID speed tiers + the hybrid speed-control card --
    TwinSpec(
        method="GET",
        path="/venue/network-integrations/locations/{isp_location_id}/speed-control",
        permission_key=ISP_ACCESS_READ,
        handler=speed_routes.get_location_speed_control,
        target="location",
        resolve_param="isp_location_id",
        params=(_Location,),
        deps={"service": speed_routes.get_speed_gateway_service, "db": get_db_session},
        # The location is already pinned to this ISP's customer by IspScope, so
        # the customer-side location confinement has nothing left to narrow.
        inject={**_org, "caller_location_scope": ("const", None)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/locations/{isp_location_id}/ssid-tiers",
        permission_key=ISP_ACCESS_READ,
        handler=ssid_tier_routes.list_ssid_tiers,
        target="location",
        resolve_param="isp_location_id",
        params=(_Location,),
        deps={
            "service": get_ssid_tier_service,
            "location_service": get_location_service,
        },
        inject={**_org, "scope_location_id": ("location",)},
    ),
    TwinSpec(
        method="PUT",
        path="/venue/locations/{isp_location_id}/ssid-tiers",
        permission_key=ISP_ACCESS_UPDATE,
        handler=ssid_tier_routes.replace_ssid_tiers,
        target="location",
        resolve_param="isp_location_id",
        # The body's only top-level field is ``items``. Each item's
        # ``policy_id`` / ``voucher_plan_ids`` are checked by the original
        # service against requesting_organization_id
        # (SsidTierService.foreign_policy_ids / foreign_voucher_plan_ids).
        params=(_Location, _body(ssid_tier_routes.SsidTierReplaceRequest)),
        deps={
            "service": get_ssid_tier_service,
            "location_service": get_location_service,
        },
        inject={**_org, "user": ("user",), "scope_location_id": ("location",)},
    ),
    # -- Internet Connection: hotspot profiles + the router's interfaces -------
    TwinSpec(
        method="GET",
        path="/venue/hotspot-profiles",
        permission_key=ISP_NETWORK_READ,
        handler=hotspot_routes.list_hotspot_profiles,
        target="header_location",
        params=(_Page, _PageSize),
        extras=(_RouterQuery,),
        deps=_hotspot,
        inject=_org,
    ),
    TwinSpec(
        method="POST",
        path="/venue/hotspot-profiles",
        permission_key=ISP_NETWORK_CREATE,
        handler=hotspot_routes.create_hotspot_profile,
        target="header_location",
        params=(_body(HotspotProfileCreateRequest),),
        body_ids=(BodyId("router_id", "router"),),
        deps=_hotspot,
        inject=_org_actor,
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/hotspot-profiles/{profile_id}",
        permission_key=ISP_NETWORK_READ,
        handler=hotspot_routes.get_hotspot_profile,
        target="header_location",
        params=(_ProfileId,),
        deps=_hotspot,
        inject=_org,
    ),
    TwinSpec(
        method="PUT",
        path="/venue/hotspot-profiles/{profile_id}",
        permission_key=ISP_NETWORK_UPDATE,
        handler=hotspot_routes.update_hotspot_profile,
        target="header_location",
        params=(_ProfileId, _body(HotspotProfileUpdateRequest)),
        deps=_hotspot,
        inject=_org_actor,
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/hotspot-profiles/{profile_id}",
        permission_key=ISP_NETWORK_DELETE,
        handler=hotspot_routes.delete_hotspot_profile,
        target="header_location",
        params=(_ProfileId,),
        deps=_hotspot,
        inject=_org_actor,
    ),
    TwinSpec(
        method="GET",
        path="/venue/vlans/device-interfaces",
        permission_key=ISP_NETWORK_READ,
        handler=vlan_routes.list_device_interfaces,
        target="header_location",
        extras=(_RouterQueryRequired,),
        deps={"service": get_vlan_service},
        inject=_org,
    ),
    TwinSpec(
        method="GET",
        path="/venue/routers/{isp_router_id}/device-interfaces",
        permission_key=ISP_NETWORK_READ,
        handler=router_routes.get_device_interfaces,
        target="header_location",
        extras=(_RouterPath,),
        deps={"router_service": get_router_service},
        inject=_org,
    ),
    # -- IP Addresses: the router's own (live) pools --------------------------
    TwinSpec(
        method="GET",
        path="/venue/dhcp-pools/routers/{isp_router_id}/live-pools",
        permission_key=ISP_NETWORK_READ,
        handler=dhcp_routes.list_router_live_pools,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_dhcp_service},
        inject=_org,
    ),
    TwinSpec(
        method="PUT",
        path="/venue/dhcp-pools/routers/{isp_router_id}/live-pools/{pool_name}",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=dhcp_routes.update_router_live_pool,
        target="header_location",
        params=(
            Param("pool_name", "path", str),
            _body(DhcpLivePoolUpdateRequest),
        ),
        extras=(_RouterPath,),
        deps={"service": get_dhcp_service},
        inject=_org_actor,
    ),
    # -- Guests: end a live session -------------------------------------------
    TwinSpec(
        method="POST",
        path="/venue/guest-sessions/{session_id}/terminate",
        permission_key=ISP_ACCESS_EXECUTE,
        handler=guest_routes.terminate_guest_session,
        # The original route is exempt from the lapsed-licence write check.
        paid_write=False,
        # F2: the original returns this as a plain, unmasked str.
        redact_fields=("guest_identifier",),
        target="header_location",
        params=(
            Param("session_id", "path", uuid.UUID),
            _body(SessionTerminateRequest),
        ),
        deps={"service": get_guest_service},
        inject={**_org, "user": ("user",)},
    ),
    # -- Reports: location-wise SMS OTP usage ---------------------------------
    TwinSpec(
        method="GET",
        path="/venue/otp/requests/sms-daily-consumption",
        permission_key=ISP_ACCESS_READ,
        handler=otp_routes.get_daily_sms_consumption,
        target="header_location",
        params=(
            Param("start_date", "query", date | None, None),
            Param("end_date", "query", date | None, None),
        ),
        deps={"service": get_otp_service},
        inject={"organization_id": ("org",)},
    ),
)
