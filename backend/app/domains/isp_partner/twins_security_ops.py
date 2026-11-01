"""Batch B4 venue twins (ADDENDUM_04 §3 Security, Operations, Devices).

Read :mod:`app.domains.isp_partner.twins` and :mod:`.twins_venue` first: the
pattern, the generated signatures, the gates and the body-id rules all apply
unchanged. These rows are registered in ``twins_all.ALL_TWINS`` (one line),
so every structural test that walks that tuple -- guards,
gate parity, body ids, handler fit, header resolution -- covers them too.

WHAT IS HERE
------------
- Security Score: ``/security/overview|score|capabilities`` (read-only).
- Block Websites: ``/content-filter-rules`` (rules + per-router app blocks)
  and ``/dns-filtering`` (category policy, per-router enable/disable and
  bypass hardening).
- Firewall: the customer's OWN rules (CRUD + per-router push), flood limit and
  guest isolation.
- Fix a Problem: ``/network-diagnostics`` ping / traceroute / run history,
  rate-limited per ISP user on top of the service's own per-router and
  per-organization limits.
- Devices: ``/connected-devices`` (clients) and ``/monitored-hardware``.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
- ``/firewall-rules/routers/{id}/band`` (install and status): the Wyfy
  firewall band is GLOBAL-pinned and Master-only by design. An ISP never
  installs, reads or edits it (ADDENDUM_04 "Not twinned on purpose").

PATHS THAT CARRY A SCOPE ID ON THE CUSTOMER SIDE
------------------------------------------------
Two DNS-filtering originals take the tenant id from the PATH
(``/organizations/{organization_id}/policy``, ``/locations/{location_id}/
policy``) -- the path-id defect shape. Their twins take NO id: the customer
org and the location are injected from the resolved header target, so a
foreign id in a URL is not something these routes can even receive. The
partner console calls ``/dns-filtering/organization-policy`` and
``/dns-filtering/location-policy``, which the shim rewrites like any other
venue path.

Likewise ``location_id`` filters on ``GET /connected-devices``, ``GET
/monitored-hardware`` and ``GET /dns-filtering/categories`` are always
INJECTED from ``X-Isp-Location-Id`` and never exposed, so the omitted-location
"None = everything in the org" fallback of those handlers cannot be reached.
"""

from __future__ import annotations

import inspect
import time
import uuid

from fastapi import Depends, Request, status
from redis.asyncio import Redis

from app.database.redis import get_redis_client
from app.domains.auth.models import AuthUser
from app.domains.connected_devices import router as connected_device_routes
from app.domains.connected_devices.dependencies import get_connected_device_service
from app.domains.connected_devices.schemas import (
    ConnectedDeviceAccessActionRequest,
    ConnectedDeviceCommentRequest,
)
from app.domains.content_filtering import router as content_filter_routes
from app.domains.content_filtering.dependencies import get_content_filter_service
from app.domains.content_filtering.schemas import (
    ContentFilterRuleCreateRequest,
    ContentFilterRuleUpdateRequest,
)
from app.domains.dns_filtering import router as dns_filter_routes
from app.domains.dns_filtering.dependencies import get_dns_filtering_service
from app.domains.dns_filtering.schemas import (
    BypassHardeningRequest,
    PolicyUpdateRequest,
)
from app.domains.firewall import router as firewall_routes
from app.domains.firewall.dependencies import get_firewall_service
from app.domains.firewall.schemas import (
    FirewallRuleCreateRequest,
    FirewallRuleUpdateRequest,
    FloodLimitUpdateRequest,
    GuestIsolationUpdateRequest,
)
from app.domains.monitored_hardware import router as monitored_hardware_routes
from app.domains.monitored_hardware.dependencies import get_monitored_hardware_service
from app.domains.monitored_hardware.schemas import MonitoredHardwareRegisterRequest
from app.domains.network_diagnostics import router as diagnostics_routes
from app.domains.network_diagnostics.dependencies import (
    get_network_diagnostics_service,
)
from app.domains.network_diagnostics.schemas import PingRequest, TracerouteRequest
from app.domains.rbac.dependencies import CurrentUser
from app.domains.security import router as security_routes
from app.domains.security.dependencies import get_security_service

from .constants import (
    ISP_MONITOR_READ,
    ISP_MONITOR_UPDATE,
    ISP_OPS_EXECUTE,
    ISP_SECURITY_CREATE,
    ISP_SECURITY_DELETE,
    ISP_SECURITY_EXECUTE,
    ISP_SECURITY_READ,
    ISP_SECURITY_UPDATE,
)
from .exceptions import IspError
from .twin_body import BodyId
from .twins import Extra, Param, TwinSpec

__all__ = [
    "DIAGNOSTICS_PER_USER_PER_MINUTE",
    "IspDiagnosticsRateLimitedError",
    "SECURITY_OPS_TWINS",
    "get_isp_rate_limited_diagnostics_service",
]

# -- Fix a Problem: the per-ISP-user rate limit (ADDENDUM_04 §3 Operations) ---

#: Ping/traceroute runs one ISP user may start per minute, across every
#: customer. The diagnostics service keeps its own per-router cooldown and
#: per-organization window on top of this.
DIAGNOSTICS_PER_USER_PER_MINUTE = 10


class IspDiagnosticsRateLimitedError(IspError):
    code = "ISP_DIAGNOSTICS_RATE_LIMITED"
    status_code_default = status.HTTP_429_TOO_MANY_REQUESTS
    default_message = (
        "Too many diagnostics started in the last minute. Wait a moment and retry."
    )


async def get_isp_rate_limited_diagnostics_service(
    request: Request,
    service=Depends(get_network_diagnostics_service),
    redis: Redis = Depends(get_redis_client),
    actor: AuthUser = Depends(CurrentUser),
):
    """The diagnostics service, after counting this ISP user's run.

    Supplied to the twin as the handler's ``service`` dependency, so the
    original handler is called unchanged. Reads (run history) are not counted.
    A Redis failure does not open the gate silently: it propagates, exactly
    as the service's own limiter does.
    """
    if request.method.upper() != "GET":
        window = int(time.time() // 60)
        key = f"isp:diagnostics:user:{actor.id}:{window}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 120)
        if count > DIAGNOSTICS_PER_USER_PER_MINUTE:
            raise IspDiagnosticsRateLimitedError()
    return service


# -- shared parameters ---------------------------------------------------------

_Page = Param("page", "query", int, 1)
_PageSize = Param("page_size", "query", int, 25)
_RuleId = Param("rule_id", "path", uuid.UUID)
_DeviceId = Param("device_id", "path", uuid.UUID)
_RunId = Param("run_id", "path", uuid.UUID)
_AppKey = Param("app_key", "path", str)

_RouterQuery = Extra("isp_router_id", "query", "router", "router_id")
_RouterPath = Extra("isp_router_id", "path", "router", "router_id", required=True)

_ORG = {"requesting_organization_id": ("org",)}
_ORG_ACTOR = {"requesting_organization_id": ("org",), "actor": ("user",)}


def _body(model) -> Param:
    return Param("payload", "body", model, inspect.Parameter.empty)


SECURITY_OPS_TWINS: tuple[TwinSpec, ...] = (
    # -- Security Score -----------------------------------------------------
    TwinSpec(
        method="GET",
        path="/venue/security/overview",
        permission_key=ISP_SECURITY_READ,
        handler=security_routes.get_security_overview,
        target="header_location",
        deps={"service": get_security_service},
        inject={
            "requesting_organization_id": ("org",),
            "requesting_location_id": ("location",),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/security/score",
        permission_key=ISP_SECURITY_READ,
        handler=security_routes.get_security_score,
        target="header_location",
        deps={"service": get_security_service},
        inject={
            "requesting_organization_id": ("org",),
            "requesting_location_id": ("location",),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/security/capabilities",
        permission_key=ISP_SECURITY_READ,
        handler=security_routes.list_security_capabilities,
        # Static: what the platform can enforce, the same for every tenant.
        # No tenant id reaches the handler, so there is nothing to resolve.
        target="none",
        deps={"service": get_security_service},
    ),
    # -- Block Websites: content-filter rules --------------------------------
    TwinSpec(
        method="GET",
        path="/venue/content-filter-rules/routers/{isp_router_id}/apps",
        permission_key=ISP_SECURITY_READ,
        handler=content_filter_routes.list_content_filter_apps,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_content_filter_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="PUT",
        path="/venue/content-filter-rules/routers/{isp_router_id}/apps/{app_key}",
        permission_key=ISP_SECURITY_UPDATE,
        handler=content_filter_routes.block_content_filter_app,
        target="header_location",
        params=(_AppKey,),
        extras=(_RouterPath,),
        deps={"service": get_content_filter_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/content-filter-rules/routers/{isp_router_id}/apps/{app_key}",
        permission_key=ISP_SECURITY_UPDATE,
        handler=content_filter_routes.unblock_content_filter_app,
        target="header_location",
        params=(_AppKey,),
        extras=(_RouterPath,),
        deps={"service": get_content_filter_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/content-filter-rules",
        permission_key=ISP_SECURITY_CREATE,
        handler=content_filter_routes.create_content_filter_rule,
        target="header_location",
        params=(_body(ContentFilterRuleCreateRequest),),
        body_ids=(BodyId("router_id", "router"),),
        deps={"service": get_content_filter_service},
        inject=_ORG_ACTOR,
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/content-filter-rules",
        permission_key=ISP_SECURITY_READ,
        handler=content_filter_routes.list_content_filter_rules,
        target="header_location",
        params=(_Page, _PageSize, Param("exclude_app_rules", "query", bool, False)),
        extras=(_RouterQuery,),
        deps={"service": get_content_filter_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="GET",
        path="/venue/content-filter-rules/{rule_id}",
        permission_key=ISP_SECURITY_READ,
        handler=content_filter_routes.get_content_filter_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_content_filter_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="PUT",
        path="/venue/content-filter-rules/{rule_id}",
        permission_key=ISP_SECURITY_UPDATE,
        handler=content_filter_routes.update_content_filter_rule,
        target="header_location",
        params=(_RuleId, _body(ContentFilterRuleUpdateRequest)),
        deps={"service": get_content_filter_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/content-filter-rules/{rule_id}",
        permission_key=ISP_SECURITY_DELETE,
        handler=content_filter_routes.delete_content_filter_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_content_filter_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/content-filter-rules/{rule_id}/push",
        permission_key=ISP_SECURITY_EXECUTE,
        handler=content_filter_routes.push_content_filter_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_content_filter_service},
        inject=_ORG_ACTOR,
    ),
    # -- Block Websites: DNS category filtering -------------------------------
    TwinSpec(
        method="GET",
        path="/venue/dns-filtering/categories",
        permission_key=ISP_SECURITY_READ,
        handler=dns_filter_routes.list_categories,
        # Cloudflare's category catalogue, the same for everyone. The
        # original's ``location_id`` exists only to pin ITS permission check
        # and is never read, so no tenant id is resolved or forwarded here.
        target="none",
        deps={"service": get_dns_filtering_service},
        inject={"location_id": ("const", None)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/dns-filtering/organization-policy",
        permission_key=ISP_SECURITY_READ,
        handler=dns_filter_routes.get_organization_policy,
        target="header_location",
        deps={"service": get_dns_filtering_service},
        inject={"organization_id": ("org",)},
    ),
    TwinSpec(
        method="PUT",
        path="/venue/dns-filtering/organization-policy",
        permission_key=ISP_SECURITY_UPDATE,
        handler=dns_filter_routes.set_organization_policy,
        target="header_location",
        params=(_body(PolicyUpdateRequest),),
        body_ids=(BodyId("category_ids", "opaque"),),
        deps={"service": get_dns_filtering_service},
        inject={"organization_id": ("org",), "actor": ("user",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/dns-filtering/location-policy",
        permission_key=ISP_SECURITY_READ,
        handler=dns_filter_routes.get_location_policy,
        target="header_location",
        deps={"service": get_dns_filtering_service},
        inject={"location_id": ("location",), "requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="PUT",
        path="/venue/dns-filtering/location-policy",
        permission_key=ISP_SECURITY_UPDATE,
        handler=dns_filter_routes.set_location_policy,
        target="header_location",
        params=(_body(PolicyUpdateRequest),),
        body_ids=(BodyId("category_ids", "opaque"),),
        deps={"service": get_dns_filtering_service},
        inject={
            "location_id": ("location",),
            "requesting_organization_id": ("org",),
            "actor": ("user",),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/dns-filtering/routers/{isp_router_id}",
        permission_key=ISP_SECURITY_READ,
        handler=dns_filter_routes.get_router_status,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_dns_filtering_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="POST",
        path="/venue/dns-filtering/routers/{isp_router_id}/enable",
        permission_key=ISP_SECURITY_EXECUTE,
        handler=dns_filter_routes.enable_router,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_dns_filtering_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/dns-filtering/routers/{isp_router_id}/disable",
        permission_key=ISP_SECURITY_EXECUTE,
        handler=dns_filter_routes.disable_router,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_dns_filtering_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="PUT",
        path="/venue/dns-filtering/routers/{isp_router_id}/bypass-hardening",
        permission_key=ISP_SECURITY_EXECUTE,
        handler=dns_filter_routes.set_bypass_hardening,
        target="header_location",
        params=(_body(BypassHardeningRequest),),
        extras=(_RouterPath,),
        deps={"service": get_dns_filtering_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="GET",
        path="/venue/dns-filtering/routers/{isp_router_id}/bypass-hardening/counters",
        permission_key=ISP_SECURITY_READ,
        handler=dns_filter_routes.get_bypass_counters,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_dns_filtering_service},
        inject=_ORG,
    ),
    # -- Firewall: the customer's own rules (never the Wyfy band) -------------
    TwinSpec(
        method="POST",
        path="/venue/firewall-rules",
        permission_key=ISP_SECURITY_CREATE,
        handler=firewall_routes.create_firewall_rule,
        target="header_location",
        params=(_body(FirewallRuleCreateRequest),),
        body_ids=(BodyId("router_id", "router"),),
        deps={"service": get_firewall_service},
        inject=_ORG_ACTOR,
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/firewall-rules",
        permission_key=ISP_SECURITY_READ,
        handler=firewall_routes.list_firewall_rules,
        target="header_location",
        params=(_Page, _PageSize),
        extras=(_RouterQuery,),
        deps={"service": get_firewall_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="GET",
        path="/venue/firewall-rules/{rule_id}",
        permission_key=ISP_SECURITY_READ,
        handler=firewall_routes.get_firewall_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_firewall_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="PUT",
        path="/venue/firewall-rules/{rule_id}",
        permission_key=ISP_SECURITY_UPDATE,
        handler=firewall_routes.update_firewall_rule,
        target="header_location",
        params=(_RuleId, _body(FirewallRuleUpdateRequest)),
        deps={"service": get_firewall_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/firewall-rules/{rule_id}",
        permission_key=ISP_SECURITY_DELETE,
        handler=firewall_routes.delete_firewall_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_firewall_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/firewall-rules/routers/{isp_router_id}/push",
        permission_key=ISP_SECURITY_EXECUTE,
        handler=firewall_routes.push_firewall_rules,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_firewall_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="GET",
        path="/venue/firewall-rules/routers/{isp_router_id}/flood-limit",
        permission_key=ISP_SECURITY_READ,
        handler=firewall_routes.get_flood_limit,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_firewall_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="PUT",
        path="/venue/firewall-rules/routers/{isp_router_id}/flood-limit",
        permission_key=ISP_SECURITY_EXECUTE,
        handler=firewall_routes.set_flood_limit,
        target="header_location",
        params=(_body(FloodLimitUpdateRequest),),
        extras=(_RouterPath,),
        deps={"service": get_firewall_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="GET",
        path="/venue/firewall-rules/routers/{isp_router_id}/guest-isolation",
        permission_key=ISP_SECURITY_READ,
        handler=firewall_routes.get_guest_isolation,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_firewall_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="PUT",
        path="/venue/firewall-rules/routers/{isp_router_id}/guest-isolation",
        permission_key=ISP_SECURITY_EXECUTE,
        handler=firewall_routes.set_guest_isolation,
        target="header_location",
        params=(_body(GuestIsolationUpdateRequest),),
        extras=(_RouterPath,),
        deps={"service": get_firewall_service},
        inject=_ORG_ACTOR,
    ),
    # -- Fix a Problem (network diagnostics) ----------------------------------
    TwinSpec(
        method="POST",
        path="/venue/network-diagnostics/routers/{isp_router_id}/ping",
        permission_key=ISP_OPS_EXECUTE,
        handler=diagnostics_routes.ping_router,
        paid_write=False,  # the original router is not on _PAID_WRITES
        target="header_location",
        params=(_body(PingRequest),),
        extras=(_RouterPath,),
        deps={"service": get_isp_rate_limited_diagnostics_service},
        inject={
            "requesting_organization_id": ("org",),
            "scope_location_id": ("location",),
            "actor": ("user",),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/network-diagnostics/routers/{isp_router_id}/traceroute",
        permission_key=ISP_OPS_EXECUTE,
        handler=diagnostics_routes.traceroute_router,
        paid_write=False,  # the original router is not on _PAID_WRITES
        target="header_location",
        params=(_body(TracerouteRequest),),
        extras=(_RouterPath,),
        deps={"service": get_isp_rate_limited_diagnostics_service},
        inject={
            "requesting_organization_id": ("org",),
            "scope_location_id": ("location",),
            "actor": ("user",),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/network-diagnostics/runs",
        permission_key=ISP_OPS_EXECUTE,
        handler=diagnostics_routes.list_diagnostic_runs,
        target="header_location",
        params=(_Page, _PageSize),
        extras=(_RouterQuery,),
        deps={"service": get_network_diagnostics_service},
        inject={
            "requesting_organization_id": ("org",),
            "scope_location_id": ("location",),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/network-diagnostics/runs/{run_id}",
        permission_key=ISP_OPS_EXECUTE,
        handler=diagnostics_routes.get_diagnostic_run,
        target="header_location",
        params=(_RunId,),
        deps={"service": get_network_diagnostics_service},
        inject={
            "requesting_organization_id": ("org",),
            "scope_location_id": ("location",),
        },
    ),
    # -- Devices: connected clients -------------------------------------------
    TwinSpec(
        method="GET",
        path="/venue/connected-devices",
        permission_key=ISP_MONITOR_READ,
        handler=connected_device_routes.list_connected_devices,
        target="header_location",
        params=(
            _Page,
            _PageSize,
            Param("is_active", "query", bool | None, None),
            Param("guest_id", "query", uuid.UUID | None, None),
        ),
        extras=(_RouterQuery,),
        deps={"service": get_connected_device_service},
        inject={"requesting_organization_id": ("org",), "location_id": ("location",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/connected-devices/sync/{isp_router_id}",
        permission_key=ISP_MONITOR_UPDATE,
        handler=connected_device_routes.sync_connected_devices,
        paid_write=False,  # connected_devices_router is not on _PAID_WRITES
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_connected_device_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="GET",
        path="/venue/connected-devices/{device_id}",
        permission_key=ISP_MONITOR_READ,
        handler=connected_device_routes.get_connected_device,
        target="header_location",
        params=(_DeviceId,),
        deps={"service": get_connected_device_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/connected-devices/{device_id}",
        permission_key=ISP_MONITOR_UPDATE,
        handler=connected_device_routes.delete_connected_device,
        paid_write=False,  # connected_devices_router is not on _PAID_WRITES
        target="header_location",
        params=(_DeviceId,),
        deps={"service": get_connected_device_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/connected-devices/{device_id}/comment",
        permission_key=ISP_MONITOR_UPDATE,
        handler=connected_device_routes.add_connected_device_comment,
        paid_write=False,  # connected_devices_router is not on _PAID_WRITES
        target="header_location",
        params=(_DeviceId, _body(ConnectedDeviceCommentRequest)),
        deps={"service": get_connected_device_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/connected-devices/{device_id}/disconnect",
        permission_key=ISP_MONITOR_UPDATE,
        handler=connected_device_routes.disconnect_connected_device,
        paid_write=False,  # connected_devices_router is not on _PAID_WRITES
        target="header_location",
        params=(_DeviceId,),
        deps={"service": get_connected_device_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/connected-devices/{device_id}/refresh",
        permission_key=ISP_MONITOR_UPDATE,
        handler=connected_device_routes.refresh_connected_device,
        paid_write=False,  # connected_devices_router is not on _PAID_WRITES
        target="header_location",
        params=(_DeviceId,),
        deps={"service": get_connected_device_service},
        inject=_ORG,
    ),
    TwinSpec(
        method="POST",
        path="/venue/connected-devices/{device_id}/block",
        permission_key=ISP_MONITOR_UPDATE,
        handler=connected_device_routes.block_connected_device,
        paid_write=False,  # connected_devices_router is not on _PAID_WRITES
        target="header_location",
        params=(_DeviceId, _body(ConnectedDeviceAccessActionRequest)),
        deps={"service": get_connected_device_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/connected-devices/{device_id}/unblock",
        permission_key=ISP_MONITOR_UPDATE,
        handler=connected_device_routes.unblock_connected_device,
        paid_write=False,  # connected_devices_router is not on _PAID_WRITES
        target="header_location",
        params=(_DeviceId,),
        deps={"service": get_connected_device_service},
        inject=_ORG_ACTOR,
    ),
    TwinSpec(
        method="POST",
        path="/venue/connected-devices/{device_id}/whitelist",
        permission_key=ISP_MONITOR_UPDATE,
        handler=connected_device_routes.whitelist_connected_device,
        paid_write=False,  # connected_devices_router is not on _PAID_WRITES
        target="header_location",
        params=(_DeviceId, _body(ConnectedDeviceAccessActionRequest)),
        deps={"service": get_connected_device_service},
        inject=_ORG_ACTOR,
    ),
    # -- Devices: monitored hardware (APs, switches) --------------------------
    TwinSpec(
        method="POST",
        path="/venue/monitored-hardware",
        permission_key=ISP_MONITOR_UPDATE,
        handler=monitored_hardware_routes.register_monitored_hardware,
        target="header_location",
        params=(_body(MonitoredHardwareRegisterRequest),),
        body_ids=(
            BodyId("location_id", "force_location"),
            BodyId("router_id", "router"),
        ),
        deps={"service": get_monitored_hardware_service},
        inject=_ORG_ACTOR,
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/monitored-hardware",
        permission_key=ISP_MONITOR_READ,
        handler=monitored_hardware_routes.list_monitored_hardware,
        target="header_location",
        params=(_Page, Param("page_size", "query", int, 100)),
        deps={"service": get_monitored_hardware_service},
        inject={"requesting_organization_id": ("org",), "location_id": ("location",)},
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/monitored-hardware/{device_id}",
        permission_key=ISP_MONITOR_UPDATE,
        handler=monitored_hardware_routes.delete_monitored_hardware,
        target="header_location",
        params=(_DeviceId,),
        deps={"service": get_monitored_hardware_service},
        inject=_ORG_ACTOR,
    ),
)
