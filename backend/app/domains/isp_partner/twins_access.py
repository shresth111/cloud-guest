"""B2 (Access & Policy): Guest Groups venue twins.

Access Rules, Guest Allow-list, Trusted Devices and Open Hours were twinned in
``twins_venue`` (cherry-picked from integ); this adds Guest Groups
(``/guest-teams`` admin router, on ``_PAID_WRITES``).

ADDENDUM_04 flags the guest-teams admin LIST as an open location-filter
defect (PR #309, not on main): with no ``location_id`` it lists every team of
the org. The twin therefore always injects the workspace's location from
``X-Isp-Location-Id`` -- it is never a request parameter, so it can never be
left empty. Create forces the body's ``organization_id``/``location_id`` the
same way. By-id routes rely on the service's org check (a team of another
customer is a 404); a team of another location of the SAME customer stays
reachable by id, which is the same customer's data.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime

from app.domains.guest import router as guest_routes
from app.domains.guest.dependencies import get_guest_service
from app.domains.guest_access import router as guest_access_routes
from app.domains.guest_access.constants import AccessRuleType
from app.domains.guest_access.dependencies import (
    get_guest_access_service,
)
from app.domains.guest_access.schemas import DeviceAccessRuleCreate
from app.domains.guest_teams import router as guest_teams_routes
from app.domains.guest_teams.dependencies import get_guest_team_service
from app.domains.guest_teams.schemas import (
    GuestTeamCreateRequest,
    GuestTeamMemberRemoveRequest,
    GuestTeamRevokeRequest,
)
from app.domains.isp import router as isp_link_routes
from app.domains.isp.dependencies import get_isp_service
from app.domains.isp.schemas import (
    IspFailoverRequest,
    IspLinkManualStatusRequest,
)
from app.domains.isp_routing import router as isp_routing_routes
from app.domains.isp_routing.dependencies import (
    get_isp_routing_service,
)
from app.domains.isp_routing.schemas import (
    IspRoutingRuleCreateRequest,
    IspRoutingRuleUpdateRequest,
)
from app.domains.location import router as location_routes
from app.domains.location.dependencies import get_location_service
from app.domains.policy import router as policy_routes
from app.domains.policy.dependencies import get_policy_service
from app.domains.policy.schemas import PolicyVersionCreateRequest
from app.domains.router import router as router_routes
from app.domains.router.dependencies import get_router_service

from .constants import (
    ISP_ACCESS_CREATE,
    ISP_ACCESS_DELETE,
    ISP_ACCESS_EXECUTE,
    ISP_ACCESS_READ,
    ISP_ACCESS_UPDATE,
    ISP_NETWORK_CREATE,
    ISP_NETWORK_DELETE,
    ISP_NETWORK_EXECUTE,
    ISP_NETWORK_READ,
    ISP_NETWORK_UPDATE,
    ISP_PARTNER_READ,
)
from .twin_body import BodyId
from .twins import Extra, Param, TwinSpec

__all__ = ["ACCESS_TWINS"]

_TeamId = Param("team_id", "path", uuid.UUID)
_deps = {"service": get_guest_team_service}


def _body(model) -> Param:
    return Param("payload", "body", model, inspect.Parameter.empty)


ACCESS_TWINS: tuple[TwinSpec, ...] = (
    TwinSpec(
        method="GET",
        path="/venue/guest-teams",
        permission_key=ISP_ACCESS_READ,
        handler=guest_teams_routes.list_guest_teams,
        target="header_location",
        params=(Param("page", "query", int, 1), Param("page_size", "query", int, 25)),
        deps=_deps,
        inject={
            "requesting_organization_id": ("org",),
            # ALWAYS the workspace location (open defect PR #309: an empty
            # location_id lists every team of the org).
            "location_id": ("location",),
            "status_filter": ("const", None),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/guest-teams",
        permission_key=ISP_ACCESS_CREATE,
        handler=guest_teams_routes.create_guest_team,
        target="header_location",
        params=(_body(GuestTeamCreateRequest),),
        body_ids=(
            BodyId("organization_id", "force_org"),
            BodyId("location_id", "force_location"),
        ),
        deps=_deps,
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/guest-teams/{team_id}",
        permission_key=ISP_ACCESS_READ,
        handler=guest_teams_routes.get_guest_team,
        target="header_location",
        params=(_TeamId,),
        deps=_deps,
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/guest-teams/{team_id}/members",
        permission_key=ISP_ACCESS_READ,
        handler=guest_teams_routes.list_guest_team_members,
        target="header_location",
        params=(_TeamId,),
        deps=_deps,
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/guest-teams/{team_id}/members/{guest_id}",
        permission_key=ISP_ACCESS_EXECUTE,
        handler=guest_teams_routes.remove_guest_team_member,
        target="header_location",
        params=(
            _TeamId,
            Param("guest_id", "path", uuid.UUID),
            _body(GuestTeamMemberRemoveRequest),
        ),
        deps=_deps,
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/guest-teams/{team_id}/revoke",
        permission_key=ISP_ACCESS_EXECUTE,
        handler=guest_teams_routes.revoke_guest_team,
        target="header_location",
        params=(_TeamId, _body(GuestTeamRevokeRequest)),
        deps=_deps,
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
    ),
)


# ---------------------------------------------------------------------------
# The rest of what the B2 customer pages call (found by the FE page collector,
# scripts/lib/isp-page-calls.mjs), plus Internet Connection (IspDetailsView).
# ---------------------------------------------------------------------------

_Page = Param("page", "query", int, 1)
_PageSize = Param("page_size", "query", int, 25)
_RuleId = Param("rule_id", "path", uuid.UUID)
_PolicyId = Param("policy_id", "path", uuid.UUID)
_LinkId = Param("link_id", "path", uuid.UUID)
_GuestId = Param("guest_id", "path", uuid.UUID)
_Location = Param("isp_location_id", "path", uuid.UUID, forward="location_id")
_RouterPath = Extra("isp_router_id", "path", "router", "router_id", required=True)
_RouterQuery = Extra("isp_router_id", "query", "router", "router_id")
_ga = {"service": get_guest_access_service}
_isp = {"service": get_isp_service}
_routing = {"service": get_isp_routing_service}
_pol = {"service": get_policy_service}
_org = {"requesting_organization_id": ("org",)}
_org_user = {"requesting_organization_id": ("org",), "user": ("user",)}
_org_actor = {"requesting_organization_id": ("org",), "actor": ("user",)}


def _row(method, path, key, handler, *, deps, inject, params=(), **kw) -> TwinSpec:
    return TwinSpec(
        method=method,
        path=path,
        permission_key=key,
        handler=handler,
        target=kw.pop("target", "header_location"),
        params=params,
        deps=deps,
        inject=inject,
        **kw,
    )


ACCESS_TWINS = ACCESS_TWINS + (
    # -- the venue's own location + routers (names, router pickers) ----------
    TwinSpec(
        method="GET",
        path="/venue/locations/{isp_location_id}",
        permission_key=ISP_PARTNER_READ,
        handler=location_routes.get_location,
        target="location",
        resolve_param="isp_location_id",
        params=(_Location,),
        deps={"location_service": get_location_service},
        inject=_org,
    ),
    TwinSpec(
        method="GET",
        path="/venue/locations/{isp_location_id}/routers",
        permission_key=ISP_PARTNER_READ,
        handler=router_routes.list_routers,
        target="location",
        resolve_param="isp_location_id",
        params=(
            _Location,
            _Page,
            _PageSize,
            Param("search", "query", str | None, None),
        ),
        deps={"router_service": get_router_service},
        inject={**_org, "router_status": ("const", None)},
    ),
    # -- guests (policy pickers) -----------------------------------------------
    _row(
        "GET",
        "/venue/guests/{guest_id}",
        ISP_ACCESS_READ,
        guest_routes.get_guest,
        params=(_GuestId,),
        deps={"service": get_guest_service},
        inject=_org,
    ),
    _row(
        "GET",
        "/venue/guest-login-history",
        ISP_ACCESS_READ,
        guest_routes.list_guest_login_history,
        params=(
            _Page,
            _PageSize,
            Param("guest_id", "query", uuid.UUID | None, None),
            Param("start_date", "query", datetime | None, None),
            Param("end_date", "query", datetime | None, None),
        ),
        deps={"service": get_guest_service},
        inject={
            **_org,
            "location_id": ("location",),
            "scope_location_id": ("location",),
        },
        redact_fields=("identifier",),
    ),
    # -- Access Rules: versions, publish, guest mapping --------------------------
    _row(
        "POST",
        "/venue/policies/{policy_id}/versions",
        ISP_ACCESS_UPDATE,
        policy_routes.create_policy_version,
        params=(_PolicyId, _body(PolicyVersionCreateRequest)),
        deps=_pol,
        inject=_org_user,
        status_code=201,
    ),
    _row(
        "POST",
        "/venue/policies/{policy_id}/versions/{version_id}/publish",
        ISP_ACCESS_EXECUTE,
        policy_routes.publish_policy_version,
        params=(_PolicyId, Param("version_id", "path", uuid.UUID)),
        deps=_pol,
        inject=_org_user,
    ),
    _row(
        "GET",
        "/venue/policies/guest-mapping/{guest_id}",
        ISP_ACCESS_READ,
        policy_routes.get_guest_group_assignment,
        params=(_GuestId,),
        deps=_pol,
        inject=_org,
    ),
    # -- Guest Allow-list: device rules ------------------------------------------
    _row(
        "GET",
        "/venue/guest-access/device-rules",
        ISP_ACCESS_READ,
        guest_access_routes.list_device_rules,
        params=(
            _Page,
            _PageSize,
            Param("mac_address", "query", str | None, None),
            Param("rule_type", "query", AccessRuleType | None, None),
        ),
        deps=_ga,
        inject={**_org, "location_id": ("location",)},
    ),
    _row(
        "POST",
        "/venue/guest-access/device-rules",
        ISP_ACCESS_CREATE,
        guest_access_routes.create_device_rule,
        params=(_body(DeviceAccessRuleCreate),),
        body_ids=(
            BodyId("organization_id", "force_org"),
            BodyId("location_id", "force_location"),
        ),
        deps=_ga,
        inject=_org_user,
        status_code=201,
    ),
    _row(
        "GET",
        "/venue/guest-access/device-rules/{rule_id}",
        ISP_ACCESS_READ,
        guest_access_routes.get_device_rule,
        params=(_RuleId,),
        deps=_ga,
        inject=_org,
    ),
    _row(
        "POST",
        "/venue/guest-access/device-rules/{rule_id}/enforce",
        ISP_ACCESS_EXECUTE,
        guest_access_routes.enforce_device_rule,
        params=(_RuleId,),
        deps=_ga,
        inject=_org_user,
    ),
    _row(
        "POST",
        "/venue/guest-access/device-rules/{rule_id}/deactivate",
        ISP_ACCESS_EXECUTE,
        guest_access_routes.deactivate_device_rule,
        params=(_RuleId,),
        deps=_ga,
        inject=_org_user,
    ),
    _row(
        "DELETE",
        "/venue/guest-access/device-rules/{rule_id}",
        ISP_ACCESS_DELETE,
        guest_access_routes.delete_device_rule,
        params=(_RuleId,),
        deps=_ga,
        inject=_org_user,
    ),
    # -- Internet Connection: manual status, failover/failback, routing rules ---
    _row(
        "POST",
        "/venue/isp/links/{link_id}/status",
        ISP_NETWORK_UPDATE,
        isp_link_routes.set_isp_link_manual_status,
        params=(_LinkId, _body(IspLinkManualStatusRequest)),
        deps=_isp,
        inject=_org_actor,
    ),
    _row(
        "POST",
        "/venue/isp/routers/{isp_router_id}/failover",
        ISP_NETWORK_EXECUTE,
        isp_link_routes.trigger_isp_failover,
        params=(_body(IspFailoverRequest),),
        extras=(_RouterPath,),
        deps=_isp,
        inject=_org_actor,
    ),
    _row(
        "POST",
        "/venue/isp/routers/{isp_router_id}/failback",
        ISP_NETWORK_EXECUTE,
        isp_link_routes.trigger_isp_failback,
        extras=(_RouterPath,),
        deps=_isp,
        inject=_org_actor,
    ),
    _row(
        "GET",
        "/venue/isp-routing/rules",
        ISP_NETWORK_READ,
        isp_routing_routes.list_isp_routing_rules,
        params=(_Page, _PageSize),
        extras=(_RouterQuery,),
        deps=_routing,
        inject=_org,
    ),
    _row(
        "POST",
        "/venue/isp-routing/rules",
        ISP_NETWORK_CREATE,
        isp_routing_routes.create_isp_routing_rule,
        params=(_body(IspRoutingRuleCreateRequest),),
        body_ids=(
            BodyId("router_id", "router"),
            BodyId(
                "isp_link_id",
                "service_checked",
                note="IspRoutingService.create_rule loads the link with "
                "requesting_organization_id and refuses a link of another router",
            ),
            BodyId("vlan_id", "opaque"),
            BodyId("policy_id", "null_only"),
        ),
        deps=_routing,
        inject=_org_actor,
        status_code=201,
    ),
    _row(
        "GET",
        "/venue/isp-routing/rules/{rule_id}",
        ISP_NETWORK_READ,
        isp_routing_routes.get_isp_routing_rule,
        params=(_RuleId,),
        deps=_routing,
        inject=_org,
    ),
    _row(
        "PUT",
        "/venue/isp-routing/rules/{rule_id}",
        ISP_NETWORK_UPDATE,
        isp_routing_routes.update_isp_routing_rule,
        params=(_RuleId, _body(IspRoutingRuleUpdateRequest)),
        body_ids=(
            BodyId(
                "isp_link_id",
                "service_checked",
                note="IspRoutingService.update_rule reloads a changed link "
                "with requesting_organization_id and checks its router",
            ),
            BodyId("vlan_id", "opaque"),
            BodyId("policy_id", "null_only"),
        ),
        deps=_routing,
        inject=_org_actor,
    ),
    _row(
        "DELETE",
        "/venue/isp-routing/rules/{rule_id}",
        ISP_NETWORK_DELETE,
        isp_routing_routes.delete_isp_routing_rule,
        params=(_RuleId,),
        deps=_routing,
        inject=_org_actor,
    ),
)
