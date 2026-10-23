"""The venue twins: the customer dashboard's own endpoints, ISP-gated.

Each row here is one customer-facing endpoint the ISP console is allowed to
call on a customer's venue. Read :mod:`app.domains.isp_partner.twins` first --
it explains the twin pattern, the generated signatures and the invariants.

WHY ``/isp/venue/*`` AND NOT ``/isp/*``
---------------------------------------
The unrelated ``app.domains.isp`` domain (WAN links, failover) already mounts
an ``APIRouter(prefix="/isp")`` and is included **before** ``isp_partner_router``
in ``app/api/v1/router.py``. A twin that reused one of its paths (``/isp/links``,
``/isp/routers/{id}/failover``, ...) would be shadowed by it and never run.
Everything in this module therefore lives under ``/isp/venue``, which nothing
else owns, and which gives the frontend shim a single prefix to rewrite.

HOW A CALL FLOWS
----------------
The partner console's venue workspace pins ``X-Isp-Customer-Id`` and
``X-Isp-Location-Id`` on the api client, then calls the customer path exactly as
the customer app does (``/api/v1/vlans``, ``/api/v1/dhcp-pools``, ...). The
shim rewrites the path prefix to ``/isp/venue/...``. The twin resolves the
location through :class:`IspScope` (404 for another ISP's, an archived one, or
one outside the caller's confinement), then calls the ORIGINAL handler with
``requesting_organization_id=<that location's customer>``. The handler's service
keeps every tenant check it already had, so a row id belonging to a different
customer still 404s inside the service.

EXPOSED PARAMETERS NEVER USE A SCOPE-ALIAS NAME
-----------------------------------------------
``organization_id`` / ``customer_id`` / ``location_id`` / ``router_id`` are RBAC
scope aliases: naming one as a route parameter would move the permission check
onto a customer org (see ``tests/unit/test_isp_partner_guards.py``). The
customer org and location therefore reach the handler through ``inject``, never
through the request, and a resource id uses the handler's own param name
(``vlan_pk`` here).
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime

from app.domains.captive_portal import router as portal_routes
from app.domains.captive_portal.dependencies import get_captive_portal_service
from app.domains.dhcp import router as dhcp_routes
from app.domains.dhcp.dependencies import get_dhcp_service
from app.domains.dhcp.schemas import (
    CaptivePortalDhcpOptionRequest,
    DhcpLeaseKeepRequest,
    DhcpPoolCreateRequest,
    DhcpPoolUpdateRequest,
)
from app.domains.guest import router as guest_routes
from app.domains.guest.dependencies import get_guest_service
from app.domains.guest_access import router as guest_access_routes
from app.domains.guest_access.constants import AccessRuleType
from app.domains.guest_access.dependencies import get_guest_access_service
from app.domains.guest_access.schemas import GuestAccessRuleCreate
from app.domains.isp import router as isp_link_routes
from app.domains.isp.dependencies import get_isp_service
from app.domains.isp.schemas import (
    IspLinkCreateRequest,
    IspLinkUpdateRequest,
    WanRoutingModeRequest,
)
from app.domains.mac_authorization import router as mac_auth_routes
from app.domains.mac_authorization.dependencies import get_mac_authorization_service
from app.domains.mac_authorization.schemas import (
    MacAuthorizationEntryCreateRequest,
    MacAuthorizationEntryUpdateRequest,
)
from app.domains.policy import router as policy_routes
from app.domains.policy.constants import PolicyType
from app.domains.policy.dependencies import get_policy_service, get_role_resolver
from app.domains.policy.schemas import (
    PolicyAssignmentCreateRequest,
    PolicyCreateRequest,
)
from app.domains.port_forwarding import router as port_forwarding_routes
from app.domains.port_forwarding.dependencies import get_port_forwarding_service
from app.domains.port_forwarding.schemas import (
    PortForwardingRuleCreateRequest,
    PortForwardingRuleUpdateRequest,
)
from app.domains.qos import router as qos_routes
from app.domains.qos.dependencies import get_qos_service
from app.domains.qos.schemas import (
    QosTrafficRuleCreateRequest,
    QosTrafficRuleUpdateRequest,
)
from app.domains.vlan import router as vlan_routes
from app.domains.vlan.dependencies import get_vlan_service
from app.domains.vlan.schemas import VlanCreateRequest, VlanUpdateRequest
from app.domains.voucher import router as voucher_routes
from app.domains.voucher.dependencies import get_voucher_service

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
)
from .twin_body import BodyId
from .twins import Extra, Param, TwinSpec

__all__ = ["VENUE_TWINS"]

_Page = Param("page", "query", int, 1)
_PageSize = Param("page_size", "query", int, 25)
_VlanPk = Param("vlan_pk", "path", uuid.UUID)
_PoolId = Param("pool_id", "path", uuid.UUID)
_RuleId = Param("rule_id", "path", uuid.UUID)
_EntryId = Param("entry_id", "path", uuid.UUID)
_PolicyId = Param("policy_id", "path", uuid.UUID)
_AssignmentId = Param("assignment_id", "path", uuid.UUID)
_LinkId = Param("link_id", "path", uuid.UUID)

#: The customer pages filter by router. ``router_id`` is a scope alias, so it
#: cannot be a parameter name here (the guard test rejects it); the frontend
#: shim renames the query key ``router_id`` -> ``isp_router_id`` on venue calls.
#: A path extra needs no rename -- a template's parameter name is never on the
#: wire.
_RouterQuery = Extra("isp_router_id", "query", "router", "router_id")
_RouterPath = Extra("isp_router_id", "path", "router", "router_id", required=True)

#: Every venue twin, in mount order.
VENUE_TWINS: tuple[TwinSpec, ...] = (
    # -- Network Zones (VLANs) ------------------------------------------------
    TwinSpec(
        method="GET",
        path="/venue/vlans",
        permission_key=ISP_NETWORK_READ,
        handler=vlan_routes.list_vlans,
        target="header_location",
        params=(_Page, _PageSize),
        # The router filter. Without it the handler falls back to its own
        # `router_id: uuid.UUID | None = Query(None)` default, and a Query
        # object reaches the repository as a bind parameter -- a 500, not an
        # unfiltered list. Found on the test box.
        extras=(_RouterQuery,),
        deps={"service": get_vlan_service},
        inject={
            "requesting_organization_id": ("org",),
            "location_id": ("location",),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/vlans",
        body_ids=(
            BodyId("router_id", "router"), BodyId("vlan_id", "opaque"),
        ),
        permission_key=ISP_NETWORK_CREATE,
        handler=vlan_routes.create_vlan,
        target="header_location",
        params=(Param("payload", "body", VlanCreateRequest, inspect.Parameter.empty),),
        deps={"service": get_vlan_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
        },
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/vlans/{vlan_pk}",
        permission_key=ISP_NETWORK_READ,
        handler=vlan_routes.get_vlan,
        target="header_location",
        params=(_VlanPk,),
        deps={"service": get_vlan_service},
        inject={
            "requesting_organization_id": ("org",),
            "vlan_pk": ("param", "vlan_pk"),
        },
    ),
    TwinSpec(
        method="PUT",
        path="/venue/vlans/{vlan_pk}",
        body_ids=(
            BodyId("vlan_id", "opaque"),
        ),
        permission_key=ISP_NETWORK_UPDATE,
        handler=vlan_routes.update_vlan,
        target="header_location",
        params=(
            _VlanPk,
            Param("payload", "body", VlanUpdateRequest, inspect.Parameter.empty),
        ),
        deps={"service": get_vlan_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "vlan_pk": ("param", "vlan_pk"),
        },
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/vlans/{vlan_pk}",
        permission_key=ISP_NETWORK_DELETE,
        handler=vlan_routes.delete_vlan,
        target="header_location",
        params=(_VlanPk,),
        deps={"service": get_vlan_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "vlan_pk": ("param", "vlan_pk"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/vlans/{vlan_pk}/push",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=vlan_routes.push_vlan,
        target="header_location",
        params=(_VlanPk,),
        deps={"service": get_vlan_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "vlan_pk": ("param", "vlan_pk"),
        },
    ),
    # -- IP Addresses (DHCP pools + a router's leases and portal option) -------
    TwinSpec(
        method="GET",
        path="/venue/dhcp-pools",
        permission_key=ISP_NETWORK_READ,
        handler=dhcp_routes.list_dhcp_pools,
        target="header_location",
        params=(_Page, _PageSize),
        extras=(_RouterQuery,),
        deps={"service": get_dhcp_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/dhcp-pools",
        body_ids=(
            BodyId("router_id", "router"),
        ),
        permission_key=ISP_NETWORK_CREATE,
        handler=dhcp_routes.create_dhcp_pool,
        target="header_location",
        params=(
            Param("payload", "body", DhcpPoolCreateRequest, inspect.Parameter.empty),
        ),
        deps={"service": get_dhcp_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/dhcp-pools/{pool_id}",
        permission_key=ISP_NETWORK_READ,
        handler=dhcp_routes.get_dhcp_pool,
        target="header_location",
        params=(_PoolId,),
        deps={"service": get_dhcp_service},
        inject={
            "requesting_organization_id": ("org",),
            "pool_id": ("param", "pool_id"),
        },
    ),
    TwinSpec(
        method="PUT",
        path="/venue/dhcp-pools/{pool_id}",
        permission_key=ISP_NETWORK_UPDATE,
        handler=dhcp_routes.update_dhcp_pool,
        target="header_location",
        params=(
            _PoolId,
            Param("payload", "body", DhcpPoolUpdateRequest, inspect.Parameter.empty),
        ),
        deps={"service": get_dhcp_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "pool_id": ("param", "pool_id"),
        },
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/dhcp-pools/{pool_id}",
        permission_key=ISP_NETWORK_DELETE,
        handler=dhcp_routes.delete_dhcp_pool,
        target="header_location",
        params=(_PoolId,),
        deps={"service": get_dhcp_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "pool_id": ("param", "pool_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/dhcp-pools/{pool_id}/push",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=dhcp_routes.push_dhcp_pool,
        target="header_location",
        params=(_PoolId,),
        deps={"service": get_dhcp_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "pool_id": ("param", "pool_id"),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/dhcp-pools/routers/{isp_router_id}/leases",
        permission_key=ISP_NETWORK_READ,
        handler=dhcp_routes.list_router_dhcp_leases,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_dhcp_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/dhcp-pools/routers/{isp_router_id}/captive-portal-option",
        permission_key=ISP_NETWORK_READ,
        handler=dhcp_routes.read_captive_portal_dhcp_option,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_dhcp_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="PUT",
        path="/venue/dhcp-pools/routers/{isp_router_id}/captive-portal-option",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=dhcp_routes.write_captive_portal_dhcp_option,
        target="header_location",
        extras=(_RouterPath,),
        params=(
            Param(
                "payload",
                "body",
                CaptivePortalDhcpOptionRequest,
                inspect.Parameter.empty,
            ),
        ),
        deps={"service": get_dhcp_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/dhcp-pools/routers/{isp_router_id}/captive-portal-option",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=dhcp_routes.remove_captive_portal_dhcp_option,
        target="header_location",
        extras=(_RouterPath,),
        deps={"service": get_dhcp_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/dhcp-pools/routers/{isp_router_id}/leases/keep-address",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=dhcp_routes.keep_router_dhcp_lease_address,
        target="header_location",
        extras=(_RouterPath,),
        params=(
            Param("payload", "body", DhcpLeaseKeepRequest, inspect.Parameter.empty),
        ),
        deps={"service": get_dhcp_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
    ),
    # -- Port Forwarding ------------------------------------------------------
    TwinSpec(
        method="GET",
        path="/venue/port-forwarding/rules",
        permission_key=ISP_NETWORK_READ,
        handler=port_forwarding_routes.list_port_forwarding_rules,
        target="header_location",
        params=(_Page, _PageSize),
        extras=(_RouterQuery,),
        deps={"service": get_port_forwarding_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/port-forwarding/rules",
        body_ids=(
            BodyId("router_id", "router"),
        ),
        permission_key=ISP_NETWORK_CREATE,
        handler=port_forwarding_routes.create_port_forwarding_rule,
        target="header_location",
        params=(
            Param(
                "payload",
                "body",
                PortForwardingRuleCreateRequest,
                inspect.Parameter.empty,
            ),
        ),
        deps={"service": get_port_forwarding_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/port-forwarding/rules/{rule_id}",
        permission_key=ISP_NETWORK_READ,
        handler=port_forwarding_routes.get_port_forwarding_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_port_forwarding_service},
        inject={
            "requesting_organization_id": ("org",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="PUT",
        path="/venue/port-forwarding/rules/{rule_id}",
        permission_key=ISP_NETWORK_UPDATE,
        handler=port_forwarding_routes.update_port_forwarding_rule,
        target="header_location",
        params=(
            _RuleId,
            Param(
                "payload",
                "body",
                PortForwardingRuleUpdateRequest,
                inspect.Parameter.empty,
            ),
        ),
        deps={"service": get_port_forwarding_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/port-forwarding/rules/{rule_id}",
        permission_key=ISP_NETWORK_DELETE,
        handler=port_forwarding_routes.delete_port_forwarding_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_port_forwarding_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/port-forwarding/rules/{rule_id}/push",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=port_forwarding_routes.push_port_forwarding_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_port_forwarding_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    # -- Call Priority (QoS) --------------------------------------------------
    TwinSpec(
        method="GET",
        path="/venue/qos-rules",
        permission_key=ISP_NETWORK_READ,
        handler=qos_routes.list_qos_rules,
        target="header_location",
        params=(_Page, _PageSize),
        extras=(_RouterQuery,),
        deps={"service": get_qos_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/qos-rules",
        body_ids=(
            BodyId("router_id", "router"),
        ),
        permission_key=ISP_NETWORK_CREATE,
        handler=qos_routes.create_qos_rule,
        target="header_location",
        params=(
            Param(
                "payload", "body", QosTrafficRuleCreateRequest, inspect.Parameter.empty
            ),
        ),
        deps={"service": get_qos_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/qos-rules/{rule_id}",
        permission_key=ISP_NETWORK_READ,
        handler=qos_routes.get_qos_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_qos_service},
        inject={
            "requesting_organization_id": ("org",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="PUT",
        path="/venue/qos-rules/{rule_id}",
        permission_key=ISP_NETWORK_UPDATE,
        handler=qos_routes.update_qos_rule,
        target="header_location",
        params=(
            _RuleId,
            Param(
                "payload", "body", QosTrafficRuleUpdateRequest, inspect.Parameter.empty
            ),
        ),
        deps={"service": get_qos_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/qos-rules/{rule_id}",
        permission_key=ISP_NETWORK_DELETE,
        handler=qos_routes.delete_qos_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_qos_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/qos-rules/{rule_id}/push",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=qos_routes.push_qos_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_qos_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    # -- Trusted Devices (MAC authorization) ----------------------------------
    TwinSpec(
        method="GET",
        path="/venue/mac-authorization/entries",
        permission_key=ISP_ACCESS_READ,
        handler=mac_auth_routes.list_mac_authorization_entries,
        target="header_location",
        params=(_Page, _PageSize),
        deps={"service": get_mac_authorization_service},
        inject={
            "requesting_organization_id": ("org",),
            "location_id": ("location",),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/mac-authorization/entries",
        body_ids=(
            BodyId("location_id", "force_location"),
        ),
        permission_key=ISP_ACCESS_CREATE,
        handler=mac_auth_routes.create_mac_authorization_entry,
        target="header_location",
        params=(
            Param(
                "payload",
                "body",
                MacAuthorizationEntryCreateRequest,
                inspect.Parameter.empty,
            ),
        ),
        deps={"service": get_mac_authorization_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/mac-authorization/entries/{entry_id}",
        permission_key=ISP_ACCESS_READ,
        handler=mac_auth_routes.get_mac_authorization_entry,
        target="header_location",
        params=(_EntryId,),
        deps={"service": get_mac_authorization_service},
        inject={
            "requesting_organization_id": ("org",),
            "entry_id": ("param", "entry_id"),
        },
    ),
    TwinSpec(
        method="PUT",
        path="/venue/mac-authorization/entries/{entry_id}",
        body_ids=(
            BodyId("location_id", "force_location"),
        ),
        permission_key=ISP_ACCESS_UPDATE,
        handler=mac_auth_routes.update_mac_authorization_entry,
        target="header_location",
        params=(
            _EntryId,
            Param(
                "payload",
                "body",
                MacAuthorizationEntryUpdateRequest,
                inspect.Parameter.empty,
            ),
        ),
        deps={"service": get_mac_authorization_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "entry_id": ("param", "entry_id"),
        },
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/mac-authorization/entries/{entry_id}",
        permission_key=ISP_ACCESS_DELETE,
        handler=mac_auth_routes.delete_mac_authorization_entry,
        target="header_location",
        params=(_EntryId,),
        deps={"service": get_mac_authorization_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "entry_id": ("param", "entry_id"),
        },
    ),
    # -- Guest Allow-list (guest access rules) --------------------------------
    TwinSpec(
        method="GET",
        path="/venue/guest-access/rules",
        permission_key=ISP_ACCESS_READ,
        handler=guest_access_routes.list_guest_rules,
        target="header_location",
        params=(
            _Page,
            _PageSize,
            # Both filters are supplied even when the caller omits them: the
            # handler's own defaults are `Query(None)` objects, which reach the
            # repository as bind parameters if they are not passed.
            Param("identifier", "query", str | None, None),
            Param("rule_type", "query", AccessRuleType | None, None),
        ),
        deps={"service": get_guest_access_service},
        inject={
            "requesting_organization_id": ("org",),
            "location_id": ("location",),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/guest-access/rules",
        body_ids=(
            BodyId("organization_id", "force_org"),
            BodyId("location_id", "force_location"),
        ),
        permission_key=ISP_ACCESS_CREATE,
        handler=guest_access_routes.create_guest_rule,
        target="header_location",
        params=(
            Param("payload", "body", GuestAccessRuleCreate, inspect.Parameter.empty),
        ),
        deps={"service": get_guest_access_service},
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/guest-access/rules/{rule_id}",
        permission_key=ISP_ACCESS_READ,
        handler=guest_access_routes.get_guest_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_guest_access_service},
        inject={
            "requesting_organization_id": ("org",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/guest-access/rules/{rule_id}/enforce",
        permission_key=ISP_ACCESS_EXECUTE,
        handler=guest_access_routes.enforce_guest_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_guest_access_service},
        inject={
            "requesting_organization_id": ("org",),
            "user": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/guest-access/rules/{rule_id}/deactivate",
        permission_key=ISP_ACCESS_UPDATE,
        handler=guest_access_routes.deactivate_guest_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_guest_access_service},
        inject={
            "requesting_organization_id": ("org",),
            "user": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/guest-access/rules/{rule_id}",
        permission_key=ISP_ACCESS_DELETE,
        handler=guest_access_routes.delete_guest_rule,
        target="header_location",
        params=(_RuleId,),
        deps={"service": get_guest_access_service},
        inject={
            "requesting_organization_id": ("org",),
            "user": ("user",),
            "rule_id": ("param", "rule_id"),
        },
    ),
    # -- Reports: guest sessions (the base of most of the report catalogue) ----
    TwinSpec(
        method="GET",
        path="/venue/guest-sessions",
        permission_key=ISP_ACCESS_READ,
        handler=guest_routes.list_guest_sessions,
        target="header_location",
        params=(
            _Page,
            _PageSize,
            Param("start_date", "query", datetime | None, None),
            Param("end_date", "query", datetime | None, None),
        ),
        extras=(_RouterQuery,),
        deps={"service": get_guest_service},
        inject={
            "requesting_organization_id": ("org",),
            "location_id": ("location",),
            # CurrentLocation is a dependency on the original route; /isp refuses
            # X-Location-Id, so the twin supplies the resolved location itself.
            "scope_location_id": ("location",),
            # Optional filters the twin does not expose. They MUST be supplied:
            # their handler defaults are Query objects, which reach the DB layer
            # as bind parameters (see the contract test).
            "guest_id": ("const", None),
            "status_filter": ("const", None),
        },
    ),
    # -- Reports: guests (the other half of the report catalogue's base) ------
    TwinSpec(
        method="GET",
        path="/venue/guests",
        permission_key=ISP_ACCESS_READ,
        handler=guest_routes.list_guests,
        target="header_location",
        params=(
            _Page,
            _PageSize,
            Param("search", "query", str | None, None),
        ),
        deps={"service": get_guest_service},
        inject={
            "requesting_organization_id": ("org",),
            "location_id": ("location",),
            "scope_location_id": ("location",),
            # Not exposed; supplied explicitly so the handler's Query default
            # never reaches the DB layer.
            "is_blocked": ("const", None),
        },
    ),
    # -- Reports: voucher batches (batch redemption rate) ---------------------
    TwinSpec(
        method="GET",
        path="/venue/voucher-batches",
        permission_key=ISP_ACCESS_READ,
        handler=voucher_routes.list_voucher_batches,
        target="header_location",
        params=(_Page, _PageSize),
        deps={"service": get_voucher_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    # -- Open Hours (the captive-portal resolve the page reads) ---------------
    TwinSpec(
        method="GET",
        path="/venue/captive-portal/resolve",
        permission_key=ISP_ACCESS_READ,
        handler=portal_routes.resolve_captive_portal_config,
        target="header_location",
        deps={"service": get_captive_portal_service},
        inject={
            "organization_id": ("org",),
            "location_id": ("location",),
        },
    ),
    # -- Access Rules (policies) ---------------------------------------------
    #
    # ORDER: ``/venue/policies/resolve`` is registered before
    # ``/venue/policies/{policy_id}``. Starlette matches in registration order,
    # so the literal path must come first or the uuid route captures it and
    # fails path-parameter parsing -- the same reason the original router
    # documents. The table order below is load-bearing.
    TwinSpec(
        method="GET",
        path="/venue/policies",
        permission_key=ISP_ACCESS_READ,
        handler=policy_routes.list_policies,
        target="header_location",
        params=(
            _Page,
            _PageSize,
            Param("policy_type", "query", PolicyType | None, None),
        ),
        deps={"service": get_policy_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/policies/resolve",
        permission_key=ISP_ACCESS_READ,
        handler=policy_routes.resolve_effective_policy,
        target="header_location",
        params=(
            Param("policy_type", "query", PolicyType, inspect.Parameter.empty),
            Param("isp_user_id", "query", uuid.UUID | None, None),
            Param("guest_id", "query", uuid.UUID | None, None),
        ),
        deps={
            "service": get_policy_service,
            "role_resolver": get_role_resolver,
        },
        inject={
            "organization_id": ("org",),
            "location_id": ("location",),
            "user_id": ("param", "isp_user_id"),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/policies/{policy_id}",
        permission_key=ISP_ACCESS_READ,
        handler=policy_routes.get_policy,
        target="header_location",
        params=(_PolicyId,),
        deps={"service": get_policy_service},
        inject={
            "requesting_organization_id": ("org",),
            "policy_id": ("param", "policy_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/policies",
        body_ids=(
            BodyId("organization_id", "force_org"),
        ),
        permission_key=ISP_ACCESS_CREATE,
        handler=policy_routes.create_policy,
        target="header_location",
        params=(
            Param("payload", "body", PolicyCreateRequest, inspect.Parameter.empty),
        ),
        deps={"service": get_policy_service},
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="POST",
        path="/venue/policies/{policy_id}/deactivate",
        permission_key=ISP_ACCESS_EXECUTE,
        handler=policy_routes.deactivate_policy,
        target="header_location",
        params=(_PolicyId,),
        deps={"service": get_policy_service},
        inject={
            "requesting_organization_id": ("org",),
            "user": ("user",),
            "policy_id": ("param", "policy_id"),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/policies/{policy_id}/assignments",
        permission_key=ISP_ACCESS_READ,
        handler=policy_routes.list_policy_assignments,
        target="header_location",
        params=(_PolicyId,),
        deps={"service": get_policy_service},
        inject={
            "requesting_organization_id": ("org",),
            "policy_id": ("param", "policy_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/policies/{policy_id}/assignments",
        body_ids=(
            BodyId("scope_id", "policy_scope"),
            BodyId("target_id", "policy_target"),
        ),
        permission_key=ISP_ACCESS_CREATE,
        handler=policy_routes.create_policy_assignment,
        target="header_location",
        params=(
            _PolicyId,
            Param(
                "payload",
                "body",
                PolicyAssignmentCreateRequest,
                inspect.Parameter.empty,
            ),
        ),
        deps={"service": get_policy_service},
        inject={
            "requesting_organization_id": ("org",),
            "user": ("user",),
            "policy_id": ("param", "policy_id"),
        },
        status_code=201,
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/policies/{policy_id}/assignments/{assignment_id}",
        permission_key=ISP_ACCESS_EXECUTE,
        handler=policy_routes.deactivate_policy_assignment,
        target="header_location",
        params=(_PolicyId, _AssignmentId),
        deps={"service": get_policy_service},
        inject={
            "requesting_organization_id": ("org",),
            "user": ("user",),
            "policy_id": ("param", "policy_id"),
            "assignment_id": ("param", "assignment_id"),
        },
    ),
    # -- Internet Connection (WAN links) --------------------------------------
    TwinSpec(
        method="GET",
        path="/venue/isp/links",
        permission_key=ISP_NETWORK_READ,
        handler=isp_link_routes.list_isp_links,
        target="header_location",
        params=(_Page, _PageSize),
        extras=(_RouterQuery,),
        deps={"service": get_isp_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/isp/links",
        body_ids=(
            BodyId("router_id", "router"),
        ),
        permission_key=ISP_NETWORK_CREATE,
        handler=isp_link_routes.create_isp_link,
        target="header_location",
        params=(
            Param("payload", "body", IspLinkCreateRequest, inspect.Parameter.empty),
        ),
        deps={"service": get_isp_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/isp/links/{link_id}",
        permission_key=ISP_NETWORK_READ,
        handler=isp_link_routes.get_isp_link,
        target="header_location",
        params=(_LinkId,),
        deps={"service": get_isp_service},
        inject={
            "requesting_organization_id": ("org",),
            "link_id": ("param", "link_id"),
        },
    ),
    TwinSpec(
        method="PUT",
        path="/venue/isp/links/{link_id}",
        permission_key=ISP_NETWORK_UPDATE,
        handler=isp_link_routes.update_isp_link,
        target="header_location",
        params=(
            _LinkId,
            Param("payload", "body", IspLinkUpdateRequest, inspect.Parameter.empty),
        ),
        deps={"service": get_isp_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "link_id": ("param", "link_id"),
        },
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/isp/links/{link_id}",
        permission_key=ISP_NETWORK_DELETE,
        handler=isp_link_routes.delete_isp_link,
        target="header_location",
        params=(_LinkId,),
        deps={"service": get_isp_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "link_id": ("param", "link_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/isp/links/{link_id}/check-health",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=isp_link_routes.check_isp_link_health,
        target="header_location",
        params=(_LinkId,),
        deps={"service": get_isp_service},
        inject={
            "requesting_organization_id": ("org",),
            "link_id": ("param", "link_id"),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/isp/links/{link_id}/speed-test",
        permission_key=ISP_NETWORK_EXECUTE,
        handler=isp_link_routes.run_isp_link_speed_test,
        target="header_location",
        params=(_LinkId,),
        deps={"service": get_isp_service},
        inject={
            "requesting_organization_id": ("org",),
            "actor": ("user",),
            "link_id": ("param", "link_id"),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/isp/links/{link_id}/health-checks",
        permission_key=ISP_NETWORK_READ,
        handler=isp_link_routes.list_isp_link_health_checks,
        target="header_location",
        params=(
            _LinkId,
            _Page,
            _PageSize,
            Param("start_date", "query", datetime | None, None),
            Param("end_date", "query", datetime | None, None),
        ),
        deps={"service": get_isp_service},
        inject={
            "requesting_organization_id": ("org",),
            "link_id": ("param", "link_id"),
        },
    ),
    TwinSpec(
        method="GET",
        path="/venue/isp/links/{link_id}/health-checks/summary",
        permission_key=ISP_NETWORK_READ,
        handler=isp_link_routes.get_isp_link_health_check_summary,
        target="header_location",
        params=(
            _LinkId,
            Param("start_date", "query", datetime, inspect.Parameter.empty),
            Param("end_date", "query", datetime, inspect.Parameter.empty),
        ),
        deps={"service": get_isp_service},
        inject={
            "requesting_organization_id": ("org",),
            "link_id": ("param", "link_id"),
        },
    ),
    TwinSpec(
        method="PUT",
        path="/venue/isp/routers/{isp_router_id}/wan-routing-mode",
        permission_key=ISP_NETWORK_UPDATE,
        handler=isp_link_routes.set_wan_routing_mode,
        target="header_location",
        extras=(_RouterPath,),
        params=(
            Param("payload", "body", WanRoutingModeRequest, inspect.Parameter.empty),
        ),
        deps={"service": get_isp_service},
        inject={"requesting_organization_id": ("org",), "actor": ("user",)},
    ),
)
