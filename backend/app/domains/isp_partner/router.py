"""``/isp`` HTTP surface (API_CONTRACT §4).

Every route carries ``isp_guards(<key>)`` -- RejectLocationRouterHeaders,
RequireOrganization, RequirePermission(<key>, scope=ORGANIZATION),
RequireIspPartner, in that order -- and the whole router sits behind
``RequireIspFeatureEnabled`` (404 while ``ISP_PARTNER_ENABLED`` is off).

Path and query ids are ``isp_customer_id`` / ``isp_location_id`` /
``isp_router_id`` / ``cpe_id`` / ``config_id`` / ``isp_user_id``. Never
``organization_id``, ``customer_id``, ``location_id`` or ``router_id``: those
are RBAC scope aliases and would move the permission check onto a customer
org. ``tests/unit/test_isp_partner_guards.py`` enforces both rules over the
mounted route table.

There is no route that creates a child under a customer and none that accepts
an org type.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field

from app.common.masking import mask_email, mask_mobile
from app.domains.auth.models import AuthUser
from app.domains.captive_portal import router as portal_routes
from app.domains.captive_portal.dependencies import get_captive_portal_service
from app.domains.captive_portal.schemas import CaptivePortalConfigUpdateRequest
from app.domains.captive_portal.service import CaptivePortalService
from app.domains.guest import router as guest_routes
from app.domains.guest.dependencies import get_radius_service
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import (
    CurrentUser,
    get_access_validator,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router import router as router_routes
from app.domains.router.dependencies import get_router_service
from app.domains.router.schemas import RouterManagementAccessRequest
from app.domains.router.service import RouterService
from app.domains.router_agent.dependencies import get_router_agent_service
from app.domains.router_agent.service import RouterAgentService
from app.domains.wireguard import router as wireguard_routes
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .config import RequireIspFeatureEnabled
from .constants import (
    AUDIT_ISP_ROUTER_SETUP_PREFIX,
    DEFAULT_PAGE_SIZE,
    ISP_PARTNER_CREATE,
    ISP_PARTNER_EXECUTE,
    ISP_PARTNER_MANAGE,
    ISP_PARTNER_READ,
    ISP_PARTNER_UPDATE,
    MAX_PAGE_SIZE,
    SETUP_SCRIPT_ROLES,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspForceNotAllowedError, IspSetupNotAllowedError
from .http import ok
from .providers import get_isp_partner_service, get_service_control
from .rbac_roles import all_permission_keys
from .schemas import (
    CustomerCreateRequest,
    CustomerUpdateRequest,
    IspLocationCreateRequest,
    IspLocationUpdateRequest,
    IspRouterCreateRequest,
    IspRouterUpdateRequest,
    SuspendRequest,
)
from .scoping import IspScope
from .service import IspPartnerService
from .service_control import IspServiceControl
from .twin_gates import (
    HAND_TWIN_GATES,
    enforce_customer_gates,
    get_twin_entitlement_checker,
)
from .twins import mount_twins
from .twins_all import ALL_TWINS

__all__ = ["isp_partner_router"]

isp_partner_router = APIRouter(
    prefix="/isp",
    tags=["ISP Partner"],
    dependencies=[Depends(RequireIspFeatureEnabled)],
)
#: Sub-router for the core routes; logs/reports/users/tr069 add their own.
core = APIRouter()

_Page = Query(default=1, ge=1)
_PageSize = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)


# ============================================================================
# 4.1 Me / 4.2 Overview
# ============================================================================


async def effective_isp_permissions(
    isp: IspContext, access_validator: AccessValidator
) -> list[str]:
    """The ISP keys this caller holds at ORGANIZATION scope on this ISP."""
    ours = set(all_permission_keys())
    grants = await access_validator.get_effective_grants(isp.user_id)

    def on_isp(grant: Any) -> bool:
        return (
            ScopeType(grant.scope.scope_type) == ScopeType.ORGANIZATION
            and grant.scope.organization_id == isp.isp_org_id
        )

    allowed = {
        g.permission_key for g in grants.allow if g.permission_key in ours and on_isp(g)
    }
    denied = {g.permission_key for g in grants.deny if on_isp(g)}
    return sorted(allowed - denied)


@core.get("/me", dependencies=isp_guards(ISP_PARTNER_READ))
async def get_me(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    access_validator: AccessValidator = Depends(get_access_validator),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    user = await isp.repository.get_user(isp.user_id)
    permissions = await effective_isp_permissions(isp, access_validator)
    return ok(request, await service.me(isp, user=user, permissions=permissions), "ISP")


@core.get("/overview", dependencies=isp_guards(ISP_PARTNER_READ))
async def get_overview(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    from app.domains.tr069.sync import sync_on_read

    await sync_on_read(isp)
    return ok(request, await service.overview(isp), "ISP overview")


class IspProfileUpdateRequest(BaseModel):
    """PRD §4.12: the ISP may edit its own support contact fields only."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    support_phone: str | None = Field(default=None, max_length=20)
    support_email: str | None = Field(default=None, max_length=255)


@core.patch("/profile", dependencies=isp_guards(ISP_PARTNER_MANAGE))
async def update_profile(
    request: Request,
    payload: IspProfileUpdateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    access_validator: AccessValidator = Depends(get_access_validator),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(isp.profile, key, value)
    isp.profile.updated_by = isp.user_id
    await isp.repository.flush()
    user = await isp.repository.get_user(isp.user_id)
    permissions = await effective_isp_permissions(isp, access_validator)
    return ok(
        request,
        await service.me(isp, user=user, permissions=permissions),
        "ISP profile",
    )


# ============================================================================
# 4.3 Customers
# ============================================================================


@core.get("/customers", dependencies=isp_guards(ISP_PARTNER_READ))
async def list_customers(
    request: Request,
    page: int = _Page,
    page_size: int = _PageSize,
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    search: str | None = Query(default=None, max_length=200),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.list_customers(
        isp, status=status_filter, search=search, page_no=page, page_size=page_size
    )
    return ok(request, data, "Customers")


@core.post(
    "/customers",
    status_code=status.HTTP_201_CREATED,
    dependencies=isp_guards(ISP_PARTNER_CREATE),
)
async def create_customer(
    request: Request,
    payload: CustomerCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.create_customer(isp, payload.model_dump())
    return ok(request, data, "Customer created")


@core.get("/customers/{isp_customer_id}", dependencies=isp_guards(ISP_PARTNER_READ))
async def get_customer(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    return ok(request, await service.get_customer(isp, isp_customer_id), "Customer")


@core.patch("/customers/{isp_customer_id}", dependencies=isp_guards(ISP_PARTNER_UPDATE))
async def update_customer(
    request: Request,
    isp_customer_id: uuid.UUID,
    payload: CustomerUpdateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.update_customer(
        isp, isp_customer_id, payload.model_dump(exclude_unset=True)
    )
    return ok(request, data, "Customer updated")


@core.post(
    "/customers/{isp_customer_id}/suspend", dependencies=isp_guards(ISP_PARTNER_MANAGE)
)
async def suspend_customer(
    request: Request,
    isp_customer_id: uuid.UUID,
    payload: SuspendRequest | None = None,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
    control: IspServiceControl = Depends(get_service_control),
) -> dict:
    service.service_control = control
    data = await service.suspend_customer(
        isp, isp_customer_id, reason=payload.reason if payload else None
    )
    return ok(request, data, "Customer suspended")


@core.post(
    "/customers/{isp_customer_id}/activate", dependencies=isp_guards(ISP_PARTNER_MANAGE)
)
async def activate_customer(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
    control: IspServiceControl = Depends(get_service_control),
) -> dict:
    service.service_control = control
    return ok(
        request,
        await service.activate_customer(isp, isp_customer_id),
        "Customer activated",
    )


# ============================================================================
# 4.4 Locations
# ============================================================================


@core.get(
    "/customers/{isp_customer_id}/locations", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def list_customer_locations(
    request: Request,
    isp_customer_id: uuid.UUID,
    page: int = _Page,
    # One customer has a few venues: default to the maximum page so a client
    # that sends no paging params gets them all (CONTRACT_CHANGES FE #5).
    page_size: int = Query(default=MAX_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    search: str | None = Query(default=None, max_length=200),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.list_locations(
        isp,
        isp_customer_id=isp_customer_id,
        status=status_filter,
        search=search,
        page_no=page,
        page_size=page_size,
    )
    return ok(request, data, "Locations")


@core.post(
    "/customers/{isp_customer_id}/locations",
    status_code=status.HTTP_201_CREATED,
    dependencies=isp_guards(ISP_PARTNER_CREATE),
)
async def create_location(
    request: Request,
    isp_customer_id: uuid.UUID,
    payload: IspLocationCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.create_location(isp, isp_customer_id, payload.model_dump())
    return ok(request, data, "Location created")


@core.get("/locations", dependencies=isp_guards(ISP_PARTNER_READ))
async def list_locations(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    page: int = _Page,
    page_size: int = _PageSize,
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    search: str | None = Query(default=None, max_length=200),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.list_locations(
        isp,
        isp_customer_id=isp_customer_id,
        status=status_filter,
        search=search,
        page_no=page,
        page_size=page_size,
    )
    return ok(request, data, "Locations")


@core.get("/locations/{isp_location_id}", dependencies=isp_guards(ISP_PARTNER_READ))
async def get_location(
    request: Request,
    isp_location_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    return ok(request, await service.get_location(isp, isp_location_id), "Location")


@core.patch("/locations/{isp_location_id}", dependencies=isp_guards(ISP_PARTNER_UPDATE))
async def update_location(
    request: Request,
    isp_location_id: uuid.UUID,
    payload: IspLocationUpdateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.update_location(
        isp, isp_location_id, payload.model_dump(exclude_unset=True)
    )
    return ok(request, data, "Location updated")


@core.post(
    "/locations/{isp_location_id}/suspend", dependencies=isp_guards(ISP_PARTNER_MANAGE)
)
async def suspend_location(
    request: Request,
    isp_location_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.set_location_status(isp, isp_location_id, suspend=True)
    return ok(request, data, "Location suspended")


@core.post(
    "/locations/{isp_location_id}/activate", dependencies=isp_guards(ISP_PARTNER_MANAGE)
)
async def activate_location(
    request: Request,
    isp_location_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.set_location_status(isp, isp_location_id, suspend=False)
    return ok(request, data, "Location activated")


# ============================================================================
# 4.5 Routers
# ============================================================================


@core.get("/routers", dependencies=isp_guards(ISP_PARTNER_READ))
async def list_routers(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp_location_id: uuid.UUID | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status", max_length=30),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.list_routers(
        isp,
        isp_customer_id=isp_customer_id,
        isp_location_id=isp_location_id,
        status=status_filter,
        page_no=page,
        page_size=page_size,
    )
    return ok(request, data, "Routers")


@core.post(
    "/locations/{isp_location_id}/routers",
    status_code=status.HTTP_201_CREATED,
    dependencies=isp_guards(ISP_PARTNER_CREATE),
)
async def create_router(
    request: Request,
    isp_location_id: uuid.UUID,
    payload: IspRouterCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.create_router(isp, isp_location_id, payload.model_dump())
    return ok(request, data, "Router registered")


@core.get("/routers/{isp_router_id}", dependencies=isp_guards(ISP_PARTNER_READ))
async def get_router(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    return ok(request, await service.get_router(isp, isp_router_id), "Router")


@core.patch("/routers/{isp_router_id}", dependencies=isp_guards(ISP_PARTNER_UPDATE))
async def update_router(
    request: Request,
    isp_router_id: uuid.UUID,
    payload: IspRouterUpdateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    data = await service.update_router(
        isp, isp_router_id, payload.model_dump(exclude_unset=True)
    )
    return ok(request, data, "Router updated")


@core.get(
    "/routers/{isp_router_id}/as-router-device",
    dependencies=isp_guards(ISP_PARTNER_READ),
)
async def get_router_as_device(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    router_service: RouterService = Depends(get_router_service),
) -> dict:
    """The existing ``GET /routers/{router_id}`` shape (same serializer),
    plus ``organization_name`` and ``location_name`` for the drilldown."""
    target = await IspScope.assert_router(isp, isp_router_id)
    device = await router_service.get_router(
        target.id, requesting_organization_id=target.organization_id
    )
    data = (await router_routes._one(device, router_service)).model_dump()
    org_names = await isp.repository.names(Organization, [device.organization_id])
    loc_names = await isp.repository.names(Location, [device.location_id])
    data["organization_name"] = org_names.get(device.organization_id)
    data["location_name"] = loc_names.get(device.location_id)
    return ok(request, data, "Router retrieved")


# ============================================================================
# 4.6 Router setup twins
#
# Each twin calls the ORIGINAL handler function (or, for management-access,
# the same service method) after IspScope has resolved the router, with
# requesting_organization_id = the customer. The response body is therefore
# the original's byte for byte. The original's own RequirePermission is a
# route decorator dependency and is not re-run; the ISP guard stack above
# replaces it.
# ============================================================================


async def _setup_target(isp: IspContext, isp_router_id: uuid.UUID) -> Any:
    if isp.role_slug not in SETUP_SCRIPT_ROLES:
        raise IspSetupNotAllowedError()
    return await IspScope.assert_router(isp, isp_router_id)


async def _audit_setup(
    audit: RBACRepositoryProtocol,
    isp: IspContext,
    router: Any,
    action: str,
    **extra: Any,
) -> None:
    await audit.create_audit_log_entry(
        actor_user_id=isp.user_id,
        action=f"{AUDIT_ISP_ROUTER_SETUP_PREFIX}{action}",
        entity_type="router",
        entity_id=router.id,
        description=f"ISP router setup: {action.replace('_', ' ')}",
        event_metadata={
            "console": "isp",
            "isp_organization_id": str(isp.isp_org_id),
            "role": isp.role_slug,
            **extra,
        },
        organization_id=router.organization_id,
        location_id=router.location_id,
    )


@core.post(
    "/routers/{isp_router_id}/provisioning-token",
    status_code=status.HTTP_201_CREATED,
    dependencies=isp_guards(ISP_PARTNER_EXECUTE),
)
async def twin_provisioning_token(
    request: Request,
    isp_router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    isp: IspContext = Depends(RequireIspPartner),
    router_service: RouterService = Depends(get_router_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    target = await _setup_target(isp, isp_router_id)
    result = await router_routes.generate_provisioning_token(
        request,
        router_id=target.id,
        user=user,
        requesting_organization_id=target.organization_id,
        router_service=router_service,
    )
    await _audit_setup(audit, isp, target, "provisioning_token")
    return result


@core.post(
    "/routers/{isp_router_id}/agent-credential/regenerate",
    dependencies=isp_guards(ISP_PARTNER_EXECUTE),
)
async def twin_regenerate_agent_credential(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    router_service: RouterService = Depends(get_router_service),
    agent_service: RouterAgentService = Depends(get_router_agent_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    target = await _setup_target(isp, isp_router_id)
    result = await router_routes.regenerate_agent_credential(
        request,
        router_id=target.id,
        requesting_organization_id=target.organization_id,
        router_service=router_service,
        agent_service=agent_service,
    )
    await _audit_setup(audit, isp, target, "agent_credential")
    return result


@core.post(
    "/routers/{isp_router_id}/wireguard-peer/allocate-external",
    status_code=status.HTTP_201_CREATED,
    dependencies=isp_guards(ISP_PARTNER_EXECUTE),
)
async def twin_allocate_tunnel(
    request: Request,
    isp_router_id: uuid.UUID,
    rotate: bool = Query(default=False),
    force: bool = Query(default=False),
    user: AuthUser = Depends(CurrentUser),
    isp: IspContext = Depends(RequireIspPartner),
    service: WireGuardService = Depends(get_wireguard_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    """``force=true`` destroys a live peer on the hub and is refused (422)."""
    if force:
        raise IspForceNotAllowedError()
    target = await _setup_target(isp, isp_router_id)
    result = await wireguard_routes.allocate_external_wireguard_peer(
        request,
        router_id=target.id,
        rotate=rotate,
        force=False,
        user=user,
        requesting_organization_id=target.organization_id,
        service=service,
    )
    await _audit_setup(audit, isp, target, "cloud_link", rotate=rotate)
    return result


@core.post(
    "/routers/{isp_router_id}/radius-nas/register-external",
    status_code=status.HTTP_201_CREATED,
    dependencies=isp_guards(ISP_PARTNER_EXECUTE),
)
async def twin_register_nas(
    request: Request,
    isp_router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    isp: IspContext = Depends(RequireIspPartner),
    service: Any = Depends(get_radius_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
    control: IspServiceControl = Depends(get_service_control),
) -> dict:
    target = await _setup_target(isp, isp_router_id)
    result = await guest_routes.register_external_radius_nas(
        request,
        router_id=target.id,
        user=user,
        requesting_organization_id=target.organization_id,
        service=service,
        wireguard_service=wireguard_service,
    )
    await _audit_setup(audit, isp, target, "radius_nas")
    # ADDENDUM_01 §A.4: a router registered while its customer is suspended
    # gets its NAS disabled at once, so it can never open a hole.
    await control.after_nas_registered(isp.isp_org_id, target, isp.user_id)
    return result


@core.put(
    "/routers/{isp_router_id}/management-access",
    dependencies=isp_guards(ISP_PARTNER_EXECUTE),
)
async def twin_management_access(
    request: Request,
    isp_router_id: uuid.UUID,
    payload: RouterManagementAccessRequest,
    isp: IspContext = Depends(RequireIspPartner),
    router_service: RouterService = Depends(get_router_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    """Same service call as ``PUT /platform/routers/{id}/management-access``
    (``RouterService.update_router``) and the same serializer, but scoped to
    the customer instead of the original's platform ``None``."""
    target = await _setup_target(isp, isp_router_id)
    updated = await router_service.update_router(
        actor_user_id=isp.user_id,
        router_id=target.id,
        requesting_organization_id=target.organization_id,
        data=payload.model_dump(exclude_unset=True),
    )
    await _audit_setup(
        audit, isp, target, "management_access", fields=sorted(payload.model_fields_set)
    )
    return ok(
        request,
        (await router_routes._one_platform(updated, router_service)).model_dump(),
        "Router management access updated",
    )


async def _hand_gate(name: str, request: Request, checker: Any, org_id) -> None:
    """ADDENDUM_04 §1: the original route's licence/feature gates, run on the
    CUSTOMER org. The declaration lives in ``twin_gates.HAND_TWIN_GATES`` so
    the parity test can compare it with the original route."""
    spec = HAND_TWIN_GATES[name]
    await enforce_customer_gates(
        checker,
        org_id,
        method=request.method,
        paid_write=spec.paid_write,
        features=spec.features,
    )


# ============================================================================
# 4.7 Captive portal (per location) -- the original handlers, customer-scoped
# ============================================================================


@core.get(
    "/locations/{isp_location_id}/captive-portal-configs",
    dependencies=isp_guards(ISP_PARTNER_READ),
)
async def list_portal_configs(
    request: Request,
    isp_location_id: uuid.UUID,
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    service: CaptivePortalService = Depends(get_captive_portal_service),
) -> dict:
    location = await IspScope.assert_location(isp, isp_location_id)
    return await portal_routes.list_captive_portal_configs(
        request,
        page=page,
        page_size=page_size,
        location_id=location.id,
        requesting_organization_id=location.organization_id,
        service=service,
    )


@core.get(
    "/captive-portal-configs/{config_id}", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def get_portal_config(
    request: Request,
    config_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: CaptivePortalService = Depends(get_captive_portal_service),
) -> dict:
    config = await IspScope.assert_portal_config(isp, config_id)
    return await portal_routes.get_captive_portal_config(
        request,
        config_id=config.id,
        requesting_organization_id=config.organization_id,
        service=service,
    )


@core.put(
    "/captive-portal-configs/{config_id}", dependencies=isp_guards(ISP_PARTNER_UPDATE)
)
async def update_portal_config(
    request: Request,
    config_id: uuid.UUID,
    payload: CaptivePortalConfigUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    isp: IspContext = Depends(RequireIspPartner),
    service: CaptivePortalService = Depends(
        portal_routes.get_entitlement_aware_captive_portal_service
    ),
    checker: Any = Depends(get_twin_entitlement_checker),
) -> dict:
    config = await IspScope.assert_portal_config(isp, config_id)
    await _hand_gate(
        "update_portal_config", request, checker, config.organization_id
    )
    return await portal_routes.update_captive_portal_config(
        request,
        config_id=config.id,
        payload=payload,
        user=user,
        requesting_organization_id=config.organization_id,
        service=service,
    )


@core.post(
    "/captive-portal-configs/{config_id}/activate",
    dependencies=isp_guards(ISP_PARTNER_UPDATE),
)
async def activate_portal_config(
    request: Request,
    config_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    isp: IspContext = Depends(RequireIspPartner),
    service: CaptivePortalService = Depends(get_captive_portal_service),
    checker: Any = Depends(get_twin_entitlement_checker),
) -> dict:
    config = await IspScope.assert_portal_config(isp, config_id)
    await _hand_gate(
        "activate_portal_config", request, checker, config.organization_id
    )
    return await portal_routes.activate_captive_portal_config(
        request,
        config_id=config.id,
        user=user,
        requesting_organization_id=config.organization_id,
        service=service,
    )


@core.post(
    "/captive-portal-configs/{config_id}/content-image",
    dependencies=isp_guards(ISP_PARTNER_UPDATE),
)
async def upload_portal_content_image(
    request: Request,
    config_id: uuid.UUID,
    file: UploadFile = File(...),
    user: AuthUser = Depends(CurrentUser),
    isp: IspContext = Depends(RequireIspPartner),
    service: CaptivePortalService = Depends(get_captive_portal_service),
    checker: Any = Depends(get_twin_entitlement_checker),
) -> dict:
    config = await IspScope.assert_portal_config(isp, config_id)
    await _hand_gate(
        "upload_portal_content_image", request, checker, config.organization_id
    )
    return await portal_routes.upload_captive_portal_content_image(
        request,
        config_id=config.id,
        file=file,
        user=user,
        requesting_organization_id=config.organization_id,
        service=service,
    )


# ============================================================================
# 4.8 Guests and sessions (read-only, masked)
# ============================================================================


def _looks_like_phone(value: str | None) -> bool:
    if not value or "@" in value:
        return False
    digits = sum(ch.isdigit() for ch in value)
    return digits >= 6


@core.get(
    "/customers/{isp_customer_id}/guests", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def list_guests(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp_location_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
) -> dict:
    from .views import page as make_page

    customer = await IspScope.assert_customer(isp, isp_customer_id)
    location_id = None
    if isp_location_id is not None:
        location = await IspScope.assert_location(isp, isp_location_id)
        if location.organization_id != customer.id:
            from .exceptions import IspLocationNotFoundError

            raise IspLocationNotFoundError()
        location_id = location.id
    rows, total = await isp.repository.list_guests(
        customer.id,
        location_id=location_id,
        search=search,
        page=page,
        page_size=page_size,
    )
    items = []
    for guest, sessions in rows:
        phone = guest.identifier if _looks_like_phone(guest.identifier) else None
        email = guest.email or (
            guest.identifier if "@" in (guest.identifier or "") else None
        )
        items.append(
            {
                "id": str(guest.id),
                "display_name": guest.display_name,
                "phone_masked": mask_mobile(phone),
                "email_masked": mask_email(email),
                "first_seen_at": guest.first_seen_at.isoformat()
                if guest.first_seen_at
                else None,
                "last_seen_at": guest.last_seen_at.isoformat()
                if guest.last_seen_at
                else None,
                "session_count": sessions,
                "isp_location_id": str(guest.location_id)
                if guest.location_id
                else None,
            }
        )
    return ok(request, make_page(items, total, page, page_size), "Guests")


@core.get(
    "/customers/{isp_customer_id}/sessions", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def list_sessions(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp_location_id: uuid.UUID | None = Query(default=None),
    status_filter: str | None = Query(
        default=None, alias="status", pattern="^(active|ended)$"
    ),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
) -> dict:
    from .views import page as make_page

    customer = await IspScope.assert_customer(isp, isp_customer_id)
    location_id = None
    if isp_location_id is not None:
        location = await IspScope.assert_location(isp, isp_location_id)
        if location.organization_id != customer.id:
            from .exceptions import IspLocationNotFoundError

            raise IspLocationNotFoundError()
        location_id = location.id
    rows, total = await isp.repository.list_sessions(
        customer.id,
        location_id=location_id,
        status=status_filter,
        since=since,
        until=until,
        page=page,
        page_size=page_size,
    )
    names = await isp.repository.names(Location, [s.location_id for s, _ in rows])
    items = [
        {
            "id": str(s.id),
            "guest_display_name": name,
            "isp_location_id": str(s.location_id),
            "location_name": names.get(s.location_id),
            "auth_method": s.auth_method,
            "status": s.status,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "ended_at": s.ended_at.isoformat() if s.ended_at else None,
            "ip_address": s.ip_address,
            "bytes_uploaded": int(s.bytes_uploaded or 0),
            "bytes_downloaded": int(s.bytes_downloaded or 0),
        }
        for s, name in rows
    ]
    return ok(request, make_page(items, total, page, page_size), "Sessions")


isp_partner_router.include_router(core)


def _include_lanes() -> None:
    """Logs, reports and users live in their own modules and mount under the
    same prefix and flag. TR-069 is its own router (``tr069_router``)."""
    from .billing_router import billing_router
    from .logs_router import logs_router
    from .reports_router import reports_router
    from .users_router import users_router

    isp_partner_router.include_router(logs_router)
    isp_partner_router.include_router(reports_router)
    isp_partner_router.include_router(users_router)
    # Phase 1b (ADDENDUM_01, ADDENDUM_03 Part A)
    from .service_router import service_router

    isp_partner_router.include_router(service_router)
    isp_partner_router.include_router(billing_router)
    # Phase 2a (ADDENDUM_02)
    from .plans_router import plans_router

    isp_partner_router.include_router(plans_router)
    # Phase 2c: the venue twins (the customer dashboard's own feature set,
    # ISP-gated). One table row per endpoint -- see ``twins.py``.
    mount_twins(isp_partner_router, ALL_TWINS)
    # The venue's answer to /me/organizations (see venue_session.py).
    from .venue_session import venue_session_router

    isp_partner_router.include_router(venue_session_router)
    # ADDENDUM_04 B5: venue alert rules, ISP alert feed, ISP->Wyfy support
    # tickets, staff activity (see monitor_support.py).
    from .monitor_support import monitor_support_router

    isp_partner_router.include_router(monitor_support_router)
    # ADDENDUM_04 B6 §2: add-on allowance (Master, GLOBAL) + per-customer
    # toggle (ISP). The Master routes ride on the platform router, which
    # app/api/v1/router.py includes after importing this module.
    from .isp_addons import addon_platform_router, isp_addons_router
    from .platform_router import isp_partner_platform_router

    isp_partner_router.include_router(isp_addons_router)
    isp_partner_platform_router.include_router(addon_platform_router)


_include_lanes()
