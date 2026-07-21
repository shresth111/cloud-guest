"""FastAPI routes for the Location domain: site CRUD and lifecycle management.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching ``app/domains/organization/router.py``. Every
mutating (and cross-tenant-sensitive read) endpoint is gated by RBAC's
existing ``RequirePermission`` dependency against the already-seeded
``locations.*`` permission keys -- this domain defines no permission keys of
its own.

``organization_id`` appears in the path for the two collection endpoints
(list/create, nested under ``/organizations/{organization_id}/locations``)
since a location is always created within a specific organization; the
remaining endpoints address a location directly by its own id. Every
endpoint additionally resolves ``CurrentOrganization`` (``X-Organization-Id``)
and passes it to ``LocationService`` as ``requesting_organization_id`` so
tenant scoping (a caller acting within organization A may only touch A's own
locations, or its MSP children's) is enforced the same way
``OrganizationService`` enforces it for organizations themselves -- not just
left to the permission check, which only verifies *what* the caller can do,
not *which tenant's data* they are doing it to.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.audit.dependencies import get_audit_service
from app.domains.audit.service import AuditService
from app.domains.auth.models import AuthUser
from app.domains.campaigns.dependencies import get_campaigns_service
from app.domains.campaigns.service import CampaignsService
from app.domains.connected_devices.dependencies import get_connected_device_service
from app.domains.connected_devices.service import ConnectedDeviceService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.vlan.dependencies import get_vlan_service
from app.domains.vlan.service import VlanService

from .dependencies import get_location_service
from .enums import LocationStatus, PropertyType
from .models import Location
from .provisioning_dependencies import get_location_provisioning_service
from .provisioning_schemas import (
    FeatureOverrideInputSchema,
    ProvisionLocationPreviewResponse,
    ProvisionLocationRequest,
    ProvisionLocationResponse,
    ResendWelcomeEmailResponse,
)
from .provisioning_service import (
    FeatureOverride,
    LocationInput,
    LocationProvisioningService,
    NewOrganizationInput,
    OwnerInput,
    ProvisionLocationInput,
    RouterInput,
)
from .schemas import (
    LocationCreateRequest,
    LocationListResponse,
    LocationOverviewResponse,
    LocationResponse,
    LocationUpdateRequest,
    MessageResponse,
)
from .service import LocationService

router = APIRouter(tags=["Locations"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _location_response(location: Location) -> LocationResponse:
    return LocationResponse(
        id=str(location.id),
        organization_id=str(location.organization_id),
        name=location.name,
        slug=location.slug,
        status=LocationStatus(location.status),
        property_type=PropertyType(location.property_type)
        if location.property_type
        else None,
        location_code=location.location_code,
        address_line1=location.address_line1,
        address_line2=location.address_line2,
        city=location.city,
        state_province=location.state_province,
        postal_code=location.postal_code,
        country=location.country,
        timezone=location.timezone,
        latitude=location.latitude,
        longitude=location.longitude,
        contact_name=location.contact_name,
        contact_phone=location.contact_phone,
        contact_email=location.contact_email,
        settings=location.settings,
        created_at=location.created_at,
        updated_at=location.updated_at,
    )


# ============================================================================
# Collection endpoints (nested under an organization)
# ============================================================================


@router.get(
    "/organizations/{organization_id}/locations",
    response_model=ApiResponse[LocationListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.read"))],
)
async def list_locations(
    request: Request,
    organization_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    search: str | None = Query(default=None, max_length=200),
    location_status: LocationStatus | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    locations, meta = await location_service.list_locations(
        organization_id=organization_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
        search=search,
        status=location_status,
    )
    payload = LocationListResponse(
        items=[_location_response(location) for location in locations],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Locations retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/organizations/{organization_id}/locations",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("locations.create"))],
)
async def create_location(
    request: Request,
    organization_id: uuid.UUID,
    payload: LocationCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    location = await location_service.create_location(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        slug=payload.slug,
        status=payload.status,
        property_type=payload.property_type,
        address_line1=payload.address_line1,
        address_line2=payload.address_line2,
        city=payload.city,
        state_province=payload.state_province,
        postal_code=payload.postal_code,
        country=payload.country,
        timezone=payload.timezone,
        latitude=payload.latitude,
        longitude=payload.longitude,
        contact_name=payload.contact_name,
        contact_phone=payload.contact_phone,
        contact_email=payload.contact_email,
        settings=payload.settings,
    )
    return build_response(
        success=True,
        message="Location created",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Direct location endpoints
# ============================================================================


@router.get(
    "/locations/{location_id}",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.read"))],
)
async def get_location(
    request: Request,
    location_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    location = await location_service.get_location(
        location_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Location retrieved",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/locations/{location_id}/overview",
    response_model=ApiResponse[LocationOverviewResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.read"))],
)
async def get_location_overview(
    request: Request,
    location_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
    router_service: RouterService = Depends(get_router_service),
    connected_device_service: ConnectedDeviceService = Depends(
        get_connected_device_service
    ),
    vlan_service: VlanService = Depends(get_vlan_service),
    campaigns_service: CampaignsService = Depends(get_campaigns_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """The "Location Workspace" overview -- composes counts already
    exposed by their own domains' list endpoints into one call. See
    ``LocationOverviewResponse``'s own docstring for exactly what is (and
    is deliberately not) included."""
    location = await location_service.get_location(
        location_id, requesting_organization_id=requesting_organization_id
    )
    _, router_meta = await router_service.list_routers(
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
        page=1,
        page_size=1,
    )
    _, device_meta = await connected_device_service.list_devices(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=1,
        page_size=1,
    )
    _, vlan_meta = await vlan_service.list_vlans(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=1,
        page_size=1,
    )
    _, campaign_meta = await campaigns_service.list_campaigns(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=1,
        page_size=1,
    )
    _, audit_meta = await audit_service.search(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=1,
        page_size=1,
    )
    payload = LocationOverviewResponse(
        location=_location_response(location),
        router_count=router_meta.total_items,
        connected_device_count=device_meta.total_items,
        vlan_count=vlan_meta.total_items,
        campaign_count=campaign_meta.total_items,
        audit_log_count=audit_meta.total_items,
    )
    return build_response(
        success=True,
        message="Location overview retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/locations/{location_id}",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.update"))],
)
async def update_location(
    request: Request,
    location_id: uuid.UUID,
    payload: LocationUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    data = payload.model_dump(exclude_unset=True)
    location = await location_service.update_location(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="Location updated",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/locations/{location_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.delete"))],
)
async def archive_location(
    request: Request,
    location_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    await location_service.archive_location(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Location archived",
        data=MessageResponse(message="Location archived").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/locations/{location_id}/suspend",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.manage"))],
)
async def suspend_location(
    request: Request,
    location_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    location = await location_service.suspend_location(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Location suspended",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/locations/{location_id}/activate",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.manage"))],
)
async def activate_location(
    request: Request,
    location_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    location = await location_service.activate_location(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Location activated",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Smart Location Provisioning
#
# Both endpoints are gated with ``scope=ScopeType.GLOBAL`` -- the same exact
# ``RequirePermission(key, scope=ScopeType.GLOBAL)`` factory call
# ``app.domains.billing.router`` already uses to restrict Plan-catalog
# writes to Super-Admin-class roles (see
# ``docs/location/FLOW.md``'s "Super-Admin gating" section). Only
# ``Super Admin``/``Platform Admin`` hold ``locations.manage`` at ``GLOBAL``
# scope per ``app.domains.rbac.seed.SYSTEM_ROLES`` -- every other seeded
# role is either scoped narrower (``ORGANIZATION``/``LOCATION``) or has no
# ``locations.manage`` grant at all, so this restricts the create-tenant path
# to exactly the "CloudGuest Super Admin" actor the spec's flowchart names.
# ============================================================================


def _feature_override(item: FeatureOverrideInputSchema) -> FeatureOverride:
    return FeatureOverride(
        feature_key=item.feature_key,
        limit_value=item.limit_value,
        is_enabled=item.is_enabled,
        tier_value=item.tier_value,
    )


def _provision_input(payload: ProvisionLocationRequest) -> ProvisionLocationInput:
    new_organization = (
        NewOrganizationInput(
            name=payload.new_organization.name,
            slug=payload.new_organization.slug,
            contact_email=payload.new_organization.contact_email,
            contact_phone=payload.new_organization.contact_phone,
            legal_name=payload.new_organization.legal_name,
            timezone=payload.new_organization.timezone,
            default_locale=payload.new_organization.default_locale,
        )
        if payload.new_organization is not None
        else None
    )
    return ProvisionLocationInput(
        location=LocationInput(
            name=payload.location.name,
            slug=payload.location.slug,
            property_type=payload.location.property_type,
            address_line1=payload.location.address_line1,
            address_line2=payload.location.address_line2,
            city=payload.location.city,
            state_province=payload.location.state_province,
            postal_code=payload.location.postal_code,
            country=payload.location.country,
            timezone=payload.location.timezone,
            latitude=payload.location.latitude,
            longitude=payload.location.longitude,
            contact_name=payload.location.contact_name,
            contact_phone=payload.location.contact_phone,
            contact_email=payload.location.contact_email,
            settings=payload.location.settings,
        ),
        owner=OwnerInput(
            first_name=payload.owner.first_name,
            last_name=payload.owner.last_name,
            email=payload.owner.email,
            username=payload.owner.username,
            phone=payload.owner.phone,
            designation=payload.owner.designation,
            department=payload.owner.department,
            employee_id=payload.owner.employee_id,
            timezone=payload.owner.timezone,
            language=payload.owner.language,
            send_welcome_sms=payload.owner.send_welcome_sms,
        ),
        router=RouterInput(
            name=payload.router.name,
            serial_number=payload.router.serial_number,
            mac_address=payload.router.mac_address,
            model=payload.router.model,
            management_ip_address=payload.router.management_ip_address,
            public_ip_address=payload.router.public_ip_address,
            api_username=payload.router.api_username,
            api_secret=payload.router.api_secret,
            settings=payload.router.settings,
        ),
        plan_id=uuid.UUID(payload.plan_id),
        existing_organization_id=(
            uuid.UUID(payload.existing_organization_id)
            if payload.existing_organization_id is not None
            else None
        ),
        new_organization=new_organization,
        feature_overrides=tuple(
            _feature_override(item) for item in payload.feature_overrides
        ),
        router_config_template_id=(
            uuid.UUID(payload.router_config_template_id)
            if payload.router_config_template_id is not None
            else None
        ),
        coupon_code=payload.coupon_code,
    )


@router.post(
    "/locations/provision/preview",
    response_model=ApiResponse[ProvisionLocationPreviewResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("locations.manage", scope=ScopeType.GLOBAL))
    ],
)
async def preview_provision_location(
    request: Request,
    payload: ProvisionLocationRequest,
    provisioning_service: LocationProvisioningService = Depends(
        get_location_provisioning_service
    ),
):
    """The Organization Provisioning Wizard's "review summary before final
    provisioning" step -- read-only, never creates anything. Takes the
    exact same request body ``POST /locations/provision`` does (so a
    client can preview, then re-submit the identical payload to commit)."""
    preview = await provisioning_service.preview_provision_location(
        data=_provision_input(payload)
    )
    response = ProvisionLocationPreviewResponse(
        organization_id=(
            str(preview.organization_id) if preview.organization_id else None
        ),
        organization_name=preview.organization_name,
        customer_id=preview.customer_id,
        site_id=preview.site_id,
        nas_id=preview.nas_id,
        controller_id=preview.controller_id,
        plan_id=str(preview.plan_id),
        plan_name=preview.plan_name,
        feature_summary=preview.feature_summary,
        owner_name=preview.owner_name,
        owner_email=preview.owner_email,
        owner_username_preview=preview.owner_username_preview,
        router_name=preview.router_name,
    )
    return build_response(
        success=True,
        message="Provisioning preview generated",
        data=response.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/locations/provision",
    response_model=ApiResponse[ProvisionLocationResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(RequirePermission("locations.manage", scope=ScopeType.GLOBAL))
    ],
)
async def provision_location(
    request: Request,
    payload: ProvisionLocationRequest,
    user: AuthUser = Depends(CurrentUser),
    provisioning_service: LocationProvisioningService = Depends(
        get_location_provisioning_service
    ),
):
    result = await provisioning_service.provision_location(
        actor_user_id=uuid.UUID(user.id),
        data=_provision_input(payload),
    )
    response = ProvisionLocationResponse(
        organization_id=str(result.organization_id),
        organization_name=result.organization_name,
        location_id=str(result.location_id),
        location_name=result.location_name,
        location_code=result.location_code,
        property_type=result.property_type,
        plan_id=str(result.plan_id),
        plan_name=result.plan_name,
        feature_summary=result.feature_summary,
        router_id=str(result.router_id),
        router_name=result.router_name,
        tunnel_ip_address=result.tunnel_ip_address,
        owner_user_id=str(result.owner_user_id),
        owner_name=result.owner_name,
        owner_username=result.owner_username,
        owner_email=result.owner_email,
        owner_temporary_password=result.owner_temporary_password,
        login_url=result.login_url,
        provisioned_at=result.provisioned_at.isoformat(),
    )
    return build_response(
        success=True,
        message="Location provisioned",
        data=response.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/locations/{location_id}/resend-welcome-email",
    response_model=ApiResponse[ResendWelcomeEmailResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("locations.manage", scope=ScopeType.GLOBAL))
    ],
)
async def resend_welcome_email(
    request: Request,
    location_id: uuid.UUID,
    provisioning_service: LocationProvisioningService = Depends(
        get_location_provisioning_service
    ),
):
    location, owner_email = await provisioning_service.resend_welcome_email(
        location_id=location_id
    )
    payload = ResendWelcomeEmailResponse(
        message="Welcome email resent",
        location_id=str(location.id),
        owner_email=owner_email,
    )
    return build_response(
        success=True,
        message="Welcome email resent",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )
