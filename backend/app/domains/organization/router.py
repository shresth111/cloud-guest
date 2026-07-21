"""FastAPI routes for the Organization domain: tenant CRUD, MSP hierarchy,
and membership management.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching ``app/domains/auth/router.py`` and
``app/domains/rbac/router.py``. Every mutating (and cross-tenant-sensitive
read) endpoint is gated by RBAC's existing ``RequirePermission`` dependency
against the already-seeded ``organizations.*`` permission keys -- this
domain defines no permission keys of its own.

Invite/accept flow shape: ``POST /organizations/{id}/members`` (invite) is
gated by ``organizations.manage`` (an administrative action). ``POST
/organizations/{id}/members/{member_id}/accept`` is deliberately **not**
gated by any ``organizations.*`` permission -- an invited-but-not-yet-active
member holds no roles/permissions in the organization yet (that is exactly
the point of membership being distinct from RBAC role assignment), so the
only thing accepting an invite requires is being the invited user
themselves (enforced in ``OrganizationService.accept_invite``). ``GET
/me/organizations`` is the self-service counterpart, listing every
organization (at any membership status) the caller belongs to.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import RequireFeature
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_organization_service
from .enums import MembershipStatus, OrganizationStatus, OrganizationType
from .models import Organization, OrganizationMember
from .schemas import (
    MessageResponse,
    OrganizationBrandingRequest,
    OrganizationBrandingResponse,
    OrganizationCreateRequest,
    OrganizationListResponse,
    OrganizationMemberInviteRequest,
    OrganizationMemberResponse,
    OrganizationResponse,
    OrganizationUpdateRequest,
)
from .service import OrganizationService

router = APIRouter(tags=["Organizations"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _organization_response(organization: Organization) -> OrganizationResponse:
    return OrganizationResponse(
        id=str(organization.id),
        name=organization.name,
        slug=organization.slug,
        legal_name=organization.legal_name,
        org_type=OrganizationType(organization.org_type),
        status=OrganizationStatus(organization.status),
        parent_organization_id=(
            str(organization.parent_organization_id)
            if organization.parent_organization_id
            else None
        ),
        contact_email=organization.contact_email,
        contact_phone=organization.contact_phone,
        timezone=organization.timezone,
        default_locale=organization.default_locale,
        settings=organization.settings,
        subscription_tier=organization.subscription_tier,
        created_at=organization.created_at,
        updated_at=organization.updated_at,
    )


def _member_response(member: OrganizationMember) -> OrganizationMemberResponse:
    return OrganizationMemberResponse(
        id=str(member.id),
        organization_id=str(member.organization_id),
        user_id=str(member.user_id),
        status=member.status,
        invited_by_user_id=(
            str(member.invited_by_user_id) if member.invited_by_user_id else None
        ),
        invited_at=member.invited_at,
        joined_at=member.joined_at,
        is_primary_contact=member.is_primary_contact,
        created_at=member.created_at,
        updated_at=member.updated_at,
    )


# ============================================================================
# Organizations
# ============================================================================


@router.get(
    "/organizations",
    response_model=ApiResponse[OrganizationListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.read"))],
)
async def list_organizations(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    search: str | None = Query(default=None, max_length=200),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    organizations, meta = await organization_service.list_organizations(
        requesting_organization_id=organization_id,
        page=page,
        page_size=page_size,
        search=search,
    )
    payload = OrganizationListResponse(
        items=[_organization_response(org) for org in organizations],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Organizations retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/organizations",
    response_model=ApiResponse[OrganizationResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("organizations.create"))],
)
async def create_organization(
    request: Request,
    payload: OrganizationCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    organization = await organization_service.create_organization(
        actor_user_id=uuid.UUID(user.id),
        name=payload.name,
        slug=payload.slug,
        legal_name=payload.legal_name,
        org_type=payload.org_type,
        status=payload.status,
        parent_organization_id=payload.parent_organization_id,
        contact_email=payload.contact_email,
        contact_phone=payload.contact_phone,
        timezone=payload.timezone,
        default_locale=payload.default_locale,
        settings=payload.settings,
        subscription_tier=payload.subscription_tier,
    )
    return build_response(
        success=True,
        message="Organization created",
        data=_organization_response(organization).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/organizations/{organization_id}",
    response_model=ApiResponse[OrganizationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.read"))],
)
async def get_organization(
    request: Request,
    organization_id: uuid.UUID,
    organization_service: OrganizationService = Depends(get_organization_service),
):
    organization = await organization_service.get_organization(organization_id)
    return build_response(
        success=True,
        message="Organization retrieved",
        data=_organization_response(organization).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/organizations/{organization_id}",
    response_model=ApiResponse[OrganizationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.update"))],
)
async def update_organization(
    request: Request,
    organization_id: uuid.UUID,
    payload: OrganizationUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    data = payload.model_dump(exclude_unset=True)
    organization = await organization_service.update_organization(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="Organization updated",
        data=_organization_response(organization).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/organizations/{organization_id}/branding",
    response_model=ApiResponse[OrganizationBrandingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("organizations.read")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def get_organization_branding(
    request: Request,
    organization_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    branding = await organization_service.get_branding(
        organization_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Organization branding retrieved",
        data=OrganizationBrandingResponse(**branding).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/organizations/{organization_id}/branding",
    response_model=ApiResponse[OrganizationBrandingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("organizations.update")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def update_organization_branding(
    request: Request,
    organization_id: uuid.UUID,
    payload: OrganizationBrandingRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    data = payload.model_dump(exclude_unset=True)
    branding = await organization_service.update_branding(
        organization_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="Organization branding updated",
        data=OrganizationBrandingResponse(**branding).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/organizations/{organization_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.delete"))],
)
async def archive_organization(
    request: Request,
    organization_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    await organization_service.archive_organization(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Organization archived",
        data=MessageResponse(message="Organization archived").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/organizations/{organization_id}/suspend",
    response_model=ApiResponse[OrganizationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.manage"))],
)
async def suspend_organization(
    request: Request,
    organization_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    organization = await organization_service.suspend_organization(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Organization suspended",
        data=_organization_response(organization).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/organizations/{organization_id}/activate",
    response_model=ApiResponse[OrganizationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.manage"))],
)
async def activate_organization(
    request: Request,
    organization_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    organization = await organization_service.activate_organization(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Organization activated",
        data=_organization_response(organization).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/organizations/{organization_id}/children",
    response_model=ApiResponse[list[OrganizationResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.read"))],
)
async def list_organization_children(
    request: Request,
    organization_id: uuid.UUID,
    organization_service: OrganizationService = Depends(get_organization_service),
):
    children = await organization_service.list_children(organization_id)
    return build_response(
        success=True,
        message="Child organizations retrieved",
        data=[_organization_response(child).model_dump() for child in children],
        request_id=_request_id(request),
    )


# ============================================================================
# Membership
# ============================================================================


@router.get(
    "/organizations/{organization_id}/members",
    response_model=ApiResponse[list[OrganizationMemberResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.read"))],
)
async def list_organization_members(
    request: Request,
    organization_id: uuid.UUID,
    organization_service: OrganizationService = Depends(get_organization_service),
):
    members = await organization_service.list_members(organization_id)
    return build_response(
        success=True,
        message="Organization members retrieved",
        data=[_member_response(member).model_dump() for member in members],
        request_id=_request_id(request),
    )


@router.post(
    "/organizations/{organization_id}/members",
    response_model=ApiResponse[OrganizationMemberResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("organizations.manage"))],
)
async def invite_organization_member(
    request: Request,
    organization_id: uuid.UUID,
    payload: OrganizationMemberInviteRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    member = await organization_service.invite_member(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        user_id=payload.user_id,
        is_primary_contact=payload.is_primary_contact,
    )
    return build_response(
        success=True,
        message="Member invited",
        data=_member_response(member).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/organizations/{organization_id}/members/{member_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("organizations.manage"))],
)
async def remove_organization_member(
    request: Request,
    organization_id: uuid.UUID,
    member_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    await organization_service.remove_member(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        member_id=member_id,
    )
    return build_response(
        success=True,
        message="Member removed",
        data=MessageResponse(message="Member removed").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/organizations/{organization_id}/members/{member_id}/accept",
    response_model=ApiResponse[OrganizationMemberResponse],
    status_code=status.HTTP_200_OK,
)
async def accept_organization_invite(
    request: Request,
    organization_id: uuid.UUID,
    member_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    member = await organization_service.accept_invite(
        user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        member_id=member_id,
    )
    return build_response(
        success=True,
        message="Invite accepted",
        data=_member_response(member).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Self-service
# ============================================================================


@router.get(
    "/me/organizations",
    response_model=ApiResponse[list[OrganizationMemberResponse]],
    status_code=status.HTTP_200_OK,
)
async def list_my_organizations(
    request: Request,
    membership_status: MembershipStatus | None = Query(default=None),
    user: AuthUser = Depends(CurrentUser),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    memberships = await organization_service.list_user_organizations(
        uuid.UUID(user.id), status=membership_status
    )
    return build_response(
        success=True,
        message="Your organization memberships",
        data=[_member_response(member).model_dump() for member in memberships],
        request_id=_request_id(request),
    )
