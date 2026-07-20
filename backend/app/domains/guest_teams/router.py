"""FastAPI routes for the Guest Teams domain: guest-facing join, and
admin-facing team create/list/detail/member-removal/revocation.

Two separate ``APIRouter`` instances share the same ``/guest-teams`` prefix
but carry two different authentication postures, mirroring
``app.domains.guest.router``'s own multi-router-per-prefix precedent:

* ``guest_router`` -- ``POST /guest-teams/join``. No ``RequirePermission``/
  ``CurrentUser`` at all, mirroring ``app.domains.otp.router``/
  ``app.domains.voucher.router``/``app.domains.guest.router``'s identical
  justification: the caller is a guest presenting a team's join code, with
  no platform-user identity RBAC could ever grant a permission to.
* ``admin_router`` -- create/list/detail/member-removal/revocation. Gated by
  RBAC's ``RequirePermission`` against the newly-seeded ``guest_teams.*``
  permission keys (see ``app/domains/rbac/seed.py
  ::MODULE_ACTIONS[PermissionModule.GUEST_TEAMS]`` and this module's own
  ``docs/guest_teams/FLOW.md`` for the full "reuse an existing module vs. add
  a new one" reasoning).

Permission-key choice worth calling out: both ``DELETE .../members/{guest_id}``
(remove a member) and ``POST .../revoke`` (revoke the whole team) are gated
by ``guest_teams.execute``, not ``.delete``/``.manage`` -- mirrors
``app.domains.guest.router``'s own choice of ``guest_sessions.execute`` for
both ``disconnect``/``terminate``: both are operational, punitive lifecycle
actions (ending a member's/team's access), not a destructive record deletion
or a platform-admin-only "manage" action, so the same front-line roles that
can operate a team (front desk, location managers) can also remove a member
or revoke it without needing ``guest_teams.manage``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import GuestTeamStatus
from .dependencies import get_guest_team_service
from .models import GuestTeam, GuestTeamMember
from .schemas import (
    GuestTeamCreateRequest,
    GuestTeamDetailResponse,
    GuestTeamJoinRequest,
    GuestTeamJoinResponse,
    GuestTeamListResponse,
    GuestTeamMemberRemovalResponse,
    GuestTeamMemberRemoveRequest,
    GuestTeamMemberResponse,
    GuestTeamResponse,
    GuestTeamRevokeRequest,
    GuestTeamRevokeResponse,
    GuestTeamSummaryResponse,
)
from .service import GuestTeamService

guest_router = APIRouter(prefix="/guest-teams", tags=["Guest Teams"])
admin_router = APIRouter(prefix="/guest-teams", tags=["Guest Teams Admin"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _team_response(team: GuestTeam) -> GuestTeamResponse:
    return GuestTeamResponse(
        id=str(team.id),
        organization_id=str(team.organization_id),
        location_id=str(team.location_id) if team.location_id else None,
        name=team.name,
        team_code=team.team_code,
        status=GuestTeamStatus(team.status),
        max_members=team.max_members,
        shared_data_limit_mb=team.shared_data_limit_mb,
        expires_at=team.expires_at,
        created_by_user_id=(
            str(team.created_by_user_id) if team.created_by_user_id else None
        ),
        revoked_at=team.revoked_at,
        revoked_reason=team.revoked_reason,
        created_at=team.created_at,
        updated_at=team.updated_at,
    )


def _member_response(member: GuestTeamMember) -> GuestTeamMemberResponse:
    return GuestTeamMemberResponse(
        id=str(member.id),
        team_id=str(member.team_id),
        guest_id=str(member.guest_id),
        joined_at=member.joined_at,
        is_active=member.is_active,
        left_at=member.left_at,
        removal_reason=member.removal_reason,
    )


# ============================================================================
# Guest-facing endpoint -- no RBAC, see module docstring
# ============================================================================


@guest_router.post(
    "/join",
    response_model=ApiResponse[GuestTeamJoinResponse],
    status_code=status.HTTP_200_OK,
)
async def join_guest_team(
    request: Request,
    payload: GuestTeamJoinRequest,
    service: GuestTeamService = Depends(get_guest_team_service),
):
    result = await service.join_team(
        team_code=payload.team_code,
        identifier=payload.identifier,
        device_mac=payload.device_mac,
        device_name=payload.device_name,
    )
    return build_response(
        success=True,
        message="Joined guest team" if result.is_new_membership else "Already a member",
        data=GuestTeamJoinResponse(
            team_id=str(result.team.id),
            guest_id=str(result.guest_id),
            identifier=result.identifier,
            is_new_guest=result.is_new_guest,
            is_new_membership=result.is_new_membership,
            membership=_member_response(result.membership),
        ).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Admin-facing endpoints
# ============================================================================


@admin_router.post(
    "",
    response_model=ApiResponse[GuestTeamResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("guest_teams.create"))],
)
async def create_guest_team(
    request: Request,
    payload: GuestTeamCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestTeamService = Depends(get_guest_team_service),
):
    team = await service.create_team(
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        organization_id=payload.organization_id,
        location_id=payload.location_id,
        name=payload.name,
        max_members=payload.max_members,
        shared_data_limit_mb=payload.shared_data_limit_mb,
        expires_at=payload.expires_at,
    )
    return build_response(
        success=True,
        message="Guest team created",
        data=_team_response(team).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.get(
    "",
    response_model=ApiResponse[GuestTeamListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_teams.read"))],
)
async def list_guest_teams(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    location_id: uuid.UUID | None = Query(default=None),
    status_filter: GuestTeamStatus | None = Query(default=None, alias="status"),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestTeamService = Depends(get_guest_team_service),
):
    teams, meta = await service.list_teams(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        status=status_filter,
        page=page,
        page_size=page_size,
    )
    payload = GuestTeamListResponse(
        items=[_team_response(team) for team in teams],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Guest teams retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@admin_router.get(
    "/{team_id}",
    response_model=ApiResponse[GuestTeamDetailResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_teams.read"))],
)
async def get_guest_team(
    request: Request,
    team_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestTeamService = Depends(get_guest_team_service),
):
    team = await service.get_team(
        team_id, requesting_organization_id=requesting_organization_id
    )
    summary = await service.get_team_summary(
        team_id, requesting_organization_id=requesting_organization_id
    )
    payload = GuestTeamDetailResponse(
        **_team_response(team).model_dump(),
        summary=GuestTeamSummaryResponse(
            member_count=summary.member_count,
            active_session_count=summary.active_session_count,
            total_bandwidth_bytes=summary.total_bandwidth_bytes,
            shared_data_limit_mb=summary.shared_data_limit_mb,
            remaining_shared_quota_mb=summary.remaining_shared_quota_mb,
            quota_exceeded=summary.quota_exceeded,
        ),
    )
    return build_response(
        success=True,
        message="Guest team retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@admin_router.delete(
    "/{team_id}/members/{guest_id}",
    response_model=ApiResponse[GuestTeamMemberRemovalResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_teams.execute"))],
)
async def remove_guest_team_member(
    request: Request,
    team_id: uuid.UUID,
    guest_id: uuid.UUID,
    payload: GuestTeamMemberRemoveRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestTeamService = Depends(get_guest_team_service),
):
    result = await service.remove_team_member(
        team_id=team_id,
        guest_id=guest_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Guest team member removed",
        data=GuestTeamMemberRemovalResponse(
            team_id=str(result.team.id),
            guest_id=str(guest_id),
            terminated_session_ids=[str(s) for s in result.terminated_session_ids],
        ).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/{team_id}/revoke",
    response_model=ApiResponse[GuestTeamRevokeResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_teams.execute"))],
)
async def revoke_guest_team(
    request: Request,
    team_id: uuid.UUID,
    payload: GuestTeamRevokeRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestTeamService = Depends(get_guest_team_service),
):
    result = await service.revoke_team(
        team_id=team_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Guest team revoked",
        data=GuestTeamRevokeResponse(
            team=_team_response(result.team),
            member_count=result.member_count,
            terminated_session_ids=[str(s) for s in result.terminated_session_ids],
            failed_member_ids=[str(g) for g in result.failed_member_ids],
        ).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["guest_router", "admin_router"]
