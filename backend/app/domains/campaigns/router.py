"""FastAPI routes for the Campaigns domain.

Two routers, mirroring ``app.domains.guest_teams.router``'s own identical
"one admin router, one guest-facing router, same domain module" split:

* ``router`` (``/campaigns``) -- admin CRUD + questions/assets + clone +
  results/export, every endpoint gated by RBAC's ``RequirePermission``
  against the already-seeded ``campaigns.*`` permission keys (see
  ``app.domains.rbac.seed`` -- ``PermissionModule.CAMPAIGNS``; zero enum/
  seed changes needed for this domain).
* ``guest_router`` (``/portal/campaigns``) -- captive-portal-facing
  serve/respond/impression endpoints. **Deliberately carries no
  ``RequirePermission``/``CurrentUser``/``CurrentOrganization`` at all**
  -- mirrors ``app.domains.guest.router``'s own ``guest_router`` exactly:
  research confirmed no "current guest session from a token" mechanism
  exists anywhere in this codebase, so guest identity is always an
  explicit ``guest_session_id`` body/query parameter, never inferred from
  auth state.

**Route ordering matters.** ``GET /campaigns`` is registered before
``GET /campaigns/{campaign_id}`` so Starlette's first-match-wins routing
resolves the literal path first, mirroring ``app.domains.qos.router``'s
same discipline.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import AnswerType, CampaignType, DisplayRule
from .dependencies import get_campaigns_service
from .models import Campaign, CampaignAsset, CampaignQuestion
from .schemas import (
    CampaignAssetCreateRequest,
    CampaignAssetResponse,
    CampaignAssetUpdateRequest,
    CampaignCloneRequest,
    CampaignCreateRequest,
    CampaignImpressionRequest,
    CampaignListResponse,
    CampaignQuestionCreateRequest,
    CampaignQuestionResponse,
    CampaignQuestionUpdateRequest,
    CampaignRespondRequest,
    CampaignResponse,
    CampaignResultsResponse,
    CampaignUpdateRequest,
    MessageResponse,
    NextCampaignAssetPayload,
    NextCampaignQuestionPayload,
    NextCampaignResponse,
    QuestionResultBreakdownResponse,
)
from .service import CampaignResults, CampaignsService, NextCampaignResult

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])
guest_router = APIRouter(prefix="/portal/campaigns", tags=["Campaigns Portal"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _pagination_fields(meta: PaginationMeta) -> dict[str, int | bool]:
    return {
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


def _campaign_response(campaign: Campaign) -> CampaignResponse:
    return CampaignResponse(
        id=str(campaign.id),
        organization_id=str(campaign.organization_id),
        location_id=str(campaign.location_id) if campaign.location_id else None,
        name=campaign.name,
        campaign_type=campaign.campaign_type,
        status=campaign.status,
        starts_at=campaign.starts_at,
        ends_at=campaign.ends_at,
        display_rule=campaign.display_rule,
        display_interval_days=campaign.display_interval_days,
        target_networks=list(campaign.target_networks),
        is_skippable=campaign.is_skippable,
        created_at=campaign.created_at,
    )


def _question_response(question: CampaignQuestion) -> CampaignQuestionResponse:
    return CampaignQuestionResponse(
        id=str(question.id),
        campaign_id=str(question.campaign_id),
        order_index=question.order_index,
        question_text=question.question_text,
        answer_type=question.answer_type,
        options=list(question.options),
        is_required=question.is_required,
    )


def _asset_response(asset: CampaignAsset) -> CampaignAssetResponse:
    return CampaignAssetResponse(
        id=str(asset.id),
        campaign_id=str(asset.campaign_id),
        image_url=asset.image_url,
        click_url=asset.click_url,
        alt_text=asset.alt_text,
        locale=asset.locale,
    )


def _results_response(results: CampaignResults) -> CampaignResultsResponse:
    return CampaignResultsResponse(
        campaign_id=str(results.campaign_id),
        total_responses=results.total_responses,
        total_impressions=results.total_impressions,
        total_skipped=results.total_skipped,
        total_clicked=results.total_clicked,
        question_breakdowns=[
            QuestionResultBreakdownResponse(
                question_id=str(b.question_id),
                question_text=b.question_text,
                answer_type=b.answer_type,
                total_answers=b.total_answers,
                option_counts=b.option_counts,
                average_rating=b.average_rating,
                rating_distribution=b.rating_distribution,
                free_text_answers=b.free_text_answers,
            )
            for b in results.question_breakdowns
        ],
    )


def _next_campaign_response(result: NextCampaignResult) -> NextCampaignResponse:
    return NextCampaignResponse(
        campaign_id=str(result.campaign.id),
        campaign_type=result.campaign.campaign_type,
        is_skippable=result.campaign.is_skippable,
        questions=[
            NextCampaignQuestionPayload(
                id=str(q.id),
                order_index=q.order_index,
                question_text=q.question_text,
                answer_type=q.answer_type,
                options=list(q.options),
                is_required=q.is_required,
            )
            for q in result.questions
        ],
        asset=(
            NextCampaignAssetPayload(
                image_url=result.asset.image_url,
                click_url=result.asset.click_url,
                alt_text=result.asset.alt_text,
            )
            if result.asset is not None
            else None
        ),
    )


# ============================================================================
# Admin: Campaign CRUD
# ============================================================================


@router.post(
    "",
    response_model=ApiResponse[CampaignResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("campaigns.create"))],
)
async def create_campaign(
    request: Request,
    payload: CampaignCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    campaign = await service.create_campaign(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        location_id=uuid.UUID(payload.location_id) if payload.location_id else None,
        name=payload.name,
        campaign_type=CampaignType(payload.campaign_type),
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
        display_rule=DisplayRule(payload.display_rule),
        display_interval_days=payload.display_interval_days,
        target_networks=payload.target_networks,
        is_skippable=payload.is_skippable,
    )
    return build_response(
        success=True,
        message="Campaign created",
        data=_campaign_response(campaign).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[CampaignListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.read"))],
)
async def list_campaigns(
    request: Request,
    location_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    campaigns, meta = await service.list_campaigns(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=page,
        page_size=page_size,
    )
    payload = CampaignListResponse(
        items=[_campaign_response(c) for c in campaigns], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Campaigns retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{campaign_id}",
    response_model=ApiResponse[CampaignResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.read"))],
)
async def get_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    campaign = await service.get_campaign(
        campaign_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Campaign retrieved",
        data=_campaign_response(campaign).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{campaign_id}",
    response_model=ApiResponse[CampaignResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def update_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    payload: CampaignUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    fields = payload.model_dump(exclude_unset=True)
    if "location_id" in fields:
        fields["location_id"] = (
            uuid.UUID(fields["location_id"]) if fields["location_id"] else None
        )
    if "display_rule" in fields and fields["display_rule"] is not None:
        fields["display_rule"] = DisplayRule(fields["display_rule"])
    campaign = await service.update_campaign(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Campaign updated",
        data=_campaign_response(campaign).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{campaign_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.delete"))],
)
async def delete_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    await service.delete_campaign(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Campaign deleted",
        data=MessageResponse(message="Campaign deleted").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{campaign_id}/clone",
    response_model=ApiResponse[CampaignResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("campaigns.create"))],
)
async def clone_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    payload: CampaignCloneRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    clone = await service.clone_campaign(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        new_name=payload.new_name,
    )
    return build_response(
        success=True,
        message="Campaign cloned",
        data=_campaign_response(clone).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Admin: lifecycle transitions
# ============================================================================


@router.post(
    "/{campaign_id}/schedule",
    response_model=ApiResponse[CampaignResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def schedule_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    campaign = await service.schedule_campaign(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Campaign scheduled",
        data=_campaign_response(campaign).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{campaign_id}/pause",
    response_model=ApiResponse[CampaignResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def pause_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    campaign = await service.pause_campaign(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Campaign paused",
        data=_campaign_response(campaign).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{campaign_id}/resume",
    response_model=ApiResponse[CampaignResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def resume_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    campaign = await service.resume_campaign(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Campaign resumed",
        data=_campaign_response(campaign).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{campaign_id}/end",
    response_model=ApiResponse[CampaignResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def end_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    campaign = await service.end_campaign(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Campaign ended",
        data=_campaign_response(campaign).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Admin: Questions (SURVEY only)
# ============================================================================


@router.post(
    "/{campaign_id}/questions",
    response_model=ApiResponse[CampaignQuestionResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def add_campaign_question(
    request: Request,
    campaign_id: uuid.UUID,
    payload: CampaignQuestionCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    question = await service.add_question(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        order_index=payload.order_index,
        question_text=payload.question_text,
        answer_type=AnswerType(payload.answer_type),
        options=payload.options,
        is_required=payload.is_required,
    )
    return build_response(
        success=True,
        message="Campaign question added",
        data=_question_response(question).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{campaign_id}/questions",
    response_model=ApiResponse[list[CampaignQuestionResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.read"))],
)
async def list_campaign_questions(
    request: Request,
    campaign_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    questions = await service.list_questions(
        campaign_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Campaign questions retrieved",
        data=[_question_response(q).model_dump() for q in questions],
        request_id=_request_id(request),
    )


@router.put(
    "/questions/{question_id}",
    response_model=ApiResponse[CampaignQuestionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def update_campaign_question(
    request: Request,
    question_id: uuid.UUID,
    payload: CampaignQuestionUpdateRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    fields = payload.model_dump(exclude_unset=True)
    if "answer_type" in fields and fields["answer_type"] is not None:
        fields["answer_type"] = AnswerType(fields["answer_type"])
    question = await service.update_question(
        question_id,
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Campaign question updated",
        data=_question_response(question).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/questions/{question_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def delete_campaign_question(
    request: Request,
    question_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    await service.delete_question(
        question_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Campaign question deleted",
        data=MessageResponse(message="Campaign question deleted").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Admin: Assets (BANNER/REDIRECT only)
# ============================================================================


@router.post(
    "/{campaign_id}/assets",
    response_model=ApiResponse[CampaignAssetResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def add_campaign_asset(
    request: Request,
    campaign_id: uuid.UUID,
    payload: CampaignAssetCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    asset = await service.add_asset(
        campaign_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        image_url=payload.image_url,
        click_url=payload.click_url,
        alt_text=payload.alt_text,
        locale=payload.locale,
    )
    return build_response(
        success=True,
        message="Campaign asset added",
        data=_asset_response(asset).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{campaign_id}/assets",
    response_model=ApiResponse[list[CampaignAssetResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.read"))],
)
async def list_campaign_assets(
    request: Request,
    campaign_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    assets = await service.list_assets(
        campaign_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Campaign assets retrieved",
        data=[_asset_response(a).model_dump() for a in assets],
        request_id=_request_id(request),
    )


@router.put(
    "/assets/{asset_id}",
    response_model=ApiResponse[CampaignAssetResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def update_campaign_asset(
    request: Request,
    asset_id: uuid.UUID,
    payload: CampaignAssetUpdateRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    fields = payload.model_dump(exclude_unset=True)
    asset = await service.update_asset(
        asset_id,
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Campaign asset updated",
        data=_asset_response(asset).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/assets/{asset_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.update"))],
)
async def delete_campaign_asset(
    request: Request,
    asset_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    await service.delete_asset(
        asset_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Campaign asset deleted",
        data=MessageResponse(message="Campaign asset deleted").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Admin: results / export
# ============================================================================


@router.get(
    "/{campaign_id}/results",
    response_model=ApiResponse[CampaignResultsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.read"))],
)
async def get_campaign_results(
    request: Request,
    campaign_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
):
    results = await service.get_results(
        campaign_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Campaign results retrieved",
        data=_results_response(results).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{campaign_id}/results/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("campaigns.export"))],
)
async def export_campaign_results(
    campaign_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CampaignsService = Depends(get_campaigns_service),
) -> Response:
    csv_text = await service.export_results_csv(
        campaign_id, requesting_organization_id=requesting_organization_id
    )
    filename = f"campaign-{campaign_id}-results.csv"
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ============================================================================
# Guest-facing endpoints -- no RBAC, see module docstring
# ============================================================================


@guest_router.get(
    "/next",
    response_model=ApiResponse[NextCampaignResponse],
    status_code=status.HTTP_200_OK,
)
async def get_next_campaign(
    request: Request,
    session_id: uuid.UUID = Query(...),
    service: CampaignsService = Depends(get_campaigns_service),
):
    result = await service.get_next_campaign_for_session(session_id)
    return build_response(
        success=True,
        message="Next campaign resolved"
        if result is not None
        else "No campaign to show",
        data=_next_campaign_response(result).model_dump()
        if result is not None
        else None,
        request_id=_request_id(request),
    )


@guest_router.post(
    "/{campaign_id}/respond",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_201_CREATED,
)
async def respond_to_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    payload: CampaignRespondRequest,
    service: CampaignsService = Depends(get_campaigns_service),
):
    await service.submit_response(
        campaign_id,
        guest_session_id=uuid.UUID(payload.guest_session_id),
        answers=payload.answers,
    )
    return build_response(
        success=True,
        message="Response recorded",
        data=MessageResponse(message="Response recorded").model_dump(),
        request_id=_request_id(request),
    )


@guest_router.post(
    "/{campaign_id}/impression",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_201_CREATED,
)
async def record_campaign_impression(
    request: Request,
    campaign_id: uuid.UUID,
    payload: CampaignImpressionRequest,
    service: CampaignsService = Depends(get_campaigns_service),
):
    await service.record_impression(
        campaign_id,
        guest_session_id=uuid.UUID(payload.guest_session_id),
        was_skipped=payload.was_skipped,
        was_clicked=payload.was_clicked,
    )
    return build_response(
        success=True,
        message="Impression recorded",
        data=MessageResponse(message="Impression recorded").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router", "guest_router"]
