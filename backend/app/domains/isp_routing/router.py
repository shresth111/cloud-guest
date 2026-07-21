"""FastAPI routes for the ISP Routing domain: traffic-steering rule CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
brand-new ``isp_routing.*`` permission key (see ``app.domains.rbac.seed``
-- ``PermissionModule.ISP_ROUTING``) and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``IspRoutingService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /isp-routing/rules`` is registered
before ``GET /isp-routing/rules/{rule_id}`` so Starlette's first-match-wins
routing resolves the literal path first, mirroring the same discipline
``app.domains.isp.router`` already follows.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import IspRoutingRuleType
from .dependencies import get_isp_routing_service
from .models import IspRoutingRule
from .schemas import (
    IspRoutingRuleCreateRequest,
    IspRoutingRuleListResponse,
    IspRoutingRuleResponse,
    IspRoutingRuleUpdateRequest,
    MessageResponse,
)
from .service import IspRoutingService

router = APIRouter(prefix="/isp-routing", tags=["ISP Routing"])


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


def _rule_response(rule: IspRoutingRule) -> IspRoutingRuleResponse:
    return IspRoutingRuleResponse(
        id=str(rule.id),
        router_id=str(rule.router_id),
        organization_id=str(rule.organization_id),
        location_id=str(rule.location_id),
        isp_link_id=str(rule.isp_link_id),
        rule_type=rule.rule_type,
        name=rule.name,
        description=rule.description,
        priority=rule.priority,
        is_enabled=rule.is_enabled,
        vlan_id=rule.vlan_id,
        source_mac_address=rule.source_mac_address,
        ip_address=rule.ip_address,
        source_cidr=rule.source_cidr,
        interface_name=rule.interface_name,
        policy_id=str(rule.policy_id) if rule.policy_id else None,
        created_at=rule.created_at,
    )


@router.post(
    "/rules",
    response_model=ApiResponse[IspRoutingRuleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("isp_routing.create"))],
)
async def create_isp_routing_rule(
    request: Request,
    payload: IspRoutingRuleCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspRoutingService = Depends(get_isp_routing_service),
):
    rule = await service.create_rule(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        isp_link_id=uuid.UUID(payload.isp_link_id),
        rule_type=IspRoutingRuleType(payload.rule_type),
        name=payload.name,
        description=payload.description,
        priority=payload.priority,
        is_enabled=payload.is_enabled,
        vlan_id=payload.vlan_id,
        source_mac_address=payload.source_mac_address,
        ip_address=payload.ip_address,
        source_cidr=payload.source_cidr,
        interface_name=payload.interface_name,
        policy_id=uuid.UUID(payload.policy_id) if payload.policy_id else None,
    )
    return build_response(
        success=True,
        message="ISP routing rule created",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/rules",
    response_model=ApiResponse[IspRoutingRuleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp_routing.read"))],
)
async def list_isp_routing_rules(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspRoutingService = Depends(get_isp_routing_service),
):
    rules, meta = await service.list_rules(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = IspRoutingRuleListResponse(
        items=[_rule_response(rule) for rule in rules], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="ISP routing rules retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/rules/{rule_id}",
    response_model=ApiResponse[IspRoutingRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp_routing.read"))],
)
async def get_isp_routing_rule(
    request: Request,
    rule_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspRoutingService = Depends(get_isp_routing_service),
):
    rule = await service.get_rule(
        rule_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="ISP routing rule retrieved",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/rules/{rule_id}",
    response_model=ApiResponse[IspRoutingRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp_routing.update"))],
)
async def update_isp_routing_rule(
    request: Request,
    rule_id: uuid.UUID,
    payload: IspRoutingRuleUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspRoutingService = Depends(get_isp_routing_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "isp_link_id" in fields:
        fields["isp_link_id"] = uuid.UUID(fields["isp_link_id"])
    if "policy_id" in fields:
        fields["policy_id"] = uuid.UUID(fields["policy_id"])
    rule = await service.update_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="ISP routing rule updated",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/rules/{rule_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp_routing.delete"))],
)
async def delete_isp_routing_rule(
    request: Request,
    rule_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspRoutingService = Depends(get_isp_routing_service),
):
    await service.delete_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="ISP routing rule deleted",
        data=MessageResponse(message="ISP routing rule deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
