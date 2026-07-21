"""FastAPI routes for the Port Forwarding Management domain: per-router
DSTNAT rule CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
already-seeded ``firewall.*`` permission keys (this domain reuses the
pre-existing ``PermissionModule.FIREWALL`` key -- port forwarding is a
real RouterOS ``/ip firewall nat`` DSTNAT concept, the same reuse posture
``app.domains.dhcp`` established for the pre-existing
``PermissionModule.DHCP``) and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``PortForwardingService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /port-forwarding/rules`` is registered
before ``GET /port-forwarding/rules/{rule_id}`` so Starlette's
first-match-wins routing resolves the literal path first, mirroring the
same discipline ``app.domains.isp_routing.router`` already follows.
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

from .constants import PortForwardingProtocol
from .dependencies import get_port_forwarding_service
from .models import PortForwardingRule
from .schemas import (
    MessageResponse,
    PortForwardingRuleCreateRequest,
    PortForwardingRuleListResponse,
    PortForwardingRuleResponse,
    PortForwardingRuleUpdateRequest,
)
from .service import PortForwardingService

router = APIRouter(prefix="/port-forwarding", tags=["Port Forwarding Management"])


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


def _rule_response(rule: PortForwardingRule) -> PortForwardingRuleResponse:
    return PortForwardingRuleResponse(
        id=str(rule.id),
        router_id=str(rule.router_id),
        organization_id=str(rule.organization_id),
        location_id=str(rule.location_id),
        name=rule.name,
        protocol=rule.protocol,
        source_address=rule.source_address,
        destination_address=rule.destination_address,
        destination_port=rule.destination_port,
        internal_address=rule.internal_address,
        internal_port=rule.internal_port,
        description=rule.description,
        is_enabled=rule.is_enabled,
        created_at=rule.created_at,
    )


@router.post(
    "/rules",
    response_model=ApiResponse[PortForwardingRuleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("firewall.create"))],
)
async def create_port_forwarding_rule(
    request: Request,
    payload: PortForwardingRuleCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PortForwardingService = Depends(get_port_forwarding_service),
):
    rule = await service.create_rule(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        name=payload.name,
        protocol=PortForwardingProtocol(payload.protocol),
        source_address=payload.source_address,
        destination_address=payload.destination_address,
        destination_port=payload.destination_port,
        internal_address=payload.internal_address,
        internal_port=payload.internal_port,
        description=payload.description,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="Port forwarding rule created",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/rules",
    response_model=ApiResponse[PortForwardingRuleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("firewall.read"))],
)
async def list_port_forwarding_rules(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PortForwardingService = Depends(get_port_forwarding_service),
):
    rules, meta = await service.list_rules(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = PortForwardingRuleListResponse(
        items=[_rule_response(rule) for rule in rules], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Port forwarding rules retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/rules/{rule_id}",
    response_model=ApiResponse[PortForwardingRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("firewall.read"))],
)
async def get_port_forwarding_rule(
    request: Request,
    rule_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PortForwardingService = Depends(get_port_forwarding_service),
):
    rule = await service.get_rule(
        rule_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Port forwarding rule retrieved",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/rules/{rule_id}",
    response_model=ApiResponse[PortForwardingRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("firewall.update"))],
)
async def update_port_forwarding_rule(
    request: Request,
    rule_id: uuid.UUID,
    payload: PortForwardingRuleUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PortForwardingService = Depends(get_port_forwarding_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    rule = await service.update_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Port forwarding rule updated",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/rules/{rule_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("firewall.delete"))],
)
async def delete_port_forwarding_rule(
    request: Request,
    rule_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PortForwardingService = Depends(get_port_forwarding_service),
):
    await service.delete_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Port forwarding rule deleted",
        data=MessageResponse(message="Port forwarding rule deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
