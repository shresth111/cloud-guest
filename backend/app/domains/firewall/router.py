"""FastAPI routes for the Firewall Rule Management domain: per-router
packet-filter rule CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
already-seeded ``firewall.*`` permission key (``PermissionModule.FIREWALL``
-- the same key ``app.domains.port_forwarding`` already reuses for its own
NAT concern, see that domain's own router docstring) and resolves
``CurrentOrganization``, passed through to ``FirewallService`` as
``requesting_organization_id``.

**Route ordering matters.** ``GET /firewall-rules`` is registered before
``GET /firewall-rules/{rule_id}`` so Starlette's first-match-wins routing
resolves the literal path first, mirroring the same discipline
``app.domains.dhcp.router`` already follows.
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

from .constants import FirewallAction, FirewallChain, FirewallProtocol
from .dependencies import get_firewall_service
from .models import FirewallRule
from .schemas import (
    FirewallRuleCreateRequest,
    FirewallRuleListResponse,
    FirewallRuleResponse,
    FirewallRuleUpdateRequest,
    MessageResponse,
)
from .service import FirewallService

router = APIRouter(prefix="/firewall-rules", tags=["Firewall Rule Management"])


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


def _rule_response(rule: FirewallRule) -> FirewallRuleResponse:
    return FirewallRuleResponse(
        id=str(rule.id),
        router_id=str(rule.router_id),
        organization_id=str(rule.organization_id),
        location_id=str(rule.location_id),
        name=rule.name,
        chain=rule.chain,
        action=rule.action,
        protocol=rule.protocol,
        source_address=rule.source_address,
        destination_address=rule.destination_address,
        source_port=rule.source_port,
        destination_port=rule.destination_port,
        in_interface=rule.in_interface,
        priority=rule.priority,
        comment=rule.comment,
        is_enabled=rule.is_enabled,
        created_at=rule.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[FirewallRuleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("firewall.create"))],
)
async def create_firewall_rule(
    request: Request,
    payload: FirewallRuleCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: FirewallService = Depends(get_firewall_service),
):
    rule = await service.create_rule(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        name=payload.name,
        chain=payload.chain,
        action=payload.action,
        protocol=payload.protocol,
        source_address=payload.source_address,
        destination_address=payload.destination_address,
        source_port=payload.source_port,
        destination_port=payload.destination_port,
        in_interface=payload.in_interface,
        priority=payload.priority,
        comment=payload.comment,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="Firewall rule created",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[FirewallRuleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("firewall.read"))],
)
async def list_firewall_rules(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: FirewallService = Depends(get_firewall_service),
):
    rules, meta = await service.list_rules(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = FirewallRuleListResponse(
        items=[_rule_response(rule) for rule in rules], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Firewall rules retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{rule_id}",
    response_model=ApiResponse[FirewallRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("firewall.read"))],
)
async def get_firewall_rule(
    request: Request,
    rule_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: FirewallService = Depends(get_firewall_service),
):
    rule = await service.get_rule(
        rule_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Firewall rule retrieved",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{rule_id}",
    response_model=ApiResponse[FirewallRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("firewall.update"))],
)
async def update_firewall_rule(
    request: Request,
    rule_id: uuid.UUID,
    payload: FirewallRuleUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: FirewallService = Depends(get_firewall_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "chain" in fields:
        fields["chain"] = FirewallChain(fields["chain"])
    if "action" in fields:
        fields["action"] = FirewallAction(fields["action"])
    if "protocol" in fields:
        fields["protocol"] = FirewallProtocol(fields["protocol"])
    rule = await service.update_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Firewall rule updated",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{rule_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("firewall.delete"))],
)
async def delete_firewall_rule(
    request: Request,
    rule_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: FirewallService = Depends(get_firewall_service),
):
    await service.delete_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Firewall rule deleted",
        data=MessageResponse(message="Firewall rule deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
