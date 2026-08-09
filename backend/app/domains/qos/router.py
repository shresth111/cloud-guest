"""FastAPI routes for the QoS & VOIP Priority domain: per-router
traffic-classification rule CRUD, plus a real device-push action.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
``qos.*`` permission key (see ``app.domains.rbac.seed`` --
``PermissionModule.QOS``) and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``QosService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /qos-rules`` is registered before
``GET /qos-rules/{rule_id}`` so Starlette's first-match-wins routing
resolves the literal path first, mirroring the same discipline
``app.domains.hotspot.router`` already follows. ``POST /{rule_id}/push``
needs no such ordering care -- it is a distinct HTTP method/path shape
from every other route here, so registration order does not matter for
it, but it is placed right after ``POST ""`` (create) so the two
mutation-then-realize actions read together.

**``POST /{rule_id}/push`` (new)** -- the real device-push endpoint this
domain gained to close the "marks traffic, never creates the paired
queue" gap (``docs/qos/FLOW.md`` Section 2,
``app.domains.qos.service.QosService.push_rule_to_device``'s own
docstring). Gated by the new ``qos.execute`` permission action (see
``app.domains.rbac.seed``'s ``PermissionModule.QOS`` entry), not
``qos.update`` -- this is real device I/O, not a field edit. This is the
real endpoint a future "Call Priority" frontend push affordance
(``cloudguest-foundation``'s ``QosManagement.tsx``, currently DB-writes
only with no push UI at all) should call; wiring that frontend affordance
is explicitly out of scope for this backend-only fix.
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

from .dependencies import get_qos_service
from .models import QosTrafficRule
from .schemas import (
    MessageResponse,
    QosTrafficRuleCreateRequest,
    QosTrafficRuleListResponse,
    QosTrafficRuleResponse,
    QosTrafficRuleUpdateRequest,
)
from .service import QosService

router = APIRouter(prefix="/qos-rules", tags=["QoS & VOIP Priority"])


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


def _rule_response(rule: QosTrafficRule) -> QosTrafficRuleResponse:
    return QosTrafficRuleResponse(
        id=str(rule.id),
        router_id=str(rule.router_id),
        organization_id=str(rule.organization_id),
        location_id=str(rule.location_id),
        name=rule.name,
        protocol=rule.protocol,
        port_range_start=rule.port_range_start,
        port_range_end=rule.port_range_end,
        dscp_value=rule.dscp_value,
        priority=rule.priority,
        is_enabled=rule.is_enabled,
        device_queue_id=rule.device_queue_id,
        device_push_status=rule.device_push_status,
        device_push_error=rule.device_push_error,
        device_pushed_at=rule.device_pushed_at,
        created_at=rule.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[QosTrafficRuleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("qos.create"))],
)
async def create_qos_rule(
    request: Request,
    payload: QosTrafficRuleCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QosService = Depends(get_qos_service),
):
    rule = await service.create_rule(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        name=payload.name,
        protocol=payload.protocol,
        port_range_start=payload.port_range_start,
        port_range_end=payload.port_range_end,
        dscp_value=payload.dscp_value,
        priority=payload.priority,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="QoS traffic rule created",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{rule_id}/push",
    response_model=ApiResponse[QosTrafficRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("qos.execute"))],
)
async def push_qos_rule(
    request: Request,
    rule_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QosService = Depends(get_qos_service),
):
    """Real device push: creates/updates this rule's own paired
    ``/queue tree`` entry on its router, referencing the exact packet-mark
    identifier ``app.domains.network_config.renderers
    .render_qos_traffic_rule`` already marks matching traffic with. The
    real endpoint the customer-facing "Call Priority" feature's own future
    push affordance should call -- see ``service.py::push_rule_to_device``'s
    own docstring for the full create-vs-update/failure-handling write-up.
    Gated by ``qos.execute`` (new -- see ``app.domains.rbac.seed``), not
    ``qos.update``: this is a real device-facing action, not a plain field
    edit, mirroring ``network_config.execute``'s identical distinction."""
    rule = await service.push_rule_to_device(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="QoS traffic rule priority queue pushed to device",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[QosTrafficRuleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("qos.read"))],
)
async def list_qos_rules(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QosService = Depends(get_qos_service),
):
    rules, meta = await service.list_rules(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = QosTrafficRuleListResponse(
        items=[_rule_response(rule) for rule in rules], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="QoS traffic rules retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{rule_id}",
    response_model=ApiResponse[QosTrafficRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("qos.read"))],
)
async def get_qos_rule(
    request: Request,
    rule_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QosService = Depends(get_qos_service),
):
    rule = await service.get_rule(
        rule_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="QoS traffic rule retrieved",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{rule_id}",
    response_model=ApiResponse[QosTrafficRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("qos.update"))],
)
async def update_qos_rule(
    request: Request,
    rule_id: uuid.UUID,
    payload: QosTrafficRuleUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QosService = Depends(get_qos_service),
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
        message="QoS traffic rule updated",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{rule_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("qos.delete"))],
)
async def delete_qos_rule(
    request: Request,
    rule_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QosService = Depends(get_qos_service),
):
    await service.delete_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="QoS traffic rule deleted",
        data=MessageResponse(message="QoS traffic rule deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
