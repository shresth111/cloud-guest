"""FastAPI routes for the notification domain: ``NotificationTemplate``
CRUD and ``NotificationDelivery`` list/retry.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against
``notifications.*`` (``PermissionModule.NOTIFICATIONS``, already seeded --
see ``app.domains.rbac.seed``) and resolves ``CurrentOrganization``,
passed through as ``requesting_organization_id`` -- the same tenant-scoping
posture every other domain's router already enforces.

**Route ordering matters.** ``GET /notifications/templates`` is registered
before ``GET /notifications/templates/{template_id}`` so Starlette's
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

from .dependencies import get_notification_service
from .models import NotificationDelivery, NotificationTemplate
from .schemas import (
    MessageResponse,
    NotificationDeliveryListResponse,
    NotificationDeliveryResponse,
    NotificationTemplateCreateRequest,
    NotificationTemplateListResponse,
    NotificationTemplateResponse,
    NotificationTemplateUpdateRequest,
)
from .service import NotificationService

router = APIRouter(prefix="/notifications", tags=["Notifications"])


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


def _template_response(template: NotificationTemplate) -> NotificationTemplateResponse:
    return NotificationTemplateResponse(
        id=str(template.id),
        organization_id=(
            str(template.organization_id) if template.organization_id else None
        ),
        event_type=template.event_type,
        channel=template.channel,
        subject_template=template.subject_template,
        body_template=template.body_template,
        is_active=template.is_active,
        created_at=template.created_at,
    )


def _delivery_response(delivery: NotificationDelivery) -> NotificationDeliveryResponse:
    return NotificationDeliveryResponse(
        id=str(delivery.id),
        organization_id=(
            str(delivery.organization_id) if delivery.organization_id else None
        ),
        template_id=str(delivery.template_id) if delivery.template_id else None,
        event_type=delivery.event_type,
        channel=delivery.channel,
        recipient=delivery.recipient,
        subject=delivery.subject,
        status=delivery.status,
        attempt_count=delivery.attempt_count,
        max_attempts=delivery.max_attempts,
        next_attempt_at=delivery.next_attempt_at,
        sent_at=delivery.sent_at,
        error_message=delivery.error_message,
        attachment_filename=delivery.attachment_filename,
        created_at=delivery.created_at,
    )


@router.post(
    "/templates",
    response_model=ApiResponse[NotificationTemplateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("notifications.create"))],
)
async def create_notification_template(
    request: Request,
    payload: NotificationTemplateCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NotificationService = Depends(get_notification_service),
):
    template = await service.create_template(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        event_type=payload.event_type,
        channel=payload.channel,
        subject_template=payload.subject_template,
        body_template=payload.body_template,
        is_active=payload.is_active,
    )
    return build_response(
        success=True,
        message="Notification template created",
        data=_template_response(template).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/templates",
    response_model=ApiResponse[NotificationTemplateListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.read"))],
)
async def list_notification_templates(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NotificationService = Depends(get_notification_service),
):
    templates, meta = await service.list_templates(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = NotificationTemplateListResponse(
        items=[_template_response(template) for template in templates],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Notification templates retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/templates/{template_id}",
    response_model=ApiResponse[NotificationTemplateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.read"))],
)
async def get_notification_template(
    request: Request,
    template_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NotificationService = Depends(get_notification_service),
):
    template = await service.get_template(
        template_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Notification template retrieved",
        data=_template_response(template).model_dump(),
        request_id=_request_id(request),
    )


@router.patch(
    "/templates/{template_id}",
    response_model=ApiResponse[NotificationTemplateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.update"))],
)
async def update_notification_template(
    request: Request,
    template_id: uuid.UUID,
    payload: NotificationTemplateUpdateRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NotificationService = Depends(get_notification_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    template = await service.update_template(
        template_id,
        requesting_organization_id=requesting_organization_id,
        data=fields,
    )
    return build_response(
        success=True,
        message="Notification template updated",
        data=_template_response(template).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/deliveries",
    response_model=ApiResponse[NotificationDeliveryListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.read"))],
)
async def list_notification_deliveries(
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    event_type: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NotificationService = Depends(get_notification_service),
):
    deliveries, meta = await service.list_deliveries(
        requesting_organization_id=requesting_organization_id,
        status=status_filter,
        event_type=event_type,
        page=page,
        page_size=page_size,
    )
    payload = NotificationDeliveryListResponse(
        items=[_delivery_response(delivery) for delivery in deliveries],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Notification deliveries retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/deliveries/{delivery_id}",
    response_model=ApiResponse[NotificationDeliveryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.read"))],
)
async def get_notification_delivery(
    request: Request,
    delivery_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NotificationService = Depends(get_notification_service),
):
    delivery = await service.get_delivery(
        delivery_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Notification delivery retrieved",
        data=_delivery_response(delivery).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/deliveries/{delivery_id}/retry",
    response_model=ApiResponse[NotificationDeliveryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.manage"))],
)
async def retry_notification_delivery(
    request: Request,
    delivery_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NotificationService = Depends(get_notification_service),
):
    delivery = await service.retry_delivery(
        delivery_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Notification delivery re-queued",
        data=_delivery_response(delivery).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router", "MessageResponse"]
