"""FastAPI routes for the Assistant (customer support chatbot) domain.

Every endpoint is a customer's own self-service action within their own
organization -- there is no admin/cross-organization view (see
``service.py``'s module docstring for why this domain is narrower than
``app.domains.support_tickets``). Gated by RBAC's existing
``RequirePermission`` dependency against the ``ai_assistant.*`` permission
keys, reusing ``app.domains.rbac.enums.PermissionModule.AI_ASSISTANT`` --
a module that already existed in ``rbac/enums.py``/``rbac/seed.py``
(``MODULE_ACTIONS``, per-role ``ScopeType.ORGANIZATION`` grants) but was
never consumed by any real endpoint before this domain; every seeded
system role already carries the grant level its own ``SystemRoleDefinition
.default_level`` implies for it (e.g. Organization Owner/Admin get
``ai_assistant.execute``+``ai_assistant.read`` for free from their own
``FULL``/high default level, with no per-module override needed), so no
RBAC reseed is required to ship this domain -- see this domain's own
migration/PR notes for the live-DB verification.

Only two actions are ever checked: ``ai_assistant.read`` (list
conversations, read message history) and ``ai_assistant.execute``
(start a conversation, send a message -- both cause the assistant to
actually run). ``ai_assistant.view``/``ai_assistant.manage`` exist on the
module (mirroring every other module's full action set) but nothing in
this pass needs them -- there is no separate "manage" action since a
customer never administers another customer's conversations.

No websockets, no streaming, no background job: ``POST .../messages``
calls the provider and returns its reply in the same response. This is a
deliberately POC-quality synchronous chat feature, not a production
real-time chat product -- mirrors this codebase's own "simplest
defensible choice, documented as such" posture used elsewhere (e.g.
``app.domains.notification``'s flat backoff over exponential).
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

from .dependencies import get_assistant_service
from .models import AssistantConversation, AssistantMessage
from .schemas import (
    ConversationCreateRequest,
    ConversationListResponse,
    ConversationResponse,
    ConversationStartResponse,
    MessageCreateRequest,
    MessageListResponse,
    MessageResponse,
)
from .service import AssistantService

router = APIRouter(prefix="/assistant", tags=["Assistant"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _conversation_response(conversation: AssistantConversation) -> ConversationResponse:
    return ConversationResponse.model_validate(conversation)


def _message_response(message: AssistantMessage) -> MessageResponse:
    return MessageResponse.model_validate(message)


@router.post(
    "/conversations",
    response_model=ApiResponse[ConversationStartResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("ai_assistant.execute"))],
)
async def start_conversation(
    request: Request,
    payload: ConversationCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: AssistantService = Depends(get_assistant_service),
):
    conversation, assistant_message = await service.start_conversation(
        requesting_organization_id=requesting_organization_id,
        user_id=uuid.UUID(user.id),
        initial_message=payload.initial_message,
    )
    data = ConversationStartResponse(
        conversation=_conversation_response(conversation),
        assistant_message=(
            _message_response(assistant_message) if assistant_message else None
        ),
    )
    return build_response(
        success=True,
        message="Conversation started",
        data=data.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/conversations",
    response_model=ApiResponse[ConversationListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("ai_assistant.read"))],
)
async def list_conversations(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: AssistantService = Depends(get_assistant_service),
):
    result = await service.list_conversations(
        requesting_organization_id=requesting_organization_id,
        user_id=uuid.UUID(user.id),
        page=page,
        page_size=page_size,
    )
    payload = ConversationListResponse(
        items=[_conversation_response(c) for c in result.items],
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Conversations retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/conversations/{conversation_id}/messages",
    response_model=ApiResponse[MessageListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("ai_assistant.read"))],
)
async def list_messages(
    request: Request,
    conversation_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: AssistantService = Depends(get_assistant_service),
):
    messages = await service.get_messages(
        conversation_id,
        requesting_organization_id=requesting_organization_id,
        user_id=uuid.UUID(user.id),
    )
    payload = MessageListResponse(items=[_message_response(m) for m in messages])
    return build_response(
        success=True,
        message="Messages retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("ai_assistant.execute"))],
)
async def send_message(
    request: Request,
    conversation_id: uuid.UUID,
    payload: MessageCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: AssistantService = Depends(get_assistant_service),
):
    assistant_message = await service.send_message(
        conversation_id,
        requesting_organization_id=requesting_organization_id,
        user_id=uuid.UUID(user.id),
        content=payload.content,
    )
    return build_response(
        success=True,
        message="Message sent",
        data=_message_response(assistant_message).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
