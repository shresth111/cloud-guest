"""FastAPI routes for the Support Tickets domain.

Customers (org members) raise a support ticket from their own
organization's dashboard (``POST``/``GET``, always scoped by
``CurrentOrganization`` -- ``X-Organization-Id``); platform admins see
every organization's tickets on the Master dashboard and update
status/assignment/resolution (``PATCH``). ``GET /support-tickets`` serves
both: when ``X-Organization-Id`` is present it lists that organization's
own tickets (the customer dashboard view); when absent -- a platform-level
caller with no organization context -- it lists across every organization
(the Master dashboard view), gated the same way every other list endpoint
in this codebase is, by ``support_tickets.read``.

Every endpoint is gated by RBAC's existing ``RequirePermission`` dependency
against the ``support_tickets.*`` permission keys
(``app.domains.rbac.seed.MODULE_ACTIONS[PermissionModule.SUPPORT_TICKETS]``)
-- mirrors ``app.domains.guest_access.router``'s identical pattern. No
``DELETE`` endpoint: tickets are closed, not deleted.

## Reply thread + WebSocket design (real-time replies)

``POST``/``GET /support-tickets/{ticket_id}/replies`` add a reply thread on
top of the ticket itself (customer <-> platform support), gated by
``support_tickets.create``/``support_tickets.read`` respectively -- the same
two permission keys the ticket endpoints above already use, not a new pair
invented for replies.

``WS /support-tickets/ws`` follows the **exact same** auth/relay/disconnect
pattern ``app.domains.monitoring.router``'s ``WS /monitoring/ws/dashboard``
/``WS /monitoring/ws/sessions`` already establish (see that module's own
"WebSocket design (BE-011 Part 3)" docstring section for the full
query-param-JWT rationale this reuses verbatim): auth via a ``?token=``
query param validated with ``JWTManager.validate_token`` *before*
``websocket.accept()``; a single shared Redis pub/sub channel
(``constants.SUPPORT_TICKETS_LIVE_CHANNEL``) every real-time write path
(``TicketService.add_reply``/``.update_ticket``) publishes a uniformly-
shaped ``{"type", "payload", "occurred_at"}`` message to; two concurrent
``asyncio`` tasks (Redis-to-client relay, client-disconnect watcher) so a
pure server-push connection still notices a client-initiated disconnect
promptly.

**What's different from monitoring's two endpoints, and why:** monitoring's
sockets serve platform-only, non-tenant-scoped observability data --
``_authenticate_websocket`` there checks the connecting user's permission
at a fixed ``ScopeType.GLOBAL``, which only a platform-level (GLOBAL-scoped)
role can ever satisfy (see ``ScopeResolver.satisfies``: a narrower
ORGANIZATION-scoped grant can never satisfy a GLOBAL-level check). Support
Tickets, unlike monitoring, must be usable by **both** platform staff (the
Master console) **and** an ordinary organization member (the customer
dashboard) -- an org-scoped "Organization Owner"/"Organization Admin" role
would be locked out entirely by a fixed-GLOBAL check. This endpoint instead
accepts an optional ``?organization_id=`` query param -- the WebSocket
equivalent of the ``X-Organization-Id`` header ``CurrentOrganization``/
``RequirePermission``'s own ``_infer_scope_type`` already use for every
REST endpoint in this router -- and checks the connecting user's
``support_tickets.read`` permission at ``ScopeType.ORGANIZATION`` scoped to
that id when present, or ``ScopeType.GLOBAL`` when absent (mirrors
``_infer_scope_type``'s identical "header present -> ORGANIZATION scope,
absent -> GLOBAL scope" inference, just resolved from a query param instead
of a header since a browser ``WebSocket`` cannot set custom headers -- see
monitoring's own module docstring for that same browser limitation, already
documented once, not re-litigated here). No separate membership check is
needed beyond the permission check itself: an ``ORGANIZATION``-scoped grant
only satisfies the check when ``grant_scope.organization_id ==
requested.organization_id`` (see ``ScopeResolver.satisfies``), so a caller
can never pass an arbitrary org id they don't actually hold a role against.
The relay then filters every message's ``payload["organization_id"]``
against the connection's own ``organization_id`` (customer connections only
ever see their own organization's tickets; a GLOBAL-scoped staff connection
with no ``organization_id`` query param sees every organization's live
updates, matching ``GET /support-tickets``'s own "no header -> cross-tenant
view" behavior).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid

from fastapi import (
    APIRouter,
    Depends,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from redis.asyncio import Redis

from app.common.responses import ApiResponse, build_response
from app.database.redis import get_pubsub_redis_client
from app.domains.auth.dependencies import get_auth_repository
from app.domains.auth.jwt import InvalidTokenError, JWTManager, TokenExpiredError
from app.domains.auth.models import AuthUser
from app.domains.auth.repository import AuthRepositoryProtocol
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
    get_access_validator,
)
from app.domains.rbac.enums import ScopeType

from .constants import SUPPORT_TICKETS_LIVE_CHANNEL
from .dependencies import get_ticket_service
from .repository import TicketRecord, TicketReplyRecord
from .schemas import (
    TicketCreateRequest,
    TicketListResponse,
    TicketReplyCreateRequest,
    TicketReplyListResponse,
    TicketReplyResponse,
    TicketResponse,
    TicketUpdateRequest,
)
from .service import TicketService

router = APIRouter(prefix="/support-tickets", tags=["Support Tickets"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _ticket_response(record: TicketRecord) -> TicketResponse:
    ticket = record.ticket
    return TicketResponse(
        id=ticket.id,
        organization_id=ticket.organization_id,
        location_id=ticket.location_id,
        created_by_user_id=ticket.created_by_user_id,
        created_by_name=record.created_by_name,
        created_by_email=record.created_by_email,
        assigned_to_user_id=ticket.assigned_to_user_id,
        assigned_to_name=record.assigned_to_name,
        subject=ticket.subject,
        description=ticket.description,
        category=ticket.category,
        priority=ticket.priority,
        status=ticket.status,
        resolution_notes=ticket.resolution_notes,
        resolved_at=ticket.resolved_at,
        created_at=ticket.created_at,
        updated_at=ticket.updated_at,
    )


def _ticket_reply_response(record: TicketReplyRecord) -> TicketReplyResponse:
    reply = record.reply
    return TicketReplyResponse(
        id=reply.id,
        ticket_id=reply.ticket_id,
        author_user_id=reply.author_user_id,
        author_name=record.author_name,
        author_email=record.author_email,
        is_staff_reply=reply.is_staff_reply,
        message=reply.message,
        created_at=reply.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[TicketResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("support_tickets.create"))],
)
async def create_ticket(
    request: Request,
    payload: TicketCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    record = await service.create_ticket(
        requesting_organization_id=requesting_organization_id,
        location_id=(
            uuid.UUID(payload.location_id) if payload.location_id is not None else None
        ),
        subject=payload.subject,
        description=payload.description,
        category=payload.category,
        priority=payload.priority,
        created_by_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Support ticket created",
        data=_ticket_response(record).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[TicketListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("support_tickets.read"))],
)
async def list_tickets(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    ticket_status: str | None = Query(default=None, alias="status"),
    priority: str | None = Query(default=None),
    search: str | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    result = await service.list_tickets(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
        status=ticket_status,
        priority=priority,
        search=search,
    )
    payload = TicketListResponse(
        items=[_ticket_response(r) for r in result.items],
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Support tickets retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{ticket_id}",
    response_model=ApiResponse[TicketResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("support_tickets.read"))],
)
async def get_ticket(
    request: Request,
    ticket_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    record = await service.get_ticket(
        ticket_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Support ticket retrieved",
        data=_ticket_response(record).model_dump(),
        request_id=_request_id(request),
    )


@router.patch(
    "/{ticket_id}",
    response_model=ApiResponse[TicketResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("support_tickets.manage"))],
)
async def update_ticket(
    request: Request,
    ticket_id: uuid.UUID,
    payload: TicketUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    data = payload.model_dump(exclude_unset=True)
    if "assigned_to_user_id" in data and data["assigned_to_user_id"] is not None:
        data["assigned_to_user_id"] = uuid.UUID(data["assigned_to_user_id"])
    record = await service.update_ticket(
        ticket_id=ticket_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Support ticket updated",
        data=_ticket_response(record).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Reply thread endpoints
# ============================================================================


@router.get(
    "/{ticket_id}/replies",
    response_model=ApiResponse[TicketReplyListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("support_tickets.read"))],
)
async def list_ticket_replies(
    request: Request,
    ticket_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    records = await service.list_replies(
        ticket_id, requesting_organization_id=requesting_organization_id
    )
    payload = TicketReplyListResponse(
        items=[_ticket_reply_response(r) for r in records]
    )
    return build_response(
        success=True,
        message="Ticket replies retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/{ticket_id}/replies",
    response_model=ApiResponse[TicketReplyResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("support_tickets.create"))],
)
async def create_ticket_reply(
    request: Request,
    ticket_id: uuid.UUID,
    payload: TicketReplyCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: TicketService = Depends(get_ticket_service),
):
    record = await service.add_reply(
        ticket_id=ticket_id,
        requesting_organization_id=requesting_organization_id,
        message=payload.message,
        author_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Reply added",
        data=_ticket_reply_response(record).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Real-time: WebSocket auth + Redis pub/sub relay
#
# See this module's own docstring ("Reply thread + WebSocket design") for
# the full write-up of how this reuses app.domains.monitoring.router's
# WebSocket pattern verbatim, adapted for per-organization tenant scoping.
# ============================================================================


async def _authenticate_websocket(
    websocket: WebSocket,
    *,
    token: str | None,
    organization_id: uuid.UUID | None,
    auth_repository: AuthRepositoryProtocol,
    access_validator: AccessValidator,
) -> AuthUser | None:
    """Authenticates + authorizes a WebSocket connection *before*
    ``websocket.accept()`` -- mirrors
    ``app.domains.monitoring.router._authenticate_websocket`` exactly (same
    query-param-JWT scheme, same private-use close codes), except the
    permission check's scope is resolved from ``organization_id`` (an
    optional ``?organization_id=`` query param) instead of a fixed
    ``ScopeType.GLOBAL`` -- see module docstring for why."""
    if not token:
        await websocket.close(code=4401, reason="Missing token query parameter")
        return None
    try:
        payload = JWTManager.validate_token(token, expected_type="access")
    except (InvalidTokenError, TokenExpiredError):
        await websocket.close(code=4401, reason="Invalid or expired token")
        return None
    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (KeyError, ValueError):
        await websocket.close(code=4401, reason="Malformed token subject")
        return None
    user = await auth_repository.get_user_by_id(user_id)
    if user is None or not user.is_active:
        await websocket.close(code=4401, reason="User is not active")
        return None

    if organization_id is not None:
        scope_type = ScopeType.ORGANIZATION
        scope_context = ScopeContext.for_organization(organization_id)
    else:
        scope_type = ScopeType.GLOBAL
        scope_context = ScopeContext.global_scope()
    allowed = await access_validator.has_permission(
        user_id,
        "support_tickets.read",
        scope_type=scope_type,
        scope_context=scope_context,
    )
    if not allowed:
        await websocket.close(code=4403, reason="Permission denied")
        return None
    return AuthUser.from_model(user)


async def _relay_redis_to_websocket(
    websocket: WebSocket,
    pubsub,
    organization_id: uuid.UUID | None,
) -> None:
    """Reads ``SUPPORT_TICKETS_LIVE_CHANNEL`` messages via ``pubsub.listen()``
    and forwards them to the connected client, filtered by tenant: when
    ``organization_id`` is set (a customer connection), only messages whose
    ``payload["organization_id"]`` matches are relayed; a platform-staff
    connection (``organization_id is None``, only reachable at all because
    ``_authenticate_websocket`` already required a GLOBAL-scoped permission
    grant for that case) receives every organization's live updates --
    mirrors ``GET /support-tickets``'s own "no X-Organization-Id -> every
    organization" cross-tenant behavior."""
    async for message in pubsub.listen():
        if message.get("type") != "message":
            continue
        raw = message.get("data")
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if organization_id is not None:
            reply_org = (data.get("payload") or {}).get("organization_id")
            if reply_org != str(organization_id):
                continue
        await websocket.send_json(data)


async def _watch_for_websocket_disconnect(websocket: WebSocket) -> None:
    """Awaits ``websocket.receive()`` purely to detect a client-initiated
    disconnect promptly -- mirrors
    ``app.domains.monitoring.router._watch_for_websocket_disconnect``
    exactly."""
    while True:
        message = await websocket.receive()
        if message.get("type") == "websocket.disconnect":
            return


async def _run_live_relay(
    websocket: WebSocket,
    redis_client: Redis,
    organization_id: uuid.UUID | None,
) -> None:
    """Subscribes to ``SUPPORT_TICKETS_LIVE_CHANNEL``, relays matching
    messages until either the client disconnects or the relay itself ends,
    then unsubscribes and closes the ``PubSub`` -- mirrors
    ``app.domains.monitoring.router._run_live_relay`` exactly."""
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(SUPPORT_TICKETS_LIVE_CHANNEL)
    relay_task = asyncio.create_task(
        _relay_redis_to_websocket(websocket, pubsub, organization_id)
    )
    disconnect_task = asyncio.create_task(_watch_for_websocket_disconnect(websocket))
    try:
        done, pending = await asyncio.wait(
            {relay_task, disconnect_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for task in done:
            if task is relay_task and task.exception() is not None:
                exc = task.exception()
                if not isinstance(exc, WebSocketDisconnect):
                    raise exc
    except WebSocketDisconnect:
        pass
    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(SUPPORT_TICKETS_LIVE_CHANNEL)
        with contextlib.suppress(Exception):
            await pubsub.aclose()


@router.websocket("/ws")
async def support_tickets_websocket(
    websocket: WebSocket,
    token: str | None = Query(default=None),
    organization_id: uuid.UUID | None = Query(default=None),
    # The dedicated, no-read-timeout Pub/Sub client -- not
    # get_redis_client's ordinary short-socket-timeout client, which would
    # kill this connection with a raw TimeoutError after ~2s of no new
    # replies. See app.database.redis.create_pubsub_redis_client's own
    # docstring for the full "confirmed with a direct reproduction"
    # write-up.
    redis_client: Redis = Depends(get_pubsub_redis_client),
    auth_repository: AuthRepositoryProtocol = Depends(get_auth_repository),
    access_validator: AccessValidator = Depends(get_access_validator),
) -> None:
    """Broadcasts ``reply_created``/``ticket_updated`` events -- requires
    ``support_tickets.read`` at ``ScopeType.ORGANIZATION`` (scoped to
    ``organization_id``) when that query param is supplied, or
    ``ScopeType.GLOBAL`` otherwise (see module docstring)."""
    user = await _authenticate_websocket(
        websocket,
        token=token,
        organization_id=organization_id,
        auth_repository=auth_repository,
        access_validator=access_validator,
    )
    if user is None:
        return
    await websocket.accept()
    await _run_live_relay(websocket, redis_client, organization_id)


__all__ = ["router"]
