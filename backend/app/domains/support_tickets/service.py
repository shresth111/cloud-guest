"""Support Tickets business logic: ``TicketService`` -- create/list/get/
update, with tenant scoping and a ``location_id`` cross-reference check
mirroring ``app.domains.location.service.LocationService``'s own
``_assert_organization_accessible`` posture.

## Composition, not duplication, with ``app.domains.location``

This module never reimplements location lookup or cross-org validation --
it composes with ``app.domains.location`` through a narrow
``LocationLookupProtocol`` (the same duck-typed composition-over-
duplication pattern ``app.domains.campaigns.service`` already establishes
for its own identical need), resolved concretely by
``app.domains.location.service.LocationService`` at the DI layer (see
``dependencies.py``).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from redis.asyncio import Redis

from app.database.utils.pagination import PaginationMeta
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.rbac.enums import AuditAction

from .constants import RESOLVED_STATUSES, SUPPORT_TICKETS_LIVE_CHANNEL, TicketRealtimeMessageType
from .exceptions import (
    CrossOrganizationTicketAccessError,
    InvalidTicketLocationError,
    OrganizationContextRequiredError,
    TicketNotFoundError,
)
from .models import SupportTicket
from .repository import TicketRecord, TicketReplyRecord, TicketRepositoryProtocol

logger = logging.getLogger(__name__)


async def _publish_live_message(
    redis_client: Redis | None,
    message_type: TicketRealtimeMessageType,
    payload: dict[str, object],
) -> None:
    """Best-effort ``PUBLISH`` to :data:`~.constants.SUPPORT_TICKETS_LIVE_CHANNEL`
    -- mirrors ``app.domains.monitoring.service._publish_live_message``
    exactly (same shape, same "never raises" resilience posture): called
    *after* the real database write already succeeded, never instead of or
    before it. A Redis publish failure only means connected WebSocket
    clients miss that one live update -- the next ``GET`` against the same
    ticket/reply-list still reflects reality, so nothing is lost from the
    actual source of truth, only from the live stream."""
    if redis_client is None:
        return
    try:
        message = {
            "type": message_type.value,
            "payload": payload,
            "occurred_at": datetime.now(UTC).isoformat(),
        }
        await redis_client.publish(
            SUPPORT_TICKETS_LIVE_CHANNEL, json.dumps(message, default=str)
        )
    except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
        logger.warning(
            "support_tickets_live_publish_failed",
            extra={"message_type": message_type.value, "error": str(exc)},
        )


def _reply_live_payload(record: TicketReplyRecord, *, organization_id: uuid.UUID) -> dict[str, object]:
    reply = record.reply
    return {
        "id": str(reply.id),
        "ticket_id": str(reply.ticket_id),
        "organization_id": str(organization_id),
        "author_user_id": str(reply.author_user_id),
        "author_name": record.author_name,
        "author_email": record.author_email,
        "is_staff_reply": reply.is_staff_reply,
        "message": reply.message,
        "created_at": reply.created_at.isoformat(),
    }


def _ticket_live_payload(ticket: SupportTicket) -> dict[str, object]:
    return {
        "id": str(ticket.id),
        "ticket_id": str(ticket.id),
        "organization_id": str(ticket.organization_id),
        "status": ticket.status,
        "priority": ticket.priority,
        "assigned_to_user_id": (
            str(ticket.assigned_to_user_id) if ticket.assigned_to_user_id else None
        ),
        "resolution_notes": ticket.resolution_notes,
        "resolved_at": ticket.resolved_at.isoformat() if ticket.resolved_at else None,
        "updated_at": ticket.updated_at.isoformat(),
    }


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class LocationLookupProtocol(Protocol):
    """The subset of ``app.domains.location.service.LocationService`` this
    module needs to validate that a ticket's ``location_id`` actually
    belongs to its ``organization_id`` -- mirrors
    ``app.domains.campaigns.service``'s own identical ``LocationLookupProtocol``
    shape."""

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> object: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Application service
# ============================================================================


@dataclass
class TicketListResult:
    items: list[TicketRecord]
    meta: PaginationMeta


class TicketService:
    """CRUD over ``support_tickets``, with tenant scoping (a caller acting
    within organization A can never read/mutate organization B's ticket)
    and a ``location_id``-belongs-to-``organization_id`` cross-reference
    check on create -- mirrors ``app.domains.guest_access.service
    .GuestAccessService``'s own ``_enforce_tenant_scope`` posture."""

    def __init__(
        self,
        repository: TicketRepositoryProtocol,
        *,
        location_lookup: LocationLookupProtocol,
        audit_writer: AuditLogWriter | None = None,
        redis_client: Redis | None = None,
    ) -> None:
        self.repository = repository
        self.location_lookup = location_lookup
        self.audit_writer = audit_writer
        # None is the default (not a required constructor arg) so every
        # existing unit test that builds a TicketService directly keeps
        # working unchanged -- mirrors
        # app.domains.monitoring.service.AlertService's identical
        # "redis_client: Redis | None = None" posture. See
        # _publish_live_message's own docstring for the "never raises"
        # behavior this enables skipping safely in tests.
        self.redis_client = redis_client

    # -- create --------------------------------------------------------------

    async def create_ticket(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        subject: str,
        description: str,
        category: str | None,
        priority: str,
        created_by_user_id: uuid.UUID,
    ) -> TicketRecord:
        """Every ticket belongs to exactly one organization -- taken
        directly from ``requesting_organization_id`` (``CurrentOrganization``
        -- ``X-Organization-Id``), never from the request body (see
        ``schemas.TicketCreateRequest``'s own module docstring: there is no
        ``organization_id`` field on it at all, unlike
        ``app.domains.guest_access``'s own admin-facing create schemas,
        since this endpoint is the org member's own self-service "raise a
        ticket about my org" action, not an admin acting on an arbitrary
        target organization)."""
        if requesting_organization_id is None:
            raise OrganizationContextRequiredError()
        organization_id = requesting_organization_id
        if location_id is not None:
            await self._assert_location_in_organization(location_id, organization_id)

        ticket = await self.repository.create(
            organization_id=organization_id,
            location_id=location_id,
            created_by_user_id=created_by_user_id,
            subject=subject,
            description=description,
            category=category,
            priority=priority,
            created_by=created_by_user_id,
            updated_by=created_by_user_id,
        )
        logger.info(
            "support_ticket_created",
            extra={
                "ticket_id": str(ticket.id),
                "organization_id": str(organization_id),
            },
        )
        await self._audit(
            created_by_user_id,
            AuditAction.SUPPORT_TICKET_CREATED,
            entity_id=ticket.id,
            description=f"Support ticket created: '{subject}'",
            organization_id=organization_id,
            location_id=location_id,
        )
        record = await self.repository.get_record_by_id(ticket.id)
        assert record is not None  # just created, must exist
        return record

    # -- read ------------------------------------------------------------

    async def get_ticket(
        self,
        ticket_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> TicketRecord:
        record = await self.repository.get_record_by_id(ticket_id)
        if record is None:
            raise TicketNotFoundError(ticket_id)
        self._enforce_tenant_scope(
            record.ticket.organization_id, requesting_organization_id
        )
        return record

    async def list_tickets(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
        status: str | None = None,
        priority: str | None = None,
        search: str | None = None,
    ) -> TicketListResult:
        """Lists tickets scoped to ``requesting_organization_id``
        (``CurrentOrganization``) when present. When absent -- a
        platform-level caller with no ``X-Organization-Id`` context -- lists
        across every organization, the Master dashboard "every
        organization's tickets" view (see ``router.py``'s own module
        docstring)."""
        items, meta = await self.repository.list_records(
            organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
            status=status,
            priority=priority,
            search=search,
        )
        return TicketListResult(items=items, meta=meta)

    # -- update ------------------------------------------------------------

    async def update_ticket(
        self,
        *,
        ticket_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
        actor_user_id: uuid.UUID | None,
    ) -> TicketRecord:
        """``data`` is the caller's already-validated
        ``TicketUpdateRequest.model_dump(exclude_unset=True)`` (mirrors
        ``app.domains.location.service.LocationService.update_location``'s
        identical ``data: dict[str, object]`` shape) -- only keys the caller
        actually set are present, so e.g. omitting ``resolution_notes``
        leaves it untouched, while explicitly setting it to ``None`` clears
        it."""
        record = await self.get_ticket(
            ticket_id, requesting_organization_id=requesting_organization_id
        )
        ticket = record.ticket

        update_data = dict(data)
        update_data["updated_by"] = actor_user_id
        if "status" in update_data:
            new_status = update_data["status"]
            # Auto-set resolved_at on transition into RESOLVED/CLOSED, and
            # auto-clear it back to None on transition out -- mirrors
            # app.domains.billing.service's own timestamp-on-transition
            # logic for subscription cancellation (cancelled_at set/cleared
            # alongside SubscriptionStatus transitions).
            update_data["resolved_at"] = (
                datetime.now(UTC) if new_status in RESOLVED_STATUSES else None
            )

        await self.repository.update(ticket, update_data)
        logger.info("support_ticket_updated", extra={"ticket_id": str(ticket.id)})
        await self._audit(
            actor_user_id,
            AuditAction.SUPPORT_TICKET_UPDATED,
            entity_id=ticket.id,
            description=f"Support ticket updated: '{ticket.subject}'",
            organization_id=ticket.organization_id,
            location_id=ticket.location_id,
        )
        updated = await self.repository.get_record_by_id(ticket_id)
        assert updated is not None
        # Publish *after* the DB write above already succeeded -- see
        # _publish_live_message's own docstring. Cheap to include alongside
        # the reply-created broadcast: a status/assignment/resolution
        # change is exactly the other half of "what changed on this ticket
        # while I was looking at it" a connected client cares about.
        await _publish_live_message(
            self.redis_client,
            TicketRealtimeMessageType.TICKET_UPDATED,
            _ticket_live_payload(updated.ticket),
        )
        return updated

    # -- replies -------------------------------------------------------------

    async def list_replies(
        self,
        ticket_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> list[TicketReplyRecord]:
        # Reuses get_ticket purely for its tenant-scope enforcement
        # (CrossOrganizationTicketAccessError/TicketNotFoundError) -- the
        # exact same "prove the caller may see this ticket at all before
        # touching anything scoped under it" gate every other per-ticket
        # method on this service already applies.
        await self.get_ticket(
            ticket_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_reply_records(ticket_id)

    async def add_reply(
        self,
        *,
        ticket_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        message: str,
        author_user_id: uuid.UUID,
    ) -> TicketReplyRecord:
        """Either party replies: the ticket-owning organization's own
        member (``requesting_organization_id`` present, ``X-Organization-Id``
        -- the customer dashboard) or a platform support agent (absent --
        the Master console, mirrors ``list_tickets``'s identical
        "organization_id is None" signal for the cross-tenant view). Never
        trusts the request body for which side is replying -- see
        ``schemas.TicketReplyCreateRequest``'s own docstring."""
        record = await self.get_ticket(
            ticket_id, requesting_organization_id=requesting_organization_id
        )
        ticket = record.ticket

        reply = await self.repository.create_reply(
            ticket_id=ticket.id,
            author_user_id=author_user_id,
            message=message,
            is_staff_reply=requesting_organization_id is None,
            created_by=author_user_id,
            updated_by=author_user_id,
        )
        logger.info(
            "support_ticket_reply_created",
            extra={"ticket_id": str(ticket.id), "reply_id": str(reply.id)},
        )
        await self._audit(
            author_user_id,
            AuditAction.SUPPORT_TICKET_REPLY_ADDED,
            entity_id=ticket.id,
            description=f"Reply added to support ticket: '{ticket.subject}'",
            organization_id=ticket.organization_id,
            location_id=ticket.location_id,
        )
        reply_records = await self.repository.list_reply_records(ticket.id)
        reply_record = next(r for r in reply_records if r.reply.id == reply.id)
        # Publish *after* the DB write above already succeeded -- see
        # _publish_live_message's own docstring.
        await _publish_live_message(
            self.redis_client,
            TicketRealtimeMessageType.REPLY_CREATED,
            _reply_live_payload(reply_record, organization_id=ticket.organization_id),
        )
        return reply_record

    # -- internal helpers ----------------------------------------------------

    async def _assert_location_in_organization(
        self, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> None:
        try:
            location = await self.location_lookup.get_location(location_id)
        except LocationNotFoundError as exc:
            raise InvalidTicketLocationError() from exc
        if getattr(location, "organization_id", None) != organization_id:
            raise InvalidTicketLocationError()

    def _enforce_tenant_scope(
        self,
        ticket_organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if (
            requesting_organization_id is not None
            and ticket_organization_id != requesting_organization_id
        ):
            raise CrossOrganizationTicketAccessError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID,
        description: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> None:
        if self.audit_writer is None or actor_user_id is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="support_ticket",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
            location_id=location_id,
        )


__all__ = ["TicketService", "TicketListResult", "LocationLookupProtocol", "AuditLogWriter"]
