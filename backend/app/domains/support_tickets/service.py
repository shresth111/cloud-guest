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

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.database.utils.pagination import PaginationMeta
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.rbac.enums import AuditAction

from .constants import RESOLVED_STATUSES
from .exceptions import (
    CrossOrganizationTicketAccessError,
    InvalidTicketLocationError,
    OrganizationContextRequiredError,
    TicketNotFoundError,
)
from .models import SupportTicket
from .repository import TicketRecord, TicketRepositoryProtocol

logger = logging.getLogger(__name__)


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
    ) -> None:
        self.repository = repository
        self.location_lookup = location_lookup
        self.audit_writer = audit_writer

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
        return updated

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
