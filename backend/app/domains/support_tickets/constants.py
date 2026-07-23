"""Enumerations and small constants for the Support Tickets domain.

``priority``/``status`` are stored as plain ``String`` columns, never
native PostgreSQL enum types -- the same reason every other domain in this
codebase documents (see e.g. ``app.domains.guest_access.constants``):
adding a new value never requires an ``ALTER TYPE`` migration, only a code
change. ``category`` is deliberately not one of these enums at all -- it
stays a free-form, application-unvalidated ``String(50)`` (billing/
technical/network/account/other are suggestions, not an enforced set) --
see ``models.py``'s module docstring for the identical "no DB enum
constraint" reasoning applied to it.
"""

from __future__ import annotations

from enum import StrEnum


class TicketPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class TicketStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


# The statuses that mean "resolution work is done" -- entering either one
# auto-sets SupportTicket.resolved_at; leaving both clears it back to None.
# See app.domains.support_tickets.service.TicketService.update_ticket.
RESOLVED_STATUSES: tuple[TicketStatus, ...] = (
    TicketStatus.RESOLVED,
    TicketStatus.CLOSED,
)

__all__ = ["TicketPriority", "TicketStatus", "RESOLVED_STATUSES"]
