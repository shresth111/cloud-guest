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

# ============================================================================
# Real-time (reply thread WebSocket + Redis pub/sub relay)
#
# Mirrors app.domains.monitoring.constants's own "one shared channel, every
# real-time write path PUBLISHes a uniformly-shaped {"type", "payload",
# "occurred_at"} message, each WebSocket endpoint filters by message type"
# design -- see app.domains.support_tickets.router's module docstring for
# the write-up of how this domain adapts it for per-organization tenant
# scoping (monitoring has no such scoping need).
# ============================================================================

SUPPORT_TICKETS_LIVE_CHANNEL = "support_tickets:live"


class TicketRealtimeMessageType(StrEnum):
    """The closed set of ``"type"`` values a message published to
    :data:`SUPPORT_TICKETS_LIVE_CHANNEL` carries."""

    REPLY_CREATED = "reply_created"
    TICKET_UPDATED = "ticket_updated"


__all__ = [
    "TicketPriority",
    "TicketStatus",
    "RESOLVED_STATUSES",
    "SUPPORT_TICKETS_LIVE_CHANNEL",
    "TicketRealtimeMessageType",
]
