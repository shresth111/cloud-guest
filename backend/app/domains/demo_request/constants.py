"""Enumerations for the Demo Request domain.

``DemoRequestStatus`` is stored as a plain ``String`` column, never a native
PostgreSQL enum type -- the same reason every other domain in this codebase
documents (see e.g. ``app.domains.support_tickets.constants``): adding a new
status never requires an ``ALTER TYPE`` migration, only a code change.
"""

from __future__ import annotations

from enum import StrEnum


class DemoRequestStatus(StrEnum):
    """The internal team's own tracking states for a submitted demo
    request -- distinct from a support ticket's lifecycle (there is no
    "resolved"/"closed-won" ambiguity to model here, just where the lead
    currently sits in the outbound follow-up flow)."""

    NEW = "new"
    CONTACTED = "contacted"
    SCHEDULED = "scheduled"
    CLOSED = "closed"


__all__ = ["DemoRequestStatus"]
