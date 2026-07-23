"""Enumerations and small constants for the Assistant (customer support
chatbot) domain.

``role`` is stored as a plain ``String(20)`` column, never a native
PostgreSQL enum type -- the same reason every other domain in this codebase
documents (see e.g. ``app.domains.support_tickets.constants``): adding a
new role later never requires an ``ALTER TYPE`` migration, only a code
change.
"""

from __future__ import annotations

from enum import StrEnum


class MessageRole(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"


__all__ = ["MessageRole"]
