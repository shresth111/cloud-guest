"""Enumerations for the Network Device (NAC) domain.

Stored as a plain ``String`` column, never a native PostgreSQL enum type
-- the same reason every other domain in this codebase documents: adding
a new value never requires an ``ALTER TYPE`` migration, only a new
additive ``StrEnum`` member.
"""

from __future__ import annotations

from enum import StrEnum


class ComplianceStatus(StrEnum):
    """An admin-assessed compliance state -- see ``__init__.py``'s own
    module docstring for why this is never auto-detected. ``UNKNOWN`` is
    the honest default for every newly-registered device: nobody has
    reviewed it yet."""

    UNKNOWN = "unknown"
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"


__all__ = ["ComplianceStatus"]
