"""Enumerations for the Monitored Hardware domain.

Stored as plain ``String`` columns, never native PostgreSQL enum types --
the same reason every other domain in this codebase documents: adding a
new value never requires an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class HardwareType(StrEnum):
    """Matches the frontend's own ``DeviceType`` union exactly (see
    ``cloudguest-foundation/src/stores/deviceStore.ts``) -- this domain's
    whole reason for existing is to give that same set of categories a
    real backend, not a redesigned one."""

    ACCESS_POINT = "Access Point"
    PRINTER = "Printer"
    ROUTER = "Router"
    CAMERA = "Camera"
    OTHER = "Other"


class HardwareStatus(StrEnum):
    """See ``__init__.py``'s own module docstring for the full "derived,
    never fabricated" reasoning behind each of these three states."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


__all__ = ["HardwareType", "HardwareStatus"]
