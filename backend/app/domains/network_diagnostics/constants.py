"""Constants for the Network Diagnostics domain.

Plain module constants, not ``Settings``/``Organization.settings``
fields -- mirrors ``app.domains.isp.constants``'s own "no new Settings
fields" discipline; per-organization tunability is a real future seam,
not implemented in this first pass.
"""

from __future__ import annotations

from enum import StrEnum


class DiagnosticType(StrEnum):
    """Which real RouterOS tool a :class:`~.models.DiagnosticRun` used."""

    PING = "ping"
    TRACEROUTE = "traceroute"


class DiagnosticStatus(StrEnum):
    """The real, honest outcome of one diagnostic execution -- ``FAILED``
    covers both a genuine device-connection failure and a completed-but-
    unreachable-target result (see ``service.py``'s own module docstring:
    every attempt is recorded, never silently dropped)."""

    SUCCESS = "success"
    FAILED = "failed"


# Real RouterOS /tool/ping parameters -- mirrors
# app.domains.isp.constants.ISP_PING_COUNT/ISP_PING_TIMEOUT_SECONDS
# exactly (same real defaults, independently named since this domain is
# router-generic, not WAN-link-specific).
DEFAULT_PING_COUNT = 5
DEFAULT_PING_TIMEOUT_SECONDS = 10

# Real RouterOS /tool traceroute parameters. RouterOS's own default
# max-hops is 30 (matching traditional Unix traceroute); a lower default
# here keeps a single admin-triggered request bounded and fast.
DEFAULT_TRACEROUTE_MAX_HOPS = 15
DEFAULT_TRACEROUTE_TIMEOUT_SECONDS = 15

__all__ = [
    "DiagnosticType",
    "DiagnosticStatus",
    "DEFAULT_PING_COUNT",
    "DEFAULT_PING_TIMEOUT_SECONDS",
    "DEFAULT_TRACEROUTE_MAX_HOPS",
    "DEFAULT_TRACEROUTE_TIMEOUT_SECONDS",
]
