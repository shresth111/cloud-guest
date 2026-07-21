"""Constants for the DNS Management domain.

``DnsRecordType`` is stored as a plain ``String`` column, never a native
PostgreSQL enum type -- the same reason every other domain in this
codebase documents: adding a new value never requires an ``ALTER TYPE``
migration, only a new additive ``StrEnum`` member.
"""

from __future__ import annotations

from enum import StrEnum

# RouterOS's own default static-DNS TTL is 1 day -- used as this domain's
# own default when a caller doesn't supply one, mirroring
# app.domains.dhcp.constants.DEFAULT_LEASE_TIME_SECONDS's identical
# "real RouterOS default, not an invented number" reasoning.
DEFAULT_TTL_SECONDS = 86_400


class DnsRecordType(StrEnum):
    """Which real RouterOS ``/ip dns static`` record shape this row is.
    Only the three most common static-entry types are modeled -- RouterOS
    also supports FWD/NXDOMAIN/regexp entries, deliberately left out of
    this first pass rather than fabricated support for a shape no caller
    has asked for yet."""

    A = "a"
    AAAA = "aaaa"
    CNAME = "cname"


__all__ = ["DEFAULT_TTL_SECONDS", "DnsRecordType"]
