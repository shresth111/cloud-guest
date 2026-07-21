"""Enumerations and small constants for the MAC Authorization domain.

``MacAuthorizationType`` is stored as a plain ``String`` column, never a
native PostgreSQL enum type -- the same reason every other domain in this
codebase documents: adding a new value never requires an ``ALTER TYPE``
migration, only a new additive ``StrEnum`` member.
"""

from __future__ import annotations

import re
from enum import StrEnum

# Six colon- or dash-separated hex octets, case-insensitive -- the two
# real-world MAC notations ("AA:BB:CC:DD:EE:FF" / "AA-BB-CC-DD-EE-FF").
# validators.normalize_mac_address accepts either and normalizes to the
# canonical uppercase colon form.
MAC_ADDRESS_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2"
    r"([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})$"
)

# Bulk import request size bound -- mirrors
# app.domains.voucher.schemas.VoucherImportRequest's own identical
# max_length=1000 bound for the same "one request, one bounded batch,
# never an unbounded body" reason.
MAX_IMPORT_BATCH_SIZE = 1000


class MacAuthorizationType(StrEnum):
    """Whether a whitelist entry is permanent or time-limited. ``expires_at``
    is required iff ``TEMPORARY`` and forbidden iff ``PERMANENT`` --
    see ``validators.validate_expiry``."""

    PERMANENT = "permanent"
    TEMPORARY = "temporary"


__all__ = ["MAC_ADDRESS_PATTERN", "MAX_IMPORT_BATCH_SIZE", "MacAuthorizationType"]
