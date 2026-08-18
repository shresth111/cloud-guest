"""Enumerations and fixed branding constants for the Channel Partner domain.

``ChannelPartnerStatus`` is stored as a plain ``String`` column, never a
native PostgreSQL enum type -- the same reason every other domain in this
codebase documents (see e.g. ``app.domains.quotation.constants``): adding a
new status never requires an ``ALTER TYPE`` migration, only a code change.
"""

from __future__ import annotations

from enum import StrEnum

CHANNEL_PARTNER_PRODUCT_NAME = "Wyfy Guest"


class ChannelPartnerStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


__all__ = ["CHANNEL_PARTNER_PRODUCT_NAME", "ChannelPartnerStatus"]
