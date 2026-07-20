"""Enumerations and small constants for the Guest Access Control domain
(Phase 1).

Stored as plain ``String`` columns, never native PostgreSQL enum types --
the same reason every other domain in this codebase documents: adding a new
rule type never requires an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class AccessRuleType(StrEnum):
    """The four "Guest Access Control" concepts this module's two rule
    tables (``GuestAccessRule``/``DeviceAccessRule``) both share -- see
    ``models.py``'s module docstring for why one column, not one table per
    type.

    * ``WHITELIST`` -- an explicit, permanent allow. Since this module does
      not flip the platform into deny-by-default mode (see
      ``service.AccessDecisionResolver``'s own docstring), a ``WHITELIST``
      rule mainly exists to *guarantee* access precedence over some other,
      broader ``BLOCKLIST`` rule that might otherwise apply (e.g. an
      org-wide blocklist entry with a location-scoped whitelist exception).
    * ``BLOCKLIST`` -- an explicit, permanent deny.
    * ``TEMPORARY`` -- a bounded-window allow. Requires ``expires_at`` (see
      ``validators.validate_rule_expiry``) -- an "temporary" rule with no
      expiry is a contradiction this module rejects at creation time, not
      silently treated as permanent.
    * ``VIP`` -- an unconditional, highest-precedence allow, overriding
      even an active ``BLOCKLIST`` rule for the same identifier/MAC. Used
      for guests who must never be blocked regardless of what other rules
      exist (e.g. a hotel's own staff testing guest WiFi, a VIP guest
      account).
    """

    WHITELIST = "whitelist"
    BLOCKLIST = "blocklist"
    TEMPORARY = "temporary"
    VIP = "vip"


# Resolution precedence, highest first -- see
# service.AccessDecisionResolver.resolve. A rule type earlier in this tuple
# always wins over one later in it, regardless of scope (location-scoped
# vs. organization-wide) or which table (guest vs. device) it came from.
ACCESS_RULE_TYPE_PRECEDENCE: tuple[AccessRuleType, ...] = (
    AccessRuleType.VIP,
    AccessRuleType.TEMPORARY,
    AccessRuleType.BLOCKLIST,
    AccessRuleType.WHITELIST,
)


__all__ = [
    "AccessRuleType",
    "ACCESS_RULE_TYPE_PRECEDENCE",
]
