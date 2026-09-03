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


class BlockEnforcementStatus(StrEnum):
    """What this platform did about the live sessions of a guest a
    ``BLOCKLIST`` rule was just written for.

    Recorded on the rule row itself, for the same reason
    ``Vlan.device_push_status`` is recorded on the VLAN: an operator
    refreshing the page after a failed enforcement must be able to see
    that the block is real in the database and was *not* made real on the
    device, rather than seeing a row that looks identical to a working
    one.

    * ``NOT_APPLICABLE`` -- the rule is not a ``BLOCKLIST``. Whitelist,
      VIP and temporary rules grant access; there is no session to end.
    * ``UNENFORCED`` -- a ``BLOCKLIST`` rule was created by a caller that
      wired no enforcer (see ``GuestAccessService.__init__``). Deliberately
      its own value rather than reusing ``NOT_APPLICABLE``: "nothing needed
      doing" and "nobody was there to do it" are different facts, and
      collapsing them is how the original defect stayed invisible.
    * ``PENDING`` -- a ``BLOCKLIST`` row written and committed, with the
      device work not yet finished. Committed before the first socket is
      opened, for the reason ``VlanService.push_vlan_to_device`` writes
      ``PROVISIONING`` before its own: a customer refreshing the page
      while a slow enforcement runs sees the work in progress rather than
      a stale outcome, and a process killed mid-write leaves a row saying
      "nobody confirmed this" instead of a false ``ENFORCED``.
    * ``ENFORCED`` -- every live session was confirmed gone from its
      router's own active table and moved to a terminal status here. Never
      set on a guess: a router that could not be read does not produce this
      value.
    * ``FAILED`` -- the block is in force for future sign-ins and at least
      one live session could not be ended. ``enforcement_error`` carries
      which and why.
    """

    NOT_APPLICABLE = "not_applicable"
    UNENFORCED = "unenforced"
    PENDING = "pending"
    ENFORCED = "enforced"
    FAILED = "failed"


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
    "BlockEnforcementStatus",
    "ACCESS_RULE_TYPE_PRECEDENCE",
]
