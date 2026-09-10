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

    * ``WHITELIST`` -- an explicit, permanent allow. At an ordinary
      property (the platform-wide default is still allow-unless-blocked --
      see ``service.AccessDecisionResolver``'s own docstring), a
      ``WHITELIST`` rule mainly exists to *guarantee* access precedence
      over some other, broader ``BLOCKLIST`` rule that might otherwise
      apply (e.g. an org-wide blocklist entry with a location-scoped
      whitelist exception). At a property that has switched on
      ``captive_portal_configs.whitelist_only_enabled``, the same rule
      takes on its second job: it is the list, and a guest who matches no
      allow-shaped rule there is refused at the portal.
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


# The ``reason`` carried by ``service._DEFAULT_DENY`` -- the decision
# ``AccessDecisionResolver`` returns when **nothing matched** and the
# property has ``captive_portal_configs.whitelist_only_enabled`` on.
#
# A stable, machine-readable token rather than a sentence, for the same
# reason ``GuestRuleImportRejectionCode`` exists: it is branched on, not
# read aloud. The words a refused guest actually sees come from that
# property's own ``whitelist_only_denied_message`` (or the default in
# ``exceptions.WhitelistOnlyAccessDeniedError``), never from here.
#
# It must never collide with a rule's own free-text ``reason``: every
# other denial this resolver produces is a BLOCKLIST match and carries the
# operator's typed note (or ``None``). "You are barred from this network"
# and "this venue admits only listed guests" are different facts about
# different people, and the portal has to be able to say different things
# -- which is why this is a distinct decision shape and not a second way
# to spell a blocklist hit. See ``AccessDecision.is_whitelist_only_denial``
# for the structural discriminator callers should branch on.
WHITELIST_ONLY_DENIAL_REASON = "whitelist_only"


# ---------------------------------------------------------------------------
# Bulk import (``POST /guest-access/rules/import``)
# ---------------------------------------------------------------------------

# One request, one bounded batch, never an unbounded body -- the identical
# bound ``app.domains.mac_authorization.constants.MAX_IMPORT_BATCH_SIZE``
# and ``app.domains.voucher.schemas.VoucherImportRequest`` already carry,
# matched deliberately rather than picked afresh so an operator who has
# learned "a thousand rows per upload" for one list does not have to learn
# a second number for another. Enforced by pydantic
# (``schemas.GuestAccessRuleImportRequest.rules``'s ``max_length``), so a
# 1001-row body is refused with a 422 before the handler runs and before a
# single row is written -- never a partial import of the first 1000.
MAX_IMPORT_BATCH_SIZE = 1000

# Which rule types this importer may write.
#
# BLOCKLIST is deliberately absent, and its absence is the point.
# ``GuestAccessService.create_guest_rule`` runs a BLOCKLIST rule through
# ``enforcement.BlocklistEnforcer`` -- a commit plus a live RouterOS API
# session per rule, to end the sessions the guest is already in. A
# thousand of those in one request would hold the connection open for the
# length of a thousand device round-trips and half-succeed in a way nobody
# could reconstruct afterwards, and the per-rule enforcement outcome
# (``enforcement_status``/``sessions_ended``) that a blocking operator has
# to see would be buried in a bulk summary. Blocking someone is a
# deliberate, one-at-a-time act with a device outcome; ``POST
# /guest-access/rules`` remains the only way to do it.
#
# What is left is the three allow-shaped types, which write a row and stop.
IMPORTABLE_RULE_TYPES: frozenset[AccessRuleType] = frozenset(
    {AccessRuleType.WHITELIST, AccessRuleType.TEMPORARY, AccessRuleType.VIP}
)


class GuestRuleImportRejectionCode(StrEnum):
    """Why one row of a bulk import was refused, as a stable string the
    dashboard can branch on.

    A human-readable ``reason`` travels alongside this (see
    ``schemas.RejectedGuestRuleImportRowResponse``) and is what an operator
    reads, but a 200-room hotel uploading a list exported from its PMS
    routinely gets forty rejections that are all the *same* problem. A code
    lets the upload screen collapse those into one instruction ("these
    forty numbers have no country code") instead of forty lines the
    operator scrolls past. Free-text reasons cannot be grouped without
    string-matching a message that is allowed to change.
    """

    #: Neither phone-shaped nor email-shaped at all (letters, empty, a
    #: spreadsheet's stray header row).
    MALFORMED_IDENTIFIER = "malformed_identifier"
    #: Phone-shaped and plausible, but written without a country code --
    #: the single most common rejection a hotel's PMS export produces, and
    #: the one with a fix the operator can apply in a spreadsheet. See
    #: ``exceptions.CountryCodeRequiredError``.
    COUNTRY_CODE_REQUIRED = "country_code_required"
    #: ``rule_type`` is not one of ``IMPORTABLE_RULE_TYPES``.
    RULE_TYPE_NOT_IMPORTABLE = "rule_type_not_importable"
    #: ``rule_type`` is not an ``AccessRuleType`` at all.
    UNKNOWN_RULE_TYPE = "unknown_rule_type"
    #: A TEMPORARY row with no expiry, or any row whose expiry is already
    #: in the past -- see ``validators.validate_rule_expiry``.
    INVALID_EXPIRY = "invalid_expiry"
    #: ``location_id`` is not a UUID.
    INVALID_LOCATION_ID = "invalid_location_id"
    #: The row named a location the caller is not confined to.
    LOCATION_OUT_OF_SCOPE = "location_out_of_scope"
    #: The optional contact ``email`` column is not email-shaped. Rejected
    #: rather than dropped: half-storing a row someone typed is how the
    #: dashboard's Whitelist form used to lose the email it collected.
    INVALID_CONTACT_EMAIL = "invalid_contact_email"


__all__ = [
    "AccessRuleType",
    "BlockEnforcementStatus",
    "ACCESS_RULE_TYPE_PRECEDENCE",
    "WHITELIST_ONLY_DENIAL_REASON",
    "MAX_IMPORT_BATCH_SIZE",
    "IMPORTABLE_RULE_TYPES",
    "GuestRuleImportRejectionCode",
]
