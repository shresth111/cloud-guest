"""Enumerations for the ISP Routing domain.

Stored as a plain ``String`` column on ``IspRoutingRule``, never a native
PostgreSQL enum type -- the same reason every other domain in this
codebase documents: adding a new value never requires an ``ALTER TYPE``
migration, only a new additive ``StrEnum`` member.
"""

from __future__ import annotations

from enum import StrEnum


class IspRoutingRuleType(StrEnum):
    """Which single match field on :class:`~.models.IspRoutingRule` is
    populated for a given rule -- mirrors
    ``app.domains.queue_management.constants.QueueTargetType``'s own
    "one discriminator enum, one populated field per member" shape, except
    each member here has its own concrete, real match column (``vlan_id``/
    ``source_mac_address``/``ip_address``/``source_cidr``/
    ``interface_name``/``policy_id``) rather than a single polymorphic
    ``target_id`` -- there is no shared shape across VLAN/user/IP/source/
    interface/policy matches the way there is across
    ``QueueAssignment``'s own uniformly-UUID-keyed targets."""

    VLAN = "vlan"
    USER = "user"
    IP = "ip"
    SOURCE = "source"
    INTERFACE = "interface"
    POLICY = "policy"


__all__ = ["IspRoutingRuleType"]
