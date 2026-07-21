"""Pure validation helpers for the ISP Routing domain -- no I/O, easy to
unit-test in isolation (mirrors every other domain's own ``validators.py``
convention, e.g. ``app.domains.isp.validators.classify_health_status``).
"""

from __future__ import annotations

import uuid

from .constants import IspRoutingRuleType
from .exceptions import IspRoutingRuleInvalidMatchFieldsError

# Which single match field a given rule_type expects populated -- see
# constants.IspRoutingRuleType's own docstring.
_EXPECTED_MATCH_FIELD: dict[IspRoutingRuleType, str] = {
    IspRoutingRuleType.VLAN: "vlan_id",
    IspRoutingRuleType.USER: "source_mac_address",
    IspRoutingRuleType.IP: "ip_address",
    IspRoutingRuleType.SOURCE: "source_cidr",
    IspRoutingRuleType.INTERFACE: "interface_name",
    IspRoutingRuleType.POLICY: "policy_id",
}


def validate_match_fields(
    rule_type: IspRoutingRuleType,
    *,
    vlan_id: int | None,
    source_mac_address: str | None,
    ip_address: str | None,
    source_cidr: str | None,
    interface_name: str | None,
    policy_id: uuid.UUID | None,
) -> None:
    """Raises :class:`~.exceptions.IspRoutingRuleInvalidMatchFieldsError`
    unless exactly the one match field ``rule_type`` names is populated and
    every other match field is ``None`` -- a rule with two populated match
    fields (or the wrong one for its own ``rule_type``) is ambiguous about
    what it actually matches, never silently resolved by picking one."""
    fields: dict[str, object | None] = {
        "vlan_id": vlan_id,
        "source_mac_address": source_mac_address,
        "ip_address": ip_address,
        "source_cidr": source_cidr,
        "interface_name": interface_name,
        "policy_id": policy_id,
    }
    expected_field = _EXPECTED_MATCH_FIELD[rule_type]
    if fields[expected_field] is None:
        raise IspRoutingRuleInvalidMatchFieldsError(
            rule_type.value, f"'{expected_field}' is required for this rule_type"
        )
    populated = [name for name, value in fields.items() if value is not None]
    if populated != [expected_field]:
        extra = [name for name in populated if name != expected_field]
        raise IspRoutingRuleInvalidMatchFieldsError(
            rule_type.value,
            f"only '{expected_field}' may be set for this rule_type, "
            f"got extra: {extra}",
        )


__all__ = ["validate_match_fields"]
