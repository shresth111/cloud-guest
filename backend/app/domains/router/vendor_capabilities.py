"""What a fleet row's ``vendor`` says about which platform machinery may
run against it.

## Why this module exists

``routers.vendor`` has been a ``String(50)`` defaulting to ``"mikrotik"``
since the Provisioning Engine added it, and for the whole life of the
product every row in that table really was a MikroTik running a platform
agent. A great deal of machinery was written on that assumption and never
had to state it: the ZTP dashboard's lifecycle stages, the readiness
checklist's heartbeat/WireGuard/RouterOS-API checks, the provisioning
token minter, the SNMP pollers.

``app.domains.network_integration`` broke the assumption. A TP-Link Omada
controller is registered as a ``Router`` row -- not because it is a
router, but because ``guest_sessions.router_id`` is NOT NULL, so an
Omada-only venue could not log a guest in without one (see that domain's
``models.py`` for the full reasoning). That row runs no agent, has no
WireGuard peer and speaks no RouterOS API.

The failure mode this module exists to prevent is not a crash. It is
worse: every one of those surfaces would answer *confidently and wrongly*
-- a perfectly healthy Omada venue reported as a MikroTik that is offline,
unprovisioned, and failing seven readiness checks. A caller cannot be
expected to remember the distinction at each of those sites, so the
question gets one home and each caller asks it.

## Why predicates rather than a column

The distinction is a property of the *vendor*, not of the row: a second
controller-managed vendor should not require a data migration, and an
operator should not be able to make a device agent-managed by editing a
flag. Deriving it from ``vendor`` means a row can never disagree with
itself.

## Why "not controller-managed" means agent-managed

Deliberately a closed list of the controller-managed vendors and an
open complement, rather than the reverse. ``DeviceVendor`` already carries
stub members (``ruckus``, ``unifi``, ``aruba``, ``cisco_meraki``) whose
adapters raise ``NotImplementedError``; no row in production carries one.
Treating the complement as agent-managed guarantees that **every existing
row keeps its existing behavior exactly**, which is the property the
migration strategy needs. When one of those stubs becomes real, whoever
implements it adds it to the right set here, and this module's tests are
where that decision gets recorded.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "CONTROLLER_MANAGED_VENDORS",
    "NOT_APPLICABLE_REASON",
    "is_agent_managed",
    "is_controller_managed",
    "supports_zero_touch_provisioning",
    "vendor_of",
]


# Vendors whose devices this platform reaches only through the vendor's own
# controller, via ``app.domains.network_integration``. String literals rather
# than an import of ``wyfy_device_gateway.controller_contract.ControllerVendor``:
# this module is imported by ``readiness`` and ``monitoring``, and putting the
# vendored gateway package into their import graph to read one constant would
# make those domains fail to import whenever it is mid-edit. The values are
# the ``routers.vendor`` column's vocabulary, whose single translation table
# is ``app.domains.network_integration.constants.ROUTER_VENDOR_BY_PROVIDER``.
CONTROLLER_MANAGED_VENDORS: frozenset[str] = frozenset({"tplink_omada"})


# What a checklist item says when it is skipped for a controller-managed
# device. Phrased as a fact about the device rather than about the check, so
# an operator reading it learns why their venue shows an empty checklist
# instead of wondering what failed.
NOT_APPLICABLE_REASON = (
    "This device is managed through its vendor's controller, so this "
    "platform runs no agent on it and this check does not apply."
)


def vendor_of(value: Any) -> str:
    """The vendor string for a router row, or for a bare vendor string.

    Both call shapes are real and both are worth supporting: the service
    layers hold a ``Router`` (or a fake standing in for one) and would
    otherwise write ``is_agent_managed(r.vendor)`` at every site, while
    ``network_integration`` holds only the vendor string it just asked a
    provider for and has no row yet. Accepting either means neither caller
    has to reach for the other's shape.

    A row whose ``vendor`` is missing or ``None`` reads as the column's own
    default rather than raising: this is a predicate used inside health
    sweeps, and a sweep that raises on one malformed row stops reporting on
    every other one.
    """
    if isinstance(value, str):
        return value
    vendor = getattr(value, "vendor", None)
    return vendor if isinstance(vendor, str) else "mikrotik"


def is_controller_managed(value: Any) -> bool:
    """True if this device is reached only through a vendor controller."""
    return vendor_of(value) in CONTROLLER_MANAGED_VENDORS


def is_agent_managed(value: Any) -> bool:
    """True if this platform's own agent runs on this device.

    The question behind "may I check its heartbeat, its WireGuard peer, or
    its RouterOS API". See the module docstring for why this is the open
    complement of :data:`CONTROLLER_MANAGED_VENDORS` rather than its own
    closed list.
    """
    return not is_controller_managed(value)


def supports_zero_touch_provisioning(value: Any) -> bool:
    """True if this device can be taken through the ZTP workflow.

    A separate name from :func:`is_agent_managed` even though the two
    currently return the same answer, because they are different questions
    and will not stay in agreement. "Runs our agent" is about what may be
    *read* from a device; "can be zero-touch provisioned" is about a
    workflow -- enrollment, approval, claim, a single-use token redeemed by
    something on the device. A vendor could plausibly arrive that this
    platform monitors through an agent but provisions by hand, and when it
    does, the two call sites must be able to diverge without one of them
    silently inheriting the other's answer.
    """
    return is_agent_managed(value)
