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

from collections.abc import Iterable
from typing import Any, TypeVar

__all__ = [
    "AGENT_EVIDENCE_FIELDS",
    "CONTROLLER_MANAGED_VENDORS",
    "MIKROTIK_MODEL_MARKERS",
    "NOT_APPLICABLE_REASON",
    "SUPPORTED_ROUTER_VENDORS",
    "looks_like_mikrotik_hardware",
    "agent_managed_rows",
    "has_agent_evidence",
    "is_agent_managed",
    "is_agent_managed_row",
    "is_controller_managed",
    "is_controller_managed_row",
    "vendor_claim_is_contradicted",
    "supports_zero_touch_provisioning",
    "vendor_of",
]

_Row = TypeVar("_Row")


# Vendors whose devices this platform reaches only through the vendor's own
# controller, via ``app.domains.network_integration``. String literals rather
# than an import of ``wyfy_device_gateway.controller_contract.ControllerVendor``:
# this module is imported by ``readiness`` and ``monitoring``, and putting the
# vendored gateway package into their import graph to read one constant would
# make those domains fail to import whenever it is mid-edit. The values are
# the ``routers.vendor`` column's vocabulary, whose single translation table
# is ``app.domains.network_integration.constants.ROUTER_VENDOR_BY_PROVIDER``.
CONTROLLER_MANAGED_VENDORS: frozenset[str] = frozenset({"tplink_omada"})


# The closed vocabulary `routers.vendor` may be *written* with.
#
# The column itself is a free `String(50)` with no enum and no CHECK
# (`models.py`, migration 0031), and that is not an oversight worth a
# migration to undo -- but it does mean nothing stopped `"unifi"` being
# written to it, and a vendor outside CONTROLLER_MANAGED_VENDORS reads as
# agent-managed everywhere. So a device type this platform has not
# implemented does not record as "unsupported"; it records as a promise that
# an agent is running on hardware that has never heard of us.
#
# Enforced at the write boundary (`RouterVendorChangeRequest`) rather than in
# the database, because the existing rows must keep loading whatever they
# hold: this is a gate on new claims, not a retroactive assertion about old
# ones. `mikrotik` first, so the ordering in the error message reads as the
# default it is.
SUPPORTED_ROUTER_VENDORS: tuple[str, ...] = ("mikrotik", "tplink_omada")


# Substrings that identify MikroTik hardware from `routers.model` alone.
#
# Not agent evidence -- the device has not *told* us anything by having a
# model string; a human typed it. But "MikroTik hEX lite (RB750r2)" sitting
# in the model column while the vendor column says the device is a TP-Link
# controller is a self-contradiction on one row, and refusing to add the
# second half of it is cheaper than reconstructing which half was true.
# Matched case-insensitively as substrings so "RB750r2", "MikroTik hEX lite
# (RB750r2)" and "CCR2004-1G-12S+2XS" all hit.
MIKROTIK_MODEL_MARKERS: tuple[str, ...] = (
    "mikrotik",
    "routerboard",
    "hex",
    "hap",
    "ccr",
    "crs",
    "rb",
)


def looks_like_mikrotik_hardware(model: str | None) -> bool:
    """True when ``routers.model`` names MikroTik hardware.

    Used only to refuse a *contradicting* vendor claim, never to assert one:
    a model string that matches nothing here proves nothing at all, since the
    column is free text an operator fills in.
    """
    if not model:
        return False
    folded = model.lower()
    return any(marker in folded for marker in MIKROTIK_MODEL_MARKERS)


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


# Columns only a platform agent, or an operator configuring one, ever
# writes. A row carrying any of them has *spoken to us as an agent-managed
# device*, whatever its `vendor` column says today.
#
# Why these four and not others:
#
# * ``last_seen_at`` and ``routeros_version`` are stamped by
#   ``RouterService.heartbeat`` and by nothing else. A controller never
#   heartbeats.
# * ``last_health_check_at`` is stamped by the provisioning engine's health
#   poll, which reaches a device over the RouterOS API.
# * ``api_credentials_encrypted`` is a RouterOS API credential. A controller
#   row is created with it NULL (`create_integration_with_fleet_device` ->
#   `RouterService.create_router`) and the controller's own credentials live
#   on the `network_integrations` row, not here.
#
# A WireGuard peer allocation is agent evidence too, and is deliberately NOT
# in this list: it lives in the `wireguard` domain's own tables, not on the
# fleet row, and this module must stay importable by `readiness` and
# `monitoring` without pulling in the ORM (see the module docstring). A row
# with a peer but none of the four above does not exist in practice -- a peer
# is allocated during provisioning, which stamps `last_health_check_at`.
AGENT_EVIDENCE_FIELDS: tuple[str, ...] = (
    "last_seen_at",
    "routeros_version",
    "last_health_check_at",
    "api_credentials_encrypted",
)


def has_agent_evidence(value: Any) -> bool:
    """True when this fleet row has ever behaved like an agent-managed device.

    A bare vendor string has no row and therefore no evidence, so this is
    ``False`` for one -- which makes every ``*_row`` predicate below degrade
    to the pure-label answer when the caller only holds a vendor. That is the
    right degradation: absence of evidence is not evidence, and a caller with
    no row cannot have any.
    """
    return any(
        getattr(value, field, None) is not None for field in AGENT_EVIDENCE_FIELDS
    )


def vendor_claim_is_contradicted(value: Any) -> bool:
    """True when a row's ``vendor`` says controller and its data says agent.

    The mislabel detector, named separately from the predicates below so a
    caller can *report* the contradiction rather than only route around it.
    """
    return is_controller_managed(value) and has_agent_evidence(value)


def is_controller_managed_row(value: Any) -> bool:
    """True if this **row** is reached only through a vendor controller.

    The row-aware sibling of :func:`is_controller_managed`, and the one every
    liveness, monitoring, readiness and alerting call site should ask.

    ## Why the evidence beats the label

    On 2026-09-10 seven live MikroTiks had their ``vendor`` set to
    ``tplink_omada`` through a dropdown with no confirmation step. Under the
    pure-label predicate that single click removed all seven from the alert
    evaluator's roster and from the ZTP dashboard, and put nothing in their
    place. ``Office Guest`` -- an RB750r2 -- was demoted to ``offline`` /
    ``unhealthy`` by the heartbeat sweep (which reads ``status``, not
    ``vendor``, and was right to) and *nobody was told*, because the thing
    that would have told them had been filtered by the label.

    A device that checked in and then stopped is down. That fact does not
    depend on what somebody typed into a dropdown afterwards. Deriving
    eligibility from evidence means a mislabel can never again silence a real
    outage -- it removes the failure class, where relabelling the seven rows
    only removes today's instance of it.

    A legitimately onboarded controller carries none of the evidence (see
    :data:`AGENT_EVIDENCE_FIELDS`) and so is unaffected: it is still
    controller-managed here, on its first day and forever.

    :func:`is_controller_managed` stays as-is for the pure-vendor question the
    adapter registries ask -- "do I have an adapter for this vendor string" is
    genuinely about the label, and over-refusing there is free.
    """
    return is_controller_managed(value) and not has_agent_evidence(value)


def is_agent_managed_row(value: Any) -> bool:
    """True if this platform's own agent runs on, or has run on, this row.

    The complement of :func:`is_controller_managed_row`; see it for why the
    evidence outranks the label.
    """
    return not is_controller_managed_row(value)


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

    Asks the *row* question (:func:`is_controller_managed_row`), not the label
    one: a mislabelled MikroTik that vanished from the ZTP dashboard entirely
    is one of the two things the 2026-09-10 relabel did, and a device that has
    checked in can certainly be taken through a workflow that ends in it
    checking in.
    """
    return is_agent_managed_row(value)


def agent_managed_rows(rows: Iterable[_Row]) -> list[_Row]:
    """The agent-managed subset of a batch of fleet rows.

    For the callers that must read the whole roster for one purpose and
    judge only part of it for another -- the alert evaluator being the
    case that forced this: the same ``list_routers`` result resolves an
    alert's router *name* (where a controller must appear, or the customer
    reads a bare UUID) and feeds the rules that decide whether a device is
    down (where it must not, because those rules read columns only an
    agent ever writes).

    A named function rather than a comprehension at each site so the
    router-read coverage test has something to recognise, and so a reader
    of the sweep sees the question being asked instead of a filter that
    looks like a performance tweak. Prefer
    ``fleet_scope.agent_managed_only`` when the rows have not been loaded
    yet -- a row a sweep never loads is a row it cannot act on by mistake.

    Judges each row with :func:`is_agent_managed_row`, so a row carrying agent
    evidence stays in the roster no matter what its ``vendor`` column claims.
    This function is the exact line that made seven live routers
    unmonitorable; see :func:`is_controller_managed_row` for the incident.

    Note that ``fleet_scope.agent_managed_only`` remains a *label* filter, and
    the two are therefore no longer identical. That is deliberate and the
    asymmetry is one-directional: the SQL helper is used where a row is about
    to be pushed configuration or dialled, and over-excluding there costs a
    skipped write; this one is used where a row is about to be *judged*, and
    over-excluding there costs an outage nobody hears about. Neither module
    restates the vendor list, so the vendor question still has one home.
    """
    return [row for row in rows if is_agent_managed_row(row)]
