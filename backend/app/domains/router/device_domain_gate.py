"""The one refusal every device domain owes a controller-managed venue.

## Why this module exists

Thirteen domains take a ``router_id`` and end in RouterOS. Seven of them
carry an adapter registry that raises when no adapter is registered for a
vendor, and the vendor-gating audit called that a pass. It is not: the
refusals were measured this session and they fail two ways.

**They fire too late.** ``POST /vlans`` writes the ``VlanNetwork`` row and
returns 201; the adapter is only fetched later, on ``push``. Same shape in
``dhcp``, ``port_forwarding``, ``qos``, ``queue_management``, ``hotspot``,
``firewall`` and ``provisioning_engine`` -- and ``network_config``'s
``netwatch/push`` goes further and *rotates a real agent credential* for a
device that runs no agent, before writing two rows. A screen that accepts a
form, writes a row and changes nothing on a device is the named failure this
platform's contract was written around.

**And when they do fire, they say the wrong thing.** Every one of the seven
services resolves device credentials exactly one line before it resolves the
adapter. A controller row has NULL credentials by construction, so the error
an Omada venue actually receives is ``"Router 'X' is missing device
connection credentials"`` -- which reads as *add some and retry*. There is
nothing to add. ``network_config/router.py``'s gate comment called this out
and fixed it in one place; this module is that fix generalised.

## Why the label, not the row

:func:`~app.domains.router.vendor_capabilities.is_controller_managed_row`
weighs agent evidence and is the right question for *judging* a device --
monitoring, alerting, readiness. This module asks the plain label question
instead, deliberately. Over-refusing here costs a venue owner one clear
sentence about a screen that was never going to work; under-refusing costs a
credential rotation or a dispatched Celery job against a controller. Those
two mistakes are not the same size, and a row mislabelled *towards*
``tplink_omada`` is exactly the case where we should decline to push
configuration until somebody has said which device it really is.

## Why 422 and not network_config's 200 + applied=False

``network_config``'s live-apply returns ``200`` with ``applied=False``
because the caller asked "apply this" about a version that legitimately
exists and the honest answer is "nothing to do". These calls are different:
they ask to *create* something for a device that cannot hold it, and there is
no later moment at which they succeed. 422, the same code and the same
reasoning ``WireGuardVendorNotSupportedError`` and
``RouterVendorNotProvisionableError`` already use.
"""

from __future__ import annotations

from typing import Any

from fastapi import status

from app.common.exceptions import CloudGuestError

from .vendor_capabilities import is_controller_managed

__all__ = [
    "ControllerManagedFeatureUnavailableError",
    "ensure_not_controller_managed",
    "unsupported_vendor_message",
]


class ControllerManagedFeatureUnavailableError(CloudGuestError):
    """A device-domain write was attempted against a controller-managed row.

    The message is written for a duty manager, not for whoever wrote the
    adapter registry. It names the feature in the words the venue's own
    console uses, says plainly that the platform does not configure this
    device, and points at the surface that does -- because "No VLAN device
    adapter is registered for vendor 'tplink_omada'" tells a customer nothing
    they can act on, and they will read it long before any console panel can
    stop them (a direct API caller, a bookmarked URL, a stale tab).
    """

    def __init__(self, *, feature: str, router_name: str, vendor: str) -> None:
        super().__init__(
            f"{feature} isn't available for this venue. Its network is run "
            f"from a {_vendor_noun(vendor)}, and '{router_name}' is that "
            "controller rather than a device we configure directly -- so "
            f"there is nothing here for us to change. {feature} is managed "
            "in the controller's own software.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


# The customer-facing name for a controller vendor. A small table rather than
# `vendor.replace("_", " ").title()`: "Tplink Omada" is not what is printed on
# the box, and a venue owner reading an error should recognise their own
# equipment in it. Unknown vendors fall back to a true, generic phrase rather
# than to a mangled identifier.
_VENDOR_NOUNS: dict[str, str] = {
    "tplink_omada": "TP-Link Omada controller",
}


def _vendor_noun(vendor: str) -> str:
    return _VENDOR_NOUNS.get(vendor, "third-party controller")


def ensure_not_controller_managed(router: Any, *, feature: str) -> None:
    """Refuse, early, if this device is reached through a vendor controller.

    Call it as the first statement after the router is loaded and **before**
    anything is persisted, any credential is decrypted or revealed, any job is
    enqueued, and any device call is made. That ordering is the whole point;
    a gate placed after the write is a gate that documents the bug rather than
    removing it.

    ``feature`` is the venue-facing name of the screen the caller came from --
    "Network Zones", "Port Forwarding", "Internet Connection". It goes
    verbatim into a sentence a customer reads, so it is a noun phrase in the
    console's own vocabulary, never a domain or module name.
    """
    if not is_controller_managed(router):
        return
    raise ControllerManagedFeatureUnavailableError(
        feature=feature,
        router_name=str(getattr(router, "name", "this device")),
        vendor=str(getattr(router, "vendor", "")),
    )


def unsupported_vendor_message(*, feature: str, vendor: str) -> str:
    """The message an adapter registry should raise with.

    Two audiences reach that raise, and until now both got the same
    sentence -- ``"No VLAN device adapter is registered for vendor
    'tplink_omada'"`` -- written for the second one.

    * A **venue owner**, whose device is a controller we deliberately do not
      configure. Nothing is broken and nothing is missing; this feature is
      simply somewhere else. They get the same sentence
      :class:`ControllerManagedFeatureUnavailableError` gives, because it is
      the same fact arriving by a later route (a direct API call, a stale
      tab, a path the early gate does not cover).
    * An **engineer**, looking at a row whose ``vendor`` is genuinely
      unrecognised -- ``"MikroTik"`` capitalised, ``"mikrotik_routeros"``,
      something a stub vendor list wrote. That is a data problem, and naming
      the exact string is the useful thing to say, so that case keeps its
      original wording.

    Deciding between them is the whole job; the registries keep their own
    exception types and status codes.
    """
    if is_controller_managed(vendor):
        return (
            f"{feature} isn't available for this venue. Its network is run "
            f"from a {_vendor_noun(vendor)} rather than from a device we "
            f"configure directly, so there is nothing here for us to change "
            f"-- {feature} is managed in the controller's own software."
        )
    return (
        f"{feature} is not available for a '{vendor}' device. This platform "
        "has no way to configure that device type; if this is MikroTik "
        "hardware, its recorded device type is wrong."
    )
