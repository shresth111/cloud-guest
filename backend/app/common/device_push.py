"""One rule, shared by every domain that pushes a row onto a router:
**editing a field the device actually carries invalidates what the device
holds.**

## The defect this closes

``vlan``/``dhcp``/``port_forwarding``/``content_filtering``/``qos`` each
own a ``device_push_status`` column whose ``ACTIVE`` value means "a real
object for this row exists on the router right now". Every one of them
wrote that value on a successful push and then never revisited it on an
edit. So an operator who pushed a DHCP pool, then widened its address
range, left a row reading ``active`` while the router still handed out the
*old* range -- and the dashboard rendered a green "Applied" badge for a
configuration the device does not have. The row was not stale about
whether it had ever been pushed; it was stale about **what** had been
pushed, which is the harder lie to see.

## The rule

An update that changes any field the device actually carries demotes the
row to ``PENDING`` -- "not yet applied", which is the truth: these are the
new values, and no router has them. An update that changes only
presentation (a display name, a description, a category) does not, because
the device state is still exactly what the row describes and demoting
would nag the operator into a pointless re-push.

Each domain declares its own ``DEVICE_CARRIED_FIELDS`` in ``constants.py``
next to its ``*DevicePushStatus`` enum, because only that domain knows
which of its columns reach its ``configure_*`` call. This module holds the
*rule*; the domains hold the *facts*.

## Two deliberate narrownesses

**Only ``ACTIVE`` is demoted.** A ``FAILED`` row is not claiming any device
state -- it is showing the operator the error from the last attempt, and
that error is the only record of it. Rewriting it to ``pending`` on an edit
would erase the one thing standing between the operator and a silent
retry loop. ``PENDING`` is already the target state, and ``vlan``'s
``PROVISIONING`` is a push in flight that will write its own terminal
status moments later.

**Only fields actually present in the update, and actually different.**
A PATCH that re-submits the same interface must not demote a live row: the
device holds that value, and saying otherwise is the same class of lie in
the other direction.

``is_enabled`` is deliberately *not* a device-carried field in any domain.
It is intent, not configuration, and no domain's push writes it -- see
each domain's own ``DEVICE_CARRIED_FIELDS`` comment.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def demote_device_push_on_edit(
    row: Any,
    fields: Mapping[str, object],
    *,
    device_carried_fields: Iterable[str],
    active_status: str,
    pending_status: str,
) -> dict[str, object]:
    """The extra columns an ``update_*`` must merge into its own write so
    the row stops claiming a device state the edit just invalidated.

    Returns an empty dict -- merge it and nothing changes -- unless the row
    is currently ``active_status`` *and* ``fields`` carries a different
    value for at least one of ``device_carried_fields``. See the module
    docstring for why those two conditions and no others.

    Callers merge the result rather than issuing a second write, so the
    demotion lands in the same UPDATE as the edit itself: a row can never
    be observed with the new values and the old ``active`` badge.
    """
    if getattr(row, "device_push_status", None) != active_status:
        return {}
    for name in device_carried_fields:
        if name in fields and fields[name] != getattr(row, name):
            return {
                "device_push_status": pending_status,
                # The stored error, if any, described a push of values this
                # row no longer has. Carrying it forward would attach an
                # obsolete reason to a state that has not been attempted.
                "device_push_error": None,
            }
    return {}


__all__ = ["demote_device_push_on_edit"]
