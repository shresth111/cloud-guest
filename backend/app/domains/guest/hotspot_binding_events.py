"""The one call a domain makes when something it just did may have taken a
MAC off a router's authorized list: a session ended, a guest was blocked, a
Trusted Device was deleted, disabled or changed.

It asks the worker to reconcile that router's ``cloudguest-authmac``
bindings shortly afterwards (``hotspot_binding_reconcile``). It decides
nothing: which bindings go is worked out in the worker, from the authorized
list as it stands then.

Kept apart from ``tasks`` so that ``guest.service``, ``guest_access`` and
``mac_authorization`` can call it without importing Celery at module scope,
and so that it can promise the one thing every caller needs: **it never
raises**. The work it requests is a clean-up on a router; it must not be
able to fail a disconnect, a block or a dashboard edit.

Nothing is published unless the removal is switched on for the router (off
by default -- see ``app.core.config``). The periodic sweep
(``tasks.run_hotspot_binding_reconcile_sweep``) is the net under every path
that does not call this, and under time-based changes that have no event at
all, such as a Trusted Device entry expiring.

The opposite event has one call here too, with the same promise:
``request_trusted_device_hotspot_gate_open``, for a Trusted Device entry
that has just put a MAC *on* the list. It asks the worker to add that
device's binding now (``hotspot_gate.open_hotspot_gate_for_trusted_entry``)
instead of leaving it to each router's next one-minute poll, and publishes
nothing unless the sign-in push is switched on.
"""

from __future__ import annotations

import uuid

from app.core.logging import get_logger

logger = get_logger(__name__)


async def request_hotspot_binding_reconcile(router_id: uuid.UUID | None) -> None:
    """Reconcile one router's session bypasses soon. Never raises."""
    if router_id is None:
        return
    try:
        from .tasks import enqueue_hotspot_binding_reconcile  # noqa: PLC0415

        await enqueue_hotspot_binding_reconcile(router_id=router_id)
    except Exception as exc:  # noqa: BLE001 -- see module docstring
        logger.warning(
            "guest_hotspot_binding_reconcile_request_failed",
            extra={"router_id": str(router_id), "error": str(exc)},
        )


async def request_hotspot_binding_reconcile_for_scope(
    *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
) -> None:
    """Reconcile every router an organization-wide (``location_id`` is
    ``None``) or one-location rule applies at. Never raises."""
    if organization_id is None:
        return
    try:
        from .tasks import enqueue_hotspot_binding_reconcile_for_scope  # noqa: PLC0415

        await enqueue_hotspot_binding_reconcile_for_scope(
            organization_id=organization_id, location_id=location_id
        )
    except Exception as exc:  # noqa: BLE001 -- see module docstring
        logger.warning(
            "guest_hotspot_binding_reconcile_request_failed",
            extra={"organization_id": str(organization_id), "error": str(exc)},
        )


async def request_trusted_device_hotspot_gate_open(
    *,
    entry_id: uuid.UUID,
    organization_id: uuid.UUID | None,
    location_id: uuid.UUID | None,
) -> None:
    """Add one Trusted Device entry's bypass soon, on every router an
    organization-wide (``location_id`` is ``None``) or one-location entry
    applies at. Never raises."""
    if organization_id is None:
        return
    try:
        from .tasks import enqueue_trusted_device_hotspot_gate_open  # noqa: PLC0415

        await enqueue_trusted_device_hotspot_gate_open(
            entry_id=entry_id,
            organization_id=organization_id,
            location_id=location_id,
        )
    except Exception as exc:  # noqa: BLE001 -- see module docstring
        logger.warning(
            "guest_hotspot_gate_trusted_device_request_failed",
            extra={"entry_id": str(entry_id), "error": str(exc)},
        )


__all__ = [
    "request_hotspot_binding_reconcile",
    "request_hotspot_binding_reconcile_for_scope",
    "request_trusted_device_hotspot_gate_open",
]
