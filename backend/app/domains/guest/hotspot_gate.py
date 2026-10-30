"""Open the router's hotspot gate for a guest who has just signed in,
instead of leaving them without internet until the router next asks.

## What was measured

On a platform-managed MikroTik (RouterOS 7.21), read-only: a guest's session
was created and was ``ACTIVE``; 35 and 51 seconds later the router still had
the device as an unauthorised hotspot host with no ``/ip hotspot active``
row and no ip-binding; 53 seconds after sign-in the router's own
``cloudguest-authmac-sched`` added ``/ip hotspot ip-binding type=bypassed
comment=cloudguest-authmac`` for the MAC, and from then on the device was
online. In the same second as the sign-in the platform had written that
guest's ``/queue simple`` row over the RouterOS API, so it could reach the
router and was already doing so.

The portal does try to open the gate itself (the browser posts to the
router's hotspot login URL and the router asks RADIUS). When that does not
happen, or does not succeed, the only thing left is the scheduler, which
polls ``GET /agent/authorized-macs`` once a minute. So the guest waits
between 0 and 60 seconds after "You're connected", and reports it as the
internet dropping after login.

## What this does

Adds the row the scheduler would add, a few seconds after sign-in, over the
same RouterOS API path the queue write uses, from a worker task. The
scheduler stays the reconciler and the only thing that ever removes one of
these rows; on its next poll it finds the binding present and does nothing.

Every rule about *whether* is somebody else's, on purpose:

* **Which sessions** -- ``router_agent.authorized_macs.resolve_session_gate``,
  the function ``GET /agent/authorized-macs`` is itself built from. If this
  module had its own idea of who is admitted, the scheduler would remove
  what it added one poll later.
* **Which routers** -- only one this platform logs in to. A controller-run
  venue and a NAS-only venue have no RouterOS to write to.
* **Whether the row may be written on this router right now** -- the
  gateway's ``ensure_hotspot_bypass_binding``: no binding of any kind for
  the MAC already, no live hotspot session for it, and an enabled
  ``cloudguest-authmac-sched`` on the router to take the row away again.

## Switched off until it has been watched on a router

``guest_hotspot_gate_push_enabled`` defaults to false and
``guest_hotspot_gate_push_router_ids`` to empty, so merging this enqueues
nothing anywhere. The second setting turns it on for named routers only.
See ``app.core.config`` for why, and for why the push waits a few seconds
(``guest_hotspot_gate_push_delay_seconds``) instead of going at once: the
guest's browser may be about to log in to the hotspot itself, and a binding
that lands first takes that login away from the hotspot.

## Never ahead of the browser, whichever request asked last

The delay is counted from the *latest* request that enqueued the push for
a session, not from the one that happened to start a given task. A venue
that requires a name enqueues twice -- at sign-in and when the name is
given -- and the first task, which would have been refused a moment
earlier, can otherwise run just after the name lands and write the binding
while the browser's hotspot login is still in flight. Each enqueue records
a "not before" instant for the session (``tasks.enqueue_hotspot_gate_open``)
and a task that starts before it re-schedules itself for that instant and
reports ``held`` without reading or writing anything on the router. If the
instant cannot be read, the task carries on as if there were none.

## A device an admin has just trusted

``open_hotspot_gate_for_trusted_entry`` is the same write for the other
half of the list: a Trusted Device entry that has just been created,
enabled or given a different MAC. Same routers, same gateway call, and the
same rule about *whether* -- the entry has to be one
``MacAuthorizationService.list_active_entries_for_router`` returns for that
router at the moment of the write, which is where the list itself gets its
trusted MACs. Nothing waits on a browser there, so it goes as soon as the
entry's own request has committed.

## What it must never do

Fail or slow a login. Nothing here runs on the request path; a router that
does not answer costs a worker a few seconds and the guest nothing they did
not already have -- the scheduler opens the gate within the minute, as now.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.registry import get_adapter

from app.common.exceptions import CloudGuestError
from app.core.logging import get_logger
from app.domains.router.vendor_capabilities import (
    is_controller_managed,
    is_nas_only,
)
from app.domains.router_agent.authorized_macs import (
    SessionGateReason,
    resolve_session_gate,
)
from app.domains.router_agent.validators import routeros_mac_address

from .constants import HOTSPOT_GATE_DEVICE_TIMEOUT_SECONDS

logger = get_logger(__name__)

_DEFAULT_API_PORT = 8728

# Outcomes that never reached a router. The rest are the gateway's own
# (``HotspotBypassBindingResult.outcome``) or a ``SessionGateReason``.
OUTCOME_ROUTER_NOT_FOUND = "router_not_found"
OUTCOME_UNSUPPORTED_VENDOR = "unsupported_vendor"
OUTCOME_NO_CREDENTIALS = "no_credentials"
#: The task started before the session's "not before" instant and has
#: re-scheduled itself; see the module docstring.
OUTCOME_HELD = "held"


class _RouterLookup(Protocol):
    async def get_router(self, router_id: uuid.UUID, **kwargs: Any) -> Any: ...

    def get_decrypted_api_secret(self, router: Any) -> str | None: ...


class _TrustedEntryLookup(Protocol):
    async def list_active_entries_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> Any: ...


class _BypassBindingWriter(Protocol):
    async def ensure_hotspot_bypass_binding(
        self, creds: DeviceCredentials, *, mac_address: str
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class HotspotGateResult:
    """``outcome`` is one word for the log line. ``wrote`` is true only when
    a binding was added and read back. ``retry`` is true only when the
    session was not among the router's ``ACTIVE`` sessions -- the one
    answer that can change within seconds, because the sign-in request that
    enqueued this may not have committed yet. ``hold_seconds`` is set only
    with ``OUTCOME_HELD``: how long until the write is allowed."""

    outcome: str
    wrote: bool = False
    retry: bool = False
    host_state: str | None = None
    existing_bindings: tuple[str, ...] = ()
    hold_seconds: float = 0.0


#: Gateway outcomes that carry ``existing_bindings`` read off the router.
_OUTCOMES_WITH_BINDINGS = frozenset({"already_bound", "raced"})


def internet_confirmation_source(result: HotspotGateResult) -> str | None:
    """Whether this gate-push attempt *read* the router letting the device
    through, and if so which reading -- an
    ``InternetConfirmationSource`` value, or ``None``.

    Only readings, never the write: a binding this task added proves the
    platform asked, not that the host is through. So:

    * ``active_session`` -- the MAC is in ``/ip hotspot active``: logged in.
    * ``created`` with ``host_state == "bypassed"`` -- after the write the
      router's own host row for the MAC reads ``bypassed=true``. ``absent``
      (device not seen by the router) and ``pending`` are not confirmation.
    * ``already_bound`` / ``raced`` with a ``bypassed`` binding and no
      ``blocked`` one -- the router's own authorized-MAC poll had already
      applied the bypass for this MAC.

    Everything else -- refusals, ``no_reconciler``, ``no_hotspot``, held,
    device errors -- is ``None``.
    """
    from .constants import InternetConfirmationSource

    if result.outcome == "active_session":
        return InternetConfirmationSource.MIKROTIK_HOTSPOT_ACTIVE.value
    if result.outcome == "created" and result.host_state == "bypassed":
        return InternetConfirmationSource.MIKROTIK_HOST_BYPASSED.value
    if result.outcome in _OUTCOMES_WITH_BINDINGS:
        types = {entry.split(":", 1)[0] for entry in result.existing_bindings}
        if "bypassed" in types and "blocked" not in types:
            return InternetConfirmationSource.MIKROTIK_BINDING_BYPASSED.value
    return None


def router_takes_hotspot_bindings(router: object) -> bool:
    """Whether ``router`` is a device this platform itself logs in to.

    A venue run from a vendor controller has no RouterOS behind its
    ``Router`` row, and a NAS-only venue has nothing this platform can call
    at all. Both are refused here rather than left to fail on missing
    credentials, so that a login at such a venue enqueues nothing."""
    return not (is_controller_managed(router) or is_nas_only(router))


async def open_hotspot_gate_for_session(
    *,
    session_id: uuid.UUID,
    router_id: uuid.UUID,
    guest_repository: Any,
    access_decision_service: Any,
    captive_portal_service: Any,
    router_lookup: _RouterLookup,
    adapter: _BypassBindingWriter | None = None,
) -> HotspotGateResult:
    """One attempt. Raises only what the device raised (the gateway's
    ``MikroTikDeviceError``/``MikroTikConnectionError``); every "should
    not" is a returned outcome, not an exception."""
    try:
        router = await router_lookup.get_router(router_id)
    except CloudGuestError:
        return HotspotGateResult(OUTCOME_ROUTER_NOT_FOUND)
    if not router_takes_hotspot_bindings(router):
        return HotspotGateResult(OUTCOME_UNSUPPORTED_VENDOR)

    # Asked immediately before the write, in the worker, never carried over
    # from the request: a guest blocked, or a session ended, in the seconds
    # between sign-in and here must not get a binding.
    decision = await resolve_session_gate(
        session_id,
        router_id,
        guest_repository=guest_repository,
        access_decision_service=access_decision_service,
        captive_portal_service=captive_portal_service,
    )
    if not decision.authorized or decision.mac_address is None:
        return HotspotGateResult(
            decision.reason.value,
            retry=decision.reason is SessionGateReason.NOT_LISTED,
        )

    host = getattr(router, "management_ip_address", None) or getattr(
        router, "public_ip_address", None
    )
    username = getattr(router, "api_username", None)
    secret = router_lookup.get_decrypted_api_secret(router)
    if not host or not username or not secret:
        return HotspotGateResult(OUTCOME_NO_CREDENTIALS)

    writer = adapter or get_adapter(DeviceVendor.MIKROTIK)
    result = await writer.ensure_hotspot_bypass_binding(
        DeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=str(host),
            username=username,
            secret=secret,
            port=getattr(router, "api_port", None) or _DEFAULT_API_PORT,
            timeout_seconds=HOTSPOT_GATE_DEVICE_TIMEOUT_SECONDS,
        ),
        mac_address=decision.mac_address,
    )
    return HotspotGateResult(
        result.outcome,
        wrote=bool(result.created),
        host_state=result.host_state,
        existing_bindings=tuple(result.existing_bindings),
    )


async def open_hotspot_gate_for_trusted_entry(
    *,
    entry_id: uuid.UUID,
    router_id: uuid.UUID,
    mac_authorization_service: _TrustedEntryLookup,
    router_lookup: _RouterLookup,
    adapter: _BypassBindingWriter | None = None,
) -> HotspotGateResult:
    """One attempt, for one router, at the binding of a device an admin
    marked Trusted. Raises only what the device raised, like
    :func:`open_hotspot_gate_for_session`.

    The entry is looked for in ``list_active_entries_for_router`` -- the
    call ``list_authorized_macs`` takes its trusted MACs from -- so "applies
    at this router, enabled, not expired, not deleted" cannot mean one thing
    here and another on the list. An entry that call does not return is
    ``not_listed`` whatever the reason, and worth one more look: the request
    that created it may not have committed yet."""
    try:
        router = await router_lookup.get_router(router_id)
    except CloudGuestError:
        return HotspotGateResult(OUTCOME_ROUTER_NOT_FOUND)
    if not router_takes_hotspot_bindings(router):
        return HotspotGateResult(OUTCOME_UNSUPPORTED_VENDOR)

    # Asked immediately before the write, in the worker: an entry disabled
    # or deleted in the moment since it was saved must not get a binding.
    entries = await mac_authorization_service.list_active_entries_for_router(
        router_id, requesting_organization_id=None
    )
    entry = next((e for e in entries if e.id == entry_id), None)
    if entry is None:
        return HotspotGateResult(SessionGateReason.NOT_LISTED.value, retry=True)
    # The list's own spelling, and its own rule for a value that is not one.
    mac_address = routeros_mac_address(entry.mac_address)
    if mac_address is None:
        return HotspotGateResult(SessionGateReason.MALFORMED_MAC.value)

    host = getattr(router, "management_ip_address", None) or getattr(
        router, "public_ip_address", None
    )
    username = getattr(router, "api_username", None)
    secret = router_lookup.get_decrypted_api_secret(router)
    if not host or not username or not secret:
        return HotspotGateResult(OUTCOME_NO_CREDENTIALS)

    writer = adapter or get_adapter(DeviceVendor.MIKROTIK)
    result = await writer.ensure_hotspot_bypass_binding(
        DeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=str(host),
            username=username,
            secret=secret,
            port=getattr(router, "api_port", None) or _DEFAULT_API_PORT,
            timeout_seconds=HOTSPOT_GATE_DEVICE_TIMEOUT_SECONDS,
        ),
        mac_address=mac_address,
    )
    return HotspotGateResult(
        result.outcome,
        wrote=bool(result.created),
        host_state=result.host_state,
        existing_bindings=tuple(result.existing_bindings),
    )


async def trusted_entry_for_session_device(
    *,
    session_id: uuid.UUID,
    router_id: uuid.UUID,
    guest_repository: Any,
    mac_authorization_service: _TrustedEntryLookup,
) -> uuid.UUID | None:
    """The Trusted Device entry, active at ``router_id``, for the device
    ``session_id`` was on -- or ``None``.

    Asked when a session ends: a device marked Trusted while it was signed
    in got no binding then (the gateway refuses a MAC with a live hotspot
    session), so it is the end of that session that makes the write
    possible. Compared in the router's own spelling of a MAC, as the list
    itself is."""
    session = await guest_repository.get_session_by_id(session_id)
    if session is None or session.device_id is None:
        return None
    device = await guest_repository.get_device_by_id(session.device_id)
    mac_address = routeros_mac_address(getattr(device, "mac_address", None))
    if mac_address is None:
        return None
    entries = await mac_authorization_service.list_active_entries_for_router(
        router_id, requesting_organization_id=None
    )
    for entry in entries:
        if routeros_mac_address(entry.mac_address) == mac_address:
            return entry.id
    return None


__all__ = [
    "HotspotGateResult",
    "OUTCOME_HELD",
    "OUTCOME_NO_CREDENTIALS",
    "OUTCOME_ROUTER_NOT_FOUND",
    "OUTCOME_UNSUPPORTED_VENDOR",
    "internet_confirmation_source",
    "open_hotspot_gate_for_session",
    "open_hotspot_gate_for_trusted_entry",
    "router_takes_hotspot_bindings",
    "trusted_entry_for_session_device",
]
