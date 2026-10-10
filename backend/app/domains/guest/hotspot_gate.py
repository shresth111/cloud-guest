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

from .constants import HOTSPOT_GATE_DEVICE_TIMEOUT_SECONDS

logger = get_logger(__name__)

_DEFAULT_API_PORT = 8728

# Outcomes that never reached a router. The rest are the gateway's own
# (``HotspotBypassBindingResult.outcome``) or a ``SessionGateReason``.
OUTCOME_ROUTER_NOT_FOUND = "router_not_found"
OUTCOME_UNSUPPORTED_VENDOR = "unsupported_vendor"
OUTCOME_NO_CREDENTIALS = "no_credentials"


class _RouterLookup(Protocol):
    async def get_router(self, router_id: uuid.UUID, **kwargs: Any) -> Any: ...

    def get_decrypted_api_secret(self, router: Any) -> str | None: ...


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
    enqueued this may not have committed yet."""

    outcome: str
    wrote: bool = False
    retry: bool = False
    host_state: str | None = None
    existing_bindings: tuple[str, ...] = ()


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


__all__ = [
    "HotspotGateResult",
    "OUTCOME_NO_CREDENTIALS",
    "OUTCOME_ROUTER_NOT_FOUND",
    "OUTCOME_UNSUPPORTED_VENDOR",
    "open_hotspot_gate_for_session",
    "router_takes_hotspot_bindings",
]
