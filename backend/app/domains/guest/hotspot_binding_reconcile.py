"""Take a router's session bypass away once nothing lists its MAC any more.

## The gap

A guest's device gets through a MikroTik hotspot by an ``/ip hotspot
ip-binding type=bypassed comment=cloudguest-authmac`` row. The router's own
``cloudguest-authmac-sched`` adds one for every MAC that
``GET /agent/authorized-macs`` lists and is meant to remove its own row for
every MAC that is no longer listed.

On every router provisioned before that script's removal pass was repaired,
the removal never fires: it compared a typename that RouterOS 7 never
returns. So on those routers a MAC once bypassed stays bypassed. A
dashboard disconnect ends the session in this platform's records and the
guest stays online; a Trusted Device deleted in the dashboard keeps its
bypass (observed on hardware: three deleted entries still bound more than
two hours later). The script only changes on a router that is
re-provisioned by hand, and a router whose scheduler is disabled or missing
has nothing that removes a row at all.

## What this does

The removal pass, performed by the platform over the RouterOS API. For one
router:

1. list the MACs the router should let through --
   ``router_agent.authorized_macs.list_authorized_macs``, the function the
   endpoint itself returns and the sign-in push (``hotspot_gate``) decides
   from, so the three cannot disagree about who is admitted;
2. read the router's bindings whose comment is exactly
   ``cloudguest-authmac``;
3. remove each one whose MAC is not listed.

It never adds anything. Adding stays with the router's scheduler and the
sign-in push.

## Why it cannot drop a signed-in guest

* **A binding is removed only if its MAC is unlisted twice**: in the list
  read before the router was read, and in a fresh list read immediately
  before that one removal, with ``grace_seconds`` between the first read
  and the first removal. A guest who signs in again in that interval is
  listed by the second read and kept.
* **Any doubt about the list removes nothing.** If the list cannot be built
  -- a database error, anything -- the run ends there, as the router's
  script ends on a failed fetch. An empty list is a legitimate answer
  (nobody is signed in) and does run the removal; an *exception* is not an
  answer. Inside the list, the lookups that can fail individually (the
  blocklist check, the venue's name requirement) already fail towards
  keeping a guest listed.
* **Removals are capped per router per run**, and hitting the cap is logged
  at ERROR. A defect that made every guest look unlisted would otherwise
  empty a venue in one pass; the cap turns that into a few rows and a loud
  line, and the rest wait for the next run.
* Only rows carrying exactly the tag are ever shown to this module by the
  gateway, and the gateway re-checks the row before removing it. An
  operator's own binding, a trusted-device bypass under another comment
  and a device block are not reachable from here.

## Routers it runs on

Any MikroTik this platform logs in to, **including one whose
``cloudguest-authmac-sched`` is disabled or missing** -- that is the router
where nothing else will ever remove a row. Controller-managed and NAS-only
venues are never touched (``hotspot_gate.router_takes_hotspot_bindings``).

## Switched off until it has been watched on a router

``guest_hotspot_gate_remove_enabled`` defaults to false and
``guest_hotspot_gate_remove_router_ids`` to empty; see ``app.core.config``.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.registry import get_adapter

from app.common.exceptions import CloudGuestError
from app.core.logging import get_logger
from app.domains.router_agent.authorized_macs import list_authorized_macs

from .constants import HOTSPOT_GATE_DEVICE_TIMEOUT_SECONDS
from .hotspot_gate import (
    OUTCOME_NO_CREDENTIALS,
    OUTCOME_ROUTER_NOT_FOUND,
    OUTCOME_UNSUPPORTED_VENDOR,
    router_takes_hotspot_bindings,
)

logger = get_logger(__name__)

_DEFAULT_API_PORT = 8728

OUTCOME_RECONCILED = "reconciled"
#: The authorized list could not be built. Nothing was read from the router
#: and nothing was removed.
OUTCOME_LIST_UNAVAILABLE = "list_unavailable"


class _RouterLookup(Protocol):
    async def get_router(self, router_id: uuid.UUID, **kwargs: Any) -> Any: ...

    def get_decrypted_api_secret(self, router: Any) -> str | None: ...


class _BypassBindingRemover(Protocol):
    async def read_hotspot_bypass_bindings(self, creds: DeviceCredentials) -> Any: ...

    async def remove_hotspot_bypass_binding(
        self,
        creds: DeviceCredentials,
        *,
        binding_id: str,
        mac_address: str,
        drop_bypassed_host: bool = True,
    ) -> Any: ...


@dataclass(slots=True)
class HotspotBindingReconcileResult:
    """One router, one run. Counts, never MAC addresses.

    ``tagged`` is how many ``cloudguest-authmac`` rows the router held;
    ``stale`` how many of those named a MAC the list did not; ``removed``
    how many were taken off. ``relisted`` were stale at the first read and
    listed again by the re-read before their removal -- kept. ``skipped``
    were gone or changed on the router by the time they were reached.
    ``deferred`` is what the cap left for the next run. ``aborted`` is true
    when a list re-read failed part-way and the run stopped removing."""

    outcome: str
    tagged: int = 0
    stale: int = 0
    removed: int = 0
    relisted: int = 0
    skipped: int = 0
    deferred: int = 0
    hosts_removed: int = 0
    aborted: bool = False
    reconciler_enabled: bool | None = None
    #: ``"<host_before>-><host_after>"`` per removal, for the log line.
    host_transitions: list[str] = field(default_factory=list)

    def as_log_extra(self) -> dict[str, object]:
        return {
            "outcome": self.outcome,
            "tagged": self.tagged,
            "stale": self.stale,
            "removed": self.removed,
            "relisted": self.relisted,
            "skipped": self.skipped,
            "deferred": self.deferred,
            "hosts_removed": self.hosts_removed,
            "aborted": self.aborted,
            "reconciler_enabled": self.reconciler_enabled,
            "host_transitions": list(self.host_transitions),
        }


async def reconcile_hotspot_bindings_for_router(
    *,
    router_id: uuid.UUID,
    guest_repository: Any,
    mac_authorization_service: Any,
    access_decision_service: Any,
    captive_portal_service: Any,
    router_lookup: _RouterLookup,
    max_removals: int,
    grace_seconds: float,
    drop_bypassed_host: bool = True,
    adapter: _BypassBindingRemover | None = None,
    refresh: Callable[[], None] | None = None,
    sleep: Callable[[float], Any] = asyncio.sleep,
) -> HotspotBindingReconcileResult:
    """One pass over one router. Raises only what the device raised (the
    gateway's ``MikroTikDeviceError``/``MikroTikConnectionError``), so the
    caller can tell an unreachable router from a finished run.

    ``refresh`` is called before every list read after the first. The list
    is built through ORM objects, and a second read inside one database
    session would otherwise answer partly from what the first read loaded;
    the worker passes ``AsyncSession.expire_all``.
    """
    try:
        router = await router_lookup.get_router(router_id)
    except CloudGuestError:
        return HotspotBindingReconcileResult(OUTCOME_ROUTER_NOT_FOUND)
    if not router_takes_hotspot_bindings(router):
        return HotspotBindingReconcileResult(OUTCOME_UNSUPPORTED_VENDOR)

    host = getattr(router, "management_ip_address", None) or getattr(
        router, "public_ip_address", None
    )
    username = getattr(router, "api_username", None)
    secret = router_lookup.get_decrypted_api_secret(router)
    if not host or not username or not secret:
        return HotspotBindingReconcileResult(OUTCOME_NO_CREDENTIALS)

    async def _listed() -> frozenset[str] | None:
        """The router's authorized MACs, or ``None`` if they could not be
        established. ``None`` is never an empty list."""
        try:
            listed = await list_authorized_macs(
                router_id,
                guest_repository=guest_repository,
                mac_authorization_service=mac_authorization_service,
                access_decision_service=access_decision_service,
                captive_portal_service=captive_portal_service,
            )
        except Exception as exc:  # noqa: BLE001 -- any doubt removes nothing
            logger.warning(
                "guest_hotspot_binding_reconcile_list_unavailable",
                extra={"router_id": str(router_id), "error": str(exc)},
            )
            return None
        return frozenset(listed.mac_addresses)

    first = await _listed()
    if first is None:
        return HotspotBindingReconcileResult(OUTCOME_LIST_UNAVAILABLE)

    creds = DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK,
        host=str(host),
        username=username,
        secret=secret,
        port=getattr(router, "api_port", None) or _DEFAULT_API_PORT,
        timeout_seconds=HOTSPOT_GATE_DEVICE_TIMEOUT_SECONDS,
    )
    device = adapter or get_adapter(DeviceVendor.MIKROTIK)
    snapshot = await device.read_hotspot_bypass_bindings(creds)

    result = HotspotBindingReconcileResult(
        OUTCOME_RECONCILED,
        tagged=len(snapshot.bindings),
        reconciler_enabled=bool(snapshot.reconciler_enabled),
    )
    stale = [row for row in snapshot.bindings if row.mac_address not in first]
    result.stale = len(stale)
    if not stale:
        return result

    allowed = max(0, max_removals)
    if len(stale) > allowed:
        result.deferred = len(stale) - allowed
        logger.error(
            "guest_hotspot_binding_reconcile_cap_hit",
            extra={
                "router_id": str(router_id),
                "stale": len(stale),
                "cap": allowed,
                "tagged": len(snapshot.bindings),
                "listed": len(first),
            },
        )

    if grace_seconds > 0:
        await sleep(grace_seconds)

    for row in stale[:allowed]:
        if refresh is not None:
            refresh()
        now = await _listed()
        if now is None:
            # The list was readable a moment ago and is not now. Stop: the
            # rows left are judged by the next run, not by a stale answer.
            result.aborted = True
            break
        if row.mac_address in now:
            result.relisted += 1
            continue
        removal = await device.remove_hotspot_bypass_binding(
            creds,
            binding_id=row.binding_id,
            mac_address=row.mac_address,
            drop_bypassed_host=drop_bypassed_host,
        )
        if not removal.removed:
            result.skipped += 1
            continue
        result.removed += 1
        result.hosts_removed += int(removal.hosts_removed)
        result.host_transitions.append(f"{removal.host_before}->{removal.host_after}")
    return result


__all__ = [
    "HotspotBindingReconcileResult",
    "OUTCOME_LIST_UNAVAILABLE",
    "OUTCOME_RECONCILED",
    "reconcile_hotspot_bindings_for_router",
]
