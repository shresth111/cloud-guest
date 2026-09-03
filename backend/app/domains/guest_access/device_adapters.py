"""Real device I/O for the Guest Access Control domain -- the piece that
made "Blocked" a lie.

## What this closes

``GuestAccessService.create_guest_rule`` wrote a ``GuestAccessRule`` row,
audited it, returned 201, and stopped. The customer dashboard's own copy
(``BlockUsers.tsx``) told them, verbatim, *"Takes effect immediately,
ending any session these users currently have."* Nothing in that method
contacted a router, ended a session, or so much as looked one up. A guest
blocked mid-stream kept streaming.

The login path was never the gap: ``GuestService._enforce_access_control``
already calls ``check_access`` before OTP, voucher, password and
MAC-whitelist logins, so a blocked guest genuinely cannot sign in *again*.
What was missing is everything about the session they are already in.

## The mechanism, and why it is this one

Ending a live captive-portal session has four candidate mechanisms. They
are not interchangeable:

1. **RADIUS Disconnect-Request (RFC 5176).** The RFC-sanctioned,
   server-initiated path, and already implemented platform-side
   (``app.domains.guest.radius_coa``). It needs three things this fleet
   does not currently have: ``/radius incoming accept=yes`` on the router
   (the lab router reads ``accept=false``), a correct NAS address and
   shared secret, and an *inbound* UDP path from the API container to the
   NAS. The last one is documented as absent in
   ``RadiusNasClient.ip_address``'s own comment -- there is no route into
   the hub's tunnel subnet -- which is why ``issue_live_disconnect`` has
   been logging "no response" fleet-wide rather than "never sent". Worst
   of all, it fails *silently*: an undelivered Disconnect looks exactly
   like a delivered one that the NAS chose not to NAK.
2. **``/ip hotspot active remove`` over the port-8728 API.** Removes the
   guest from the table RouterOS consults to decide whether to forward
   their packets -- which is what a router does in response to a
   Disconnect-Request anyway. Needs only port 8728, the transport every
   other write in this platform's gateway already uses and the only one
   confirmed to reach fleet routers. Either succeeds or raises.
3. **``/ip hotspot ip-binding type=blocked``.** Durable, survives a
   reconnect, and genuinely the right primitive for a *device* (MAC)
   blocklist. It is the wrong primitive here: this domain's guest rules
   are keyed on a login identifier (a phone number, an email), and the
   MAC a guest happens to be holding right now is not that identity --
   phones rotate it per-SSID by default. A binding written for today's
   randomized MAC blocks a stranger next week and stops blocking the
   guest. See ``docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md`` §2.4.
4. **Terminating this platform's own ``GuestSession`` row.** Necessary --
   without it the next RADIUS re-authorization finds an ``ACTIVE``
   session and re-admits the guest (``RadiusService.authorize`` checks
   session status, and a separate ``Guest.is_blocked`` flag this form
   never sets, but not access rules). And on its own, a lie of exactly
   the kind being fixed: a row that says "ended" while the device is
   still forwarding.

**The chosen mechanism is 2 + 4**, in that order, with 1 *read but not
sent* and 3 left to the device-rule work it belongs to. 2 without 4 leaves
a re-auth hole; 4 without 2 is the same class of falsehood as the bug.

## CoA is read from the device, never inferred

``read_session_control`` reads ``/radius incoming`` per router and reports
``coa_accept``/``coa_port`` as facts about *that* router at *this* moment.
It is deliberately not used to decide whether the block succeeds -- the
8728 path does that -- but it is reported, because "the RFC path into this
router is shut" is something an operator needs to know and cannot
currently learn from anywhere.

The reason it must be a read is recorded in the lab router itself: it
holds ``accept=false port=3799``, and 3799 is not RouterOS's default
(1700) -- it is exactly the value this codebase writes, in both places it
writes it, in the same statement that sets ``accept=yes``. Half of that
write is on the device and half is not, and nothing here knows why. Any
code that reasons "we configured CoA, so CoA works" is wrong about that
router today.

## Shape

Mirrors ``app.domains.vlan.device_adapters`` deliberately -- own narrow
credentials dataclass, own Protocol naming only what this domain needs, a
concrete MikroTik implementation delegating to
``wyfy_device_gateway.registry.get_adapter``, and a small vendor registry.

``MikroTikConnectionError`` subclasses ``MikroTikDeviceError``, so it is
caught first here for the same reason the VLAN adapter documents: catch
the base class first and every connection failure is mislabelled as an
operation failure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.contract import DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    GuestAccessDeviceConnectionError,
    GuestAccessDeviceOperationError,
    UnsupportedGuestAccessVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class GuestAccessCredentials:
    """What an adapter needs to open a real connection, resolved by the
    caller from the target ``Router``'s own connection fields. An
    independently-defined identical shape to
    ``app.domains.vlan.device_adapters.VlanCredentials``, not an import,
    so the two domains' device-I/O layers stay uncoupled."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True, slots=True)
class SessionControlSnapshot:
    """What one router can currently be asked to do about a live session,
    read from it rather than assumed.

    ``hotspot_servers == 0`` is load-bearing, not decoration: a router
    running no hotspot has no ``/ip hotspot active`` table, so "we removed
    zero rows" would be indistinguishable from "the guest was not online",
    and both would be reported as a successful block.
    """

    hotspot_servers: int
    coa_accept: bool
    coa_port: int | None

    @property
    def runs_hotspot(self) -> bool:
        return self.hotspot_servers > 0


@dataclass(frozen=True, slots=True)
class SessionEndOutcome:
    """The honest outcome of one router being asked to end one guest's
    live session.

    ``still_active`` comes from a *second* read of ``/ip hotspot active``
    taken after the removals. Without it this type could only report "the
    removes raised nothing", which is the exact claim this platform has
    already been burned by twice (a heartbeat with ``run-count=475`` over
    a NAT chain at 0 bytes; a content-filter DROP rule whose own dedup
    read-back passes forever at the bottom of a chain it never reaches).

    It is still not a claim about the data plane. Whether an
    already-established TCP flow keeps forwarding after its row leaves the
    table is a question only real hardware and a real transfer answer --
    ``docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md`` §7, test T7.
    """

    control: SessionControlSnapshot
    matched: int
    removed: int
    still_active: int

    @property
    def ended_cleanly(self) -> bool:
        return self.still_active == 0


class BaseGuestAccessAdapter(Protocol):
    """What a vendor implements to plug real session termination into this
    domain."""

    vendor: str

    async def read_session_control(
        self, credentials: GuestAccessCredentials
    ) -> SessionControlSnapshot:
        """Reads whether this router runs a captive portal and whether it
        currently accepts an RFC 5176 Disconnect-Request.

        Read-only, and never a write: see this module's docstring for why
        repairing ``/radius incoming accept=no`` is deliberately not done
        from a customer-triggered path.
        """
        ...

    async def end_sessions(
        self,
        credentials: GuestAccessCredentials,
        *,
        mac_address: str | None,
        username: str | None,
    ) -> SessionEndOutcome:
        """Ends every live session on this router belonging to one guest,
        identified by MAC address and/or portal username.

        Idempotent: a guest with no live session matches nothing, removes
        nothing, and raises nothing -- so blocking an already-blocked
        guest, or retrying after a partial failure, completes cleanly.

        Never widens: both identifiers ``None`` ends *zero* sessions, not
        every session on the router.
        """
        ...


class MikroTikGuestAccessAdapter:
    """Real MikroTik implementation, delegating to the shared gateway."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: GuestAccessCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def read_session_control(
        self, credentials: GuestAccessCredentials
    ) -> SessionControlSnapshot:
        creds = self._gateway_credentials(credentials)
        try:
            control = await get_adapter(
                DeviceVendor.MIKROTIK
            ).read_hotspot_session_control(creds)
        # MikroTikConnectionError subclasses MikroTikDeviceError -- catch the
        # narrower one first, or every connection failure is mislabelled.
        except MikroTikConnectionError as exc:
            raise GuestAccessDeviceConnectionError(
                credentials.host, exc.detail
            ) from exc
        except MikroTikDeviceError as exc:
            raise GuestAccessDeviceOperationError(
                "read_session_control", exc.detail
            ) from exc
        return SessionControlSnapshot(
            hotspot_servers=control.hotspot_servers,
            coa_accept=control.coa_accept,
            coa_port=control.coa_port,
        )

    async def end_sessions(
        self,
        credentials: GuestAccessCredentials,
        *,
        mac_address: str | None,
        username: str | None,
    ) -> SessionEndOutcome:
        creds = self._gateway_credentials(credentials)
        try:
            result = await get_adapter(DeviceVendor.MIKROTIK).end_hotspot_sessions(
                creds, mac_address=mac_address, username=username
            )
        except MikroTikConnectionError as exc:
            raise GuestAccessDeviceConnectionError(
                credentials.host, exc.detail
            ) from exc
        except MikroTikDeviceError as exc:
            raise GuestAccessDeviceOperationError("end_sessions", exc.detail) from exc
        return SessionEndOutcome(
            control=SessionControlSnapshot(
                hotspot_servers=result.control.hotspot_servers,
                coa_accept=result.control.coa_accept,
                coa_port=result.control.coa_port,
            ),
            matched=len(result.matched),
            removed=len(result.removed_ids),
            still_active=len(result.still_active),
        )


_GUEST_ACCESS_ADAPTERS: dict[str, BaseGuestAccessAdapter] = {
    "mikrotik": MikroTikGuestAccessAdapter()
}


def get_guest_access_adapter(vendor: str) -> BaseGuestAccessAdapter:
    """Raises :class:`~.exceptions.UnsupportedGuestAccessVendorError` if no
    adapter is registered for ``vendor``.

    ``Router.vendor`` is a free ``String(50)``, so a row carrying
    ``"MikroTik"`` or ``"mikrotik_routeros"`` lands here rather than in the
    gateway's own enum lookup -- and gets this domain's typed 400 instead
    of an opaque error from inside the gateway. Matched case-insensitively
    for that same reason.
    """
    adapter = _GUEST_ACCESS_ADAPTERS.get(vendor.strip().lower())
    if adapter is None:
        raise UnsupportedGuestAccessVendorError(vendor)
    return adapter


def list_supported_guest_access_vendors() -> list[str]:
    return sorted(_GUEST_ACCESS_ADAPTERS)


__all__ = [
    "BaseGuestAccessAdapter",
    "GuestAccessCredentials",
    "MikroTikGuestAccessAdapter",
    "SessionControlSnapshot",
    "SessionEndOutcome",
    "get_guest_access_adapter",
    "list_supported_guest_access_vendors",
]
