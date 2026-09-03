"""Making a ``BLOCKLIST`` rule true -- the work
``GuestAccessService.create_guest_rule`` used to skip entirely.

## What was wrong

The customer dashboard's Blocked Guests form says, verbatim:

    Takes effect immediately, ending any session these users currently
    have.

``create_guest_rule`` inserted a row and wrote an audit entry. It never
looked up a session, never contacted a router, and never terminated
anything. A guest blocked mid-stream kept streaming, and the product
asserted the opposite.

Signing in *again* was never the gap --
``GuestService._enforce_access_control`` already consults these rules
before every OTP, voucher, password and MAC-whitelist login. The gap is
the session the guest is already in, which is also the only part the copy
promises.

## Both halves are required, and neither is sufficient

**The device.** A live captive-portal guest is a row in the router's
``/ip hotspot active`` table. While that row exists RouterOS forwards
their packets, regardless of what this database says. Removing it is what
actually cuts them off.

**The record.** ``RadiusService.authorize`` re-authorizes a guest by
looking for an ``ACTIVE`` ``GuestSession`` on the router; it checks
session status and a separate ``Guest.is_blocked`` flag that the Blocked
Guests form never sets, but it does not consult access rules. So a session
row left ``ACTIVE`` is a standing re-admission ticket: kick the guest on
the device and the very next re-auth lets them back in.

A record that says "ended" while the device still forwards is the same
class of lie as the bug being fixed, so the two are done together, device
first (see :meth:`BlocklistEnforcer.enforce`).

## Why not a RADIUS Disconnect-Request

See ``device_adapters``'s module docstring for the full comparison. In
short: the RFC 5176 path needs ``/radius incoming accept=yes`` (the lab
router reads ``accept=false``), a correct NAS address and secret, and an
inbound UDP route from the API container into the hub's tunnel subnet that
does not exist -- and it fails *silently*, which is the one property this
enforcement cannot tolerate. CoA availability is read from each router and
reported; it is never the thing the block depends on, and it is never
inferred from what this platform believes it configured.

## Composition, not a new dependency edge

``app.domains.guest_access`` has no import-time dependency on
``app.domains.guest`` -- the dependency runs guest -> guest_access (see
``service.py``'s own module docstring), and reversing it would close a
cycle that FastAPI's dependency resolution cannot unwind. So everything
this module needs from the guest domain arrives through narrow
``Protocol``\\ s satisfied structurally by
``app.domains.guest.repository.GuestRepository``, and the one guest-domain
*value* it needs -- the session status a blocked guest's session moves to
-- is injected as a string by ``dependencies.py``, which is the wiring
layer and the right place for that knowledge to live.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .device_adapters import (
    BaseGuestAccessAdapter,
    GuestAccessCredentials,
    SessionEndOutcome,
    get_guest_access_adapter,
)
from .exceptions import (
    BlockEnforcementMissingCredentialsError,
    RouterHasNoHotspotError,
    SessionStillActiveOnDeviceError,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Narrow cross-domain protocols
# ============================================================================


class BlockedGuestRow(Protocol):
    """The one field this module reads off a guest row."""

    id: uuid.UUID


class BlockedDeviceRow(Protocol):
    """The one field this module reads off a guest device row."""

    mac_address: str


class LiveSessionRow(Protocol):
    """The three fields this module reads off a live session row.

    Deliberately not ``app.domains.guest.models.GuestSession``: naming the
    concrete model here would couple two domains through their ORM
    classes, where the only facts needed are which router the session is
    on and which device is holding it.
    """

    id: uuid.UUID
    router_id: uuid.UUID
    device_id: uuid.UUID | None


class LiveSessionLookupProtocol(Protocol):
    """Satisfied structurally by ``app.domains.guest.repository
    .GuestRepository``.

    The *repository*, not ``GuestService``, and that is deliberate for the
    same reason ``VlanService`` composes ``DhcpRepository`` rather than
    ``DhcpService``: ``GuestService`` already composes this domain's
    ``check_access`` as its access-control hook, and two services
    depending on each other is a FastAPI dependency cycle that never
    resolves. Repositories depend on nothing but a session.
    """

    async def get_guest_by_identifier(
        self, organization_id: uuid.UUID, identifier: str
    ) -> BlockedGuestRow | None: ...

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[LiveSessionRow]: ...

    async def get_device_by_id(
        self, device_id: uuid.UUID
    ) -> BlockedDeviceRow | None: ...

    async def update_session(
        self, session: LiveSessionRow, data: dict[str, object]
    ) -> LiveSessionRow: ...


class BlockRouterRow(Protocol):
    """The router fields this module needs to open a connection."""

    id: uuid.UUID
    vendor: str
    api_username: str | None
    management_ip_address: str | None
    public_ip_address: str | None


class RouterLookupProtocol(Protocol):
    """Satisfied structurally by ``app.domains.router.service
    .RouterService``.

    ``get_decrypted_api_secret`` is declared because this path really
    calls it: leaving it out would let a collaborator satisfy the
    annotation and still blow up at runtime, with no type checker able to
    see it coming -- the exact correction ``VlanService``'s own
    ``RouterLookupProtocol`` already carries.
    """

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> BlockRouterRow: ...

    def get_decrypted_api_secret(self, router: BlockRouterRow) -> str | None: ...


# ============================================================================
# Result
# ============================================================================


@dataclass(frozen=True, slots=True)
class BlockEnforcementReport:
    """What actually happened, in terms a caller can record and a UI can
    show without overstating any of it."""

    #: Live sessions this platform believed the guest held.
    sessions_found: int
    #: Sessions confirmed gone from the router's own active table *and*
    #: moved to a terminal status here. Never incremented on a guess.
    sessions_ended: int
    #: Distinct routers a connection was actually opened to.
    routers_contacted: int
    #: ``True``/``False`` only once a router was read; ``None`` when none
    #: was contacted, because "the guest had no live session" is not
    #: evidence about any router's ``/radius incoming``.
    coa_available: bool | None


_NOTHING_TO_DO = BlockEnforcementReport(
    sessions_found=0, sessions_ended=0, routers_contacted=0, coa_available=None
)


# ============================================================================
# Enforcer
# ============================================================================


class BlocklistEnforcer:
    """Ends every live session held by a newly-blocked guest.

    Idempotent end to end. Enforcing a block twice, or enforcing one for a
    guest who has since gone offline, matches nothing on the device,
    removes nothing, writes nothing, and raises nothing.
    """

    def __init__(
        self,
        *,
        session_lookup: LiveSessionLookupProtocol,
        router_lookup: RouterLookupProtocol,
        terminated_session_status: str,
        adapter_factory: object = None,
    ) -> None:
        self.session_lookup = session_lookup
        self.router_lookup = router_lookup
        # Injected rather than imported: see this module's docstring for
        # why the guest domain's own enum may not be imported here.
        self.terminated_session_status = terminated_session_status
        self._adapter_factory = adapter_factory or get_guest_access_adapter

    async def enforce(
        self,
        *,
        organization_id: uuid.UUID,
        identifier: str,
        reason: str | None,
        actor_user_id: uuid.UUID | None,
    ) -> BlockEnforcementReport:
        """Cuts ``identifier`` off, on the device and in this platform's
        records, and reports honestly on both.

        ``identifier`` must already be normalized -- the caller
        (``GuestAccessService.create_guest_rule``) runs
        ``normalize_identifier`` before the rule row is written, and this
        method's guest lookup is an exact-string match against the same
        normalized value every guest-creation path stores.

        **Device work happens before any session row is written**, and
        that ordering is the whole point. Reversed, a router that could
        not be reached would leave a row reading "terminated" over a guest
        the device is still forwarding -- the precise falsehood this
        enforcement exists to remove. In this order, a device failure
        raises before anything here claims the session is over, and the
        rows that were already cut on a previous router simply stay
        ``ACTIVE`` until a retry: a record that under-claims, which is the
        safe direction to be wrong in.

        Raises :class:`~.exceptions.RouterHasNoHotspotError`,
        :class:`~.exceptions.SessionStillActiveOnDeviceError`,
        :class:`~.exceptions.GuestAccessDeviceConnectionError`,
        :class:`~.exceptions.GuestAccessDeviceOperationError`,
        :class:`~.exceptions.BlockEnforcementMissingCredentialsError` or
        :class:`~.exceptions.UnsupportedGuestAccessVendorError`. All are
        real non-2xx responses, never a ``200 {"success": false}`` --
        which the frontend's interceptor would read as success.
        """
        guest = await self.session_lookup.get_guest_by_identifier(
            organization_id, identifier
        )
        if guest is None:
            # A rule may legitimately be created for someone who has never
            # connected -- that is why these tables are identifier-keyed
            # rather than foreign-keyed to ``guests`` (see models.py). No
            # guest, no session, nothing to end.
            return _NOTHING_TO_DO

        sessions = await self.session_lookup.list_active_sessions_for_guest(guest.id)
        if not sessions:
            return _NOTHING_TO_DO

        outcomes: list[tuple[LiveSessionRow, SessionEndOutcome]] = []
        contacted_routers: set[uuid.UUID] = set()
        coa_available: bool | None = None

        for session in sessions:
            outcome = await self._end_on_device(
                session=session,
                organization_id=organization_id,
                identifier=identifier,
            )
            contacted_routers.add(session.router_id)
            # ``False`` from any router wins: reporting "CoA is available"
            # for a block that spanned a router where it is not would be
            # the same over-claim as the bug.
            coa_available = (
                outcome.control.coa_accept
                if coa_available is None
                else (coa_available and outcome.control.coa_accept)
            )
            outcomes.append((session, outcome))

        now = datetime.now(UTC)
        for session, _ in outcomes:
            await self.session_lookup.update_session(
                session,
                {
                    "status": self.terminated_session_status,
                    "ended_at": now,
                    "disconnect_reason": self._disconnect_reason(reason),
                    "updated_by": actor_user_id,
                },
            )

        logger.info(
            "guest_access_block_enforced",
            extra={
                "event_identifier": identifier,
                "event_organization_id": str(organization_id),
                "event_sessions_ended": len(outcomes),
                "event_routers_contacted": len(contacted_routers),
                "event_coa_available": coa_available,
            },
        )
        return BlockEnforcementReport(
            sessions_found=len(sessions),
            sessions_ended=len(outcomes),
            routers_contacted=len(contacted_routers),
            coa_available=coa_available,
        )

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _disconnect_reason(reason: str | None) -> str:
        return f"Blocked: {reason}" if reason else "Blocked by a guest access rule"

    async def _end_on_device(
        self,
        *,
        session: LiveSessionRow,
        organization_id: uuid.UUID,
        identifier: str,
    ) -> SessionEndOutcome:
        router = await self.router_lookup.get_router(
            session.router_id, requesting_organization_id=organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter: BaseGuestAccessAdapter = self._adapter_factory(router.vendor)

        mac_address = await self._session_mac_address(session)
        outcome = await adapter.end_sessions(
            credentials, mac_address=mac_address, username=identifier
        )

        if not outcome.control.runs_hotspot:
            # Checked after the call, not before, so it costs no extra
            # connection: the adapter reads ``/ip hotspot`` on the same
            # socket it uses for the removal.
            raise RouterHasNoHotspotError(router.id, credentials.host)
        if not outcome.ended_cleanly:
            raise SessionStillActiveOnDeviceError(
                identifier=identifier,
                host=credentials.host,
                still_active=outcome.still_active,
                coa_accept=outcome.control.coa_accept,
                coa_port=outcome.control.coa_port,
            )
        return outcome

    async def _session_mac_address(self, session: LiveSessionRow) -> str | None:
        """The MAC the guest is on, when this platform knows it.

        Best-effort by design, and its absence is not a failure: the
        adapter also matches on the portal ``user``, which is this
        identifier, so a session with no recorded device is still found.
        Passing a MAC as well matters for the case the RADIUS incident of
        2026-08-18 turned up -- a live session whose ``user`` on the device
        does not match what this platform stored.
        """
        if session.device_id is None:
            return None
        device = await self.session_lookup.get_device_by_id(session.device_id)
        return device.mac_address if device is not None else None

    def _resolve_device_credentials(
        self, router: BlockRouterRow
    ) -> GuestAccessCredentials:
        """Raise rather than guess -- mirrors ``VlanService``/``qos``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise BlockEnforcementMissingCredentialsError(router.id)
        return GuestAccessCredentials(
            host=host, username=router.api_username, password=secret
        )


__all__ = [
    "BlockEnforcementReport",
    "BlockRouterRow",
    "BlockedDeviceRow",
    "BlockedGuestRow",
    "BlocklistEnforcer",
    "LiveSessionLookupProtocol",
    "LiveSessionRow",
    "RouterLookupProtocol",
]
