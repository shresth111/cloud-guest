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
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.domains.router.vendor_capabilities import is_controller_managed

from .constants import BlockEnforcementStatus
from .device_adapters import (
    BaseGuestAccessAdapter,
    GuestAccessCredentials,
    SessionControlSnapshot,
    SessionEndOutcome,
    get_guest_access_adapter,
)
from .exceptions import (
    BlockEnforcementMissingCredentialsError,
    ControllerSessionTerminationUnavailableError,
    RouterHasNoHotspotError,
    SessionStillActiveOnDeviceError,
)
from .validators import identifier_match_terms

logger = logging.getLogger(__name__)


# ============================================================================
# Narrow cross-domain protocols
# ============================================================================


class BlockedGuestRow(Protocol):
    """The two fields this module reads off a guest row.

    ``identifier`` is read rather than reusing the rule's own, because
    the two are not always the same string: a rule written before the
    2026-09 identifier fix spells the number without its country code (or
    without the "+"), while the router's hotspot ``user`` is whatever the
    guest signed in with -- which is exactly what ``Guest.identifier``
    holds. Sending the rule's spelling to the device removes nothing.
    """

    id: uuid.UUID
    identifier: str


class BlockedDeviceRow(Protocol):
    """The one field this module reads off a guest device row."""

    mac_address: str


class LiveSessionRow(Protocol):
    """The four fields this module reads off a live session row.

    Deliberately not ``app.domains.guest.models.GuestSession``: naming the
    concrete model here would couple two domains through their ORM
    classes, where the only facts needed are which router the session is
    on and which device is holding it.
    """

    id: uuid.UUID
    router_id: uuid.UUID
    location_id: uuid.UUID
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

    async def list_devices_for_guest_ids(
        self,
        *,
        guest_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[BlockedDeviceRow]:
        """Every device this platform has ever recorded for these guests.

        The identifier -> MAC bridge, and the reason it is this lookup
        rather than a new one: a ``BLOCKLIST`` rule names a person, a
        controller blocks a MAC, and the only thing that knows which MACs
        belong to a person is the guest domain's own device table. The
        session-end path already reaches the same table one row at a time
        (``get_device_by_id`` above, for the device holding a live
        session); this is the same fact asked for a whole guest, which is
        what a block needs -- their *other* phone is exactly the device a
        block that only looked at the live session would miss.

        Ordered newest-seen first by the repository, so a venue that ever
        needs to bound the fan-out bounds it at the devices the guest
        actually uses.
        """
        ...

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
    #: Read only on the controller-managed path, where the session is ended
    #: by location rather than by a connection to this row -- a synthetic
    #: controller row has no host or credentials to connect to at all.
    location_id: uuid.UUID | None


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


class ControllerSessionTerminatorProtocol(Protocol):
    """Ending a session on a venue whose network is run from a vendor
    controller rather than from a device this platform logs in to.

    Injected as a value rather than imported, for the reason this module's
    docstring gives about ``app.domains.guest``: ``guest_access`` may not
    depend on ``app.domains.network_integration`` at import time -- that
    domain's own wiring imports ``guest.dependencies``, so the edge only runs
    one way. The wiring layer supplies a callable built by
    ``network_integration.client_hooks
    .build_controller_session_terminator``, and this module never learns
    which vendor is behind it.

    Deliberately a plain callable rather than a service handle. The service
    that owns this capability already holds the ``LiveSessionTerminator``
    itself, so handing the terminator the service would close an object cycle
    as well as an import one; a bound function closes neither.

    ``None`` is a legitimate value: a deployment without the network
    integration domain wired, or a test. That is reported as a refusal
    naming the vendor, never as a silent success.
    """

    async def __call__(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class ControllerBlockOutcome:
    """What a venue's controller did about **one** device MAC.

    Per device, because the result genuinely is: a rule names a person who
    may hold five devices, and "three of them are blocked" is not a
    sentence a single status can say.

    ``status`` reuses :class:`~.constants.BlockEnforcementStatus` rather
    than inventing a second vocabulary, and each of its values means here
    what its own docstring says it means:

    * ``ENFORCED`` -- the controller confirmed the block.
    * ``NOT_APPLICABLE`` -- nothing needed doing: the controller has no
      record of this device at this venue, so there is nothing there to
      block. ``error_code`` carries the vendor's own not-found code.
    * ``FAILED`` -- the controller knows the device and refused, or could
      not be reached. ``error_code``/``error_message`` say which.
    * ``UNENFORCED`` -- nobody was there to do it: this venue's
      integration cannot block at all (a hotspot-operator connection), and
      ``error_message`` carries the provider's own reason for that.

    **``NOT_APPLICABLE`` and ``FAILED`` must never be collapsed.** A
    boolean ``performed: false`` conflates "the venue's controller has
    never seen this phone" with "the venue's controller refused to block
    this phone", and only the second is something an operator can act on.
    """

    location_id: uuid.UUID
    mac_address: str
    status: str
    error_code: str | None = None
    error_message: str | None = None

    @property
    def blocked(self) -> bool:
        """Whether a block is now believed to be held on the controller.

        The one predicate that may decide to persist a releasable row --
        and deliberately narrow: only a confirmed block is releasable,
        because a release aimed at a MAC the controller never held is a
        write with no subject.
        """
        return self.status == BlockEnforcementStatus.ENFORCED.value


@dataclass(frozen=True, slots=True)
class ControllerReleaseOutcome:
    """What a venue's controller did about clearing one block.

    ``released`` is the controller's own answer, never an assumption. A
    release that did not land leaves the stored row **uncleared**, which is
    the whole point of storing it: the device stays findable and the next
    sweep tries again. Reporting a release this platform did not get is how
    a customer's device is stranded with no record that it ever was.
    """

    released: bool
    error_message: str | None = None


class ControllerDeviceBlockerProtocol(Protocol):
    """Blocking and unblocking one device MAC on the venue's own
    controller.

    Injected as a value rather than imported, for exactly the reason
    :class:`ControllerSessionTerminatorProtocol` above gives:
    ``guest_access`` may not depend on ``app.domains.network_integration``
    at import time. The wiring layer supplies an object built by
    ``network_integration.client_hooks.build_controller_device_blocker``,
    and this module never learns which vendor is behind it, which venues
    have one, or what a "site" is.

    ``None`` is a legitimate value -- a deployment without the network
    integration domain wired, or a test. It means no device is ever asked
    about, which is reported as no outcomes at all rather than as a set of
    blocks nobody placed.

    ## What this is, and the four things it is not

    It is a **deterrent**, and the honest description is narrow.

    It is not this platform's blocklist. ``guest_access``'s ``BLOCKLIST``
    rules are vendor-neutral, are consulted at every login and by the
    RADIUS authorize path, and remain the thing that actually refuses the
    person. This stops one *device* associating; the rule stops the
    *person* signing in.

    It is not durable against a phone that randomizes its MAC per SSID. The
    flag is keyed on the MAC, and forgetting the network produces a new
    one.

    It does not roam between venues. A controller block is per-site.

    And what it does to a guest who holds a live portal authorization right
    now is **unmeasured** (CAPABILITY-MATRIX §4.6): the authorization record
    and the block flag are separate objects with separate lifecycles, so
    nothing here claims the block is what cut them off. Ending the live
    session is a different call, made separately, by
    :class:`LiveSessionTerminator` above.
    """

    async def controller_present(
        self, *, location_id: uuid.UUID, organization_id: uuid.UUID | None
    ) -> bool:
        """Whether this venue's network is run from a controller at all.

        Asked first, and asked before anything else is looked up, so a
        RouterOS venue costs exactly one indexed query and produces no
        outcome, no row and no write. That is not an optimization -- it is
        what makes this change unable to alter MikroTik behaviour.
        """
        ...

    async def block_device(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
    ) -> ControllerBlockOutcome: ...

    async def release_device(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
    ) -> ControllerReleaseOutcome: ...


class ControllerBlockRecord(Protocol):
    """The three fields a release needs off a stored block row.

    Satisfied structurally by
    ``app.domains.guest_access.models.GuestAccessControllerBlock``. Named
    as a Protocol for symmetry with the rest of this module, not because a
    second implementation is expected -- it keeps the release path
    testable without a database.
    """

    organization_id: uuid.UUID
    location_id: uuid.UUID
    mac_address: str


class DeviceLookupProtocol(Protocol):
    """The one lookup ending a session needs beyond router credentials:
    which MAC the guest is holding, when this platform knows it.

    Narrower than ``LiveSessionLookupProtocol`` deliberately -- the guest
    side of this module composes the terminator below with nothing but a
    repository that can answer this one question.
    """

    async def get_device_by_id(
        self, device_id: uuid.UUID
    ) -> BlockedDeviceRow | None: ...


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
    #: One entry per (controller-managed venue, known device MAC) this
    #: platform asked the venue's controller to block, carrying what the
    #: controller said about each. Empty at a RouterOS venue, where nothing
    #: is asked -- see :class:`ControllerDeviceBlockerProtocol`.
    #:
    #: Deliberately not summarised to a count here. "Three of five" needs
    #: the five, and a caller that wants the count can take the length of
    #: the ones it cares about.
    device_blocks: tuple[ControllerBlockOutcome, ...] = ()


_NOTHING_TO_DO = BlockEnforcementReport(
    sessions_found=0, sessions_ended=0, routers_contacted=0, coa_available=None
)


# ============================================================================
# The device half, shared by both callers
# ============================================================================


class LiveSessionTerminator:
    """Ends one live guest session on its own router, over the RouterOS API.

    There are two reasons a session has to stop being real on the device,
    and they are the same work: an admin blocks the guest
    (``BlocklistEnforcer`` below), or a session ends or is killed for any
    other reason (``app.domains.guest.service.issue_live_disconnect``,
    whose callers are the operator's "Terminate session", the guest's own
    logout, and the timeout/FUP/data-cap sweeps). Both mean "remove this
    guest from ``/ip hotspot active``, then read the table back and say
    whether they are actually gone", so both go through here.

    Small on purpose: it owns no policy about *why* a session is ending,
    writes no session row, and decides nothing about status transitions.
    It opens a connection, removes rows, reads back, and reports.

    Raises rather than returning a quiet failure, because
    ``BlocklistEnforcer`` must be able to refuse a block that did not
    happen. The session-end caller is the one that swallows -- it runs
    after a status transition that has already committed and must never be
    the thing that fails an operator's disconnect; see that function's own
    docstring.
    """

    def __init__(
        self,
        *,
        router_lookup: RouterLookupProtocol,
        device_lookup: DeviceLookupProtocol,
        adapter_factory: object = None,
        controller_terminator: ControllerSessionTerminatorProtocol | None = None,
    ) -> None:
        self.router_lookup = router_lookup
        self.device_lookup = device_lookup
        self._adapter_factory = adapter_factory or get_guest_access_adapter
        self.controller_terminator = controller_terminator

    async def end_on_router(
        self,
        *,
        session: LiveSessionRow,
        identifier: str,
        organization_id: uuid.UUID | None = None,
    ) -> SessionEndOutcome:
        """Ends every live session on this router belonging to ``identifier``.

        ``identifier`` is the portal ``user`` the router knows the guest
        by -- ``Guest.identifier``, not whatever a rule or a caller happens
        to spell it as. It addresses the RouterOS branch only: a
        controller-managed venue is addressed by the session's MAC instead,
        for the reason ``_end_on_controller`` gives at length.

        Raises :class:`~.exceptions.RouterHasNoHotspotError`,
        :class:`~.exceptions.SessionStillActiveOnDeviceError`,
        :class:`~.exceptions.BlockEnforcementMissingCredentialsError`,
        :class:`~.exceptions.GuestAccessDeviceConnectionError`,
        :class:`~.exceptions.GuestAccessDeviceOperationError` or
        :class:`~.exceptions.UnsupportedGuestAccessVendorError`. The
        hotspot check happens *after* the call, not before, so it costs no
        extra connection: the adapter reads ``/ip hotspot`` on the same
        socket it uses for the removal.
        """
        router = await self.router_lookup.get_router(
            session.router_id, requesting_organization_id=organization_id
        )

        # The vendor question is asked FIRST, and the ordering is the fix.
        #
        # This used to resolve device credentials before resolving the
        # adapter. A controller-managed row -- the synthetic ``Router`` an
        # Omada integration creates for its fleet -- has no host, no API
        # username and no secret by construction, so it failed on the
        # credential line and a venue admin blocking a guest got
        # ``BlockEnforcementMissingCredentialsError``: *"missing device
        # connection credentials"*, a 400 that reads as "add some and retry".
        # There is nothing to add. The truth is that this vendor is reached
        # another way, and nobody could learn that from the error.
        #
        # Exactly the failure ``router.device_domain_gate``'s module docstring
        # describes -- "every one of the seven services resolves device
        # credentials exactly one line before it resolves the adapter" -- and
        # this is the eighth. Asking the vendor first costs nothing on the
        # MikroTik path, which reaches the same two lines in the same order
        # one branch later, with the same adapter and the same credentials.
        if is_controller_managed(router):
            return await self._end_on_controller(
                router, session=session, organization_id=organization_id
            )

        credentials = self._resolve_device_credentials(router)
        adapter: BaseGuestAccessAdapter = self._adapter_factory(router.vendor)

        mac_address = await self._session_mac_address(session)
        outcome = await adapter.end_sessions(
            credentials, mac_address=mac_address, username=identifier
        )

        if not outcome.control.runs_hotspot:
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

    async def _end_on_controller(
        self,
        router: BlockRouterRow,
        *,
        session: LiveSessionRow,
        organization_id: uuid.UUID | None,
    ) -> SessionEndOutcome:
        """End the session through the venue's controller instead of through
        a connection to this row.

        Reached only for a controller-managed router, where there is no host
        to open a socket to. The controller is asked to drop the client, and
        the outcome is reported in the same shape the RouterOS path reports,
        so every caller above is unchanged.

        **A controller is addressed by MAC, and only by MAC.** This takes the
        whole ``session`` rather than the ``identifier`` the RouterOS branch
        uses, because the two branches genuinely need different things and
        that difference is the bug this signature exists to make impossible.
        RouterOS matches a hotspot row on the portal ``user`` *or* the MAC, so
        passing ``Guest.identifier`` there is correct and a missing MAC costs
        nothing. A controller has no equivalent: ``client_hooks.terminate``
        normalizes what it is given and refuses anything that is not
        MAC-shaped. ``Guest.identifier`` is a phone number for every OTP guest
        -- which is nearly all of them -- so it was refused every time, and
        the sweep that expired the row reported enforcement it had not
        performed. Measured shape of the failure: the platform's records said
        the guest was gone and the guest was still online.

        **The snapshot's two numbers are claims, so here is what each one
        claims.** ``hotspot_servers=1`` says this venue runs captive-portal
        guest access -- which it does, through the controller's own portal;
        the caller reads it only to tell "this device runs no hotspot at all"
        apart from "the guest was not online", and the first is false here.
        ``coa_accept=False`` says this platform will not end the session by
        RFC 5176 Disconnect-Request, which is true and is not a statement
        about the controller: the controller does listen on 3799, but the
        packet has to reach *into* the venue's NAT and no such route exists,
        so nothing here sends one.

        **What this achieves, exactly.** The controller ends the client's
        authorization: the device stops being forwarded now. It does not
        prevent the person signing in again -- the platform's own blocklist
        is what does that, it is vendor-neutral, and it is consulted at every
        login and by the RADIUS authorize path. So a block enforced here is
        as real as a block enforced on RouterOS, by the same two halves.
        """
        if self.controller_terminator is None:
            raise ControllerSessionTerminationUnavailableError(router.id)
        location_id = getattr(router, "location_id", None)
        if location_id is None:
            raise ControllerSessionTerminationUnavailableError(router.id)
        # Raise rather than send something the controller cannot act on.
        # A session with no recorded device is a real case (a login that
        # carried no ``device_mac``; see ``GuestService
        # .adopt_nas_asserted_device``), and for this branch it means there
        # is nothing to address -- exactly what the falsy-``ended`` branch
        # below already treats as "not delivered". Raising here says so one
        # call earlier, without a pointless round trip to the controller,
        # and keeps both callers' contracts intact: ``BlocklistEnforcer``
        # refuses a block it did not enforce, and ``issue_live_disconnect``
        # records ``disconnect_enforced=False`` and warns.
        client_mac = await self._session_mac_address(session)
        if not client_mac:
            raise ControllerSessionTerminationUnavailableError(router.id)
        ended = await self.controller_terminator(
            location_id=location_id,
            organization_id=organization_id,
            client_mac=client_mac,
        )
        if not ended:
            # The controller was never reached, or it knows no client at
            # this MAC (the guest had already gone). Either way the
            # guest may still be online, and the caller must be able to say
            # so: `BlocklistEnforcer` refuses a block it did not enforce, and
            # `issue_live_disconnect` records `enforcement_delivered: False`.
            # Reporting success here is the exact falsehood this whole module
            # was written to remove.
            raise ControllerSessionTerminationUnavailableError(router.id)
        return SessionEndOutcome(
            control=SessionControlSnapshot(
                hotspot_servers=1, coa_accept=False, coa_port=None
            ),
            matched=1,
            removed=1,
            # The controller's disconnect either succeeded or raised -- there
            # is no partial outcome to report, and `disconnect_client_at_
            # location` raises on a controller failure rather than returning
            # a quiet False. So reaching this line means the session ended.
            still_active=0,
        )

    async def release_rate_limit(
        self,
        *,
        session: LiveSessionRow,
        organization_id: uuid.UUID | None = None,
    ) -> None:
        """Take this platform's per-device speed limit back off the MAC this
        session used. Ends nothing.

        Called by ``guest.service.issue_live_disconnect`` on **every** way a
        session ends, including the one where the device ended it itself and
        no disconnect is issued. That is the whole point: a controller's
        per-client limit is a field on the known-client record with no
        session lifetime, so if the release rides on this platform issuing a
        disconnect, then at a RADIUS-mode venue -- where an Accounting-Stop
        is the normal ending -- it is never issued and the limit stays on
        the record for whatever device next holds that MAC.

        **A RouterOS venue is untouched.** The vendor question is asked
        first and this returns immediately for a non-controller router: no
        connection, no credential resolution, no ``/queue simple`` write.
        Queue-row cleanup on RouterOS is a real and separate problem; this
        method is not a quiet start on it.

        Never raises, for the same reason the session-end call path never
        does: it runs after a status transition that has already committed,
        and a venue's equipment must not be able to fail an operator's
        disconnect. A limit that could not be released is recorded in the
        integration's own event feed by the layer that tried.
        """
        release = getattr(self.controller_terminator, "release_rate_limit", None)
        if release is None:
            # No controller half wired (a deployment without the network
            # integration domain, or a test). Nothing to release, and
            # nothing to report -- this is not a failure to enforce.
            return
        try:
            router = await self.router_lookup.get_router(
                session.router_id, requesting_organization_id=organization_id
            )
            if not is_controller_managed(router):
                return
            location_id = getattr(router, "location_id", None)
            client_mac = await self._session_mac_address(session)
            if location_id is None or not client_mac:
                # Nothing to address the controller with. The limit, if any,
                # was set against a MAC this row no longer carries.
                return
            await release(
                location_id=location_id,
                organization_id=organization_id,
                client_mac=client_mac,
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "guest_rate_limit_release_failed",
                extra={"error": str(exc)},
            )

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
        device = await self.device_lookup.get_device_by_id(session.device_id)
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
        controller_terminator: ControllerSessionTerminatorProtocol | None = None,
        device_blocker: ControllerDeviceBlockerProtocol | None = None,
    ) -> None:
        self.session_lookup = session_lookup
        self.router_lookup = router_lookup
        # Injected rather than imported: see this module's docstring for
        # why the guest domain's own enum may not be imported here.
        self.terminated_session_status = terminated_session_status
        self._adapter_factory = adapter_factory or get_guest_access_adapter
        # ``session_lookup`` is a ``GuestRepository``, which satisfies
        # ``DeviceLookupProtocol`` as well -- see that Protocol's own note.
        #
        # ``controller_terminator`` is accepted here only to hand down: this
        # class does no device work itself, it delegates every session end to
        # the terminator below. Without the pass-through, blocking a guest at
        # a controller-managed venue would reach `end_on_router` with no way
        # to end anything, which is the state that shipped and 500'd.
        self.terminator = LiveSessionTerminator(
            router_lookup=router_lookup,
            device_lookup=session_lookup,
            adapter_factory=adapter_factory,
            controller_terminator=controller_terminator,
        )
        # The other half of "make the block true on the device", and a
        # different half from the terminator above. The terminator ends the
        # session the guest is in *now*; this keeps the device from coming
        # back on. Only a controller-managed venue has it: on RouterOS the
        # block is carried entirely by the platform rule and the hotspot
        # removal, and nothing here writes an address list, an ip-binding
        # or a filter rule -- see ``TestRetryAndUnblock
        # .test_unblocking_needs_no_device_work_because_nothing_was_left_there``
        # for why that absence is load-bearing rather than incidental.
        #
        # ``None`` by default, and the default is safe rather than silent:
        # a caller that wires none gets no ``device_blocks`` at all, which
        # reads as "nothing was asked", not as "nothing was blocked".
        self.device_blocker = device_blocker

    async def enforce(
        self,
        *,
        organization_id: uuid.UUID,
        identifier: str,
        reason: str | None,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
    ) -> BlockEnforcementReport:
        """Cuts ``identifier`` off, on the device and in this platform's
        records, and reports honestly on both.

        ``identifier`` must already be canonical -- the caller
        (``GuestAccessService.create_guest_rule``) runs
        ``canonicalize_rule_identifier`` before the rule row is written.
        The guest lookup itself is *not* an exact-string match: see
        ``_resolve_guest``.

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
        guest = await self._resolve_guest(organization_id, identifier)
        if guest is None:
            # A rule may legitimately be created for someone who has never
            # connected -- that is why these tables are identifier-keyed
            # rather than foreign-keyed to ``guests`` (see models.py). No
            # guest, no session, nothing to end.
            return _NOTHING_TO_DO

        sessions = await self.session_lookup.list_active_sessions_for_guest(guest.id)
        if location_id is not None:
            # A rule written for one venue governs that venue only --
            # ``repository.list_matching_guest_rules`` applies it at
            # ``location_id`` or nowhere. Ending the same guest's session at
            # a sibling venue the rule does not cover would be enforcing a
            # block the login gate itself would not honour there.
            sessions = [s for s in sessions if s.location_id == location_id]
        if not sessions:
            # No live session is no longer the end of the story. A guest
            # who is offline at this moment still has known devices, and a
            # controller block lives on the **known-client record**, not on
            # a live association -- measured on real hardware: a client
            # that was offline for eight hours was accepted and stored as
            # blocked (CAPABILITY-MATRIX §4.3). Blocking only the guests
            # who happen to be online would make the feature depend on the
            # timing of the operator's click.
            device_blocks = await self._block_known_devices(
                organization_id=organization_id,
                guest=guest,
                rule_location_id=location_id,
                session_locations=frozenset(),
            )
            if not device_blocks:
                return _NOTHING_TO_DO
            return BlockEnforcementReport(
                sessions_found=0,
                sessions_ended=0,
                routers_contacted=0,
                coa_available=None,
                device_blocks=device_blocks,
            )

        outcomes: list[tuple[LiveSessionRow, SessionEndOutcome]] = []
        contacted_routers: set[uuid.UUID] = set()
        coa_available: bool | None = None

        for session in sessions:
            outcome = await self.terminator.end_on_router(
                session=session,
                organization_id=organization_id,
                # The guest's own stored identifier, not the rule's --
                # see ``BlockedGuestRow``. This is the string the router
                # knows them by.
                identifier=guest.identifier,
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

        # Last, and after the session rows are written, deliberately. The
        # session half is what the dashboard's own copy promises and what
        # this path must never fail to deliver; the controller block is an
        # additional deterrent layered on top of it. Ordered the other way
        # round, a controller that refused a block would have stood between
        # an operator and the disconnection they actually asked for.
        device_blocks = await self._block_known_devices(
            organization_id=organization_id,
            guest=guest,
            rule_location_id=location_id,
            session_locations=frozenset(s.location_id for s in sessions),
        )

        logger.info(
            "guest_access_block_enforced",
            extra={
                "event_identifier": identifier,
                "event_organization_id": str(organization_id),
                "event_sessions_ended": len(outcomes),
                "event_routers_contacted": len(contacted_routers),
                "event_coa_available": coa_available,
                "event_devices_blocked": sum(1 for d in device_blocks if d.blocked),
                "event_devices_attempted": len(device_blocks),
            },
        )
        return BlockEnforcementReport(
            sessions_found=len(sessions),
            sessions_ended=len(outcomes),
            routers_contacted=len(contacted_routers),
            coa_available=coa_available,
            device_blocks=device_blocks,
        )

    async def _block_known_devices(
        self,
        *,
        organization_id: uuid.UUID,
        guest: BlockedGuestRow,
        rule_location_id: uuid.UUID | None,
        session_locations: frozenset[uuid.UUID],
    ) -> tuple[ControllerBlockOutcome, ...]:
        """Ask each controller-managed venue in scope to block each device
        this platform associates with the blocked guest.

        ## One rule, several devices

        The rule names a person; the controller blocks a MAC. So the bridge
        is the guest's own ``GuestDevice`` rows -- every device, not just
        the one holding a live session, because their *other* phone is
        precisely what a block that only looked at the live session would
        miss. Each device is one write and one outcome, so a guest with
        five devices produces five answers and three of them being
        ``ENFORCED`` is a fact the caller can record and a console can show.

        A guest with **no** recorded device produces no writes and no
        outcomes. That is the common, legitimate case for a rule written
        about somebody who has never connected -- which is exactly what
        these tables are identifier-keyed to allow (see ``models.py``) --
        and the platform blocklist still refuses them at sign-in, which is
        the half that actually matters.

        ## Which venues

        Entirely from the rule's own ``(organization, location)``, and from
        nothing a caller supplied. A rule scoped to one venue is applied at
        that venue. An organization-wide rule has no venue of its own, so
        the venues are the ones the guest's live sessions were on -- the
        same sessions that were just ended, resolved under the same
        organization. An org-wide rule for a guest who is offline therefore
        blocks nothing on any controller, and says so by returning nothing:
        there is no venue this platform can name, and guessing one would be
        writing a block into somebody else's site.

        ## A RouterOS venue reaches nothing here

        ``controller_present`` is asked first and is one indexed query. A
        venue without a controller integration produces no device lookup,
        no write, no outcome and no stored row -- so a MikroTik block ends
        the session exactly as it did before this method existed, and its
        address lists, ip-bindings and filter rules stay untouched.
        """
        if self.device_blocker is None:
            return ()
        locations = (
            frozenset({rule_location_id})
            if rule_location_id is not None
            else session_locations
        )
        if not locations:
            return ()
        controller_locations = [
            location_id
            for location_id in sorted(locations, key=str)
            if await self.device_blocker.controller_present(
                location_id=location_id, organization_id=organization_id
            )
        ]
        if not controller_locations:
            return ()

        devices = await self.session_lookup.list_devices_for_guest_ids(
            guest_ids=[guest.id], organization_id=organization_id
        )
        # Ordered, de-duplicated, and stable: the repository returns newest
        # seen first, and one MAC can appear on more than one row only if
        # the device table is being repaired, in which case blocking it
        # twice is a wasted call rather than a second block.
        macs: list[str] = []
        for device in devices:
            mac = getattr(device, "mac_address", None)
            if mac and mac not in macs:
                macs.append(mac)
        if not macs:
            return ()

        outcomes: list[ControllerBlockOutcome] = []
        for location_id in controller_locations:
            for mac in macs:
                outcomes.append(
                    await self.device_blocker.block_device(
                        location_id=location_id,
                        organization_id=organization_id,
                        client_mac=mac,
                    )
                )
        return tuple(outcomes)

    async def release_devices(
        self,
        records: Sequence[ControllerBlockRecord],
    ) -> list[tuple[ControllerBlockRecord, ControllerReleaseOutcome]]:
        """Ask each venue's controller to let these devices go again.

        Takes the **stored rows** rather than re-deriving anything, and
        that is the whole design. The controller offers no readable list of
        blocked clients through the connection this platform holds
        (measured -- CAPABILITY-MATRIX §4.4), so what was blocked is
        knowable only from what was written down at the time. Re-deriving
        it from the guest's devices would miss a device the guest has since
        replaced, and that device would stay blocked on a customer's
        network with nothing left anywhere pointing at it.

        Never raises. A release runs on the back of an operator's unblock,
        deletion or an expiry sweep, and a controller that cannot be
        reached must leave the row **uncleared** so the next attempt finds
        it again -- not abort the unblock the operator actually asked for.
        The failure is returned, and the caller records it on the row.

        With no blocker wired, nothing is released and nothing is reported
        as released: every row comes back with its own refusal, which keeps
        it in the set the next sweep retries.
        """
        results: list[tuple[ControllerBlockRecord, ControllerReleaseOutcome]] = []
        for record in records:
            if self.device_blocker is None:
                results.append(
                    (
                        record,
                        ControllerReleaseOutcome(
                            released=False,
                            error_message=(
                                "No controller connection is wired in this "
                                "process, so the block could not be cleared."
                            ),
                        ),
                    )
                )
                continue
            results.append(
                (
                    record,
                    await self.device_blocker.release_device(
                        location_id=record.location_id,
                        organization_id=record.organization_id,
                        client_mac=record.mac_address,
                    ),
                )
            )
        return results

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _disconnect_reason(reason: str | None) -> str:
        return f"Blocked: {reason}" if reason else "Blocked by a guest access rule"

    async def _resolve_guest(
        self, organization_id: uuid.UUID, identifier: str
    ) -> BlockedGuestRow | None:
        """The guest a rule's ``identifier`` names, tried against every
        stored spelling of the same phone number rather than one exact
        string.

        A single exact lookup is the 2026-09 "Always Allowed matches
        nobody" defect wearing a different hat: rules and guests spell the
        same number differently, so re-enforcing an older block
        (``GuestAccessService.enforce_guest_rule`` -- the retry an
        operator reaches for when a router was unreachable) found no
        guest, ended nothing, and recorded ``ENFORCED`` over a guest who
        was still streaming.

        Candidates come from ``validators.identifier_match_terms`` and are
        tried in its order -- canonical first, legacy spellings after --
        so an exact match still wins and still costs one query. This
        recovers the "+"-dropped spellings the old, "+"-optional
        ``_PHONE_RE`` let into the table ("919876543210" for a guest
        stored as "+919876543210").

        **It does not recover a bare national number** ("9876543210" for
        that same guest). That needs the ``prefix_patterns`` half of the
        widening, which needs a ``LIKE``, and ``LiveSessionLookupProtocol``
        offers only an exact lookup -- deliberately: the guest domain owns
        that query and the dependency runs guest -> guest_access, not back
        (see this module's docstring). ``check_access`` does match those
        rows, so the rule still governs every *new* login; it is only the
        end-the-session-they-are-already-in half that cannot see them.
        Under-reaching is the safe direction here and the one this module
        already chose everywhere else -- it ends fewer sessions than it
        might, and never claims more than it ended.
        """
        for candidate in identifier_match_terms(identifier).exact:
            guest = await self.session_lookup.get_guest_by_identifier(
                organization_id, candidate
            )
            if guest is not None:
                return guest
        return None


# ``BlocklistEnforcer`` used to carry ``_end_on_device`` /
# ``_session_mac_address`` / ``_resolve_device_credentials`` itself. They
# moved to ``LiveSessionTerminator`` above, unchanged, when the ordinary
# session-end path needed the same device work -- the terminator is now
# the only place in this codebase that removes a guest from a router's
# ``/ip hotspot active`` table.


__all__ = [
    "BlockEnforcementReport",
    "BlockRouterRow",
    "BlockedDeviceRow",
    "BlockedGuestRow",
    "BlocklistEnforcer",
    "DeviceLookupProtocol",
    "LiveSessionLookupProtocol",
    "LiveSessionRow",
    "LiveSessionTerminator",
    "RouterLookupProtocol",
]
