"""Which MACs a router should let straight through its hotspot -- the one
definition, read by two consumers.

1. ``GET /agent/authorized-macs`` (``router.agent_authorized_macs``), which
   the router's own ``cloudguest-authmac-sched`` polls once a minute and
   turns into ``/ip hotspot ip-binding type=bypassed`` rows. That script is
   the reconciler: it adds a binding for every listed MAC and removes its
   own binding for every MAC no longer listed.
2. The sign-in push (``app.domains.guest.hotspot_gate``), which writes the
   same binding for one session straight after a login instead of leaving
   the guest without internet until the next poll.

They have to agree exactly, in both directions. If the push admitted a
session the list leaves out, the script would remove the binding a minute
later and the guest would drop off mid-use; if it applied a different
spelling of the MAC, the script would not recognise the row as the one it
wants. So neither consumer holds any rule of its own: the list is built by
calling :func:`session_authorized_mac` for each session, and the push asks
:func:`resolve_session_gate`, which finds its session in the very query the
list is built from and puts it through the same function.

Nothing here grants anything, and nothing here touches a device.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

from app.common.exceptions import CloudGuestError
from app.domains.captive_portal.exceptions import (
    CaptivePortalConfigNotConfiguredError,
)
from app.domains.captive_portal.service import CaptivePortalService
from app.domains.guest.repository import GuestRepositoryProtocol
from app.domains.guest.validators import session_awaits_required_name
from app.domains.guest_access.service import GuestAccessService, is_blocklisted
from app.domains.mac_authorization.service import MacAuthorizationService

from .validators import routeros_mac_address

#: ``(organization_id, location_id) -> require_guest_name``, resolved at
#: most once per key per list (or per single-session question).
RequireNameCache = dict[tuple[uuid.UUID, uuid.UUID | None], bool]


async def _awaits_required_name(
    session: object,
    guest: object,
    captive_portal_service: CaptivePortalService,
    require_cache: RequireNameCache,
) -> bool:
    """``validators.session_awaits_required_name`` with the venue's
    ``require_guest_name`` resolved once per (organization, location) per
    poll. Only resolved for a session that could be held at all (OTP, no
    name on file), so a fleet of named guests costs no config reads.

    Same resolution rule as ``GuestService.session_awaits_required_name``:
    no config at all reads as the owner's default (required); any other
    resolution failure fails OPEN, since this list is what keeps admitted
    guests online and an unrelated error must not strip them."""
    if not session_awaits_required_name(
        session=session,  # type: ignore[arg-type]
        guest=guest,  # type: ignore[arg-type]
        require_guest_name=True,
    ):
        return False
    key = (session.organization_id, session.location_id)  # type: ignore[attr-defined]
    if key not in require_cache:
        try:
            resolved = await captive_portal_service.resolve_portal_config(
                organization_id=key[0], location_id=key[1]
            )
            require_cache[key] = bool(
                getattr(resolved.config, "require_guest_name", True)
            )
        except CaptivePortalConfigNotConfiguredError:
            require_cache[key] = True
        except CloudGuestError:
            require_cache[key] = False
    return require_cache[key]


class SessionGateReason(StrEnum):
    """Why one ``ACTIVE`` session does, or does not, put a MAC on the list."""

    AUTHORIZED = "authorized"
    NO_DEVICE = "no_device"
    AWAITING_NAME = "awaiting_name"
    BLOCKLISTED = "blocklisted"
    #: Only ever returned by :func:`resolve_session_gate`: the session is
    #: not among this router's ``ACTIVE`` sessions at all -- ended, on
    #: another router, or not yet visible to this transaction.
    NOT_LISTED = "not_listed"
    #: Only ever returned by :func:`resolve_session_gate`: the session is
    #: admitted, and what its device recorded is not a MAC address. The
    #: list drops such an entry and counts it.
    MALFORMED_MAC = "malformed_mac"


@dataclass(frozen=True, slots=True)
class SessionGateDecision:
    """``mac_address`` is set only for ``AUTHORIZED``. From
    :func:`session_authorized_mac` it is the address as recorded (the list
    counts the ones that turn out not to be MACs); from
    :func:`resolve_session_gate` it is the router's own spelling."""

    reason: SessionGateReason
    mac_address: str | None = None

    @property
    def authorized(self) -> bool:
        return self.reason is SessionGateReason.AUTHORIZED


async def session_authorized_mac(
    session: object,
    *,
    guest_repository: GuestRepositoryProtocol,
    access_decision_service: GuestAccessService,
    captive_portal_service: CaptivePortalService,
    require_cache: RequireNameCache,
) -> SessionGateDecision:
    """Whether one ``ACTIVE`` session contributes its device's MAC.

    The caller owns "is this session ``ACTIVE`` on this router" -- both
    callers answer it with ``list_active_sessions_for_router``. Everything
    after that is here."""
    if session.device_id is None:  # type: ignore[attr-defined]
        return SessionGateDecision(SessionGateReason.NO_DEVICE)
    device = await guest_repository.get_device_by_id(session.device_id)  # type: ignore[attr-defined]
    if device is None:
        return SessionGateDecision(SessionGateReason.NO_DEVICE)
    # A guest blocked after they were admitted keeps an ``ACTIVE`` row
    # whenever the device-side removal failed (see
    # ``guest_access.enforcement``). Returning their MAC here kept a
    # ``type=bypassed`` binding on the router -- internet with no
    # login and no expiry. Leaving it out makes the agent's own
    # reconciliation withdraw that binding on its next poll.
    guest = await guest_repository.get_guest_by_id(session.guest_id)  # type: ignore[attr-defined]
    # Name required at sign-in. A session that verified its OTP but
    # whose guest has not yet given the name the venue requires exists
    # and is ACTIVE -- and without this, the next 60-second poll would
    # put a ``type=bypassed`` binding on it and the guest would be
    # online without ever answering the "Your name" screen. Same
    # predicate as RADIUS Authorize; config by the SESSION's location.
    if await _awaits_required_name(
        session, guest, captive_portal_service, require_cache
    ):
        return SessionGateDecision(SessionGateReason.AWAITING_NAME)
    if await is_blocklisted(
        access_decision_service,
        organization_id=session.organization_id,  # type: ignore[attr-defined]
        location_id=session.location_id,  # type: ignore[attr-defined]
        identifier=guest.identifier if guest is not None else None,
        mac_address=device.mac_address,
    ):
        return SessionGateDecision(SessionGateReason.BLOCKLISTED)
    return SessionGateDecision(SessionGateReason.AUTHORIZED, device.mac_address)


@dataclass(frozen=True, slots=True)
class AuthorizedMacList:
    """``mac_addresses`` is sorted, de-duplicated and in the router's own
    spelling. ``dropped`` counts recorded values that were not MACs."""

    mac_addresses: tuple[str, ...]
    dropped: int


async def list_authorized_macs(
    router_id: uuid.UUID,
    *,
    guest_repository: GuestRepositoryProtocol,
    mac_authorization_service: MacAuthorizationService,
    access_decision_service: GuestAccessService,
    captive_portal_service: CaptivePortalService,
) -> AuthorizedMacList:
    """Every MAC ``router_id`` should let straight through: the device of
    each ``ACTIVE`` session :func:`session_authorized_mac` admits, **and**
    the devices an admin marked Trusted. See ``router.agent_authorized_macs``
    for why Trusted Devices are a union here."""
    sessions = await guest_repository.list_active_sessions_for_router(router_id)
    macs: list[str] = []
    require_cache: RequireNameCache = {}
    for session in sessions:
        decision = await session_authorized_mac(
            session,
            guest_repository=guest_repository,
            access_decision_service=access_decision_service,
            captive_portal_service=captive_portal_service,
            require_cache=require_cache,
        )
        if decision.authorized and decision.mac_address is not None:
            macs.append(decision.mac_address)

    # Scoped by the service against this router's own organization and
    # location; the agent identity is the router, so there is no caller
    # organization to pass and none to check against.
    trusted = await mac_authorization_service.list_active_entries_for_router(
        router_id, requesting_organization_id=None
    )
    macs.extend(entry.mac_address for entry in trusted)

    # One spelling, and only real MACs -- see ``routeros_mac_address`` for
    # what either failure does to the script that reads this. An entry that
    # is dropped is a device the router will not let through, so it is
    # counted rather than vanishing: that guest's sign-in recorded
    # something that is not a MAC address.
    canonical = {mac for raw in macs if (mac := routeros_mac_address(raw)) is not None}
    dropped = sum(1 for raw in macs if routeros_mac_address(raw) is None)
    return AuthorizedMacList(mac_addresses=tuple(sorted(canonical)), dropped=dropped)


async def resolve_session_gate(
    session_id: uuid.UUID,
    router_id: uuid.UUID,
    *,
    guest_repository: GuestRepositoryProtocol,
    access_decision_service: GuestAccessService,
    captive_portal_service: CaptivePortalService,
) -> SessionGateDecision:
    """Does :func:`list_authorized_macs` list a MAC *because of this
    session*, and if so which.

    Deliberately not a lookup by id followed by a status check: the session
    is found in ``list_active_sessions_for_router`` -- the query the list
    itself starts from -- so "``ACTIVE`` on this router" cannot mean one
    thing here and another there. A session that query does not return is
    ``NOT_LISTED``, whatever the reason.

    The MAC returned is the canonical one the list would carry. A session
    whose device is listed only because an admin trusted it, while the
    session itself is held or blocked, is *not* authorized by this
    function: the question is about the session.
    """
    sessions = await guest_repository.list_active_sessions_for_router(router_id)
    session = next((s for s in sessions if s.id == session_id), None)
    if session is None:
        return SessionGateDecision(SessionGateReason.NOT_LISTED)
    decision = await session_authorized_mac(
        session,
        guest_repository=guest_repository,
        access_decision_service=access_decision_service,
        captive_portal_service=captive_portal_service,
        require_cache={},
    )
    if not decision.authorized:
        return decision
    canonical = routeros_mac_address(decision.mac_address)
    if canonical is None:
        return SessionGateDecision(SessionGateReason.MALFORMED_MAC)
    return SessionGateDecision(SessionGateReason.AUTHORIZED, canonical)


__all__ = [
    "AuthorizedMacList",
    "RequireNameCache",
    "SessionGateDecision",
    "SessionGateReason",
    "list_authorized_macs",
    "resolve_session_gate",
    "session_authorized_mac",
]
