"""The reconciliation pass, and the NAS-rebinding half of it.

See this package's ``__init__`` for why it is a package rather than a
method on either domain's service.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.guest.constants import NasStatus
from app.domains.guest.radius_bridge import RadiusBridgePushError, push_nas_client
from app.domains.router.crypto import decrypt_secret
from app.domains.wireguard.constants import FleetPeerStatus
from app.domains.wireguard.service import WireGuardService

from .constants import MAX_NAS_REBINDS_PER_SWEEP

logger = logging.getLogger(__name__)


class NasBindingStore(Protocol):
    """The only two things this package needs from ``RadiusService``.

    Declared as a Protocol, and the reason is operational rather than
    stylistic. The Celery task in ``tasks.py`` has no FastAPI DI container
    to build a service graph for it, and hand-constructing the full
    ``RadiusService`` tree there -- ``GuestService`` (itself needing OTP,
    voucher, captive-portal, monitoring, guest-access, queue, policy, MAC
    and Redis collaborators), ``RouterService``, ``LocationService``,
    ``NasCodeCounterRepository`` -- would mean assembling nine services to
    reach two methods that touch none of them.

    That is not merely wasteful, it is the exact failure mode this whole
    change exists to prevent: a subtly wrong collaborator deep in a tree
    nothing on this path reads produces a task that runs, logs success, and
    silently does the wrong thing. Narrowing the contract to what is
    actually used means a mistake in the unused nine cannot exist, rather
    than existing and being harmless until it isn't.

    ``RadiusService`` satisfies this structurally and is what the HTTP
    endpoints inject; nothing about the request path changes.
    """

    async def list_nas_clients(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = ...,
        router_id: uuid.UUID | None = ...,
        status: object = ...,
        page: int = ...,
        page_size: int = ...,
    ) -> tuple[list, object]: ...

    async def record_hub_client_sync(
        self,
        *,
        nas_id: uuid.UUID,
        tunnel_ip_address: str,
        requesting_organization_id: uuid.UUID | None = ...,
    ) -> object: ...


@dataclasses.dataclass(frozen=True, slots=True)
class NasRebindResult:
    """Outcome of pushing one router's NAS client to the address its peer
    is actually on. ``reason`` is populated only when nothing was pushed --
    an operator reading a reconciliation report needs "there is no NAS for
    this router" and "the hub refused" to look different."""

    router_id: uuid.UUID
    nas_identifier: str | None
    tunnel_ip_address: str
    pushed: bool
    reason: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """What one pass observed and what it changed. Returned rather than only
    logged so the endpoint can show it and a scheduled run can assert on
    it."""

    summary: dict[str, int]
    adopted_public_keys: list[str]
    nas_rebinds: list[NasRebindResult]
    drift_public_keys: list[str]
    # Stale bindings this pass recognised but did not push, because the
    # per-pass cap was reached. Non-zero means a backlog is draining, not
    # that anything failed -- see ``constants.MAX_NAS_REBINDS_PER_SWEEP``.
    rebinds_deferred: int = 0


class HubReconciliationService:
    """Owns the pair: a WireGuard identity and the RADIUS client binding
    that has to follow it.

    Composed of the two real domain services, not a reimplementation of
    either -- the same duck-typed-composition posture ``WireGuardService``
    already takes toward ``RouterService``.
    """

    def __init__(
        self,
        wireguard_service: WireGuardService,
        radius_service: NasBindingStore,
        *,
        max_rebinds_per_pass: int = MAX_NAS_REBINDS_PER_SWEEP,
    ) -> None:
        self.wireguard_service = wireguard_service
        self.radius_service = radius_service
        # Blast-radius bound, not a performance knob -- see
        # ``constants.MAX_NAS_REBINDS_PER_SWEEP``. Every push restarts
        # freeradius for the WHOLE fleet, so an uncapped pass is an outage
        # generator the first time it meets a backlog.
        self.max_rebinds_per_pass = max_rebinds_per_pass

    async def rebind_nas_for_router(
        self,
        *,
        router_id: uuid.UUID,
        tunnel_ip_address: str,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> NasRebindResult:
        """Re-push this router's NAS client so the hub's ``client{}`` stanza
        is keyed on ``tunnel_ip_address``, then record what the hub
        confirmed.

        **Pushes before recording, always.** The whole class of bug this
        code keeps meeting is a database that says an external system was
        changed when it was not: 21 live ``client{}`` stanzas against 0
        active NAS rows, a peer row on ``.8`` against a device on ``.6``. So
        ``record_hub_client_sync`` is only ever reached after a 2xx.

        Re-pushing is safe to repeat: ``radius_agent.add_client`` strips
        every stanza with this ``shortname`` and writes exactly one, so the
        file converges to the same content however many times this runs and
        whatever state a previous half-finished attempt left.

        The shared secret is re-read from the NAS row (decrypted) rather
        than regenerated. Rotating a secret because an *address* changed
        would break the device, which is still holding the old one -- the
        two are independent facts and this method only owns the address.
        """
        clients, _meta = await self.radius_service.list_nas_clients(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            status=NasStatus.ACTIVE,
            page=1,
            page_size=1,
        )
        if not clients:
            return NasRebindResult(
                router_id=router_id,
                nas_identifier=None,
                tunnel_ip_address=tunnel_ip_address,
                pushed=False,
                reason=(
                    "no active RADIUS NAS client is registered for this router "
                    "-- nothing to rebind; register one before guests can "
                    "authenticate"
                ),
            )
        nas_client = clients[0]
        # Decrypted here rather than through a new `RadiusService
        # .reveal_shared_secret()`. The plaintext is deliberately hard to
        # get at -- `register_nas`/`regenerate_secret` return it exactly
        # once and never again, and `authenticate_nas` only ever compares
        # it. Adding a general-purpose reveal method to the service would
        # make "hand me this NAS's live credential" a supported operation
        # for every future caller, which is a much larger change than this
        # one needs. `decrypt_secret` is the same helper `authenticate_nas`
        # already uses, and the plaintext never leaves this function.
        secret = decrypt_secret(nas_client.shared_secret_encrypted)

        try:
            await push_nas_client(
                tunnel_ip=tunnel_ip_address,
                nas_identifier=nas_client.nas_identifier,
                secret=secret,
            )
        except RadiusBridgePushError as exc:
            logger.warning(
                "radius_nas_rebind_failed",
                extra={
                    "router_id": str(router_id),
                    "nas_identifier": nas_client.nas_identifier,
                    "tunnel_ip_address": tunnel_ip_address,
                    "detail": exc.detail,
                },
            )
            return NasRebindResult(
                router_id=router_id,
                nas_identifier=nas_client.nas_identifier,
                tunnel_ip_address=tunnel_ip_address,
                pushed=False,
                reason=exc.detail,
            )

        await self.radius_service.record_hub_client_sync(
            nas_id=nas_client.id,
            tunnel_ip_address=tunnel_ip_address,
            requesting_organization_id=requesting_organization_id,
        )
        return NasRebindResult(
            router_id=router_id,
            nas_identifier=nas_client.nas_identifier,
            tunnel_ip_address=tunnel_ip_address,
            pushed=True,
        )

    async def reconcile(self, *, adopt: bool = True) -> ReconciliationReport:
        """One full pass: read the hub, classify, adopt what is provably
        adoptable, and make every RADIUS binding follow the address its
        peer is actually on.

        Two independent repairs, deliberately not conditional on each
        other:

        1. ``get_fleet_status(adopt=...)`` fixes WireGuard identities. Each
           adoption that moves an address fires ``PeerAddressListener``,
           which is wired to ``rebind_nas_for_router`` -- so an adoption
           carries its own RADIUS repair with it.
        2. Every peer whose NAS binding is *already* stale then gets
           re-pushed, whether or not anything was adopted this pass. This
           is what makes the system converge rather than depend on the
           moment of change: a re-push that failed last time (hub
           restarting, a lost race with ``wyfy-radius-sync.timer``) is
           simply retried, because the condition that identifies it --
           ``hub_client_synced_ip`` disagreeing with the peer's address --
           is still true.

        Idempotent by construction. Running it twice in a row changes
        nothing the second time, which is the property that makes it safe
        to run on a schedule.
        """
        fleet = await self.wireguard_service.get_fleet_status(adopt=adopt)
        rebinds: list[NasRebindResult] = []
        drift: list[str] = []
        deferred = 0

        for entry in fleet.peers:
            if entry.status in (
                FleetPeerStatus.ADOPTABLE_MISMATCH,
                FleetPeerStatus.UNTRACKED_CONNECTED,
                FleetPeerStatus.TRACKED_MISSING_FROM_HUB,
            ):
                # Reported, never auto-resolved. Each of these is either
                # ambiguous (two live identities for one router) or
                # unattributable (no issuance record), and the correct
                # response is an operator with context, not a background
                # job with a heuristic.
                drift.append(entry.public_key)
                continue
            if entry.router_id is None or entry.tunnel_ip_address is None:
                continue
            if entry.status is FleetPeerStatus.TRACKED_KEY_MISMATCH:
                # The hub routes this key somewhere this table does not
                # expect. The hub's routing table wins -- it is what decides
                # where packets go -- so the RADIUS binding follows IT, not
                # our record. This is the one place the two addresses being
                # different is resolved rather than merely reported.
                drift.append(entry.public_key)
                continue
            if entry.hub_tunnel_ip_address is None:
                continue
            if len(rebinds) >= self.max_rebinds_per_pass:
                # CAP REACHED -- deferred, not dropped. The condition that
                # identified this binding as stale is still true in five
                # minutes, so the backlog drains across passes instead of
                # restarting freeradius for the whole fleet N times in a
                # row. Counted so a backlog is visible rather than silent.
                deferred += 1
                continue
            # PER-ROUTER FAILURE ISOLATION.
            #
            # One venue must never be able to abort the pass for every
            # other venue. `rebind_nas_for_router` already converts the
            # expected failure (`RadiusBridgePushError`) into a reported
            # result, so anything reaching here is unexpected -- a bug, a
            # decryption failure on one NAS row, a DB error on one record.
            # Those are exactly the cases where continuing matters most:
            # without this, a single corrupt row would stop reconciliation
            # for the entire fleet, indefinitely, and the symptom would be
            # silence.
            try:
                rebind = await self._rebind_if_stale(
                    router_id=entry.router_id,
                    tunnel_ip_address=entry.hub_tunnel_ip_address,
                )
            except Exception as exc:  # noqa: BLE001 -- see the note above
                logger.warning(
                    "hub_reconciliation_rebind_raised",
                    extra={
                        "router_id": str(entry.router_id),
                        "tunnel_ip_address": entry.hub_tunnel_ip_address,
                        "error": str(exc),
                    },
                    exc_info=True,
                )
                rebinds.append(
                    NasRebindResult(
                        router_id=entry.router_id,
                        nas_identifier=None,
                        tunnel_ip_address=entry.hub_tunnel_ip_address,
                        pushed=False,
                        reason=f"unexpected error: {exc}",
                    )
                )
                continue
            if rebind is not None:
                rebinds.append(rebind)

        return ReconciliationReport(
            summary={status.value: count for status, count in fleet.summary.items()},
            adopted_public_keys=list(fleet.adopted_public_keys),
            nas_rebinds=rebinds,
            drift_public_keys=drift,
            rebinds_deferred=deferred,
        )

    async def _rebind_if_stale(
        self, *, router_id: uuid.UUID, tunnel_ip_address: str
    ) -> NasRebindResult | None:
        """Pushes only when the recorded confirmed address disagrees.

        The check is on ``hub_client_synced_ip``, not ``ip_address``,
        because only the former claims to describe what is in
        ``clients.conf``. Skipping when they agree matters operationally:
        every push restarts FreeRADIUS for the whole fleet
        (``_validate_and_restart``), so a reconciliation pass that pushed
        unconditionally would bounce authentication for every venue on
        every run -- turning a repair into an outage generator."""
        clients, _meta = await self.radius_service.list_nas_clients(
            requesting_organization_id=None,
            router_id=router_id,
            status=NasStatus.ACTIVE,
            page=1,
            page_size=1,
        )
        if not clients:
            return None
        if clients[0].hub_client_synced_ip == tunnel_ip_address:
            return None
        logger.info(
            "radius_nas_binding_stale",
            extra={
                "router_id": str(router_id),
                "nas_identifier": clients[0].nas_identifier,
                "recorded_synced_ip": clients[0].hub_client_synced_ip,
                "peer_tunnel_ip": tunnel_ip_address,
            },
        )
        return await self.rebind_nas_for_router(
            router_id=router_id, tunnel_ip_address=tunnel_ip_address
        )


__all__ = [
    "HubReconciliationService",
    "NasRebindResult",
    "ReconciliationReport",
]
