"""Discovery pre-flight -- enumerate, check, and *name* every precondition
``DiscoveryService.discover_router`` genuinely has, before it opens a socket.

## Why this exists (confirmed production incident, 2026-08-22)

An operator provisioning a real MikroTik ran the fleet wizard's Discover
step and got::

    Could not connect to device at '10.20.0.64' for discovery: timed out

That message is *honest* -- the socket really did time out -- but it is
not *identifying*. ``10.20.0.64`` is a WireGuard tunnel address, and at
least four independent things must all be true before a byte can flow to
it. The message names none of them, so an operator cannot tell whether
the tunnel was never pasted onto the device, the tunnel exists but has
never handshaked, the RouterOS API user was never created, the stored
credentials are wrong, or the platform itself has no route into the
overlay. Each has a completely different fix, and the wizard happily
offered the button in every one of those states.

This module is the "which of them is missing" half. It maps each
precondition to a stable key, a status, and -- when unmet -- a sentence
that names the missing thing *and* the operator's next step.

## The honesty rules this module is built around

**Unknown is not fine.** Two of Discovery's preconditions cannot be
established without doing the very connection that is failing (does the
RouterOS API user actually exist on the device? is the API service
listening?). Those are reported as :attr:`PreconditionStatus.UNKNOWN`
with an explicit "cannot be verified without connecting" detail. They
deliberately do **not** count as passing, and
:attr:`DiscoveryPreflightReport.unverified` exists so a caller must
render them rather than silently treat them as satisfied.

**Never blame WireGuard for a connection that never used it.** A
router's ``management_ip_address`` is operator-set and is *not*
guaranteed to equal its peer's ``tunnel_ip_address`` -- some routers are
managed over a LAN or public address with no tunnel involved. The
tunnel checks therefore report
:attr:`PreconditionStatus.PASS` with a "not attempted over the tunnel"
detail when the attempted host is not the tunnel IP, exactly as
``app.domains.wireguard.connection_diagnostics`` does for the
failure-enrichment path. Blaming the tunnel for a non-tunnel connection
would be its own misdiagnosis bug.

**Handshake state is device-*reported*, not ``wg show``.**
``WireGuardPeer.last_handshake_at`` is written by the platform's own
check-in path, so "never handshaked" means "the platform has never been
told about a handshake". That is strong enough to block on -- it is the
only handshake signal the platform has -- but the wording says
*recorded* rather than asserting the hub's live opinion.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from app.domains.wireguard.constants import HealthStatus
from app.domains.wireguard.exceptions import WireGuardPeerNotFoundError

__all__ = [
    "PreconditionStatus",
    "PreconditionKey",
    "PreconditionCheck",
    "DiscoveryPreflightReport",
    "SecretResolution",
    "evaluate_preconditions",
    "build_discovery_preflight",
]


class PreconditionStatus(StrEnum):
    """Ternary on purpose. ``UNKNOWN`` is a first-class outcome, not a
    polite spelling of ``PASS`` -- see the module docstring."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class PreconditionKey(StrEnum):
    """Stable machine keys. The UI keys its rendering off these, so they
    are part of the API contract -- rename only with a frontend change."""

    MANAGEMENT_ADDRESS = "management_address"
    API_USERNAME = "api_username"
    API_SECRET = "api_secret"
    WIREGUARD_PEER = "wireguard_peer"
    WIREGUARD_HANDSHAKE = "wireguard_handshake"
    DEVICE_API_SERVICE = "device_api_service"


@dataclass(frozen=True)
class PreconditionCheck:
    """One precondition, its verdict, and -- when it is not satisfied --
    what the operator should actually do about it."""

    key: PreconditionKey
    label: str
    status: PreconditionStatus
    detail: str
    next_step: str | None = None

    @property
    def is_blocking(self) -> bool:
        return self.status is PreconditionStatus.FAIL


@dataclass(frozen=True)
class DiscoveryPreflightReport:
    checks: tuple[PreconditionCheck, ...] = field(default_factory=tuple)

    @property
    def blocking(self) -> tuple[PreconditionCheck, ...]:
        return tuple(c for c in self.checks if c.status is PreconditionStatus.FAIL)

    @property
    def unverified(self) -> tuple[PreconditionCheck, ...]:
        """Preconditions that could not be established cheaply. Callers
        must surface these; they are *not* evidence of readiness."""
        return tuple(c for c in self.checks if c.status is PreconditionStatus.UNKNOWN)

    @property
    def can_attempt(self) -> bool:
        """True when nothing *known* blocks the attempt.

        Deliberately not "everything passed": the two device-side checks
        are unknowable without connecting, so requiring them would mean
        Discovery could never run at all. ``unverified`` carries them so
        the UI can say "we could not check these" instead of implying a
        clean bill of health.
        """
        return not self.blocking

    @property
    def summary(self) -> str | None:
        """One sentence naming the missing thing and the next step --
        the message that replaces a bare timeout. ``None`` when nothing
        known blocks."""
        blocking = self.blocking
        if not blocking:
            return None
        first = blocking[0]
        parts = [first.detail]
        if first.next_step:
            parts.append(first.next_step)
        head = " ".join(parts)
        remaining = len(blocking) - 1
        if remaining:
            head += f" ({remaining} other precondition(s) also unmet.)"
        return head


@dataclass(frozen=True)
class SecretResolution:
    """Outcome of trying to decrypt the stored API secret.

    Three-valued because ``get_decrypted_api_secret`` can *raise*
    (``RouterCredentialDecryptionError``) when the Fernet key has been
    rotated out from under stored ciphertext. That is a genuinely
    different situation from "no secret stored", and collapsing it into
    ``None`` would tell an operator to re-enter a password that is
    already there.
    """

    secret: str | None = None
    undecryptable_reason: str | None = None

    @property
    def is_present(self) -> bool:
        return bool(self.secret)


class WireGuardTunnelLookupProtocol(Protocol):
    """Same narrow, duck-typed cross-domain read convention used by
    ``app.domains.wireguard.connection_diagnostics`` and
    ``app.domains.readiness.service``."""

    async def get_peer(
        self, *, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> object: ...

    def compute_health_status(
        self, peer: object, *, now: object | None = None
    ) -> object: ...


# ---------------------------------------------------------------------------
# Pure core -- no I/O, exhaustively unit-testable.
# ---------------------------------------------------------------------------


def evaluate_preconditions(
    *,
    host: str | None,
    api_username: str | None,
    secret: SecretResolution,
    peer_tunnel_ip: str | None,
    peer_health: object | None,
) -> DiscoveryPreflightReport:
    """Classify every Discovery precondition from already-loaded values.

    ``peer_tunnel_ip`` / ``peer_health`` are ``None`` when the router has
    no WireGuard peer at all. ``host`` is the address Discovery would
    actually dial (``management_ip_address or public_ip_address``).
    """
    checks: list[PreconditionCheck] = [
        _check_management_address(host),
        _check_api_username(api_username),
        _check_api_secret(secret),
    ]
    checks.extend(
        _check_tunnel(host=host, peer_tunnel_ip=peer_tunnel_ip, peer_health=peer_health)
    )
    checks.append(_check_device_api_service(api_username))
    return DiscoveryPreflightReport(checks=tuple(checks))


def _check_management_address(host: str | None) -> PreconditionCheck:
    if host:
        return PreconditionCheck(
            key=PreconditionKey.MANAGEMENT_ADDRESS,
            label="Management address",
            status=PreconditionStatus.PASS,
            detail=f"Discovery will dial {host}.",
        )
    return PreconditionCheck(
        key=PreconditionKey.MANAGEMENT_ADDRESS,
        label="Management address",
        status=PreconditionStatus.FAIL,
        detail="This router has no management or public IP address recorded, "
        "so there is no address to dial.",
        next_step="Wait for the router's first heartbeat (it reports its own "
        "management address), or set one on the router record.",
    )


def _check_api_username(api_username: str | None) -> PreconditionCheck:
    if api_username:
        return PreconditionCheck(
            key=PreconditionKey.API_USERNAME,
            label="RouterOS API username",
            status=PreconditionStatus.PASS,
            detail=f"Discovery will authenticate as '{api_username}'.",
        )
    return PreconditionCheck(
        key=PreconditionKey.API_USERNAME,
        label="RouterOS API username",
        status=PreconditionStatus.FAIL,
        detail="No RouterOS API username is stored for this router, so "
        "Discovery has no account to log in as.",
        next_step="Run the 'API Access' chunk of the router setup script on "
        "the device, then save the same username and password on the router "
        "record -- nothing creates that account automatically.",
    )


def _check_api_secret(secret: SecretResolution) -> PreconditionCheck:
    if secret.undecryptable_reason:
        return PreconditionCheck(
            key=PreconditionKey.API_SECRET,
            label="RouterOS API password",
            status=PreconditionStatus.FAIL,
            detail="A RouterOS API password is stored for this router but "
            f"could not be decrypted ({secret.undecryptable_reason}).",
            next_step="This usually means the platform's router encryption "
            "key changed after the password was saved. Re-save the API "
            "password on the router record.",
        )
    if secret.is_present:
        return PreconditionCheck(
            key=PreconditionKey.API_SECRET,
            label="RouterOS API password",
            status=PreconditionStatus.PASS,
            detail="An API password is stored and decrypts cleanly.",
        )
    return PreconditionCheck(
        key=PreconditionKey.API_SECRET,
        label="RouterOS API password",
        status=PreconditionStatus.FAIL,
        detail="No RouterOS API password is stored for this router.",
        next_step="Run the 'API Access' chunk of the router setup script on "
        "the device, then save the same username and password on the router "
        "record.",
    )


def _not_over_tunnel(
    key: PreconditionKey, label: str, host: str | None
) -> PreconditionCheck:
    return PreconditionCheck(
        key=key,
        label=label,
        status=PreconditionStatus.PASS,
        detail=f"Not applicable -- Discovery dials {host or 'this router'}, "
        "which is not this router's WireGuard tunnel address, so the tunnel "
        "is not on the path.",
    )


def _check_tunnel(
    *, host: str | None, peer_tunnel_ip: str | None, peer_health: object | None
) -> list[PreconditionCheck]:
    """The peer-exists and peer-has-handshaked pair.

    Both collapse to a non-blocking "not applicable" when the attempted
    host is not the tunnel IP -- see the module docstring on why blaming
    the tunnel for a non-tunnel connection is its own bug.
    """
    # No peer at all. We cannot prove this is wrong -- a router legitimately
    # managed over a LAN or public address needs no tunnel -- but we also
    # cannot prove it is fine, because we have no way here to tell whether
    # ``host`` is an overlay address that only a tunnel could reach. So:
    # UNKNOWN, surfaced, never silently treated as satisfied.
    if peer_tunnel_ip is None:
        return [
            PreconditionCheck(
                key=PreconditionKey.WIREGUARD_PEER,
                label="WireGuard tunnel",
                status=PreconditionStatus.UNKNOWN,
                detail="This router has no WireGuard peer allocated. That is "
                "expected only if it is managed over a LAN or public address; "
                f"if {host or 'its recorded address'} is a tunnel address, "
                "nothing can reach it.",
                next_step="If this router is meant to be reached over "
                "WireGuard, issue it a tunnel and paste the WireGuard chunk "
                "from the router setup script on the device.",
            ),
            _not_over_tunnel(
                PreconditionKey.WIREGUARD_HANDSHAKE, "WireGuard handshake", host
            ),
        ]

    if host != peer_tunnel_ip:
        return [
            _not_over_tunnel(PreconditionKey.WIREGUARD_PEER, "WireGuard tunnel", host),
            _not_over_tunnel(
                PreconditionKey.WIREGUARD_HANDSHAKE, "WireGuard handshake", host
            ),
        ]

    peer_check = PreconditionCheck(
        key=PreconditionKey.WIREGUARD_PEER,
        label="WireGuard tunnel",
        status=PreconditionStatus.PASS,
        detail=f"A WireGuard peer is allocated at {peer_tunnel_ip}.",
    )
    return [peer_check, _check_handshake(peer_health)]


def _check_handshake(peer_health: object | None) -> PreconditionCheck:
    value = getattr(peer_health, "value", str(peer_health))
    label = "WireGuard handshake"
    if value == HealthStatus.HEALTHY.value:
        return PreconditionCheck(
            key=PreconditionKey.WIREGUARD_HANDSHAKE,
            label=label,
            status=PreconditionStatus.PASS,
            detail="The tunnel handshaked recently.",
        )
    if value == HealthStatus.UNKNOWN.value:
        return PreconditionCheck(
            key=PreconditionKey.WIREGUARD_HANDSHAKE,
            label=label,
            status=PreconditionStatus.FAIL,
            detail="This router's WireGuard tunnel has never recorded a "
            "handshake, so nothing is listening at its tunnel address yet.",
            next_step="Paste the WireGuard chunk from the router setup "
            "script on the device, then wait for it to check in and retry.",
        )
    if value == HealthStatus.STALE.value:
        return PreconditionCheck(
            key=PreconditionKey.WIREGUARD_HANDSHAKE,
            label=label,
            status=PreconditionStatus.FAIL,
            detail="This router's WireGuard tunnel handshaked before but not "
            "recently, so it looks disconnected right now.",
            next_step="Check the router's WAN is up and outbound UDP to the "
            "hub is not blocked, then retry.",
        )
    if value == HealthStatus.REVOKED.value:
        return PreconditionCheck(
            key=PreconditionKey.WIREGUARD_HANDSHAKE,
            label=label,
            status=PreconditionStatus.FAIL,
            detail="This router's WireGuard tunnel has been revoked, so the "
            "device currently has no way to reach the platform.",
            next_step="Issue the router a fresh tunnel, paste the new "
            "WireGuard chunk on the device, then retry.",
        )
    # An unrecognized future HealthStatus. Do not fabricate a verdict --
    # say we do not know, and let it show up under ``unverified``.
    return PreconditionCheck(
        key=PreconditionKey.WIREGUARD_HANDSHAKE,
        label=label,
        status=PreconditionStatus.UNKNOWN,
        detail=f"The tunnel is in an unrecognized state ('{value}'), so its "
        "handshake status could not be classified.",
        next_step="Check the router's WireGuard peer directly before retrying.",
    )


def _check_device_api_service(api_username: str | None) -> PreconditionCheck:
    """Always ``UNKNOWN``, on purpose.

    Whether the ``/user`` account actually exists on the device and
    whether ``/ip service api`` is listening cannot be established
    without making the connection that Discovery is about to make. No
    backend code path creates that account -- it lives in a setup-script
    chunk an admin pastes by hand -- so assuming it is present is exactly
    the fabricated-success-path this module exists to avoid.
    """
    who = f"'{api_username}'" if api_username else "the API user"
    return PreconditionCheck(
        key=PreconditionKey.DEVICE_API_SERVICE,
        label="RouterOS API service and user on the device",
        status=PreconditionStatus.UNKNOWN,
        detail=f"Cannot be verified without connecting: whether {who} exists "
        "on the device and the RouterOS API service is enabled is only "
        "knowable by attempting the connection. No automated step creates "
        "that account.",
        next_step="If Discovery fails after every other precondition passes, "
        "run the 'API Access' chunk of the router setup script on the device.",
    )


# ---------------------------------------------------------------------------
# I/O shell -- thin, and never lets a diagnostic failure become the story.
# ---------------------------------------------------------------------------


async def build_discovery_preflight(
    *,
    host: str | None,
    api_username: str | None,
    secret: SecretResolution,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None,
    wireguard_lookup: WireGuardTunnelLookupProtocol | None,
) -> DiscoveryPreflightReport:
    """Load the tunnel half, then classify via :func:`evaluate_preconditions`.

    A failure of the WireGuard lookup itself never blocks Discovery and
    never masks the real preconditions -- the tunnel pair simply comes
    back unclassified.
    """
    peer_tunnel_ip: str | None = None
    peer_health: object | None = None
    if wireguard_lookup is not None:
        try:
            peer = await wireguard_lookup.get_peer(
                router_id=router_id,
                requesting_organization_id=requesting_organization_id,
            )
        except WireGuardPeerNotFoundError:
            peer = None
        except Exception:  # noqa: BLE001 -- a broken diagnostic must not break Discovery
            peer = None
        if peer is not None:
            peer_tunnel_ip = getattr(peer, "tunnel_ip_address", None)
            try:
                peer_health = wireguard_lookup.compute_health_status(peer)
            except Exception:  # noqa: BLE001 -- same reasoning
                peer_health = None
    return evaluate_preconditions(
        host=host,
        api_username=api_username,
        secret=secret,
        peer_tunnel_ip=peer_tunnel_ip,
        peer_health=peer_health,
    )
