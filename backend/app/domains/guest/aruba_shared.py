"""The shared Aruba Instant On RADIUS listener: venue identity from inside
the packet, not from the source address.

## Why

FreeRADIUS chooses a client (and so the secret and ``%{client:shortname}``)
by the Access-Request's SOURCE address. An Instant On venue's public address
is not stable: measured 2026-10-03 on the AP21, the office left from
103.84.202.195 and, an hour later, from 111.223.3.241, and the hub dropped
the AP's requests as an unknown client. Dynamic IPs, dual WAN and failover
are normal at small venues; a per-venue ``client{}`` keyed on an address
cannot follow them.

## What

A separate listener -- ``server wyfy_aruba_shared`` on UDP 1912 (auth) and
1913 (acct), ``backend/ops/freeradius/sites-aruba-shared.conf`` -- with its
OWN client list (never ``clients.conf``): one catch-all client per address
family and ONE platform-wide Aruba shared secret, with
``require_message_authenticator = yes``. The default 1812/1813 listeners and
every per-venue stanza (MikroTik, Omada, address-keyed Aruba) are untouched.

FreeRADIUS forwards, as headers, the shared client's ``backend_secret``, the
packet's ``NAS-Identifier`` and its ``Called-Station-Id``. This module turns
those into a NAS row, or a logged refusal:

1. the header secret must equal the shared listener's HUB-ONLY backend
   secret (constant-time) -- proof the packet came through the shared
   listener and passed its Message-Authenticator check. It is NOT the
   RADIUS shared secret: that one is typed into every Aruba customer's
   Instant On profile, so it is known to every customer and cannot be an
   HTTP credential (review of #342: a direct HTTPS POST with it and forged
   NAS-ID / Called-Station-Id headers was answered). The backend secret is
   ``backend_secret_for(radius_secret, hub agent secret)``: an HMAC keyed
   with the hub agent secret, which only the backend and the hub hold. The
   agent derives and writes it (``radius_agent.set_shared_secret``); the
   backend derives it again to compare. Nothing new is stored, and rotating
   the RADIUS secret rotates it too;
2. ``NAS-Identifier`` must name an ACTIVE NAS row whose router is an
   ``aruba_instant_on`` fleet row -- no MikroTik or Omada NAS can ever be
   reached through this listener;
3. the AP MAC at the front of ``Called-Station-Id`` must equal that router's
   recorded AP MAC.

The secret is minted by the platform (``rotate``), pushed to the hub agent
first, stored encrypted (``system_settings`` key ``aruba_shared_radius``),
and returned exactly once. Only its fingerprint is ever shown again.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx

from app.core.config import get_settings
from app.domains.guest.constants import NasStatus
from app.domains.guest.nas_number_generator import (
    generate_alphanumeric_shared_secret,
    secret_fingerprint,
)
from app.domains.guest.radius_bridge import (
    RETRY_DELAYS,
    RadiusBridgePushError,
    bridge_error_detail,
)
from app.domains.router.crypto import decrypt_secret, encrypt_secret
from app.domains.router.vendor_capabilities import ARUBA_INSTANT_ON_VENDOR
from app.domains.system_settings.constants import SystemSettingKey

logger = logging.getLogger(__name__)

#: Headers FreeRADIUS's ``wyfy_aruba_shared`` server sends to the backend.
#: The secret header is the same name the per-venue path uses; the other two
#: are new, and only the shared listener sets them.
SHARED_SECRET_HEADER = "X-RADIUS-Shared-Secret"
PACKET_NAS_IDENTIFIER_HEADER = "X-RADIUS-Packet-NAS-Identifier"
CALLED_STATION_ID_HEADER = "X-RADIUS-Called-Station-Id"

#: The only NAS-Identifier shape the shared listener resolves: what
#: ``register_public_radius_nas`` / ``register_shared_radius_nas`` mint.
ARUBA_NAS_IDENTIFIER_RE = re.compile(r"^cg-aruba-[0-9a-f]{8}$")

#: Domain-separation label of the backend-secret derivation. Must match
#: ``radius_agent.BACKEND_SECRET_LABEL`` byte for byte (pinned by a test).
BACKEND_SECRET_LABEL = b"wyfy-aruba-shared-backend-v1:"

# A MAC at the START of Called-Station-Id, in any of the usual spellings,
# optionally followed by ":<SSID>" (RFC 3580 s3.20's "AA-BB-..:SSID" form).
_MAC_PREFIX_RE = re.compile(
    r"^\s*("
    r"(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}"  # aa:bb:.. / aa-bb-..
    r"|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"  # aabb.ccdd.eeff
    r"|[0-9A-Fa-f]{12}"  # aabbccddeeff
    r")(?![0-9A-Fa-f])"
)


class SharedRejectReason:
    """Closed set of reasons a shared-listener request is refused. Logged
    with the request, never sent to the NAS."""

    SECRET_NOT_CONFIGURED = "shared_secret_not_configured"
    BACKEND_SECRET_UNAVAILABLE = "backend_secret_unavailable"
    SECRET_MISMATCH = "shared_secret_mismatch"
    NAS_IDENTIFIER_MISSING = "nas_identifier_missing"
    NAS_IDENTIFIER_MALFORMED = "nas_identifier_malformed"
    NAS_UNKNOWN = "nas_unknown"
    NAS_INACTIVE = "nas_inactive"
    NOT_ARUBA = "nas_not_aruba_instant_on"
    ROUTER_HAS_NO_AP_MAC = "router_has_no_ap_mac"
    CALLED_STATION_ID_MISSING = "called_station_id_missing"
    CALLED_STATION_ID_UNPARSEABLE = "called_station_id_unparseable"
    AP_MAC_MISMATCH = "ap_mac_mismatch"


class ArubaSharedRequestRejected(Exception):
    """The request reached the shared listener but does not belong to the
    Aruba venue it names. ``reason`` is a ``SharedRejectReason`` value."""

    def __init__(self, reason: str, **context: Any) -> None:
        super().__init__(reason)
        self.reason = reason
        self.context = context


class ApRegistry(Protocol):
    """The approved access points of a multi-AP Instant On site. See
    ``app.domains.network_integration.aruba_access_points``. ``touch`` and
    ``record_unknown`` are best-effort and never raise."""

    async def approved_macs(self, router_id: uuid.UUID) -> set[str]: ...

    async def touch(self, router_id: uuid.UUID, mac: str) -> None: ...

    async def record_unknown(self, router: Any, mac: str) -> None: ...


class ArubaSharedNotConfiguredError(Exception):
    """No hub agent URL for the shared listener on this deployment."""


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def canonical_mac(raw: str | None) -> str | None:
    if not raw:
        return None
    hexed = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(hexed) != 12:
        return None
    return ":".join(hexed[i : i + 2] for i in range(0, 12, 2)).upper()


def is_placeholder_mac(mac: str | None) -> bool:
    """True for a MAC no real access point carries: all zeros, broadcast,
    multicast, or locally administered (bit 1 of the first octet).

    ``routers.mac_address`` is NOT NULL, so an Instant On site added without
    its AP's MAC gets a minted one (``synthesize_nas_only_identity``), which
    is locally administered precisely so it can never collide with real
    hardware. Treating that value as "the AP MAC" would make the shared
    listener's MAC check unpassable for the real AP (and the "no AP MAC"
    refusal unreachable), so it counts as no MAC at all."""
    canonical = canonical_mac(mac)
    if canonical is None:
        return True
    first = int(canonical[:2], 16)
    if canonical in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return True
    return bool(first & 0b01) or bool(first & 0b10)


def recorded_ap_mac(router: Any) -> str | None:
    """The router's AP MAC, canonical, or None when it has none -- missing,
    unparseable, or a minted placeholder (``is_placeholder_mac``)."""
    canonical = canonical_mac(getattr(router, "mac_address", None))
    if canonical is None or is_placeholder_mac(canonical):
        return None
    return canonical


def backend_secret_for(radius_secret: str, hub_agent_secret: str) -> str:
    """The shared listener's hub-only backend secret: what FreeRADIUS sends
    in ``X-RADIUS-Shared-Secret``. HMAC-SHA256 keyed with the hub agent
    secret (never typed into any device), over the RADIUS shared secret (so
    it rotates with it). Hex, 64 chars: safe as a FreeRADIUS config value."""
    return hmac.new(
        hub_agent_secret.encode(),
        BACKEND_SECRET_LABEL + radius_secret.encode(),
        hashlib.sha256,
    ).hexdigest()


def ap_mac_from_called_station_id(raw: str | None) -> str | None:
    """The AP MAC at the front of ``Called-Station-Id``, canonical
    ``AA:BB:CC:DD:EE:FF``, or None. Accepts ``AA-BB-..``, ``aa:bb:..``,
    ``aabb.ccdd.eeff`` and bare hex, each optionally followed by
    ``:<SSID>``."""
    if not raw:
        return None
    match = _MAC_PREFIX_RE.match(raw)
    return canonical_mac(match.group(1)) if match else None


# ---------------------------------------------------------------------------
# The shared secret: stored encrypted in system_settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SharedSecretState:
    configured: bool
    fingerprint: str | None
    length: int | None
    rotated_at: str | None
    hub_confirmed: bool


class ArubaSharedSecretStore:
    """``system_settings[aruba_shared_radius]`` =
    ``{"secret_encrypted", "rotated_at", "hub_fingerprint"}``. Never part
    of the platform-settings read (that response is built from typed fields
    only)."""

    KEY = SystemSettingKey.ARUBA_SHARED_RADIUS.value

    def __init__(self, repository: Any) -> None:
        self.repository = repository

    async def _value(self) -> dict:
        value = await self.repository.get_value(self.KEY)
        return value if isinstance(value, dict) else {}

    async def secret(self) -> str | None:
        encrypted = (await self._value()).get("secret_encrypted")
        if not encrypted:
            return None
        try:
            return decrypt_secret(encrypted)
        except Exception:  # noqa: BLE001 -- an unreadable secret is "none"
            logger.error("aruba_shared_secret_undecryptable")
            return None

    async def state(self) -> SharedSecretState:
        value = await self._value()
        secret = await self.secret()
        if secret is None:
            return SharedSecretState(False, None, None, None, False)
        fp = secret_fingerprint(secret)
        return SharedSecretState(
            configured=True,
            fingerprint=fp,
            length=len(secret),
            rotated_at=value.get("rotated_at"),
            hub_confirmed=value.get("hub_fingerprint") == fp,
        )

    async def save(
        self, secret: str, *, hub_fingerprint: str, actor_user_id: object
    ) -> None:
        await self.repository.upsert(
            self.KEY,
            {
                "secret_encrypted": encrypt_secret(secret),
                "rotated_at": datetime.now(UTC).isoformat(),
                "hub_fingerprint": hub_fingerprint,
            },
            actor_user_id=actor_user_id,
        )


async def push_shared_secret(secret: str) -> tuple[str, str]:
    """Hand the new secret to the hub agent (``POST /radius/shared-client``)
    and return ``(fingerprint, backend_fingerprint)`` the agent reports it
    wrote (an agent that predates the hub-only backend secret reports no
    backend fingerprint). Same retry and
    error contract as the per-NAS push: 5xx/transport retried on
    ``RETRY_DELAYS``, a 4xx reported at once with the agent's own detail."""
    settings = get_settings()
    url = settings.hub_radius_aruba_shared_agent_url
    if not url:
        raise ArubaSharedNotConfiguredError()
    resp: httpx.Response | None = None
    last_error: httpx.HTTPError | None = None
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    url,
                    headers={
                        "X-Agent-Secret": settings.hub_radius_agent_secret,
                        "Content-Type": "application/json",
                    },
                    json={"secret": secret},
                )
            last_error = None
            if resp.status_code < 500:
                break
        except httpx.HTTPError as exc:
            last_error, resp = exc, None
        if attempt < len(RETRY_DELAYS):
            await asyncio.sleep(RETRY_DELAYS[attempt])
    if resp is None:
        raise RadiusBridgePushError(
            f"Could not reach the RADIUS server bridge: {last_error!s}",
            transport=True,
            status_code=None,
        )
    if resp.status_code >= 400:
        raise RadiusBridgePushError(
            f"The RADIUS server bridge refused the shared Aruba secret "
            f"(HTTP {resp.status_code}): {bridge_error_detail(resp)}",
            transport=False,
            status_code=resp.status_code,
        )
    try:
        body = resp.json()
        reported = str(body.get("fingerprint") or "")
        reported_backend = str(body.get("backend_fingerprint") or "")
    except (ValueError, AttributeError):
        reported, reported_backend = "", ""
    return reported, reported_backend


async def rotate_shared_secret(
    store: ArubaSharedSecretStore, *, actor_user_id: object
) -> tuple[str, str]:
    """Mint, push FIRST, then store. Returns ``(secret, fingerprint)``; the
    secret is never retrievable again. A hub that refuses leaves the stored
    secret (and every venue already typed with it) exactly as it was."""
    secret = generate_alphanumeric_shared_secret()
    fp = secret_fingerprint(secret)
    reported, reported_backend = await push_shared_secret(secret)
    if reported != fp:
        raise RadiusBridgePushError(
            "The RADIUS server bridge reported a different secret fingerprint "
            f"({reported or 'none'}) than the one sent ({fp}); nothing was stored.",
            transport=False,
            status_code=None,
        )
    expected_backend = secret_fingerprint(
        backend_secret_for(secret, get_settings().hub_radius_agent_secret)
    )
    if reported_backend != expected_backend:
        # The hub wrote the RADIUS secret but not the backend secret this
        # platform expects (an agent from before the split, or a different
        # agent key): every shared-listener request would be refused.
        raise RadiusBridgePushError(
            "The RADIUS server bridge did not confirm the shared listener's "
            f"backend secret (reported {reported_backend or 'none'}, expected "
            f"{expected_backend}); upgrade radius_agent.py on the hub. "
            "Nothing was stored.",
            transport=False,
            status_code=None,
        )
    await store.save(secret, hub_fingerprint=reported, actor_user_id=actor_user_id)
    logger.warning(
        # WARNING: rotating this secret breaks every venue using the shared
        # listener until it is retyped in Instant On. Worth an alert rule.
        "aruba_shared_secret_rotated",
        extra={"fingerprint": fp, "actor_user_id": str(actor_user_id)},
    )
    return secret, fp


# ---------------------------------------------------------------------------
# The resolver
# ---------------------------------------------------------------------------


async def resolve_shared_nas(
    *,
    presented_secret: str | None,
    nas_identifier: str | None,
    called_station_id: str | None,
    store: ArubaSharedSecretStore,
    radius_service: Any,
    hub_agent_secret: str | None = None,
    ap_registry: ApRegistry | None = None,
):  # noqa: ANN201 -- RadiusNasClient
    """The NAS row a shared-listener request belongs to, or
    ``ArubaSharedRequestRejected`` with the reason. Secret first, so a
    request without it learns nothing about which NAS identifiers exist.

    ``presented_secret`` must be the hub-only BACKEND secret
    (``backend_secret_for``), never the RADIUS shared secret the APs hold:
    presenting the latter is a ``shared_secret_mismatch`` like any other
    wrong value. ``hub_agent_secret`` defaults to this deployment's
    ``hub_radius_agent_secret``.

    ``ap_registry`` (multi-AP sites): the AP MAC may also be any
    ``approved`` row of ``aruba_access_points`` for this router. A MAC that
    matches nothing is still refused, and is handed to
    ``ap_registry.record_unknown`` so Master can review it -- never approved
    from the packet. Without a registry the check is exactly the single
    recorded-MAC comparison it always was."""
    radius_secret = await store.secret()
    if radius_secret is None:
        raise ArubaSharedRequestRejected(SharedRejectReason.SECRET_NOT_CONFIGURED)
    if hub_agent_secret is None:
        hub_agent_secret = get_settings().hub_radius_agent_secret
    if not hub_agent_secret:
        # Without the hub-only key there is no backend secret to compare
        # against; falling back to the RADIUS secret would reopen the hole.
        raise ArubaSharedRequestRejected(
            SharedRejectReason.BACKEND_SECRET_UNAVAILABLE
        )
    expected = backend_secret_for(radius_secret, hub_agent_secret)
    if not presented_secret or not secrets.compare_digest(
        presented_secret.encode(), expected.encode()
    ):
        raise ArubaSharedRequestRejected(SharedRejectReason.SECRET_MISMATCH)

    ident = (nas_identifier or "").strip()
    if not ident:
        raise ArubaSharedRequestRejected(SharedRejectReason.NAS_IDENTIFIER_MISSING)
    if not ARUBA_NAS_IDENTIFIER_RE.match(ident):
        raise ArubaSharedRequestRejected(
            SharedRejectReason.NAS_IDENTIFIER_MALFORMED, nas_identifier=ident[:64]
        )
    nas = await radius_service.repository.get_nas_client_by_identifier(ident)
    if nas is None:
        raise ArubaSharedRequestRejected(
            SharedRejectReason.NAS_UNKNOWN, nas_identifier=ident
        )
    if str(nas.status) != NasStatus.ACTIVE.value:
        raise ArubaSharedRequestRejected(
            SharedRejectReason.NAS_INACTIVE, nas_identifier=ident
        )
    try:
        router = await radius_service.router_lookup.get_router(nas.router_id)
    except Exception:  # noqa: BLE001 -- a missing fleet row is an unknown NAS
        raise ArubaSharedRequestRejected(
            SharedRejectReason.NAS_UNKNOWN, nas_identifier=ident
        ) from None
    if str(getattr(router, "vendor", "")) != ARUBA_INSTANT_ON_VENDOR:
        raise ArubaSharedRequestRejected(
            SharedRejectReason.NOT_ARUBA, nas_identifier=ident
        )
    recorded = recorded_ap_mac(router)
    allowed: set[str] = {recorded} if recorded is not None else set()
    if ap_registry is not None:
        allowed |= await ap_registry.approved_macs(router.id)
    if not allowed:
        raise ArubaSharedRequestRejected(
            SharedRejectReason.ROUTER_HAS_NO_AP_MAC, nas_identifier=ident
        )
    if not (called_station_id or "").strip():
        raise ArubaSharedRequestRejected(
            SharedRejectReason.CALLED_STATION_ID_MISSING, nas_identifier=ident
        )
    presented = ap_mac_from_called_station_id(called_station_id)
    if presented is None:
        raise ArubaSharedRequestRejected(
            SharedRejectReason.CALLED_STATION_ID_UNPARSEABLE,
            nas_identifier=ident,
            called_station_id=(called_station_id or "")[:80],
        )
    if presented not in allowed:
        if ap_registry is not None:
            await ap_registry.record_unknown(router, presented)
        raise ArubaSharedRequestRejected(
            SharedRejectReason.AP_MAC_MISMATCH,
            nas_identifier=ident,
            called_station_id=(called_station_id or "")[:80],
            expected_ap_mac=recorded,
        )
    if ap_registry is not None:
        await ap_registry.touch(router.id, presented)
    return nas


def log_rejection(exc: ArubaSharedRequestRejected, *, kind: str) -> None:
    logger.warning(
        "radius_aruba_shared_rejected",
        extra={"kind": kind, "reason": exc.reason, **exc.context},
    )


def would_be_nas_identifier(router_id: uuid.UUID) -> str:
    return f"cg-aruba-{str(router_id)[:8]}"


__all__ = [
    "ARUBA_NAS_IDENTIFIER_RE",
    "ApRegistry",
    "ArubaSharedNotConfiguredError",
    "ArubaSharedRequestRejected",
    "ArubaSharedSecretStore",
    "CALLED_STATION_ID_HEADER",
    "PACKET_NAS_IDENTIFIER_HEADER",
    "SHARED_SECRET_HEADER",
    "SharedRejectReason",
    "SharedSecretState",
    "BACKEND_SECRET_LABEL",
    "ap_mac_from_called_station_id",
    "backend_secret_for",
    "canonical_mac",
    "is_placeholder_mac",
    "log_rejection",
    "push_shared_secret",
    "recorded_ap_mac",
    "resolve_shared_nas",
    "rotate_shared_secret",
    "would_be_nas_identifier",
]
