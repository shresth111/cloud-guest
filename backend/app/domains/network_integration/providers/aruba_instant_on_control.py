"""Write half of the Aruba Instant On portal API: block, unblock, and the
guest network's per-client speed cap.

## Why this exists

An Instant On AP sits behind the venue's NAT with a dynamic egress, so
nothing can reach it with a RADIUS CoA/Disconnect, and Instant On has no
dynamic-authorization setting anyway. The only thing that *can* reach the AP
mid-session is Instant On's own cloud. This module talks to that cloud the way
the portal web app does (``wyfy-ops/aruba-ap21/INSTANT_ON_CLOUD_CONTROL.md``
has the evidence for every endpoint below: portal bundle 3.4.2.0-26 plus live
GETs of the Wyfy test site, 2026-10-03).

## What the API offers, and what it does not

* **Block a client** -- ``POST /api/sites/{site}/blockedClients`` with
  ``{"kind": "blockedClients", "macAddress": "aa:bb:cc:dd:ee:ff"}``. The
  portal's own copy for the action is "Block network access to the client"
  and its list shows a just-blocked row as "is being disconnected...". It is
  a site-wide MAC deny: the device is dropped and cannot re-associate to any
  network on the site until unblocked. Max 256 per site (``clientSummary``
  ``metaData.maxBlockedClients``, measured).
* **Unblock** -- ``DELETE /api/sites/{site}/blockedClients/{id}``; the id
  comes from ``GET .../blockedClients``.
* **No deauthorize/disconnect verb exists.** The only per-client actions in
  the bundle are watchlist, power-cycle (PoE), IP reservation and block. A
  *disconnect* is therefore a block followed, after a short hold, by an
  unblock -- see ``instant_on_control.py``.
* **No per-client speed limit.** Policies with bandwidth limits exist, but
  the site's own capability list (measured) gives ``qosBandwidthLimiting``
  only to policies whose source is a *network*, never to the ``clients``
  source -- on any product. The finest grain Instant On has is the guest
  network's static per-client cap (``qos.perClient*BandwidthLimitInMbps``,
  integer Mbps, 1..1000), which applies to every guest on that SSID alike.

## Every write is read back

The Omada lesson (memory ``wyfy_omada_write_readback_rule``): a write's own
2xx proves nothing. Every write here is followed by a GET of the same
resource, and success is decided by that read alone. A write whose answer was
lost (timeout) is not retried -- a POST is not idempotent -- the read-back
decides whether it landed.

## Not the read client

:class:`~.aruba_instant_on_client.InstantOnClient` is GET-only by
construction and its tests pin that. This class is deliberately separate, is
only ever built behind ``Settings.instant_on_cloud_control_enabled`` plus a
per-router allowlist, and authenticates as a *different* service account (one
with a management role that may write) through the same token manager.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from app.core.logging import get_logger

from .aruba_instant_on_client import (
    InstantOnApiDriftError,
    InstantOnAuthError,
    InstantOnError,
    InstantOnForbiddenError,
    InstantOnRateLimitedError,
    InstantOnTokenManager,
    InstantOnUpstreamError,
    _json_body,
    _retry_after_seconds,
    validate_site_id,
)

logger = get_logger(__name__)

__all__ = [
    "MAX_BANDWIDTH_MBPS",
    "BlockResult",
    "GuestNetworkRateLimit",
    "InstantOnClientNotBlockableError",
    "InstantOnControlClient",
    "InstantOnNetworkNotFoundError",
    "InstantOnWriteNotConfirmedError",
    "normalize_instant_on_mac",
]

#: ``policies.capabilities.maxQosDownload/UploadBandwidthLimitInMbps``
#: (measured 1000/1000) and the UI's bandwidth enum top value.
MAX_BANDWIDTH_MBPS = 1000

_HEX = frozenset("0123456789abcdef")


class InstantOnWriteNotConfirmedError(InstantOnError):
    """The write answered (or timed out) but the read-back does not show the
    requested state. Never reported as success."""

    code = "write_not_confirmed"


class InstantOnClientNotBlockableError(InstantOnError):
    """Instant On itself says this client cannot be blocked
    (``isBlockable: false`` -- wired, VPN or watchlisted, per the portal's
    bulk-block copy)."""

    code = "not_blockable"


class InstantOnNetworkNotFoundError(InstantOnError):
    code = "network_not_found"


def normalize_instant_on_mac(value: str) -> str:
    """``aa:bb:cc:dd:ee:ff`` -- the form the portal sends
    (``MacAddress.getFormattedStr``: lower case, ``-`` replaced by ``:``) and
    the form ``clientSummary``/``blockedClients`` return (measured)."""
    text = (value or "").strip().lower()
    # Anything but hex digits and separators is not a MAC -- a phone number
    # like "+9198..." must never be stripped down to 12 "hex" digits.
    if any(ch not in _HEX and ch not in ":-." for ch in text):
        raise ValueError("Not a MAC address")
    raw = "".join(ch for ch in text if ch in _HEX)
    if len(raw) != 12:
        raise ValueError("Not a MAC address")
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


@dataclass(frozen=True, slots=True)
class BlockResult:
    mac: str
    #: The read-back shows the MAC on the site's blocked list.
    blocked: bool
    #: This call created the entry (False: it was already blocked).
    created: bool
    entry_id: str | None


@dataclass(frozen=True, slots=True)
class GuestNetworkRateLimit:
    network_id: str
    network_name: str | None
    enabled: bool
    download_mbps: int | None
    upload_mbps: int | None
    #: ``type == "guest"`` or the guest portal is on for it (measured fields).
    is_guest: bool = False

    @classmethod
    def from_network(cls, network: dict[str, Any]) -> GuestNetworkRateLimit:
        qos = network.get("qos") if isinstance(network.get("qos"), dict) else {}
        enabled = bool(qos.get("isBandwidthLimitEnabled"))
        per_client = qos.get("bandwidthLimitMode") == "perClient"
        down = (
            qos.get("perClientDownloadBandwidthLimitInMbps")
            if enabled and per_client and qos.get("isDownloadBandwidthLimitEnabled")
            else None
        )
        up = (
            qos.get("perClientUploadBandwidthLimitInMbps")
            if enabled and per_client and qos.get("isUploadBandwidthLimitEnabled")
            else None
        )
        return cls(
            network_id=str(network.get("id") or ""),
            network_name=network.get("networkName"),
            enabled=enabled and per_client and (down is not None or up is not None),
            download_mbps=down if isinstance(down, int) else None,
            upload_mbps=up if isinstance(up, int) else None,
            is_guest=bool(
                network.get("type") == "guest" or network.get("isGuestPortalEnabled")
            ),
        )


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _check_mbps(value: int | None, what: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{what} must be an integer number of Mbps")
    if not 1 <= value <= MAX_BANDWIDTH_MBPS:
        raise ValueError(f"{what} must be between 1 and {MAX_BANDWIDTH_MBPS} Mbps")
    return value


class InstantOnControlClient:
    """Block/unblock and guest-network speed cap, each read back."""

    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        tokens: InstantOnTokenManager,
        api_base_url: str,
        api_version: int,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._http = http
        self._tokens = tokens
        self._api_base_url = api_base_url.rstrip("/")
        self._api_version = str(api_version)
        self._sleep = sleep
        self._clock = clock

    # -- reads used by the writes ------------------------------------------

    async def list_blocked_clients(self, site_id: str) -> list[dict[str, Any]]:
        payload = await self._call("GET", site_id, "blockedClients")
        return _elements(payload, "blockedClients")

    async def find_blocked(self, site_id: str, mac: str) -> dict[str, Any] | None:
        target = normalize_instant_on_mac(mac)
        for entry in await self.list_blocked_clients(site_id):
            try:
                if (
                    normalize_instant_on_mac(str(entry.get("macAddress") or ""))
                    == target
                ):
                    return entry
            except ValueError:
                continue
        return None

    async def get_client(self, site_id: str, mac: str) -> dict[str, Any] | None:
        """The live ``clientSummary`` row for ``mac`` (its ``id`` is the MAC,
        measured), or ``None`` when the AP does not currently see it."""
        target = normalize_instant_on_mac(mac)
        payload = await self._call("GET", site_id, "clientSummary")
        for row in _elements(payload, "clientSummary"):
            for key in ("macAddress", "id"):
                try:
                    if normalize_instant_on_mac(str(row.get(key) or "")) == target:
                        return row
                except ValueError:
                    continue
        return None

    async def get_network(self, site_id: str, network_id: str) -> dict[str, Any]:
        payload = await self._call("GET", site_id, "networksSummary")
        for row in _elements(payload, "networksSummary"):
            if str(row.get("id")) == network_id:
                return row
        raise InstantOnNetworkNotFoundError(
            "That network is not on this Instant On site", reason="network_not_found"
        )

    async def list_guest_network_rate_limits(
        self, site_id: str, *, guest_only: bool = True
    ) -> list[GuestNetworkRateLimit]:
        """Every wireless network on the site with its current per-client
        cap -- the read half for speed tiers by SSID (one cap per network;
        a venue can run several guest SSIDs at different caps). Read-only."""
        payload = await self._call("GET", site_id, "networksSummary")
        limits = [
            GuestNetworkRateLimit.from_network(row)
            for row in _elements(payload, "networksSummary")
            if row.get("isWireless", True) is not False
        ]
        return [n for n in limits if n.is_guest] if guest_only else limits

    async def get_guest_network_rate_limit(
        self, site_id: str, network_id: str
    ) -> GuestNetworkRateLimit:
        return GuestNetworkRateLimit.from_network(
            await self.get_network(site_id, network_id)
        )

    # -- writes --------------------------------------------------------------

    async def block_client(self, site_id: str, mac: str) -> BlockResult:
        """Idempotent: an already-blocked MAC is reported, not re-posted."""
        target = normalize_instant_on_mac(mac)
        existing = await self.find_blocked(site_id, target)
        if existing is not None:
            return BlockResult(
                mac=target, blocked=True, created=False, entry_id=_id_of(existing)
            )
        live = await self.get_client(site_id, target)
        if live is not None and live.get("isBlockable") is False:
            raise InstantOnClientNotBlockableError(
                "Instant On says this client cannot be blocked "
                "(wired, VPN or watchlisted)",
                reason="not_blockable",
            )
        await self._write(
            "POST",
            site_id,
            "blockedClients",
            body={"kind": "blockedClients", "macAddress": target},
        )
        confirmed = await self.find_blocked(site_id, target)
        if confirmed is None:
            raise InstantOnWriteNotConfirmedError(
                "Instant On did not list the client as blocked after the write",
                reason="block_not_listed",
            )
        logger.info(
            "instant_on_client_blocked",
            extra={"site_id": site_id, "entry_id": _id_of(confirmed)},
        )
        return BlockResult(
            mac=target, blocked=True, created=True, entry_id=_id_of(confirmed)
        )

    async def unblock_client(self, site_id: str, mac: str) -> bool:
        """``True`` once the read-back shows the MAC is not blocked --
        including when it never was (the state the caller wants)."""
        target = normalize_instant_on_mac(mac)
        existing = await self.find_blocked(site_id, target)
        if existing is None:
            return True
        entry_id = _id_of(existing)
        if not entry_id:
            raise InstantOnApiDriftError(
                "blockedClients entry has no id", reason="shape_blockedClients"
            )
        await self._write(
            "DELETE", site_id, f"blockedClients/{quote(entry_id, safe=':')}"
        )
        if await self.find_blocked(site_id, target) is not None:
            raise InstantOnWriteNotConfirmedError(
                "Instant On still lists the client as blocked after the write",
                reason="unblock_still_listed",
            )
        logger.info("instant_on_client_unblocked", extra={"site_id": site_id})
        return True

    async def set_guest_network_rate_limit(
        self,
        site_id: str,
        network_id: str,
        *,
        download_mbps: int | None,
        upload_mbps: int | None,
    ) -> GuestNetworkRateLimit:
        """Set (or, with both ``None``, clear) the guest network's per-client
        cap. Every guest on the SSID gets the same cap: Instant On has no
        per-client rate on any path we can reach.

        The network resource is replaced whole by ``PUT`` (the portal sends
        its full model), so the body is the network exactly as just read,
        with only the QoS fields changed -- the Omada lesson that an omitted
        field is a reset field. The body carries the network's own secrets
        (PSK, RADIUS shared secret) back to the API unchanged; it is never
        logged.
        """
        down = _check_mbps(download_mbps, "download")
        up = _check_mbps(upload_mbps, "upload")
        network = await self.get_network(site_id, network_id)
        body = copy.deepcopy(network)
        qos = body.get("qos")
        if not isinstance(qos, dict):
            raise InstantOnApiDriftError(
                "Network has no qos object", reason="shape_network_qos"
            )
        enabled = down is not None or up is not None
        qos["isBandwidthLimitEnabled"] = enabled
        qos["bandwidthLimitMode"] = "perClient"
        qos["isDownloadBandwidthLimitEnabled"] = down is not None
        qos["isUploadBandwidthLimitEnabled"] = up is not None
        if down is not None:
            qos["perClientDownloadBandwidthLimitInMbps"] = down
        if up is not None:
            qos["perClientUploadBandwidthLimitInMbps"] = up
        # The same fields at the top level (the portal's older model, still
        # returned by the API -- measured). Kept consistent with ``qos`` so
        # whichever one the server reads, it reads the same thing.
        body["isBandwidthLimitEnabled"] = enabled
        body["bandwidthLimitMode"] = "perClient"
        if down is not None:
            body["perClientBandwidthLimitInMbps"] = down
        if up is not None:
            body["perClientUploadBandwidthLimitInMbps"] = up

        await self._write(
            "PUT", site_id, f"networksSummary/{quote(network_id, safe='')}", body=body
        )
        after = await self.get_guest_network_rate_limit(site_id, network_id)
        wanted_down = down if enabled else None
        wanted_up = up if enabled else None
        if (
            after.enabled != enabled
            or after.download_mbps != wanted_down
            or after.upload_mbps != wanted_up
        ):
            raise InstantOnWriteNotConfirmedError(
                "Instant On did not keep the requested guest speed limit",
                reason="rate_limit_not_kept",
            )
        logger.info(
            "instant_on_guest_rate_limit_set",
            extra={
                "site_id": site_id,
                "network_id": network_id,
                "download_mbps": wanted_down,
                "upload_mbps": wanted_up,
            },
        )
        return after

    # -- transport -------------------------------------------------------------

    async def _write(
        self, method: str, site_id: str, resource: str, *, body: Any = None
    ) -> None:
        """One write. A lost answer is *not* an error here: the caller's
        read-back decides whether it landed. Every other non-2xx raises."""
        try:
            await self._call(method, site_id, resource, body=body)
        except InstantOnUpstreamError as error:
            if error.reason in ("timeout", "connection_failed"):
                logger.warning(
                    "instant_on_write_answer_lost",
                    extra={"method": method, "reason": error.reason},
                )
                return
            raise

    async def _call(
        self, method: str, site_id: str, resource: str, *, body: Any = None
    ) -> Any:
        url = f"{self._api_base_url}/sites/{validate_site_id(site_id)}/{resource}"
        is_read = method == "GET"
        token = await self._tokens.get_access_token()
        refreshed = False
        transient_retried = False
        while True:
            headers = {
                "Authorization": f"Bearer {token}",
                "x-ion-api-version": self._api_version,
                "Accept": "application/json",
            }
            try:
                response = await self._http.request(
                    method,
                    url,
                    json=body if body is not None else None,
                    headers=headers,
                    follow_redirects=False,
                )
            except httpx.TimeoutException:
                if is_read and not transient_retried:
                    transient_retried = True
                    await self._sleep(1.0)
                    continue
                raise InstantOnUpstreamError(
                    "Instant On API timed out", reason="timeout"
                ) from None
            except httpx.HTTPError as exc:
                if is_read and not transient_retried:
                    transient_retried = True
                    await self._sleep(1.0)
                    continue
                raise InstantOnUpstreamError(
                    f"Instant On API unreachable ({type(exc).__name__})",
                    reason="connection_failed",
                ) from None

            status = response.status_code
            if 200 <= status < 300:
                if is_read:
                    return _json_body(response, resource.rsplit("/", 1)[-1])
                return None
            if status == 401:
                # Safe to repeat even for a write: a 401 means the request
                # was refused before anything was done.
                if refreshed:
                    await self._tokens.mark_auth_failed("api_rejected_token")
                    raise InstantOnAuthError(
                        "Instant On rejected a freshly renewed token",
                        reason="api_rejected_token",
                    )
                refreshed = True
                token = await self._tokens.force_refresh(rejected_token=token)
                continue
            if status == 404 and method == "DELETE":
                # Already gone; the caller's read-back confirms it.
                return None
            if status in (403, 404) and is_read:
                raise InstantOnForbiddenError(
                    "The service account cannot read this Instant On site "
                    f"(HTTP {status})",
                    reason=f"http_{status}",
                )
            if status == 403:
                raise InstantOnForbiddenError(
                    "The service account may not change this Instant On site "
                    "(HTTP 403); it needs a management role that can write, "
                    "not Viewer",
                    reason="write_forbidden",
                )
            if status == 429:
                raise InstantOnRateLimitedError(
                    "Instant On rate-limited this account",
                    retry_after_seconds=_retry_after_seconds(response, self._clock()),
                )
            if status >= 500:
                if is_read and not transient_retried:
                    transient_retried = True
                    await self._sleep(1.0)
                    continue
                raise InstantOnUpstreamError(
                    f"Instant On API failed with HTTP {status}",
                    reason=f"http_{status}",
                )
            raise InstantOnApiDriftError(
                f"Instant On answered HTTP {status} to {method} "
                f"{resource.split('/')[0]} "
                f"(api version {self._api_version})",
                reason=f"http_{status}",
            )


def _id_of(entry: dict[str, Any]) -> str | None:
    value = entry.get("id")
    return str(value) if value not in (None, "") else None


def _elements(payload: Any, resource: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise InstantOnApiDriftError(
            f"{resource} is not an object", reason=f"shape_{resource}"
        )
    elements = payload.get("elements")
    if not isinstance(elements, list) or not all(isinstance(e, dict) for e in elements):
        raise InstantOnApiDriftError(
            f"{resource} has no elements list", reason=f"shape_{resource}"
        )
    return elements
