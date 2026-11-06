"""An HTTP client for URLs that tenants type in (notification webhooks).

A venue admin can point a "generic webhook" (or a Slack/Teams/Discord
channel) at any URL, and the backend POSTs to it. Without a guard that is a
way to make the backend send requests into its own network: the database,
object storage, the API itself, the cloud metadata service.

:class:`PublicOnlyTransport` resolves the destination host on every request
(redirect hops included, since httpx sends each hop through the transport)
and refuses anything that is not a public, globally-routable address:
loopback, RFC 1918, link-local (where the metadata service lives), CGNAT,
multicast, reserved and unspecified ranges, in IPv4 and IPv6, including
IPv4-mapped IPv6.

Hosts the platform configured itself (the platform alert Slack webhook) are
trusted as configured and skip the check.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import urlsplit

import httpx


class BlockedDestinationError(httpx.TransportError):
    """The destination resolves to an address this client will not reach."""


def is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def host_is_literal_non_public(host: str) -> bool:
    """True for ``localhost`` or an IP literal that is not public. Used to
    refuse an obviously-internal URL at save time, before any DNS lookup."""
    bare = host.strip("[]").lower()
    if bare == "localhost" or bare.endswith(".localhost"):
        return True
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        return False
    return not is_public_address(bare)


async def _resolve(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


class PublicOnlyTransport(httpx.AsyncHTTPTransport):
    def __init__(self, *, trusted_hosts: Iterable[str] = (), **kwargs: object):
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._trusted_hosts = {h.lower() for h in trusted_hosts if h}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host.lower()
        if host not in self._trusted_hosts:
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            try:
                addresses = await _resolve(host, port)
            except OSError as exc:
                raise httpx.ConnectError(
                    f"could not resolve {host}", request=request
                ) from exc
            if not addresses or not all(is_public_address(a) for a in addresses):
                raise BlockedDestinationError(
                    "destination is a private or internal address", request=request
                )
        return await super().handle_async_request(request)


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    return urlsplit(url).hostname


def public_only_client(*, trusted_urls: Iterable[str | None] = ()) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` that only reaches public addresses and never
    follows redirects on its own."""
    trusted = [h for h in (host_of(u) for u in trusted_urls) if h]
    return httpx.AsyncClient(
        transport=PublicOnlyTransport(trusted_hosts=trusted),
        follow_redirects=False,
    )


__all__ = [
    "BlockedDestinationError",
    "PublicOnlyTransport",
    "host_is_literal_non_public",
    "is_public_address",
    "public_only_client",
]
