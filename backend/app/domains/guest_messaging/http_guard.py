"""Outbound HTTP to a URL a venue typed in, without becoming an SSRF.

The Custom HTTP adapter (and WATI, whose API host is per account) sends a
request to a URL the customer supplied, from inside our VPC. Every request
made here:

* must be ``https://`` on port 443, with a hostname (no userinfo);
* resolves the hostname on THIS connect and refuses it if ANY resolved
  address is loopback, private, link-local (169.254.169.254 included),
  CGNAT, multicast, reserved or in ``marketing_smtp_blocked_cidrs`` -- a
  mixed answer is a DNS-rebinding tell -- then connects to the vetted
  address itself, so there is no second lookup to rebind. TLS still
  verifies the certificate against the hostname (SNI is the hostname);
* never follows a redirect (a 3xx is a failed send, not a hop to an
  internal host);
* ignores proxy environment variables, and times out in a few seconds.

The address checks are the ones the marketing SMTP guard already uses
(:func:`app.domains.marketing.providers.ip_is_blocked`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.config import Settings

TIMEOUT = httpx.Timeout(8.0, connect=4.0)

Resolver = Callable[[str, int], list[str]]


class UrlNotAllowedError(Exception):
    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"{reason}")


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


def check_url_shape(url: str) -> str:
    """Static checks (no DNS). Returns the hostname or raises."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise UrlNotAllowedError(url, "not a valid URL") from exc
    if parts.scheme != "https":
        raise UrlNotAllowedError(url, "must start with https://")
    if parts.username or parts.password:
        raise UrlNotAllowedError(url, "must not contain a username or password")
    host = parts.hostname or ""
    if not host:
        raise UrlNotAllowedError(url, "has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlNotAllowedError(url, "has an invalid port") from exc
    if port not in (None, 443):
        raise UrlNotAllowedError(url, "must use the standard HTTPS port 443")
    if host.lower() in ("localhost",) or host.lower().endswith(
        (".localhost", ".internal", ".local")
    ):
        raise UrlNotAllowedError(url, "points at an internal host")
    return host


def vet_host(
    host: str,
    port: int,
    *,
    resolver: Resolver = system_resolver,
    settings: Settings | None = None,
) -> str:
    """Resolve ``host``; return the first address, refusing the host if any
    resolved address is internal."""
    from app.domains.marketing.providers import ip_is_blocked

    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            addresses = resolver(host, port)
        except OSError as exc:
            raise UrlNotAllowedError(host, "does not resolve") from exc
    if not addresses:
        raise UrlNotAllowedError(host, "does not resolve")
    for address in addresses:
        if ip_is_blocked(address, settings=settings):
            raise UrlNotAllowedError(host, "resolves to a non-public address")
    return addresses[0]


class _GuardedBackend:
    """httpcore network backend that vets and pins every TCP connect."""

    def __init__(self, inner: Any, vet: Callable[[str, int], str]) -> None:
        self._inner = inner
        self._vet = vet

    async def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):  # noqa: ANN001, E501
        ip = await asyncio.to_thread(self._vet, host, port)
        return await self._inner.connect_tcp(
            ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, *args, **kwargs):  # noqa: ANN002, ANN003
        raise UrlNotAllowedError("unix", "unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    def __init__(self, vet: Callable[[str, int], str]) -> None:
        super().__init__(retries=0, trust_env=False)
        pool = self._pool
        pool._network_backend = _GuardedBackend(pool._network_backend, vet)  # noqa: SLF001


def guarded_client(
    *,
    settings: Settings | None = None,
    resolver: Resolver = system_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """A client for customer-supplied URLs. ``transport`` is for tests only
    (a ``MockTransport`` bypasses the socket layer, so the DNS vetting is
    exercised separately through :func:`vet_host`)."""
    return httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        transport=transport
        or GuardedTransport(
            lambda host, port: vet_host(
                host, port, resolver=resolver, settings=settings
            )
        ),
    )


__all__ = [
    "GuardedTransport",
    "UrlNotAllowedError",
    "check_url_shape",
    "guarded_client",
    "system_resolver",
    "vet_host",
]
