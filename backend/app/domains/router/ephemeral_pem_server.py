"""A single-use, TTL-bounded, peer-bound HTTP file server, alive only for the
duration of one certificate push.

## Why this exists at all

The hotspot certificate push used to run ``scp`` + ``ssh`` to the router.
Measured against the live fleet on 2026-09-06: on the only reachable router,
ports 21/22/23/80/443/8291 all *time out* -- filtered by a firewall drop, not
refused -- and only 8728/8729 answer. Nothing can be pushed *to* a router, so
the push was inverted: the router pulls both PEMs itself with ``/tool fetch``,
which is an ordinary RouterOS API command on 8728.

Inverting the direction moves a real risk. ``scp`` carried the private key
inside an authenticated session; a fetch URL is a bare GET, and for as long as
it is valid, whoever reaches it gets the Let's Encrypt private key for
``wifi.wyfyguest.com`` / ``*.portal.wyfyguest.com`` -- which is to say, the
ability to terminate TLS for every guest on the fleet. This module is the
answer to "what makes that safe", and it is four independent things, none of
which is sufficient alone:

1. **Not routable from the internet.** :meth:`EphemeralPemServer.start`
   refuses to bind a wildcard address. The caller passes the app server's own
   WireGuard tunnel address, so the listener exists only on the tunnel the
   fleet already authenticates into. This is also why plain HTTP is
   acceptable: the tunnel is the encryption and the authentication, and the
   alternative -- HTTPS on a private tunnel IP -- means either a certificate
   the router cannot verify or ``check-certificate=no``, which is not
   security, it is the appearance of it.
2. **Bound to one peer.** Every grant names the router that may collect it.
   A request whose source address is anything else is answered 404 and
   logged, whether it comes from another router, another container, or a
   process on the same box.
3. **Single use.** The token is consumed the instant a matching request is
   accepted -- before a single byte is written, so a truncated transfer burns
   it too. A retry needs a new grant, which is correct: a URL that still
   works after the router has already used it is a credential lying around.
4. **Short TTL.** Grants expire on a wall clock as well, so a push that dies
   between minting a URL and using it does not leave one valid.

And one thing this is NOT: it is not an endpoint on the public API. There is
deliberately no route, no dependency, no ``include_router`` -- the whole
listener exists for the seconds a push takes and is closed in a ``finally``.
A permanent path that serves private keys under some token check is exactly
the sort of thing that survives, gets refactored by someone who does not know
what it is for, and is still there in a year.

Nothing here has been exercised against a real router: whether a router can
reach an HTTP URL on the app server at all is genuinely unproven -- the tunnel
has only ever carried app-server-to-router traffic. The tests do exercise the
server itself over a real loopback socket with a real HTTP client, so the
half that lives on this side is proven; the half that needs a device is the
router originating the connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import secrets
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Long enough that a router on a slow uplink can finish two small downloads
# and short enough that a URL left behind by a crashed push is dead before
# anyone could find it. A PEM pair is a few kilobytes; this is not a transfer
# budget, it is a validity window.
DEFAULT_GRANT_TTL_SECONDS = 120

# A fetch URL's whole security rests on the token being unguessable, so it is
# sized like a session secret rather than like a filename. 32 bytes of
# os.urandom, url-safe base64 encoded.
_TOKEN_BYTES = 32

# A RouterOS /tool fetch request is tiny. Anything larger is not a router.
_MAX_REQUEST_BYTES = 8192
_REQUEST_READ_TIMEOUT_SECONDS = 10

# Closing a socket that still has unread bytes in its receive buffer makes the
# kernel send an RST, and an RST discards whatever we had already written -- so
# a peer whose request we rejected would see a connection failure rather than
# the 404 we actually sent it. That is the difference between "the URL is dead"
# and "the app server is broken" in an operator's hands, so the reject path
# reads the rest of the request off the wire first. Bounded in both bytes and
# time, because a peer being rejected is by definition one there is no reason
# to trust.
_MAX_DRAIN_BYTES = 256 * 1024
_DRAIN_TIMEOUT_SECONDS = 0.2


class EphemeralPemServerError(RuntimeError):
    """Raised for a misconfiguration that would weaken the guarantees above --
    always before the listener opens, never after."""


@dataclass(frozen=True, slots=True)
class _Grant:
    payload: bytes
    peer_ip: str
    expires_at: float
    label: str


@dataclass(slots=True)
class EphemeralPemServer:
    """Serve a handful of one-shot payloads on ``bind_host``.

    Use as an async context manager; the listener is closed and every
    outstanding grant dropped on exit, including on the failure path.
    """

    bind_host: str
    bind_port: int = 0
    ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS
    _grants: dict[str, _Grant] = field(default_factory=dict, init=False)
    _server: asyncio.AbstractServer | None = field(default=None, init=False)
    _port: int = field(default=0, init=False)
    _url_host: str = field(default="", init=False)
    # Recorded for the caller's log line: a rejected request is the one event
    # here worth a human looking at.
    rejections: list[str] = field(default_factory=list, init=False)

    async def __aenter__(self) -> EphemeralPemServer:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def start(self) -> None:
        address = self._validated_bind_address()
        self._server = await asyncio.start_server(
            self._handle_client,
            host=str(address),
            port=self.bind_port,
            limit=_MAX_REQUEST_BYTES,
        )
        sockets = self._server.sockets or ()
        if not sockets:
            raise EphemeralPemServerError("listener opened with no socket")
        self._port = sockets[0].getsockname()[1]
        # An IPv6 literal has to be bracketed inside a URL's authority or the
        # colons in the address are read as the port separator. RouterOS would
        # be handed a URL it cannot parse and the failure would surface as
        # "the router could not fetch" -- i.e. indistinguishable from the one
        # genuinely unproven thing in this whole path.
        self._url_host = (
            f"[{address}]"
            if isinstance(address, ipaddress.IPv6Address)
            else str(address)
        )
        logger.info(
            "hotspot_cert_pem_server_started",
            extra={"bind_host": str(address), "port": self._port},
        )

    def _validated_bind_address(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """A literal, specific, non-wildcard address -- or nothing at all.

        A hostname is refused rather than resolved: what this binds to decides
        who can reach the private key, and that must be readable in the
        command that started it, not dependent on whatever DNS says at the
        moment. ``0.0.0.0``/``::`` are refused for the obvious reason -- on
        the app server they include the public interface.
        """
        try:
            address = ipaddress.ip_address(self.bind_host.strip())
        except ValueError as exc:
            raise EphemeralPemServerError(
                f"bind host {self.bind_host!r} is not an IP literal. Pass this "
                "server's own WireGuard tunnel address; a name is refused "
                "because what this listener is reachable from must not depend "
                "on DNS."
            ) from exc
        if address.is_unspecified:
            raise EphemeralPemServerError(
                f"refusing to bind {self.bind_host!r}: a wildcard listener puts "
                "the fleet private key on every interface this host has, "
                "including the public one. Bind the WireGuard tunnel address."
            )
        return address

    async def close(self) -> None:
        self._grants.clear()
        server, self._server = self._server, None
        if server is None:
            return
        server.close()
        await server.wait_closed()

    @property
    def port(self) -> int:
        if not self._port:
            raise EphemeralPemServerError("server has not been started")
        return self._port

    def grant(self, payload: bytes, *, peer_ip: str, label: str) -> str:
        """Mint one single-use URL for ``payload``, collectable only by
        ``peer_ip``. Returns the full URL to hand to the device.

        ``label`` is for logs only and must never contain the payload or
        anything derived from it.
        """
        if not self._port:
            raise EphemeralPemServerError("server has not been started")
        try:
            ipaddress.ip_address(peer_ip.strip())
        except ValueError as exc:
            raise EphemeralPemServerError(
                f"peer address {peer_ip!r} is not an IP literal -- a grant that "
                "cannot name exactly who may collect it is not a grant"
            ) from exc
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        self._grants[token] = _Grant(
            payload=payload,
            peer_ip=peer_ip.strip(),
            expires_at=time.monotonic() + self.ttl_seconds,
            label=label,
        )
        return f"http://{self._url_host}:{self._port}/{token}"

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else ""
        try:
            token = await self._read_token(reader)
            grant = self._consume(token, peer_ip)
            if grant is None:
                await self._drain_request(reader)
                await self._respond(writer, b"404 Not Found", b"not found\n")
                return
            await self._respond(writer, b"200 OK", grant.payload)
            logger.info(
                "hotspot_cert_pem_served",
                extra={"peer": peer_ip, "label": grant.label},
            )
        except (TimeoutError, OSError, asyncio.IncompleteReadError):
            # A half-open connection is not interesting; a rejected grant is,
            # and that is logged in _consume.
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError, ConnectionError):
                await writer.wait_closed()

    async def _read_token(self, reader: asyncio.StreamReader) -> str:
        try:
            line = await asyncio.wait_for(
                reader.readline(), timeout=_REQUEST_READ_TIMEOUT_SECONDS
            )
        except ValueError:
            # asyncio raises LimitOverrunError (a ValueError) when the request
            # line exceeds the stream limit set in start(). A RouterOS fetch
            # request is a few dozen bytes; anything that overruns is not a
            # router, and it gets the same 404 as any other unusable request
            # rather than an unhandled traceback in the server's task.
            return ""
        parts = line.decode("latin-1").split()
        if len(parts) < 2 or parts[0] != "GET":
            return ""
        path = parts[1]
        if not path.startswith("/") or "/" in path[1:] or "?" in path:
            return ""
        return path[1:]

    async def _drain_request(self, reader: asyncio.StreamReader) -> None:
        """Read and discard whatever the peer is still sending, so that the
        response we are about to write actually survives the close.

        Only on the reject path. A router that gets its payload sent a request
        we consumed in full, so there is nothing to drain and nothing to wait
        for; a rejected peer is exactly the one that may still be mid-write
        (an over-long request line is the obvious case). See
        ``_MAX_DRAIN_BYTES``/``_DRAIN_TIMEOUT_SECONDS`` for the bounds and why
        they are there.
        """
        remaining = _MAX_DRAIN_BYTES
        try:
            while remaining > 0:
                chunk = await asyncio.wait_for(
                    reader.read(min(remaining, 4096)),
                    timeout=_DRAIN_TIMEOUT_SECONDS,
                )
                if not chunk:
                    return
                remaining -= len(chunk)
        except (TimeoutError, OSError, ValueError):
            return

    def _consume(self, token: str, peer_ip: str) -> _Grant | None:
        """Look the token up, check it, and burn it -- in that order.

        Burned *before* the body is written, deliberately: if the transfer is
        interrupted the router gets a truncated PEM, the import fails, and the
        push reports it. What must not happen is the URL still being live
        afterwards for whoever finds it in a log.
        """
        grant = self._grants.get(token) if token else None
        if grant is None:
            self._rejected("unknown or already-used token", peer_ip)
            return None
        if time.monotonic() > grant.expires_at:
            del self._grants[token]
            self._rejected(f"expired grant ({grant.label})", peer_ip)
            return None
        if peer_ip != grant.peer_ip:
            # Not deleted: the router this was minted for may still be about
            # to collect it, and letting somebody else invalidate its grant
            # would be a denial of service handed to anyone on the tunnel.
            self._rejected(
                f"grant for {grant.label} is bound to {grant.peer_ip}", peer_ip
            )
            return None
        del self._grants[token]
        return grant

    def _rejected(self, reason: str, peer_ip: str) -> None:
        message = f"{reason} (from {peer_ip or 'unknown'})"
        self.rejections.append(message)
        logger.warning("hotspot_cert_pem_request_rejected", extra={"detail": message})

    async def _respond(
        self, writer: asyncio.StreamWriter, status: bytes, body: bytes
    ) -> None:
        writer.write(
            b"HTTP/1.1 "
            + status
            + b"\r\nContent-Type: application/x-pem-file"
            b"\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"Cache-Control: no-store\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        await writer.drain()
