"""Platform overhead: the router's own traffic to the platform.

A managed router keeps a WireGuard tunnel to the platform's hub. API
sessions, syslog and the flow export itself ride inside it. The router
accounts that traffic like any other, so without this module an idle venue
reads as "mostly UDP/<the tunnel port>" for ever -- and a customer is shown
the tunnel, which no customer surface may show.

It is not the venue's traffic. It is counted (the bytes are real and the
Master console shows them as their own line) and kept out of every share,
total, list and finding.

## What is recognised, in a collector row

Two shapes, both exact matches on values the app already holds. Nothing is
a port-only guess, and no address is written in this repository.

* **Inside the tunnel.** One end of the row IS the exporter: its address
  equals the row's own ``peer_ip_src``, which is the router's tunnel
  address (WireGuard binds it to the router's key). Needs no configuration.
* **The tunnel itself.** UDP between the router's WAN side and a hub
  WireGuard endpoint: one end's address and port equal a
  ``wireguard_servers`` row's ``endpoint_host`` and ``endpoint_port`` -- the
  very values rendered into the router's peer configuration -- or an address
  listed in ``Settings.traffic_flow_platform_addresses``.

## What it misses, on purpose or not

* A hub endpoint stored as a **hostname** that has never resolved. Names
  are resolved by the pull sweep (see "Hostnames" below), never on a
  request or per row; until the first answer the tunnel shape is not
  matched for that hub, and ``unresolved_hosts`` names it so the Master
  status can say so.
* A hub reached through an address the app does not know (a NAT in front of
  the hub, a changed address not yet in the table).
* Collector rows without protocol and ports (the first collector config):
  the tunnel shape cannot be matched; the in-tunnel shape still is.
* Other things the router does for itself -- NTP, its own DNS lookups --
  are the router's traffic but not to the platform. They stay client
  traffic and can still lead a quiet venue's list.

## Hostnames

``endpoint_host`` is often a name. The pull sweep resolves each active
hub's name (A and AAAA) at most once per ``PLATFORM_HOST_TTL_SECONDS`` and
stores the answer on the ingest-state row, where every process reads it:
the sweep's own ingest and the API's reads alike. So there is no lookup per
request and none per row, and a read never waits on DNS.

A failed lookup keeps the last good answer -- for as long as it keeps
failing -- and records the error and the time beside it. An answer is only
ever replaced by another answer. ``Settings.traffic_flow_platform_addresses``
is added on top as an override; it is normally empty.

A venue's own WireGuard to somewhere else -- same protocol, very often the
same port -- is NOT matched: the address differs. That is why the port
alone is never enough.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

#: A stored answer older than this is looked up again by the next sweep.
PLATFORM_HOST_TTL_SECONDS = 600
#: One lookup may take this long; then it counts as failed and the sweep
#: goes on with what it had.
PLATFORM_HOST_LOOKUP_TIMEOUT_SECONDS = 3.0

__all__ = [
    "NO_PLATFORM_ENDPOINTS",
    "PLATFORM_OVERHEAD_NOTE",
    "PlatformEndpoints",
    "PLATFORM_HOST_TTL_SECONDS",
    "HostResolution",
    "load_platform_endpoints",
    "refresh_platform_hosts",
    "refreshed_hosts",
    "resolve_host",
    "platform_endpoints_from",
    "platform_endpoints_of",
]

PROTOCOL_UDP = 17

#: The one sentence a screen may show. No tunnel, no protocol, no port.
PLATFORM_OVERHEAD_NOTE = (
    "Traffic the router exchanges with Wyfy to be managed is not counted."
)


def _canonical(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _is_udp(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, int):
        return value == PROTOCOL_UDP
    text = str(value).strip().lower()
    return text in {"udp", str(PROTOCOL_UDP)}


def _port(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class HostResolution:
    """What the sweep last learned about one hub hostname."""

    host: str
    addresses: tuple[str, ...] = ()
    #: When ``addresses`` were answered. ``None``: never resolved.
    resolved_at: datetime | None = None
    #: The last attempt, successful or not.
    attempted_at: datetime | None = None
    #: Why the last attempt failed; ``None`` after a success.
    last_error: str | None = None


def _instant(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def host_resolutions(stored: Any) -> dict[str, HostResolution]:
    """The ingest-state row's ``platform_hosts`` JSON as records. Anything
    malformed reads as "nothing held", never as an address."""
    out: dict[str, HostResolution] = {}
    if not isinstance(stored, Mapping):
        return out
    for host, entry in stored.items():
        if not isinstance(entry, Mapping):
            continue
        addresses = tuple(
            dict.fromkeys(
                canonical
                for canonical in map(_canonical, entry.get("addresses") or [])
                if canonical is not None
            )
        )
        out[str(host)] = HostResolution(
            host=str(host),
            addresses=addresses,
            resolved_at=_instant(entry.get("resolved_at")) if addresses else None,
            attempted_at=_instant(entry.get("attempted_at")),
            last_error=str(entry["last_error"]) if entry.get("last_error") else None,
        )
    return out


def _stored(resolution: HostResolution) -> dict[str, Any]:
    return {
        "addresses": list(resolution.addresses),
        "resolved_at": resolution.resolved_at.isoformat()
        if resolution.resolved_at
        else None,
        "attempted_at": resolution.attempted_at.isoformat()
        if resolution.attempted_at
        else None,
        "last_error": resolution.last_error,
    }


async def resolve_host(host: str) -> list[str]:
    """A and AAAA for ``host``, through the system resolver, off the event
    loop and bounded in time. Raises on failure or timeout."""
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, None, type=socket.SOCK_DGRAM),
        timeout=PLATFORM_HOST_LOOKUP_TIMEOUT_SECONDS,
    )
    return [str(info[4][0]) for info in infos]


async def refreshed_hosts(
    stored: Any,
    hosts: Iterable[str],
    *,
    now: datetime,
    resolver: Callable[[str], Awaitable[Iterable[str]]] = resolve_host,
    ttl_seconds: int = PLATFORM_HOST_TTL_SECONDS,
) -> dict[str, Any]:
    """``stored`` brought up to date for ``hosts`` (the names of the active
    hubs), as the JSON to store.

    * A host answered less than ``ttl_seconds`` ago is not looked up.
    * A lookup that fails, times out or returns no usable address keeps the
      addresses already held and records the error.
    * A host no longer among ``hosts`` is dropped.
    Never raises: whatever the resolver does, the sweep goes on."""
    held = host_resolutions(stored)
    out: dict[str, Any] = {}
    for host in dict.fromkeys(str(h).strip() for h in hosts):
        if not host or _canonical(host) is not None:
            continue  # an address needs no lookup
        current = held.get(host, HostResolution(host=host))
        fresh = (
            current.attempted_at is not None
            and (now - current.attempted_at).total_seconds() < ttl_seconds
        )
        if fresh:
            out[host] = _stored(current)
            continue
        try:
            answered = tuple(
                dict.fromkeys(
                    canonical
                    for canonical in map(_canonical, await resolver(host))
                    if canonical is not None
                )
            )
            error = None if answered else "no address in the answer"
        except Exception as exc:  # noqa: BLE001 -- recorded; the sweep must go on
            answered = ()
            error = f"{type(exc).__name__}: {exc}"[:200].rstrip(": ")
        if answered:
            current = HostResolution(
                host=host,
                addresses=tuple(sorted(answered)),
                resolved_at=now,
                attempted_at=now,
            )
        else:
            # Keep the last good answer; say that this attempt failed.
            current = HostResolution(
                host=host,
                addresses=current.addresses,
                resolved_at=current.resolved_at,
                attempted_at=now,
                last_error=error,
            )
        out[host] = _stored(current)
    return out


async def refresh_platform_hosts(
    repository: Any,
    *,
    now: datetime,
    resolver: Callable[[str], Awaitable[Iterable[str]]] = resolve_host,
) -> bool:
    """Run by the pull sweep, before it reads the endpoints. Looks up what
    is due and stores it on the ingest-state row (the caller's commit saves
    it). Returns whether anything changed. A repository that cannot list the
    hubs, or any failure at all, changes nothing."""
    list_hosts = getattr(repository, "platform_server_hosts", None)
    get_state = getattr(repository, "get_state", None)
    if list_hosts is None or get_state is None:
        return False
    try:
        hosts = await list_hosts()
        state = await get_state()
        before = getattr(state, "platform_hosts", None) or {}
        after = await refreshed_hosts(before, hosts, now=now, resolver=resolver)
    except Exception:  # noqa: BLE001 -- DNS must never stop an ingest
        return False
    if after == before:
        return False
    # A new object, so the JSON column is seen as changed.
    state.platform_hosts = after
    return True


@dataclass(frozen=True, slots=True)
class PlatformEndpoints:
    """The hub's WireGuard endpoints as (canonical address, UDP port)."""

    endpoints: frozenset[tuple[str, int]] = frozenset()
    #: Endpoint hosts that are names and have NEVER resolved: not matched
    #: (see the module docstring), reported instead of silently ignored.
    unresolved_hosts: tuple[str, ...] = ()
    #: What is held for every hub that is a name, resolved or not.
    hosts: tuple[HostResolution, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.endpoints)

    @property
    def addresses(self) -> frozenset[str]:
        return frozenset(address for address, _port_number in self.endpoints)

    def is_endpoint(self, address: Any, protocol: Any, port: Any) -> bool:
        """An outside end that is the hub's tunnel endpoint: UDP, this
        address AND this port."""
        if not self.endpoints or not _is_udp(protocol):
            return False
        canonical = _canonical(address)
        number = _port(port)
        return (
            canonical is not None
            and number is not None
            and (canonical, number) in self.endpoints
        )

    def row_direction(self, row: Mapping[str, Any]) -> str | None:
        """``"up"`` (router to platform) or ``"down"`` when the collector
        row is platform overhead, else ``None``.

        In-tunnel first: it needs nothing but the row."""
        exporter = _canonical(row.get("peer_ip_src"))
        src = _canonical(row.get("ip_src"))
        dst = _canonical(row.get("ip_dst"))
        if exporter is not None:
            if src == exporter:
                return "up"
            if dst == exporter:
                return "down"
        protocol = row.get("ip_proto")
        if self.is_endpoint(dst, protocol, row.get("port_dst")):
            return "up"
        if self.is_endpoint(src, protocol, row.get("port_src")):
            return "down"
        return None

    def bucket_condition(self, model: Any) -> Any | None:
        """SQL: this bucket row (``remote_address``, ``protocol``,
        ``remote_port``) is the tunnel to the hub. ``None`` when no endpoint
        is known -- then nothing can be recognised, and nothing is hidden."""
        if not self.endpoints:
            return None
        from sqlalchemy import and_, cast, literal, or_
        from sqlalchemy.dialects.postgresql import INET

        return and_(
            model.protocol == PROTOCOL_UDP,
            or_(
                *[
                    and_(
                        model.remote_address == cast(literal(address), INET),
                        model.remote_port == port,
                    )
                    for address, port in sorted(self.endpoints)
                ]
            ),
        )

    def record_condition(self, model: Any) -> Any | None:
        """SQL: this flow record (source and destination with their ports)
        is the tunnel to the hub, in either direction."""
        if not self.endpoints:
            return None
        from sqlalchemy import and_, cast, literal, or_
        from sqlalchemy.dialects.postgresql import INET

        ends = []
        for address, port in sorted(self.endpoints):
            host = cast(literal(address), INET)
            ends.append(and_(model.dst_address == host, model.dst_port == port))
            ends.append(and_(model.src_address == host, model.src_port == port))
        return and_(model.protocol == PROTOCOL_UDP, or_(*ends))


NO_PLATFORM_ENDPOINTS = PlatformEndpoints()


def platform_endpoints_from(
    servers: Iterable[tuple[Any, Any]],
    extra_addresses: Iterable[str] = (),
    resolved: Any = None,
) -> PlatformEndpoints:
    """``servers``: (endpoint_host, endpoint_port) of every hub.
    ``resolved``: the stored lookups (``platform_hosts``) for hubs that are
    names. ``extra_addresses``: the override setting -- further addresses of
    the same hubs, each paired with every known endpoint port."""
    held = host_resolutions(resolved)
    endpoints: set[tuple[str, int]] = set()
    unresolved: list[str] = []
    named: dict[str, HostResolution] = {}
    ports: set[int] = set()
    for host, port in servers:
        number = _port(port)
        if number is None:
            continue
        ports.add(number)
        canonical = _canonical(host)
        if canonical is not None:
            endpoints.add((canonical, number))
            continue
        text = str(host or "").strip()
        if not text:
            continue
        resolution = held.get(text, HostResolution(host=text))
        named[text] = resolution
        for address in resolution.addresses:
            endpoints.add((address, number))
        if not resolution.addresses and text not in unresolved:
            unresolved.append(text)
    for address in extra_addresses:
        canonical = _canonical(address)
        if canonical is None:
            continue
        for number in ports:
            endpoints.add((canonical, number))
    return PlatformEndpoints(
        frozenset(endpoints), tuple(unresolved), tuple(named.values())
    )


def _active_servers_statement() -> Any:
    from sqlalchemy import select

    from app.domains.wireguard.models import WireGuardServer

    return select(WireGuardServer.endpoint_host, WireGuardServer.endpoint_port).where(
        WireGuardServer.is_deleted.is_(False), WireGuardServer.is_active.is_(True)
    )


async def load_platform_server_hosts(session: Any) -> list[str]:
    """``endpoint_host`` of every active hub (names and addresses alike)."""
    rows = (await session.execute(_active_servers_statement())).all()
    return [str(host) for host, _port_number in rows if host]


async def load_platform_endpoints(session: Any, settings: Any) -> PlatformEndpoints:
    """The active hubs' endpoints from ``wireguard_servers`` (the values
    rendered into every router's peer configuration), with names replaced by
    what the sweep last resolved them to, plus the override setting. Two
    reads of the database; no DNS."""
    from .models import TrafficFlowIngestState

    rows = (await session.execute(_active_servers_statement())).all()
    state = await session.get(TrafficFlowIngestState, 1)
    extra = [
        part.strip()
        for part in str(
            getattr(settings, "traffic_flow_platform_addresses", "") or ""
        ).split(",")
        if part.strip()
    ]
    return platform_endpoints_from(
        [(host, port) for host, port in rows],
        extra,
        getattr(state, "platform_hosts", None),
    )


async def platform_endpoints_of(repository: Any, settings: Any) -> PlatformEndpoints:
    """The endpoints through whatever repository a service holds. A
    repository without the method (or a failing lookup) yields none: then
    nothing is recognised by address, and nothing is hidden by mistake."""
    loader = getattr(repository, "platform_endpoints", None)
    if loader is None:
        return NO_PLATFORM_ENDPOINTS
    found = await loader(settings)
    return found if isinstance(found, PlatformEndpoints) else NO_PLATFORM_ENDPOINTS
