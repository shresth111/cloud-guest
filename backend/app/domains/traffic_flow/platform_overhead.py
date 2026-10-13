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

* A hub endpoint stored as a **hostname**. It is not resolved here (no DNS
  lookup on the ingest or read path); list its addresses in the setting.
  ``unresolved_hosts`` names such hosts so the Master status can say so.
* A hub reached through an address the app does not know (a NAT in front of
  the hub, a changed address not yet in the table).
* Collector rows without protocol and ports (the first collector config):
  the tunnel shape cannot be matched; the in-tunnel shape still is.
* Other things the router does for itself -- NTP, its own DNS lookups --
  are the router's traffic but not to the platform. They stay client
  traffic and can still lead a quiet venue's list.

A venue's own WireGuard to somewhere else -- same protocol, very often the
same port -- is NOT matched: the address differs. That is why the port
alone is never enough.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "NO_PLATFORM_ENDPOINTS",
    "PLATFORM_OVERHEAD_NOTE",
    "PlatformEndpoints",
    "load_platform_endpoints",
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
class PlatformEndpoints:
    """The hub's WireGuard endpoints as (canonical address, UDP port)."""

    endpoints: frozenset[tuple[str, int]] = frozenset()
    #: Endpoint hosts that are names, not addresses: not matched (see the
    #: module docstring), reported instead of silently ignored.
    unresolved_hosts: tuple[str, ...] = ()

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
    servers: Iterable[tuple[Any, Any]], extra_addresses: Iterable[str] = ()
) -> PlatformEndpoints:
    """``servers``: (endpoint_host, endpoint_port) of every hub.
    ``extra_addresses``: further addresses of the same hubs (a hostname's
    addresses, a NAT's), each paired with every known endpoint port."""
    endpoints: set[tuple[str, int]] = set()
    unresolved: list[str] = []
    ports: set[int] = set()
    for host, port in servers:
        number = _port(port)
        if number is None:
            continue
        ports.add(number)
        canonical = _canonical(host)
        if canonical is None:
            text = str(host or "").strip()
            if text and text not in unresolved:
                unresolved.append(text)
            continue
        endpoints.add((canonical, number))
    for address in extra_addresses:
        canonical = _canonical(address)
        if canonical is None:
            continue
        for number in ports:
            endpoints.add((canonical, number))
    return PlatformEndpoints(frozenset(endpoints), tuple(unresolved))


async def load_platform_endpoints(session: Any, settings: Any) -> PlatformEndpoints:
    """The hub endpoints from ``wireguard_servers`` (the values rendered into
    every router's peer configuration) plus
    ``Settings.traffic_flow_platform_addresses``."""
    from sqlalchemy import select

    from app.domains.wireguard.models import WireGuardServer

    rows = (
        await session.execute(
            select(WireGuardServer.endpoint_host, WireGuardServer.endpoint_port).where(
                WireGuardServer.is_deleted.is_(False)
            )
        )
    ).all()
    extra = [
        part.strip()
        for part in str(
            getattr(settings, "traffic_flow_platform_addresses", "") or ""
        ).split(",")
        if part.strip()
    ]
    return platform_endpoints_from([(host, port) for host, port in rows], extra)


async def platform_endpoints_of(repository: Any, settings: Any) -> PlatformEndpoints:
    """The endpoints through whatever repository a service holds. A
    repository without the method (or a failing lookup) yields none: then
    nothing is recognised by address, and nothing is hidden by mistake."""
    loader = getattr(repository, "platform_endpoints", None)
    if loader is None:
        return NO_PLATFORM_ENDPOINTS
    found = await loader(settings)
    return found if isinstance(found, PlatformEndpoints) else NO_PLATFORM_ENDPOINTS
