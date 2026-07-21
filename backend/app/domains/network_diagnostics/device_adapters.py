"""Real device I/O adapters for the Network Diagnostics domain -- the
Strategy/Adapter seam that keeps this domain's own core engine
(``service.py``) completely vendor-agnostic, mirroring
``app.domains.isp.device_adapters``'s identical shape almost exactly
(same ``librouteros`` dependency, same "one vendor registered today"
registry, same honest-about-being-unexercised-against-a-live-device
posture).

## Honest scope: real client code, never exercised end-to-end here

:class:`MikroTikDiagnosticsAdapter` issues genuine RouterOS API commands
-- ``/tool/ping`` and ``/tool/traceroute`` -- against an admin-supplied
target, via the exact same ``librouteros.connect(...)`` connection this
codebase's other MikroTik adapters already open. There is no live
MikroTik device anywhere in this sandbox -- if actually invoked here, it
raises a real :class:`~.exceptions.DiagnosticsDeviceConnectionError` the
moment it tries to open a real socket, never a fabricated result.

## ``ping``: identical logic to ``app.domains.isp.device_adapters``, not imported

``app.domains.isp.device_adapters.MikroTikIspHealthAdapter.ping`` already
implements this exact RouterOS command and reply-parsing correctly. That
logic (the command string, the "read the last cumulative row" parsing,
the RouterOS duration-string parser) is mirrored here rather than
imported at runtime -- Network Diagnostics is a router-generic tool, not
an ISP-WAN-link-specific one, so depending on ``app.domains.isp`` at
runtime for a capability that has nothing to do with ISP links would be
a real, if narrow, architectural mismatch (this domain would otherwise
need to construct/inject ISP's own credentials/adapter types for a
concept it doesn't share). Mirroring the parsing logic once, explaining
why here, is preferred over either duplicating it silently or importing
across an unrelated domain boundary.

## ``traceroute``: genuinely new -- no precedent anywhere in this codebase

A full-tree grep confirmed zero existing traceroute implementation. RouterOS's
own ``/tool/traceroute`` streams one reply row per completed probe,
updating a given hop's cumulative stats across several rows before
moving to the next hop (the same "repeated cumulative updates for one
target" shape ``/tool/ping`` uses, just per-hop instead of per-command).
:func:`_parse_traceroute_rows` collapses consecutive same-``address``
rows into one :class:`TracerouteHop` each, assigning hop numbers by
position in the reply stream (RouterOS's own traceroute does not number
hops as an explicit reply field) -- a defensible, honestly-described
interpretation of the real reply stream shape, not a fabricated one.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Protocol

import librouteros
from librouteros.exceptions import LibRouterosError

from .exceptions import (
    DiagnosticsDeviceConnectionError,
    DiagnosticsDeviceOperationError,
    UnsupportedDiagnosticsVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728

# RouterOS duration tokens: an integer immediately followed by one of these
# unit suffixes, e.g. "1ms200us", "850us", "2s", "1m30s" -- identical
# format app.domains.isp.device_adapters parses; mirrored here rather
# than imported (see module docstring).
_ROUTEROS_DURATION_TOKEN = re.compile(r"(\d+)(d|h|ms|us|s|m)")
_ROUTEROS_DURATION_UNIT_TO_MS: dict[str, float] = {
    "d": 86_400_000.0,
    "h": 3_600_000.0,
    "m": 60_000.0,
    "s": 1_000.0,
    "ms": 1.0,
    "us": 0.001,
}


@dataclass(frozen=True, slots=True)
class DiagnosticsCredentials:
    """What an adapter needs to open a real connection -- resolved by the
    caller from the target ``Router``'s own connection fields, mirroring
    ``app.domains.isp.device_adapters.IspCredentials`` exactly."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = 10


@dataclass(frozen=True, slots=True)
class PingResult:
    """The real, parsed result of one ``/tool/ping`` execution."""

    sent: int
    received: int
    packet_loss_percentage: float
    avg_rtt_ms: float | None


@dataclass(frozen=True, slots=True)
class TracerouteHop:
    """One hop's own final, cumulative state from a ``/tool/traceroute``
    execution. ``address`` is ``None`` for a hop that never responded."""

    hop_number: int
    address: str | None
    packet_loss_percentage: float
    avg_rtt_ms: float | None


@dataclass(frozen=True, slots=True)
class TracerouteResult:
    """The real, parsed result of one ``/tool/traceroute`` execution."""

    hops: list[TracerouteHop] = field(default_factory=list)


class BaseDiagnosticsAdapter(Protocol):
    """What a vendor implements to plug real ``ping``/``traceroute``
    execution into the Network Diagnostics domain. A new vendor is
    exactly: implement this Protocol, register it (mirrors
    ``app.domains.isp.device_adapters``'s own registry pattern)."""

    vendor: str

    async def ping(
        self,
        credentials: DiagnosticsCredentials,
        *,
        target: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        """Issues ``count`` real ICMP echoes at ``target`` *from the
        router itself* (not from this backend) and returns the parsed,
        cumulative result."""
        ...

    async def traceroute(
        self,
        credentials: DiagnosticsCredentials,
        *,
        target: str,
        max_hops: int,
        timeout_seconds: int,
    ) -> TracerouteResult:
        """Issues a real traceroute *from the router itself* toward
        ``target`` and returns the parsed, per-hop result."""
        ...


class MikroTikDiagnosticsAdapter:
    """See module docstring for the full "real client code, untested
    end-to-end here" write-up."""

    vendor = "mikrotik"

    async def ping(
        self,
        credentials: DiagnosticsCredentials,
        *,
        target: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        return await asyncio.to_thread(
            self._ping_sync, credentials, target, count, timeout_seconds
        )

    async def traceroute(
        self,
        credentials: DiagnosticsCredentials,
        *,
        target: str,
        max_hops: int,
        timeout_seconds: int,
    ) -> TracerouteResult:
        return await asyncio.to_thread(
            self._traceroute_sync, credentials, target, max_hops, timeout_seconds
        )

    def _connect_api(self, credentials: DiagnosticsCredentials):  # noqa: ANN202
        try:
            return librouteros.connect(
                host=credentials.host,
                username=credentials.username,
                password=credentials.password,
                port=credentials.api_port,
                timeout=credentials.timeout_seconds,
            )
        except (LibRouterosError, OSError) as exc:
            raise DiagnosticsDeviceConnectionError(credentials.host, str(exc)) from exc

    def _ping_sync(
        self,
        credentials: DiagnosticsCredentials,
        target: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        api = self._connect_api(credentials)
        try:
            rows = list(api("/tool/ping", address=target, count=str(count)))
        except LibRouterosError as exc:
            raise DiagnosticsDeviceOperationError("ping", str(exc)) from exc
        finally:
            api.close()
        return _parse_ping_rows(rows, requested_count=count)

    def _traceroute_sync(
        self,
        credentials: DiagnosticsCredentials,
        target: str,
        max_hops: int,
        timeout_seconds: int,
    ) -> TracerouteResult:
        api = self._connect_api(credentials)
        try:
            rows = list(
                api(
                    "/tool/traceroute",
                    address=target,
                    **{"max-hops": str(max_hops)},
                )
            )
        except LibRouterosError as exc:
            raise DiagnosticsDeviceOperationError("traceroute", str(exc)) from exc
        finally:
            api.close()
        return TracerouteResult(hops=_parse_traceroute_rows(rows))


def _parse_ping_rows(
    rows: list[dict[str, object]], *, requested_count: int
) -> PingResult:
    """Real RouterOS behavior: the last yielded row of a completed
    ``/tool/ping`` carries the cumulative ``sent``/``received``/
    ``packet-loss``/``avg-rtt`` fields -- identical parsing to
    ``app.domains.isp.device_adapters._parse_ping_rows`` (see module
    docstring for why mirrored, not imported). An empty ``rows`` list (no
    reply at all) is treated as total, 100% loss -- never silently
    reported as "no data"."""
    if not rows:
        return PingResult(
            sent=requested_count,
            received=0,
            packet_loss_percentage=100.0,
            avg_rtt_ms=None,
        )
    last = rows[-1]
    sent = _safe_int(last.get("sent"), default=requested_count)
    received = _safe_int(last.get("received"), default=0)
    packet_loss = _safe_float(last.get("packet-loss"), default=None)
    if packet_loss is None:
        packet_loss = 100.0 * (1 - received / sent) if sent else 100.0
    avg_rtt_ms = _parse_routeros_duration_ms(last.get("avg-rtt"))
    return PingResult(
        sent=sent,
        received=received,
        packet_loss_percentage=packet_loss,
        avg_rtt_ms=avg_rtt_ms,
    )


def _parse_traceroute_rows(rows: list[dict[str, object]]) -> list[TracerouteHop]:
    """See module docstring: collapses consecutive same-``address`` reply
    rows into one final :class:`TracerouteHop` each, numbering hops by
    position in the reply stream."""
    hops: list[TracerouteHop] = []
    current_address: object = object()  # sentinel matching no real address
    for row in rows:
        address = row.get("address") or None
        if address != current_address or not hops:
            hops.append(_build_hop(len(hops) + 1, row))
            current_address = address
        else:
            hops[-1] = _build_hop(hops[-1].hop_number, row)
    return hops


def _build_hop(hop_number: int, row: dict[str, object]) -> TracerouteHop:
    address = row.get("address")
    loss_default = 100.0 if not address else 0.0
    return TracerouteHop(
        hop_number=hop_number,
        address=str(address) if address else None,
        packet_loss_percentage=_safe_float(row.get("loss"), default=loss_default)
        or loss_default,
        avg_rtt_ms=_parse_routeros_duration_ms(row.get("avg")),
    )


def _safe_int(value: object, *, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _safe_float(value: object, *, default: float | None) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _parse_routeros_duration_ms(value: object) -> float | None:
    """Parses a RouterOS duration string (e.g. ``"1ms200us"``, ``"850us"``,
    ``"12ms"``, ``"2s"``) into a plain float of milliseconds. Returns
    ``None`` for anything empty/unparsable rather than raising."""
    if not value:
        return None
    text = str(value)
    total_ms = 0.0
    matched_any = False
    for amount, unit in _ROUTEROS_DURATION_TOKEN.findall(text):
        total_ms += int(amount) * _ROUTEROS_DURATION_UNIT_TO_MS[unit]
        matched_any = True
    return total_ms if matched_any else None


_DIAGNOSTICS_ADAPTERS: dict[str, BaseDiagnosticsAdapter] = {
    "mikrotik": MikroTikDiagnosticsAdapter()
}


def get_diagnostics_adapter(vendor: str) -> BaseDiagnosticsAdapter:
    """Raises :class:`~.exceptions.UnsupportedDiagnosticsVendorError` if
    no adapter is registered for ``vendor``."""
    adapter = _DIAGNOSTICS_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedDiagnosticsVendorError(vendor)
    return adapter


def list_supported_diagnostics_vendors() -> list[str]:
    return sorted(_DIAGNOSTICS_ADAPTERS)


__all__ = [
    "DiagnosticsCredentials",
    "PingResult",
    "TracerouteHop",
    "TracerouteResult",
    "BaseDiagnosticsAdapter",
    "MikroTikDiagnosticsAdapter",
    "get_diagnostics_adapter",
    "list_supported_diagnostics_vendors",
]
