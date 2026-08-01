"""Real device I/O adapters for the ISP Management domain -- the
Strategy/Adapter seam that keeps this domain's own core engine
(``service.py``) completely vendor-agnostic, mirroring
``app.domains.queue_management.device_adapters``'s identical shape almost
exactly (same ``librouteros`` dependency, same "one vendor registered
today" registry, same honest-about-being-unexercised-against-a-live-device
posture -- see that module's own docstring for the full "why this
dependency, why no live device here" write-up this one shares).

## Honest scope: real client code, never exercised end-to-end here

:class:`MikroTikIspHealthAdapter` issues a genuine RouterOS API command --
``/tool/ping`` -- against the target IP (a link's own
``gateway_ip_address``), via the exact same ``librouteros.connect(...)``
connection this codebase's other MikroTik adapters already open. There is
no live MikroTik device anywhere in this sandbox -- if actually invoked
here, it raises a real :class:`~.exceptions.IspDeviceConnectionError` the
moment it tries to open a real socket, never a fabricated ping result.

## ``/tool/ping`` via the raw ``Api`` callable, not a ``Path``

Every other adapter in this codebase (``queue_management``,
``provisioning_engine``) only ever calls ``.add``/``.update``/``.remove``/
iterates a `Path` menu (``api.path("queue", "simple")``) -- all CRUD
operations against a stable RouterOS *menu*. ``/tool/ping`` is not a menu
CRUD operation; it is a one-shot RouterOS *command* invocation. Confirmed
directly against the installed ``librouteros`` package's own source
(``site-packages/librouteros/api.py``): ``Api.__call__(self, cmd: str,
**kwargs)`` is a generator that writes ``cmd`` as a raw sentence and yields
each reply row -- the correct, library-native way to invoke a bare command
word like ``"/tool/ping"`` that isn't scoped under a menu's own
``add``/``set``/``remove``. This module is the first call site in this
codebase to use that raw form (rather than ``.path(...)``), documented
here rather than silently copied without explanation.

## Parsing a real RouterOS ping reply

A RouterOS API ``/tool/ping`` call (given ``count=N``) yields one reply
sentence per echo attempt, each carrying cumulative ``sent``/``received``/
``packet-loss``/``avg-rtt`` fields that update as probes complete -- this
adapter reads the **last** yielded row (the final, cumulative tally) for
those four fields, mirroring
``device_adapters.MikroTikQueueAdapter._read_status_sync``'s own
"iterate the full reply, take what's needed" convention.
``avg-rtt``/``min-rtt``/``max-rtt`` are RouterOS duration strings (e.g.
``"1ms200us"``, ``"850us"``, ``"12ms"``) -- ``_parse_routeros_duration_ms``
is a small, real parser for that specific format (RouterOS never emits
plain ISO-8601 durations here), not a generic duration library.

## DHCP/PPPOE: real target *discovery*, not a manually-typed value

A real WAN uplink is one of three connection modes (see
``constants.IspConnectionMode``), and only ``STATIC`` ever has a fixed
gateway IP an admin can type in ahead of time:

* ``get_dynamic_default_gateway`` -- for ``DHCP`` links. Reads
  ``/ip/route`` (a stable RouterOS *menu*, so the established
  ``.path(*segments)`` + client-side filter form is used here, exactly
  like ``MikroTikQueueAdapter._read_status_sync``'s own precedent --
  unlike ``/tool/ping``, this is real menu CRUD/print, not a one-shot
  command) and returns the ``gateway`` field of whichever row has
  ``dst-address == "0.0.0.0/0"`` and ``dynamic == "true"`` -- RouterOS's
  own real, live representation of "the gateway my DHCP client actually
  negotiated right now." Deliberately never filtered by interface name:
  a router has at most one live default route regardless of how many
  interfaces exist, and filtering by this link's own (possibly stale --
  interfaces get renamed on the router independently of this platform)
  ``interface`` field would only add a real failure mode for no real
  benefit.
* ``get_pppoe_interface_status`` -- for ``PPPOE`` links. Reads
  ``/interface/pppoe-client`` the same way and reports whether the named
  interface is up (``running == "true"`` and ``disabled != "true"``).
  Unlike the route lookup above, this genuinely needs to know *which*
  interface -- but a renamed/stale ``IspLink.interface`` value is a real,
  expected failure mode (an admin renames interfaces on the router
  without this platform ever being told), so an exact-name miss falls
  back to the router's own single PPPoE interface when there is exactly
  one, rather than hard-failing on a name mismatch alone. Genuine
  ambiguity (zero or multiple candidates with no exact match) still
  raises rather than guessing.

## Traffic load: raw counters here, rate computed in ``service.py``

``get_interface_traffic_counters`` reads ``/interface``'s own
``rx-byte``/``tx-byte`` fields for a link's own ``interface`` -- real,
cumulative-since-last-reset counters RouterOS already tracks on every
interface, always present (unlike ``/interface monitor-traffic``, a
streaming/blocking command genuinely unsuited to a periodic poll -- this
module never uses it). This adapter returns one snapshot; turning two
successive snapshots into a Mbps rate is ``IspService
.sample_link_traffic``'s job, mirroring ``app.domains.guest.service``'s
own "store the counter, compute the delta against the previous reading"
convention. This holds uniformly for STATIC/DHCP/PPPOE alike -- for a
PPPOE link, ``interface`` names the PPPoE client's own virtual interface
(e.g. ``"pppoe-out1"``), which RouterOS gives independent counters
reflecting only the traffic actually inside that PPP tunnel, not the
underlying physical port's raw counters (which would double-count
encapsulation overhead and any other traffic sharing that port).
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Protocol

import librouteros
from librouteros.exceptions import LibRouterosError

from .exceptions import (
    IspDeviceConnectionError,
    IspDeviceOperationError,
    UnsupportedIspVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728

# RouterOS duration tokens: an integer immediately followed by one of these
# unit suffixes, e.g. "1ms200us", "850us", "2s", "1m30s". Order matters --
# "ms" must be tried before "s" alone, since "ms" itself ends in "s".
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
class IspCredentials:
    """What an adapter needs to open a real connection -- resolved by the
    caller from the target ``Router``'s own connection fields, mirroring
    ``app.domains.queue_management.device_adapters.QueueCredentials``
    exactly."""

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


class BaseIspHealthAdapter(Protocol):
    """What a vendor implements to plug a real WAN-link health check into
    the ISP Management domain. A new vendor is exactly: implement this
    Protocol, register it (mirrors
    ``app.domains.queue_management.device_adapters``'s own registry
    pattern)."""

    vendor: str

    async def ping(
        self,
        credentials: IspCredentials,
        *,
        target_ip: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        """Issues ``count`` real ICMP echoes at ``target_ip`` *from the
        router itself* (not from this backend) and returns the parsed,
        cumulative result."""
        ...

    async def get_dynamic_default_gateway(
        self, credentials: IspCredentials
    ) -> str | None:
        """Real, live lookup of the router's own current DHCP-negotiated
        default gateway -- ``None`` if no dynamic default route currently
        exists (e.g. the DHCP client hasn't leased yet). See module
        docstring."""
        ...

    async def get_pppoe_interface_status(
        self, credentials: IspCredentials, *, interface_name: str
    ) -> bool:
        """Whether the named PPPoE client interface is really up right
        now (``running`` and not ``disabled``). See module docstring for
        the stale-interface-name fallback."""
        ...

    async def get_interface_traffic_counters(
        self, credentials: IspCredentials, *, interface_name: str
    ) -> tuple[int, int] | None:
        """Real, cumulative ``(rx_bytes, tx_bytes)`` counters for the
        named interface right now -- ``None`` if no interface with that
        name exists on the router. A single snapshot, never a rate (the
        caller computes the rate from two successive snapshots -- see
        module docstring)."""
        ...


class MikroTikIspHealthAdapter:
    """See module docstring for the full "real client code, untested
    end-to-end here" write-up."""

    vendor = "mikrotik"

    async def ping(
        self,
        credentials: IspCredentials,
        *,
        target_ip: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        return await asyncio.to_thread(
            self._ping_sync, credentials, target_ip, count, timeout_seconds
        )

    def _connect_api(self, credentials: IspCredentials):  # noqa: ANN202
        try:
            return librouteros.connect(
                host=credentials.host,
                username=credentials.username,
                password=credentials.password,
                port=credentials.api_port,
                timeout=credentials.timeout_seconds,
            )
        except (LibRouterosError, OSError) as exc:
            raise IspDeviceConnectionError(credentials.host, str(exc)) from exc

    def _ping_sync(
        self,
        credentials: IspCredentials,
        target_ip: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        api = self._connect_api(credentials)
        try:
            rows = list(api("/tool/ping", address=target_ip, count=str(count)))
        except LibRouterosError as exc:
            raise IspDeviceOperationError("ping", str(exc)) from exc
        finally:
            api.close()
        return _parse_ping_rows(rows, requested_count=count)

    async def get_dynamic_default_gateway(
        self, credentials: IspCredentials
    ) -> str | None:
        return await asyncio.to_thread(
            self._get_dynamic_default_gateway_sync, credentials
        )

    def _get_dynamic_default_gateway_sync(
        self, credentials: IspCredentials
    ) -> str | None:
        api = self._connect_api(credentials)
        try:
            # `/ip/route` is a real menu (not a one-shot command like
            # `/tool/ping`), so this uses the same `.path(*segments)` +
            # client-side filter form `MikroTikQueueAdapter
            # ._read_status_sync` already establishes -- a router's own
            # routing table is small, so a full print + filter is a real,
            # correct, easily-testable-via-fake-transport choice, not a
            # shortcut. See module docstring for why this is never
            # filtered by interface.
            rows = list(api.path("ip", "route"))
        except LibRouterosError as exc:
            raise IspDeviceOperationError(
                "read_dynamic_default_route", str(exc)
            ) from exc
        finally:
            api.close()
        for row in rows:
            if (
                row.get("dst-address") == "0.0.0.0/0"
                and str(row.get("dynamic", "false")).lower() == "true"
            ):
                gateway = row.get("gateway")
                return str(gateway) if gateway else None
        return None

    async def get_pppoe_interface_status(
        self, credentials: IspCredentials, *, interface_name: str
    ) -> bool:
        return await asyncio.to_thread(
            self._get_pppoe_interface_status_sync, credentials, interface_name
        )

    def _get_pppoe_interface_status_sync(
        self, credentials: IspCredentials, interface_name: str
    ) -> bool:
        api = self._connect_api(credentials)
        try:
            rows = list(api.path("interface", "pppoe-client"))
        except LibRouterosError as exc:
            raise IspDeviceOperationError(
                "read_pppoe_interface_status", str(exc)
            ) from exc
        finally:
            api.close()
        row = next((r for r in rows if r.get("name") == interface_name), None)
        if row is None and len(rows) == 1:
            # Exact-name miss but exactly one real PPPoE client interface
            # exists on this router -- almost certainly the same
            # interface under a name this platform's own stored
            # `IspLink.interface` hasn't caught up with (renamed directly
            # on the router). See module docstring: a real, expected
            # staleness case, not guessed data -- we still read that one
            # real interface's own live state, never fabricate a result.
            logger.warning(
                "isp_pppoe_interface_name_mismatch_fallback",
                extra={
                    "requested_interface": interface_name,
                    "actual_interface": rows[0].get("name"),
                },
            )
            row = rows[0]
        if row is None:
            raise IspDeviceOperationError(
                "read_pppoe_interface_status",
                f"no PPPoE client interface named '{interface_name}' found "
                f"(and {len(rows)} candidates exist, too ambiguous to guess)",
            )
        running = str(row.get("running", "false")).lower() == "true"
        disabled = str(row.get("disabled", "false")).lower() == "true"
        return running and not disabled

    async def get_interface_traffic_counters(
        self, credentials: IspCredentials, *, interface_name: str
    ) -> tuple[int, int] | None:
        return await asyncio.to_thread(
            self._get_interface_traffic_counters_sync, credentials, interface_name
        )

    def _get_interface_traffic_counters_sync(
        self, credentials: IspCredentials, interface_name: str
    ) -> tuple[int, int] | None:
        api = self._connect_api(credentials)
        try:
            # `/interface` (real menu, same `.path(*segments)` + client-
            # side filter form as the two lookups above) -- every real
            # interface row RouterOS returns already carries its own
            # cumulative `rx-byte`/`tx-byte` counters, no separate
            # "stats" mode needed over the API.
            rows = list(api.path("interface"))
        except LibRouterosError as exc:
            raise IspDeviceOperationError(
                "read_interface_traffic_counters", str(exc)
            ) from exc
        finally:
            api.close()
        row = next((r for r in rows if r.get("name") == interface_name), None)
        if row is None:
            return None
        rx_bytes = _safe_int(row.get("rx-byte"), default=0)
        tx_bytes = _safe_int(row.get("tx-byte"), default=0)
        return rx_bytes, tx_bytes


def _parse_ping_rows(
    rows: list[dict[str, object]], *, requested_count: int
) -> PingResult:
    """Real RouterOS behavior: the last yielded row of a completed
    ``/tool/ping`` carries the cumulative ``sent``/``received``/
    ``packet-loss``/``avg-rtt`` fields. An empty ``rows`` list (no reply at
    all -- e.g. the device itself never answered) is treated as a total,
    100% loss -- never silently reported as "no data" (mirrors
    ``validators.classify_health_status``'s own "a missing reading is
    never assumed fine" posture)."""
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
    ``None`` for anything empty/unparsable rather than raising -- a
    missing/odd ``avg-rtt`` must never crash a health check that otherwise
    has a perfectly good ``sent``/``received`` tally."""
    if not value:
        return None
    text = str(value)
    total_ms = 0.0
    matched_any = False
    for amount, unit in _ROUTEROS_DURATION_TOKEN.findall(text):
        total_ms += int(amount) * _ROUTEROS_DURATION_UNIT_TO_MS[unit]
        matched_any = True
    return total_ms if matched_any else None


_ISP_HEALTH_ADAPTERS: dict[str, BaseIspHealthAdapter] = {
    "mikrotik": MikroTikIspHealthAdapter()
}


def get_isp_health_adapter(vendor: str) -> BaseIspHealthAdapter:
    """Raises :class:`~.exceptions.UnsupportedIspVendorError` if no adapter
    is registered for ``vendor``."""
    adapter = _ISP_HEALTH_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedIspVendorError(vendor)
    return adapter


def list_supported_isp_vendors() -> list[str]:
    return sorted(_ISP_HEALTH_ADAPTERS)


__all__ = [
    "IspCredentials",
    "PingResult",
    "BaseIspHealthAdapter",
    "MikroTikIspHealthAdapter",
    "get_isp_health_adapter",
    "list_supported_isp_vendors",
]
