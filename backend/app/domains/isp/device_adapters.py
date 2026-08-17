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

* ``get_active_default_gateway`` -- for ``DHCP`` links. Reads
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

  **Static-route fallback (added 2026-08-17, fleet-wide production
  bug):** this platform's own Setup Script generator
  (``buildRouterSetupScriptChunks`` in cloudguest-foundation's
  ``RouterDetailTabs.tsx``) deliberately sets ``add-default-route=no``
  on every ``dhcp-client`` it creates and instead provisions a *static*
  ``0.0.0.0/0`` route with ``check-gateway=ping`` -- on purpose, to keep
  RouterOS's own dhcp-client-created dynamic route from fighting this
  platform's own routing-mark/failover mangle rules. That means a router
  provisioned exactly as this platform's own generator intends
  legitimately never has a ``dynamic=="true"`` default route, so
  ``dynamic=="true"``-only used to make every DHCP-mode link on every
  such router permanently, incorrectly report unavailable (confirmed
  fleet-wide in production, router "gurugram" -- see this method's own
  docstring, and ``wyfy_device_gateway.mikrotik_adapter
  ._select_default_gateway``, for the full incident writeup). When no
  dynamic default route exists, this now falls back to any other
  ``0.0.0.0/0`` route that is currently RouterOS-``active`` (not merely
  present -- ``active`` goes false the instant a ``check-gateway`` probe
  fails, so a genuinely down static gateway still correctly reports
  unavailable) and not administratively disabled. Still never filtered
  by interface name, for the identical reason above.
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

## Now delegates to wyfy-device-gateway

Per the ``wyfy-device-gateway`` PRD (section 7, Step 3, item 2),
``MikroTikIspHealthAdapter``'s methods (``ping``,
``get_active_default_gateway``, ``get_pppoe_interface_status``,
``get_interface_traffic_counters``, and ``run_speed_test`` -- the last
added later, for the on-demand "Run Speed Test" feature, not part of the
original migration) now call
``wyfy_device_gateway.registry.get_adapter(DeviceVendor.MIKROTIK)``
instead of opening ``librouteros`` directly -- that package is a straight
port of this module's own four ``_*_sync`` methods (same RouterOS
commands, same PPPoE stale-interface-name single-candidate fallback,
same never-filtered-by-interface default-gateway lookup, including its
dynamic-route-or-active-static-route fallback). ``ping`` is the
same gateway method ``network_diagnostics/device_adapters.py`` also
delegates to -- both call sites issue the identical real ``/tool/ping``
command. Public signatures/return shapes are unchanged; the gateway's
``MikroTikConnectionError``/``MikroTikDeviceError`` distinction is
translated back into this domain's own
``IspDeviceConnectionError``/``IspDeviceOperationError`` pair.

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

import logging
import re
from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.contract import DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import MikroTikConnectionError, MikroTikDeviceError
from wyfy_device_gateway.registry import get_adapter

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


@dataclass(frozen=True, slots=True)
class SpeedTestResult:
    """The real, measured result of one on-demand "Run Speed Test" action --
    see ``wyfy_device_gateway.mikrotik_adapter.MikroTikAdapter
    .run_speed_test``'s own docstring for exactly how this is measured
    (RouterOS ``/tool/fetch``) and confirmed against a real device. No
    ``upload_mbps`` field exists here on purpose -- no genuine method to
    measure real upload throughput against the public internet from this
    hardware class was found; a caller must never synthesize one."""

    download_mbps: float
    downloaded_bytes: int
    duration_seconds: float


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

    async def get_active_default_gateway(
        self, credentials: IspCredentials
    ) -> str | None:
        """Real, live lookup of the router's own currently-usable
        ``0.0.0.0/0`` gateway for a DHCP-mode link. Prefers a genuinely
        *dynamic* default route (RouterOS's own live DHCP-negotiated
        gateway); falls back to any other default route that is currently
        RouterOS-``active`` (not merely present -- a route whose
        ``check-gateway`` probe has failed is not ``active``, so a real
        outage still correctly resolves to unavailable) and not
        administratively disabled -- e.g. the static default route this
        platform's own Setup Script generator provisions in place of a
        dhcp-client's own dynamic route (see module docstring). ``None``
        only if no usable default route exists either way (e.g. the DHCP
        client hasn't leased yet and no static fallback exists)."""
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

    async def run_speed_test(
        self, credentials: IspCredentials, *, download_url: str
    ) -> SpeedTestResult:
        """Issues a real, on-demand download of ``download_url`` *from the
        router itself* and returns the genuine measured download
        throughput -- never a simulated/estimated number. See
        ``service.IspService.run_speed_test`` for the caller-side timeout
        sizing this genuinely slow, multi-second real action needs."""
        ...


class MikroTikIspHealthAdapter:
    """See module docstring for the "now delegates to wyfy-device-gateway"
    write-up."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: IspCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def ping(
        self,
        credentials: IspCredentials,
        *,
        target_ip: str,
        count: int,
        timeout_seconds: int,
    ) -> PingResult:
        creds = self._gateway_credentials(credentials)
        try:
            result = await get_adapter(DeviceVendor.MIKROTIK).ping(
                creds, target=target_ip, count=count, timeout_seconds=timeout_seconds
            )
        except MikroTikConnectionError as exc:
            raise IspDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise IspDeviceOperationError("ping", exc.detail) from exc
        return PingResult(
            sent=result.sent,
            received=result.received,
            packet_loss_percentage=result.packet_loss_percentage,
            avg_rtt_ms=result.avg_rtt_ms,
        )

    async def get_active_default_gateway(
        self, credentials: IspCredentials
    ) -> str | None:
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).get_active_default_gateway(
                creds
            )
        except MikroTikConnectionError as exc:
            raise IspDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise IspDeviceOperationError(
                "read_active_default_route", exc.detail
            ) from exc

    async def get_pppoe_interface_status(
        self, credentials: IspCredentials, *, interface_name: str
    ) -> bool:
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).get_pppoe_interface_status(
                creds, interface_name=interface_name
            )
        except MikroTikConnectionError as exc:
            raise IspDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise IspDeviceOperationError(
                "read_pppoe_interface_status", exc.detail
            ) from exc

    async def get_interface_traffic_counters(
        self, credentials: IspCredentials, *, interface_name: str
    ) -> tuple[int, int] | None:
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(
                DeviceVendor.MIKROTIK
            ).get_interface_traffic_counters(creds, interface_name=interface_name)
        except MikroTikConnectionError as exc:
            raise IspDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise IspDeviceOperationError(
                "read_interface_traffic_counters", exc.detail
            ) from exc

    async def run_speed_test(
        self, credentials: IspCredentials, *, download_url: str
    ) -> SpeedTestResult:
        creds = self._gateway_credentials(credentials)
        try:
            result = await get_adapter(DeviceVendor.MIKROTIK).run_speed_test(
                creds, download_url=download_url
            )
        except MikroTikConnectionError as exc:
            raise IspDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise IspDeviceOperationError("run_speed_test", exc.detail) from exc
        return SpeedTestResult(
            download_mbps=result.download_mbps,
            downloaded_bytes=result.downloaded_bytes,
            duration_seconds=result.duration_seconds,
        )


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
    "SpeedTestResult",
    "BaseIspHealthAdapter",
    "MikroTikIspHealthAdapter",
    "get_isp_health_adapter",
    "list_supported_isp_vendors",
]
