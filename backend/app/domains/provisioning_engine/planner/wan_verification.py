"""Pure WAN verification evaluator (P7) — no device I/O.

Composes structured checks from an ``IspLink`` row plus the outcome of a
real ``IspService.ping_link`` call (or a captured error).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.domains.isp.constants import IspConnectionMode
from app.domains.isp.device_adapters import PingResult
from app.domains.isp.models import IspLink

from .constants import VerificationCheckStatus, WanVerificationOverall
from .schemas import VerificationCheck


@dataclass(frozen=True)
class WanLinkVerificationInput:
    link: IspLink
    slot: int
    ping: PingResult | None = None
    error_message: str | None = None


def _check(
    *,
    name: str,
    status: VerificationCheckStatus,
    observed: str | None = None,
    expected: str | None = None,
    detail: str | None = None,
    duration_ms: int = 0,
) -> VerificationCheck:
    return VerificationCheck(
        name=name,
        status=status,
        observed=observed,
        expected=expected,
        detail=detail,
        duration_ms=duration_ms,
    )


def evaluate_wan_link_verification(
    data: WanLinkVerificationInput,
) -> tuple[WanVerificationOverall, list[VerificationCheck]]:
    """Evaluate one WAN uplink and return overall status + checks."""
    link = data.link
    checks: list[VerificationCheck] = []

    if not link.is_enabled:
        checks.append(
            _check(
                name="link_enabled",
                status=VerificationCheckStatus.PASS,
                observed="disabled",
                expected="disabled",
                detail="Link is administratively disabled",
            )
        )
        return WanVerificationOverall.DISABLED, checks

    checks.append(
        _check(
            name="link_enabled",
            status=VerificationCheckStatus.PASS,
            observed="enabled",
            expected="enabled",
        )
    )

    if data.error_message:
        checks.append(
            _check(
                name="gateway_ping",
                status=VerificationCheckStatus.ERROR,
                detail=data.error_message,
            )
        )
        return WanVerificationOverall.ERROR, checks

    iface = link.routing_interface or link.interface
    mode = IspConnectionMode(link.connection_mode)
    if not iface:
        checks.append(
            _check(
                name="link_up",
                status=VerificationCheckStatus.ERROR,
                detail="No routing/legacy interface configured on this link",
            )
        )
        return WanVerificationOverall.ERROR, checks

    checks.append(
        _check(
            name="link_up",
            status=VerificationCheckStatus.PASS,
            observed=iface,
            expected="interface configured",
        )
    )

    ping = data.ping
    if ping is None:
        checks.append(
            _check(
                name="gateway_ping",
                status=VerificationCheckStatus.ERROR,
                detail="No ping result available",
            )
        )
        return WanVerificationOverall.ERROR, checks

    loss = ping.packet_loss_percentage
    latency = ping.avg_rtt_ms
    observed_ping = f"loss={loss}% latency={latency}ms"

    if mode is IspConnectionMode.PPPOE:
        if loss >= 100:
            checks.append(
                _check(
                    name="gateway_ping",
                    status=VerificationCheckStatus.ERROR,
                    observed=observed_ping,
                    expected="PPPoE session up",
                    detail="PPPoE virtual interface is down",
                )
            )
            return WanVerificationOverall.OFFLINE, checks
        checks.append(
            _check(
                name="gateway_ping",
                status=VerificationCheckStatus.PASS,
                observed=observed_ping,
                expected="PPPoE session up",
            )
        )
        checks.append(
            _check(
                name="address_acquired",
                status=VerificationCheckStatus.PASS,
                observed=iface,
                expected="PPPoE client running",
            )
        )
        return WanVerificationOverall.ONLINE, checks

    if loss >= 100 or ping.received == 0:
        checks.append(
            _check(
                name="gateway_ping",
                status=VerificationCheckStatus.ERROR,
                observed=observed_ping,
                expected="gateway reachable",
            )
        )
        return WanVerificationOverall.OFFLINE, checks

    if loss > 0 or (latency is not None and latency > 500):
        ping_status = VerificationCheckStatus.WARNING
        overall = WanVerificationOverall.ONLINE
    else:
        ping_status = VerificationCheckStatus.PASS
        overall = WanVerificationOverall.ONLINE

    checks.append(
        _check(
            name="gateway_ping",
            status=ping_status,
            observed=observed_ping,
            expected="low packet loss to gateway",
        )
    )

    if mode is IspConnectionMode.STATIC:
        addr_status = (
            VerificationCheckStatus.PASS
            if link.gateway_ip_address
            else VerificationCheckStatus.WARNING
        )
        checks.append(
            _check(
                name="address_acquired",
                status=addr_status,
                observed=link.gateway_ip_address,
                expected="static gateway configured",
            )
        )
    else:
        checks.append(
            _check(
                name="address_acquired",
                status=VerificationCheckStatus.PASS,
                observed="dhcp",
                expected="active default route",
            )
        )

    return overall, checks


def wan_verification_gate_passes(
    *,
    enabled_link_ids: set,
    runs: list,
) -> bool:
    """Hard gate (R8): every enabled WAN link's latest run must be ONLINE.

    ``runs`` must be the per-link rows from the router's most recent WAN
    ``run_group_id``. Disabled links are ignored.
    """
    if not enabled_link_ids:
        return False
    by_link = {run.isp_link_id: run for run in runs if run.isp_link_id is not None}
    for link_id in enabled_link_ids:
        run = by_link.get(link_id)
        if run is None:
            return False
        if run.overall != WanVerificationOverall.ONLINE.value:
            return False
    return True
