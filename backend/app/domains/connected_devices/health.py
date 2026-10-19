"""Health verdict for one monitored device, from one sweep's observations.

Pure: no I/O, no clock. ``service.run_monitored_hardware_liveness_sweep``
gathers the facts (port link state from the router's LAN snapshot, the
ICMP/ARP probe) and asks :func:`judge` what they mean. Kept apart so the
state machine is testable as a table.

## States

* ``up``        -- answered this sweep.
* ``degraded``  -- answering, but its port flapped repeatedly in 24h; or it
                  just missed a probe and has not missed enough to be DOWN.
* ``down``      -- its port is link-down/disabled (immediately), or it
                  missed ``down_after`` probes in a row.
* ``unknown``   -- never judged (no health row yet). Not emitted here.

``is_active`` (what alerts and ``status`` read) is ``up`` or ``degraded``.
So a ``degraded``/``probe_failing`` device is still "up" to alerting -- that
is the debounce.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class HealthState(StrEnum):
    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"


class HealthReason(StrEnum):
    """Machine-readable; the console owns the words."""

    #: up: answered ICMP.
    ICMP = "icmp"
    #: up: ICMP silent, answered ARP from its own MAC.
    ARP = "arp"
    #: degraded: missed fewer than ``down_after`` probes in a row.
    PROBE_FAILING = "probe_failing"
    #: degraded: answering, but its port dropped link repeatedly in 24h.
    LINK_FLAPPING = "link_flapping"
    #: down: the router port it is plugged into has no link.
    PORT_LINK_DOWN = "port_link_down"
    #: down: that port is administratively disabled on the router.
    PORT_DISABLED = "port_disabled"
    #: down: port up (or unknown), ARP ping sent, no reply from its MAC.
    NO_ARP_REPLY = "no_arp_reply"
    #: down: no ICMP reply and no ARP ping was possible.
    NO_PING_REPLY = "no_ping_reply"
    #: down: the router has no trace of the MAC (bridge host, ARP, lease).
    NOT_ON_LAN = "not_on_lan"


UP_STATES = frozenset({HealthState.UP, HealthState.DEGRADED})


@dataclass(frozen=True, slots=True)
class Observation:
    """What one sweep learned about one device.

    ``port_running``/``port_disabled`` are ``None`` when the port is not
    known (no LAN snapshot, or the MAC was never seen on a bridge port).
    ``on_lan`` is ``None`` when the sweep had no reason to look it up (the
    probe answered)."""

    alive: bool
    method: HealthReason | None = None
    arp_attempted: bool = False
    on_lan: bool | None = None
    port_running: bool | None = None
    port_disabled: bool = False
    link_flaps_24h: int = 0


@dataclass(frozen=True, slots=True)
class Verdict:
    state: HealthState
    reason: HealthReason
    consecutive_failures: int

    @property
    def is_active(self) -> bool:
        return self.state in UP_STATES


def judge(
    *,
    previous_state: HealthState,
    previous_failures: int,
    observation: Observation,
    down_after: int,
    flap_threshold: int,
) -> Verdict:
    """``previous_state`` for a device with no health row yet is derived by
    the caller from ``ConnectedDevice.is_active`` (UP or DOWN), so a first
    failed probe on a row that was active debounces like any other."""
    obs = observation
    # An answer is direct evidence and outranks port facts: a port we only
    # *remember* the device on can be down because the device moved.
    if obs.alive:
        if obs.link_flaps_24h >= flap_threshold:
            return Verdict(HealthState.DEGRADED, HealthReason.LINK_FLAPPING, 0)
        return Verdict(HealthState.UP, obs.method or HealthReason.ICMP, 0)

    failures = previous_failures + 1
    # No answer and no link: physical, so no debounce.
    if obs.port_disabled:
        return Verdict(HealthState.DOWN, HealthReason.PORT_DISABLED, failures)
    if obs.port_running is False:
        return Verdict(HealthState.DOWN, HealthReason.PORT_LINK_DOWN, failures)
    if failures < down_after and previous_state in UP_STATES:
        return Verdict(HealthState.DEGRADED, HealthReason.PROBE_FAILING, failures)
    if obs.on_lan is False:
        reason = HealthReason.NOT_ON_LAN
    elif obs.arp_attempted:
        reason = HealthReason.NO_ARP_REPLY
    else:
        reason = HealthReason.NO_PING_REPLY
    return Verdict(HealthState.DOWN, reason, failures)


def coarse(state: HealthState | str) -> str:
    """The up/down axis "up since" / "down since" is measured on: a blip
    from up to degraded does not reset "up since"."""
    return "up" if HealthState(state) in UP_STATES else str(HealthState(state))


__all__ = [
    "HealthReason",
    "HealthState",
    "Observation",
    "UP_STATES",
    "Verdict",
    "coarse",
    "judge",
]
