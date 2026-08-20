"""IP subnet overlap detection (P9 / R6) — pure functions, no device I/O.

Compares desired guest/VLAN subnets against networks already present on the
router snapshot (``ip_addresses`` and non-default ``routes``) and against each
other. Any overlap yields a ``PlanConflict`` with ``BLOCKED`` status.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Protocol

from .constants import CompatibilityCheckStatus
from .schemas import PlanConflict


class SubnetSnapshotLike(Protocol):
    ip_addresses: list[Any] | None
    routes: list[Any] | None


def parse_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a RouterOS-style address or CIDR into an ``ipaddress`` network.

    Host bits may be set (e.g. ``192.168.1.1/24``) — ``strict=False`` matches
    how operators type addresses on MikroTik.
    """
    value = cidr.strip()
    if not value:
        raise ValueError("empty CIDR")
    if "/" not in value:
        parsed = ipaddress.ip_address(value)
        prefix = 128 if parsed.version == 6 else 32
        value = f"{value}/{prefix}"
    return ipaddress.ip_network(value, strict=False)


def networks_overlap(
    left: str,
    right: str,
) -> bool:
    """Return True when two CIDR strings represent overlapping networks."""
    return parse_network(left).overlaps(parse_network(right))


def _address_field(row: Any) -> str | None:
    if isinstance(row, dict):
        raw = row.get("address")
    else:
        raw = getattr(row, "address", None)
    if raw is None or raw == "":
        return None
    return str(raw)


def _route_dst(row: Any) -> str | None:
    if isinstance(row, dict):
        raw = row.get("dst_address") or row.get("dst-address")
    else:
        raw = getattr(row, "dst_address", None)
    if raw is None or raw == "":
        return None
    dst = str(raw)
    if dst in {"0.0.0.0/0", "::/0"}:
        return None
    return dst


def collect_snapshot_networks(
    snapshot: SubnetSnapshotLike,
) -> list[tuple[str, str]]:
    """Return ``(source_label, cidr)`` pairs from a snapshot."""
    networks: list[tuple[str, str]] = []
    for index, row in enumerate(snapshot.ip_addresses or []):
        address = _address_field(row)
        if address:
            networks.append((f"snapshot.ip_addresses[{index}]", address))
    for index, row in enumerate(snapshot.routes or []):
        dst = _route_dst(row)
        if dst:
            networks.append((f"snapshot.routes[{index}]", dst))
    return networks


def _conflict(
    *,
    left_label: str,
    left_cidr: str,
    right_label: str,
    right_cidr: str,
) -> PlanConflict:
    return PlanConflict(
        code="subnet_overlap",
        status=CompatibilityCheckStatus.BLOCKED,
        summary=f"Subnet overlap between {left_cidr} and {right_cidr}",
        detail=(
            f"{left_label} ({left_cidr}) overlaps {right_label} ({right_cidr})"
        ),
        cidrs=[left_cidr, right_cidr],
    )


def detect_subnet_conflicts(
    snapshot: SubnetSnapshotLike,
    *,
    desired_cidrs: list[str],
    desired_labels: list[str] | None = None,
) -> list[PlanConflict]:
    """Detect overlapping subnets (snapshot vs desired, and desired vs desired)."""
    if not desired_cidrs:
        return []

    labels = desired_labels or [
        f"desired[{index}]" for index in range(len(desired_cidrs))
    ]
    if len(labels) != len(desired_cidrs):
        raise ValueError("desired_labels length must match desired_cidrs")

    snapshot_networks = collect_snapshot_networks(snapshot)
    desired_networks = list(zip(labels, desired_cidrs, strict=True))
    conflicts: list[PlanConflict] = []
    seen: set[tuple[str, str, str, str]] = set()

    def _record(
        left_label: str,
        left_cidr: str,
        right_label: str,
        right_cidr: str,
    ) -> None:
        key = tuple(sorted((left_label, left_cidr, right_label, right_cidr)))
        if key in seen:
            return
        seen.add(key)
        conflicts.append(
            _conflict(
                left_label=left_label,
                left_cidr=left_cidr,
                right_label=right_label,
                right_cidr=right_cidr,
            )
        )

    for left_label, left_cidr in desired_networks:
        for right_label, right_cidr in desired_networks:
            if left_label >= right_label:
                continue
            if networks_overlap(left_cidr, right_cidr):
                _record(left_label, left_cidr, right_label, right_cidr)

    for desired_label, desired_cidr in desired_networks:
        for snap_label, snap_cidr in snapshot_networks:
            if networks_overlap(desired_cidr, snap_cidr):
                _record(desired_label, desired_cidr, snap_label, snap_cidr)

    return conflicts


__all__ = [
    "SubnetSnapshotLike",
    "parse_network",
    "networks_overlap",
    "collect_snapshot_networks",
    "detect_subnet_conflicts",
]
