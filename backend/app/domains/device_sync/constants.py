"""Enumerations for the Device Synchronization domain.

Stored as plain ``String`` values inside ``DeviceSyncRun
.component_results`` (a JSONB column), never a native PostgreSQL enum
type -- the same reason every other domain in this codebase documents.
"""

from __future__ import annotations

from enum import StrEnum


class SyncComponent(StrEnum):
    """Every component a sync run reports on -- see module docstring for
    which three are real device operations and which three are honestly
    reported as not-yet-provisioned."""

    CONNECTED_DEVICES = "connected_devices"
    QUEUE_MANAGEMENT = "queue_management"
    PROVISIONING = "provisioning"
    DHCP = "dhcp"
    VLAN = "vlan"
    PORT_FORWARDING = "port_forwarding"


class SyncComponentStatus(StrEnum):
    """One component's own outcome within a single sync run."""

    SUCCESS = "success"
    FAILED = "failed"
    NO_JOBS = "no_jobs"
    NOT_PROVISIONED = "not_provisioned"


class SyncRunStatus(StrEnum):
    """The overall outcome of one sync run, computed from its own
    ``component_results`` -- see ``validators.compute_overall_status``."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


# Components with no real device push in this codebase today --
# always reported SyncComponentStatus.NOT_PROVISIONED, never counted
# against overall SUCCESS/FAILED (see validators.compute_overall_status).
UNPROVISIONED_COMPONENTS: frozenset[SyncComponent] = frozenset(
    {SyncComponent.DHCP, SyncComponent.VLAN, SyncComponent.PORT_FORWARDING}
)


__all__ = [
    "SyncComponent",
    "SyncComponentStatus",
    "SyncRunStatus",
    "UNPROVISIONED_COMPONENTS",
]
