"""Pydantic request/response schemas for router discovery snapshots.

Never include secrets -- snapshots are already sanitized at the
``ReadOnlyDeviceReader`` boundary and again in the collector. Response
schemas expose only the fields the wizard / fleet UI needs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .constants import (
    CompatibilityCheckStatus,
    CompatibilityOverall,
    InterfaceAvailabilityStatus,
    PlanActionType,
    PlanRisk,
    PlanStatus,
    SnapshotStatus,
    SnapshotTrigger,
    VerificationCheckStatus,
    WanVerificationOverall,
)


class InterfaceSnapshot(BaseModel):
    name: str
    type: str | None = None
    running: bool | None = None
    disabled: bool | None = None
    comment: str | None = None
    is_wyfy_managed: bool = False


class BridgeSnapshot(BaseModel):
    name: str
    comment: str | None = None
    is_wyfy_managed: bool = False
    ports: list[str] = Field(default_factory=list)


class IpAddressSnapshot(BaseModel):
    address: str | None = None
    interface: str | None = None
    comment: str | None = None
    is_wyfy_managed: bool = False


class DhcpClientSnapshot(BaseModel):
    interface: str | None = None
    status: str | None = None
    comment: str | None = None
    is_wyfy_managed: bool = False
    has_password: bool | None = None


class DhcpServerSnapshot(BaseModel):
    name: str | None = None
    interface: str | None = None
    address_pool: str | None = None
    comment: str | None = None
    is_wyfy_managed: bool = False


class RouteSnapshot(BaseModel):
    dst_address: str | None = None
    gateway: str | None = None
    distance: int | None = None
    active: bool | None = None
    comment: str | None = None
    is_wyfy_managed: bool = False


class VlanSnapshot(BaseModel):
    name: str | None = None
    vlan_id: int | None = None
    interface: str | None = None
    comment: str | None = None
    is_wyfy_managed: bool = False


class ServiceSnapshot(BaseModel):
    name: str | None = None
    port: int | None = None
    disabled: bool | None = None


class PackageSnapshot(BaseModel):
    name: str | None = None
    version: str | None = None
    disabled: bool | None = None


class RuleSummary(BaseModel):
    """Counts-only firewall / NAT summary -- never full rule bodies."""

    total_count: int = 0
    wyfy_tagged_count: int = 0
    disabled_count: int = 0


class HotspotStateSnapshot(BaseModel):
    server_count: int = 0
    profile_count: int = 0
    walled_garden_count: int = 0
    servers: list[dict[str, Any]] = Field(default_factory=list)


class CompatibilityCheck(BaseModel):
    name: str
    status: CompatibilityCheckStatus
    detail: str


class CompatibilityReport(BaseModel):
    overall: CompatibilityOverall
    checks: list[CompatibilityCheck]


class TopologyFinding(BaseModel):
    """One P8 topology observation (recommendation — never auto-applied)."""

    code: str
    status: CompatibilityCheckStatus
    summary: str
    detail: str | None = None
    resources: list[str] = Field(default_factory=list)


class TopologyReport(BaseModel):
    overall: CompatibilityOverall
    findings: list[TopologyFinding]


class PlanConflict(BaseModel):
    """Hard-stop conflict (P9 / R6) — planner must not continue."""

    code: str
    status: CompatibilityCheckStatus
    summary: str
    detail: str | None = None
    cidrs: list[str] = Field(default_factory=list)


class RouterSnapshotResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    captured_at: datetime
    trigger: SnapshotTrigger
    status: SnapshotStatus
    model: str | None = None
    routeros_version: str | None = None
    architecture: str | None = None
    total_memory_bytes: int | None = None
    free_memory_bytes: int | None = None
    free_storage_bytes: int | None = None
    interfaces: list[InterfaceSnapshot] = Field(default_factory=list)
    bridges: list[BridgeSnapshot] = Field(default_factory=list)
    ip_addresses: list[IpAddressSnapshot] = Field(default_factory=list)
    dhcp_clients: list[DhcpClientSnapshot] = Field(default_factory=list)
    dhcp_servers: list[DhcpServerSnapshot] = Field(default_factory=list)
    routes: list[RouteSnapshot] = Field(default_factory=list)
    dns_config: dict[str, Any] = Field(default_factory=dict)
    firewall_summary: RuleSummary = Field(default_factory=RuleSummary)
    nat_summary: RuleSummary = Field(default_factory=RuleSummary)
    hotspot_state: HotspotStateSnapshot = Field(default_factory=HotspotStateSnapshot)
    vlans: list[VlanSnapshot] = Field(default_factory=list)
    services: list[ServiceSnapshot] = Field(default_factory=list)
    packages: list[PackageSnapshot] = Field(default_factory=list)
    error_detail: str | None = None
    created_at: datetime | None = None


class RouterSnapshotListResponse(BaseModel):
    snapshots: list[RouterSnapshotResponse]
    total: int


class DiscoverRouterResponse(BaseModel):
    """POST /routers/{id}/discover payload: snapshot plus compatibility."""

    snapshot: RouterSnapshotResponse
    compatibility: CompatibilityReport


class VerificationCheck(BaseModel):
    name: str
    status: VerificationCheckStatus
    observed: str | None = None
    expected: str | None = None
    detail: str | None = None
    duration_ms: int = 0


class WanLinkVerificationResponse(BaseModel):
    isp_link_id: str
    slot: int
    overall: WanVerificationOverall
    checks: list[VerificationCheck]


class WanVerificationRunResponse(BaseModel):
    id: str
    run_group_id: str
    isp_link_id: str | None
    overall: WanVerificationOverall
    checks: list[VerificationCheck]
    started_at: datetime
    completed_at: datetime | None


class WanVerificationResponse(BaseModel):
    router_id: str
    run_group_id: str
    gate_passes: bool
    links: list[WanLinkVerificationResponse]


class WanVerificationGateResponse(BaseModel):
    router_id: str
    passes: bool
    run_group_id: str | None = None
    message: str | None = None


class GuestInterfaceAvailability(BaseModel):
    name: str
    status: InterfaceAvailabilityStatus
    detail: str | None = None
    bridge: str | None = None


class GuestInputRecommendation(BaseModel):
    recommended_interfaces: list[str] = Field(default_factory=list)
    parent_bridge_hint: str | None = None
    message: str | None = None


class GuestInterfaceAvailabilityReport(BaseModel):
    snapshot_id: str | None = None
    interfaces: list[GuestInterfaceAvailability]
    recommendation: GuestInputRecommendation


class GuestInterfaceAvailabilityResponse(BaseModel):
    router_id: str
    snapshot_id: str
    interfaces: list[GuestInterfaceAvailability]
    recommendation: GuestInputRecommendation


class GuestVlanRequest(BaseModel):
    vlan_id: int
    name: str
    subnet_cidr: str
    enable_hotspot: bool = True


class GuestNetworkRequest(BaseModel):
    guest_interfaces: list[str] = Field(default_factory=list)
    vlan_mode: bool = False
    vlans: list[GuestVlanRequest] = Field(default_factory=list)
    parent_bridge: str | None = None


class PlanAction(BaseModel):
    seq: int
    rule_id: str
    action_type: PlanActionType
    resource_kind: str
    routeros_path: str
    resource_ref: str
    summary: str
    risk: PlanRisk = PlanRisk.NONE
    details: dict[str, Any] = Field(default_factory=dict)


class PlanDecision(BaseModel):
    code: str
    summary: str
    detail: str | None = None
    options: list[str] = Field(default_factory=list)


class PlanSummary(BaseModel):
    action_count: int = 0
    conflict_count: int = 0
    decision_count: int = 0
    highest_risk: PlanRisk = PlanRisk.NONE


class BuildConfigurationPlanRequest(BaseModel):
    requested_config: GuestNetworkRequest


class ConfigurationPlanResponse(BaseModel):
    id: str
    router_id: str
    snapshot_id: str
    status: PlanStatus
    engine_version: str
    requested_config: GuestNetworkRequest
    actions: list[PlanAction]
    conflicts: list[PlanConflict]
    decisions: list[PlanDecision]
    summary: PlanSummary


class ConfigurationPlanRenderResponse(BaseModel):
    plan_id: str
    config_version_id: str
    config_version_number: int
    status: PlanStatus
    profiles_used: list[str]
    secret_refs: list[str]
    line_count: int
    requires_safety_net: bool = False


class ConfigurationPlanPrepareResponse(BaseModel):
    plan_id: str
    pre_apply_backup_version_id: str
    pre_apply_backup_version_number: int
    status: PlanStatus
    requires_safety_net: bool


__all__ = [
    "InterfaceSnapshot",
    "BridgeSnapshot",
    "IpAddressSnapshot",
    "DhcpClientSnapshot",
    "DhcpServerSnapshot",
    "RouteSnapshot",
    "VlanSnapshot",
    "ServiceSnapshot",
    "PackageSnapshot",
    "RuleSummary",
    "HotspotStateSnapshot",
    "CompatibilityCheck",
    "CompatibilityReport",
    "TopologyFinding",
    "TopologyReport",
    "PlanConflict",
    "RouterSnapshotResponse",
    "RouterSnapshotListResponse",
    "DiscoverRouterResponse",
    "VerificationCheck",
    "WanLinkVerificationResponse",
    "WanVerificationRunResponse",
    "WanVerificationResponse",
    "WanVerificationGateResponse",
    "GuestInterfaceAvailability",
    "GuestInputRecommendation",
    "GuestInterfaceAvailabilityReport",
    "GuestInterfaceAvailabilityResponse",
    "GuestVlanRequest",
    "GuestNetworkRequest",
    "PlanAction",
    "PlanDecision",
    "PlanSummary",
    "BuildConfigurationPlanRequest",
    "ConfigurationPlanResponse",
    "ConfigurationPlanRenderResponse",
    "ConfigurationPlanPrepareResponse",
]
