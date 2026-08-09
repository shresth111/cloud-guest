"""Pydantic response schemas for the Network Configuration Management
domain API.

Version list/get/diff/apply responses are **not** redefined here --
``router.py`` reuses ``app.domains.router_provisioning.schemas``'s own
``ConfigVersionResponse``/``ConfigVersionListResponse``/
``ConfigVersionDiffResponse``/``ConfigVersionApplyResponse`` directly
(all ``from_attributes=True``, so they validate straight off the real
``ConfigVersion``/``ProvisioningJob`` ORM rows this domain's service
returns). Re-declaring an identical schema here would duplicate the
exact shape that module already owns and tests. ``NetworkConfigPreviewResponse``
and ``NetworkConfigNetwatchPushResponse`` are the two schemas this module
owns directly -- neither has an analog anywhere else.
"""

from __future__ import annotations

from pydantic import BaseModel

from app.domains.router_provisioning.schemas import (
    ConfigVersionResponse,
    ProvisioningJobResponse,
)

__all__ = ["NetworkConfigPreviewResponse", "NetworkConfigNetwatchPushResponse"]


class NetworkConfigPreviewResponse(BaseModel):
    router_id: str
    rendered_content: str
    dhcp_pool_count: int
    vlan_count: int
    port_forwarding_rule_count: int
    hotspot_profile_count: int
    qos_traffic_rule_count: int
    dns_record_count: int
    firewall_rule_count: int
    mac_authorization_entry_count: int


class NetworkConfigNetwatchPushResponse(BaseModel):
    """``POST /network-config/routers/{router_id}/netwatch/push``'s own
    response -- the applied ``ConfigVersion``/queued ``ProvisioningJob``
    (identical shape to the main push's own ``ConfigVersionApplyResponse``)
    plus ``watched_link_count``, the one Netwatch-specific fact worth
    surfacing directly (how many of this router's ISP links actually got a
    real Netwatch entry, vs. silently skipped for being DHCP/PPPOE-mode --
    see ``NetworkConfigService.push_isp_netwatch_config``'s own
    docstring)."""

    version: ConfigVersionResponse
    job: ProvisioningJobResponse
    watched_link_count: int
