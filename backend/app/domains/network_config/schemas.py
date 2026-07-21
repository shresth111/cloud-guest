"""Pydantic response schemas for the Network Configuration Management
domain API.

Version list/get/diff/apply responses are **not** redefined here --
``router.py`` reuses ``app.domains.router_provisioning.schemas``'s own
``ConfigVersionResponse``/``ConfigVersionListResponse``/
``ConfigVersionDiffResponse``/``ConfigVersionApplyResponse`` directly
(all ``from_attributes=True``, so they validate straight off the real
``ConfigVersion``/``ProvisioningJob`` ORM rows this domain's service
returns). Re-declaring an identical schema here would duplicate the
exact shape that module already owns and tests. The one schema this
module does own, ``NetworkConfigPreviewResponse``, has no analog
anywhere else -- a dry-run rendering that never touches the database.
"""

from __future__ import annotations

from pydantic import BaseModel

__all__ = ["NetworkConfigPreviewResponse"]


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
