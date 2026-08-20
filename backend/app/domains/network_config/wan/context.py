"""Input models for WAN profile rendering."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.domains.isp.constants import IspConnectionMode, WanRoutingMode


@dataclass(frozen=True)
class WanRenderLink:
    """One WAN uplink resolved for script generation."""

    link_id: uuid.UUID
    slot: int
    connection_mode: IspConnectionMode
    physical_interface: str
    effective_interface: str  # routing/NAT/mangle target (pppoe virtual or physical)
    gateway: str | None = None
    static_address: str | None = None  # "ip/prefix" e.g. "203.0.113.5/24"
    pppoe_username: str | None = None
    pppoe_password: str | None = None
    load_balance_weight: int | None = None


@dataclass(frozen=True)
class WanRenderContext:
    links: list[WanRenderLink]
    wan_routing_mode: WanRoutingMode = WanRoutingMode.LOAD_BALANCE
    lan_bridge: str = "bridge1"
    dns_servers: str = "8.8.8.8,1.1.1.1"
    static_address_by_slot: dict[int, str] = field(default_factory=dict)
