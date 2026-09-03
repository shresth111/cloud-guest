"""Pydantic request/response schemas for the VLAN Management domain API.

Follows the same pydantic v2 conventions as
``app.domains.isp_routing.schemas``: plain ``str`` fields for every UUID,
explicit response-builder functions in ``router.py`` doing the ``str(...)``
conversion rather than ``ConfigDict(from_attributes=True)`` auto-mapping,
and ``MessageResponse`` re-exported from the auth domain rather than
duplicated.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "VlanCreateRequest",
    "VlanUpdateRequest",
    "VlanResponse",
    "VlanListResponse",
    "VlanDeviceInterfaceResponse",
    "VlanDeviceInterfacesResponse",
]


class VlanCreateRequest(BaseModel):
    router_id: str
    vlan_id: int = Field(..., ge=1, le=4094)
    name: str
    gateway_ip_address: str | None = None
    cidr: str | None = None
    interface: str | None = None
    port_mode: Literal["trunk", "access"] = "trunk"
    enable_hotspot: bool = False
    nat_enabled: bool = False
    description: str | None = None
    is_enabled: bool = True


class VlanUpdateRequest(BaseModel):
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    name: str | None = None
    gateway_ip_address: str | None = None
    cidr: str | None = None
    interface: str | None = None
    port_mode: Literal["trunk", "access"] | None = None
    enable_hotspot: bool | None = None
    nat_enabled: bool | None = None
    description: str | None = None
    is_enabled: bool | None = None


class VlanResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    vlan_id: int
    name: str
    gateway_ip_address: str | None
    cidr: str | None
    interface: str | None
    port_mode: str
    enable_hotspot: bool
    # Whether this VLAN's subnet is masqueraded onto the router's WAN --
    # i.e. whether its guests actually reach the internet. Realized (or
    # removed) by the device push, never by create/update alone.
    nat_enabled: bool
    description: str | None
    is_enabled: bool
    # Whether this row has ever reached a real router, and what happened.
    # Independent of is_enabled: a VLAN can be enabled for months and never
    # have been on a device, which was true of every row before this domain
    # had a push at all.
    # PENDING / PROVISIONING / ACTIVE / FAILED. Never ACTIVE until the
    # device has accepted every write.
    device_push_status: str
    # The spec's ``error_message``: the device's own words from the last
    # failed push, verbatim, shown to the customer. There is no second
    # column -- one fact, one place to look.
    device_push_error: str | None
    device_pushed_at: datetime | None
    # What the router was actually told to call this interface --
    # ``vlan<id>`` on a trunk, the physical port in access mode. NULL until
    # the first successful push, because before one this platform has no
    # claim about what any router carries.
    mikrotik_interface_name: str | None
    created_at: datetime


class VlanListResponse(BaseModel):
    items: list[VlanResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class VlanDeviceInterfaceResponse(BaseModel):
    """One interface as the router currently has it.

    ``is_bridge_port`` is the field ``app.domains.router``'s own
    ``DeviceInterfaceResponse`` does not carry, and the reason this shape
    is not simply reused: an access-mode VLAN takes a port *out of* a
    bridge, so a port in no bridge is not a candidate, and a picker should
    not have to infer that from whether ``bridge`` happens to be null.
    """

    name: str
    type: str | None
    running: bool
    disabled: bool
    bridge: str | None
    is_bridge_port: bool
    has_ip_address: bool


class VlanDeviceInterfacesResponse(BaseModel):
    interfaces: list[VlanDeviceInterfaceResponse]
