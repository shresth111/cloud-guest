"""Pydantic request/response schemas for the DHCP Pool Management domain
API.

Follows the same pydantic v2 conventions as ``app.domains.vlan.schemas``:
plain ``str`` fields for every UUID, explicit response-builder functions in
``router.py`` doing the ``str(...)`` conversion rather than
``ConfigDict(from_attributes=True)`` auto-mapping, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse
from app.domains.dhcp.constants import DEFAULT_LEASE_TIME_SECONDS

__all__ = [
    "MessageResponse",
    "DhcpPoolCreateRequest",
    "DhcpPoolUpdateRequest",
    "DhcpPoolResponse",
    "DhcpPoolListResponse",
    "CaptivePortalDhcpOptionRequest",
    "CaptivePortalDhcpOptionStateResponse",
    "CaptivePortalDhcpOptionConvergenceResponse",
]


class DhcpPoolCreateRequest(BaseModel):
    router_id: str
    name: str
    address_range_start: str
    address_range_end: str
    interface: str | None = None
    gateway_ip_address: str | None = None
    dns_primary: str | None = None
    dns_secondary: str | None = None
    lease_time_seconds: int = Field(default=DEFAULT_LEASE_TIME_SECONDS, ge=1)
    is_enabled: bool = True


class DhcpPoolUpdateRequest(BaseModel):
    name: str | None = None
    address_range_start: str | None = None
    address_range_end: str | None = None
    interface: str | None = None
    gateway_ip_address: str | None = None
    dns_primary: str | None = None
    dns_secondary: str | None = None
    lease_time_seconds: int | None = Field(default=None, ge=1)
    is_enabled: bool | None = None


class DhcpPoolResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    name: str
    interface: str | None
    address_range_start: str
    address_range_end: str
    gateway_ip_address: str | None
    dns_primary: str | None
    dns_secondary: str | None
    lease_time_seconds: int
    is_enabled: bool
    # Whether this pool actually exists on the router right now, and why
    # not if it doesn't. Separate from is_enabled, which is only intent --
    # a pool can be enabled and never have reached a device.
    device_push_status: str
    device_push_error: str | None
    device_pushed_at: datetime | None
    created_at: datetime


class DhcpPoolListResponse(BaseModel):
    items: list[DhcpPoolResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class CaptivePortalDhcpOptionRequest(BaseModel):
    """Body for *writing* the captive-portal DHCP option (code 114).

    ``option_value`` is required and has no default. This platform has
    never stored a per-router option-114 value -- the only writer was a
    human pasting the Master Console setup script -- so a default here
    would be a fabricated URI handed to every client on a guest network.
    The removal endpoint takes no body at all, because a removal is
    identified by the option's name and discovers its own attachments from
    the device.

    ``network_addresses`` are the ``/ip dhcp-server network`` subnets to
    bind the option set to, in RouterOS's own CIDR form
    (``"10.5.50.0/24"``). A subnet with no network row on the device is
    skipped rather than created: this endpoint attaches an option, and
    inventing a network row would invent a gateway and DNS for a subnet
    nobody asked it about.
    """

    option_value: str = Field(min_length=1)
    network_addresses: list[str] = Field(default_factory=list)


class CaptivePortalDhcpOptionStateResponse(BaseModel):
    """What the router says right now.

    ``supported`` is ``False`` for a RouterOS with no ``/ip dhcp-server
    option`` menu at all -- which is *not* the same fact as ``advertised:
    false``, and is carried separately so an audit cannot read a router it
    could not ask as a router that answered "clean"."""

    router_id: str
    supported: bool
    advertised: bool
    option_name: str
    option_code: int
    option_value: str | None
    force: bool
    option_set_names: list[str]
    bindings: list[str]


class CaptivePortalDhcpOptionConvergenceResponse(BaseModel):
    """What the convergence actually did to the device.

    ``changed`` is the field worth reading. Both directions are idempotent,
    so a 200 is equally true of a router that was already in the desired
    state; ``changed`` is the only thing that distinguishes "this venue
    still had it" from "this venue was cleaned already"."""

    router_id: str
    present: bool
    changed: bool
    option_removed: bool
    option_sets_removed: list[str]
    option_sets_rewritten: list[str]
    bindings_detached: list[str]
