"""Pydantic request/response schemas for the Firewall Rule Management
domain API. Follows the same pydantic v2 conventions as
``app.domains.dhcp.schemas``.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

from .constants import DEFAULT_PRIORITY, FirewallAction, FirewallChain, FirewallProtocol

__all__ = [
    "MessageResponse",
    "FirewallRuleCreateRequest",
    "FirewallRuleUpdateRequest",
    "FirewallRuleResponse",
    "FirewallRuleListResponse",
    "FirewallPushResponse",
    "FirewallBandResponse",
]


class FirewallRuleCreateRequest(BaseModel):
    router_id: str
    name: str
    chain: FirewallChain = FirewallChain.FORWARD
    action: FirewallAction = FirewallAction.ACCEPT
    protocol: FirewallProtocol = FirewallProtocol.ALL
    source_address: str | None = None
    destination_address: str | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    in_interface: str | None = None
    priority: int = DEFAULT_PRIORITY
    comment: str | None = None
    is_enabled: bool = True


class FirewallRuleUpdateRequest(BaseModel):
    name: str | None = None
    chain: FirewallChain | None = None
    action: FirewallAction | None = None
    protocol: FirewallProtocol | None = None
    source_address: str | None = None
    destination_address: str | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    in_interface: str | None = None
    priority: int | None = None
    comment: str | None = None
    is_enabled: bool | None = None


class FirewallRuleResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    name: str
    chain: str
    action: str
    protocol: str
    source_address: str | None
    destination_address: str | None
    source_port: int | None
    destination_port: int | None
    in_interface: str | None
    priority: int
    comment: str | None
    is_enabled: bool
    #: ``pending`` | ``active`` | ``failed`` -- whether this rule is on its
    #: router. See ``constants.FirewallDevicePushStatus``.
    device_push_status: str
    device_push_error: str | None = None
    device_pushed_at: datetime | None = None
    created_at: datetime


class FirewallPushResponse(BaseModel):
    """A router's rules after a successful push. ``added``/``removed``/
    ``unchanged`` are counted from the writes the push issued; an unchanged
    re-push reports every rule as unchanged and wrote nothing."""

    router_id: str
    added: int
    removed: int
    unchanged: int
    rules: list[FirewallRuleResponse]


class FirewallBandResponse(BaseModel):
    """Master-console result of placing a router's sentinel band.
    ``created=False`` means a band already existed and was left in place."""

    router_id: str
    created: bool
    begin_id: str
    end_id: str
    anchor_id: str | None = None


class FirewallRuleListResponse(BaseModel):
    items: list[FirewallRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
