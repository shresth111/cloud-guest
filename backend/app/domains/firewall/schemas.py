"""Pydantic request/response schemas for the Firewall Rule Management
domain API. Follows the same pydantic v2 conventions as
``app.domains.dhcp.schemas``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

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
    "FirewallBandStatusResponse",
    "FloodLimitResponse",
    "FloodLimitUpdateRequest",
    "GuestIsolationPortResponse",
    "GuestIsolationResponse",
    "GuestIsolationUpdateRequest",
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


#: Fields a rule cannot exist without. Omitting one leaves it unchanged; an
#: explicit ``null`` has no meaning for it and is refused rather than ignored.
_NON_CLEARABLE_FIELDS: frozenset[str] = frozenset(
    {"name", "chain", "action", "protocol", "priority", "is_enabled"}
)


class FirewallRuleUpdateRequest(BaseModel):
    """Partial update. A field left out is unchanged; a field sent as
    ``null`` is cleared -- "any address", "any port", no interface, no
    comment. The two used to be indistinguishable: every ``null`` was
    dropped, so removing an address from a rule returned 200 and kept the
    old address, and the router kept enforcing it on the next push."""

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

    @model_validator(mode="after")
    def _refuse_null_on_required(self) -> FirewallRuleUpdateRequest:
        cleared = sorted(
            name
            for name in self.model_fields_set & _NON_CLEARABLE_FIELDS
            if getattr(self, name) is None
        )
        if cleared:
            raise ValueError(f"cannot be cleared: {', '.join(cleared)}")
        return self

    def changed_fields(self) -> dict[str, object]:
        """Exactly the fields the caller sent, ``null`` included."""
        return self.model_dump(exclude_unset=True)


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


class FirewallBandStatusResponse(BaseModel):
    """Whether a push to this router would find its sentinel band.

    ``ready``: a push can proceed. ``missing``: the band was never placed
    (a push is refused with ``ACCESS_RULES_BAND_MISSING``). ``invalid``:
    something is there but a push would refuse it too. ``reason`` is
    venue-readable text, ``None`` when ready. Carries no RouterOS ``.id``
    and no rule comment.

    ``guest_networks`` are the networks the router serves guests on, and
    ``guest_dns_servers`` what DHCP hands them (empty = the router itself),
    read off the router in the same look -- so a venue can be offered "keep
    guests off your private networks" without typing an address."""

    state: Literal["ready", "missing", "invalid"]
    reason: str | None = None
    checked_at: datetime
    guest_networks: list[str] = []
    guest_dns_servers: list[str] = []


class FirewallRuleListResponse(BaseModel):
    items: list[FirewallRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class FloodLimitUpdateRequest(BaseModel):
    """Turn "Limit connection floods" on at a preset, or ``off``."""

    preset: Literal["off", "relaxed", "normal", "strict"]


class FloodLimitResponse(BaseModel):
    """A router's "Limit connection floods" switch, read off the router.

    ``preset`` is ``off`` when nothing is on the router, one of the three
    presets when its cap matches one, and ``null`` when the router holds a
    cap none of them writes. ``limit`` is that cap: connections one guest
    device may hold before its next new connection is dropped.
    ``consistent`` is false when a guest network is missing its row or the
    rows disagree; turning the switch on again repairs it. ``band_state`` is
    ``ready`` when the switch can be turned on here."""

    router_id: str
    preset: Literal["off", "relaxed", "normal", "strict"] | None
    limit: int | None
    enabled: bool
    consistent: bool
    band_state: Literal["ready", "missing", "invalid"]
    guest_networks: list[str] = []
    presets: dict[str, int]
    checked_at: datetime


class GuestIsolationUpdateRequest(BaseModel):
    """Turn "Guests can't see each other" on or off."""

    enabled: bool


class GuestIsolationPortResponse(BaseModel):
    """One port of the guest network. ``excluded_reason`` is why the router
    leaves it out (``wan``, ``carries_vlan``, ``has_address``,
    ``not_physical``, ``dynamic``, ``disabled``)."""

    interface: str
    running: bool
    isolatable: bool
    isolated: bool
    excluded_reason: str | None = None
    is_radio: bool = False


class GuestIsolationResponse(BaseModel):
    """A router's "Guests can't see each other" switch, read off the router.

    ``between_ports``: guests on different ports cannot reach each other --
    what the router enforces. ``ap_ports``: guest ports with an access point
    (or switch) plugged in. ``ap_isolation_needed``: guests on the SAME
    access point are switched inside it and the router never sees them; the
    owner must turn on each access point's own "AP isolation" / "Client
    isolation". ``routed_guard``: the firewall row that also stops a guest
    routing to another through the router (needs the firewall band).
    ``radios_isolated``: the router's own Wi-Fi, ``null`` when it has none.
    ``refusal``: why it cannot be turned on here, or ``null``.
    ``summary``: the honest one-line status."""

    router_id: str
    enabled: bool
    consistent: bool
    between_ports: bool
    routed_guard: bool
    radios_isolated: bool | None
    band_state: Literal["ready", "missing", "invalid"]
    guest_ports: int
    isolated_ports: int
    ap_ports: int
    ap_isolation_needed: bool
    ports: list[GuestIsolationPortResponse] = []
    refusal: str | None = None
    summary: str
    checked_at: datetime
