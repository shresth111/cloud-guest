"""ORM models for Cloudflare Gateway DNS filtering.

Three tables, because there are three different owners:

``dns_filtering_profiles`` -- **platform-owned.** One row per distinct set
of blocked categories, shared by every venue (in any organization) that
chose that set. A profile that has at least one router owns exactly **one
Gateway DNS location** (its DoH endpoint) and **one Gateway DNS rule** whose
selector is that one location. Routers are never given a location of their
own: Cloudflare's plan allowance for DNS locations is small (Zero Trust
Standard lists 25; Free lists none; the 250 in the account-limits doc is an
upper bound, not the plan allowance), so locations in use equal the number
of *distinct active category sets*, not routers. A profile carries no
tenant data -- only category ids, and names keyed on its own UUID -- so
sharing one across organizations exposes nothing about either.

``dns_filtering_policies`` -- **tenant-owned.** What an organization (as a
default, ``location_id IS NULL``) or one venue chose. A venue's own policy
overrides its organization's default.

``dns_filtering_router_locations`` -- **per router.** Which profile's DoH
endpoint the router currently points at (``applied_profile_id``), which one
it is being switched to (``switching_to_profile_id``, so a concurrent
release of that profile cannot delete the location mid-switch), the
snapshot of the router's own DNS settings taken before the first switch
(what disable restores), and the device-push record. The table keeps its
name from the per-router design; it no longer holds a Cloudflare location.

What sharing costs: Cloudflare's own query logs are per location, so they
cannot tell the venues of one profile apart. The platform does not surface
those logs today.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import (
    BypassHardeningStatus,
    DevicePushStatus,
    ProfileSyncStatus,
    RouterFilteringState,
)


class DnsFilteringProfile(BaseModel):
    """One distinct category set, its Gateway location and the one Gateway
    rule enforcing it on that location."""

    __tablename__ = "dns_filtering_profiles"

    # sha256 of the sorted id list -- constants.profile_fingerprint.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    category_ids: Mapped[list[int]] = mapped_column(JSONB, nullable=False)
    # All three NULL while no router uses the profile: the rule and the
    # location are deleted at Cloudflare to give both slots back.
    # The location's name is constants.gateway_location_name(profile.id).
    cf_location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    doh_subdomain: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cf_rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Unique per account at Cloudflare's side too; assigned once, on create.
    rule_precedence: Mapped[int] = mapped_column(Integer, nullable=False)
    sync_status: Mapped[str] = mapped_column(
        String(20),
        default=ProfileSyncStatus.PENDING.value,
        server_default=ProfileSyncStatus.PENDING.value,
        nullable=False,
    )
    sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_dns_filtering_profiles_fingerprint",
            "fingerprint",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index(
            "uq_dns_filtering_profiles_rule_precedence",
            "rule_precedence",
            unique=True,
        ),
    )


class DnsFilteringPolicy(BaseModel):
    """A tenant's category choice for its whole organization
    (``location_id IS NULL``) or for one venue."""

    __tablename__ = "dns_filtering_policies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    category_ids: Mapped[list[int]] = mapped_column(JSONB, nullable=False)
    # NULL when category_ids is empty: "block nothing" is a choice, not a
    # profile.
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_filtering_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_dns_filtering_policies_organization_id", "organization_id"),
        Index(
            "uq_dns_filtering_policies_org_default",
            "organization_id",
            unique=True,
            postgresql_where=text("location_id IS NULL AND is_deleted = false"),
        ),
        Index(
            "uq_dns_filtering_policies_location",
            "location_id",
            unique=True,
            postgresql_where=text("location_id IS NOT NULL AND is_deleted = false"),
        ),
    )


class DnsFilteringRouterLocation(BaseModel):
    """One router's Gateway DNS location and push state."""

    __tablename__ = "dns_filtering_router_locations"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The profile whose DoH endpoint the router currently points at, if any.
    applied_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_filtering_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Set (and committed) before a switch starts, cleared when it ends: a
    # profile with a router mid-switch is not "unused" and must not have its
    # location released under it.
    switching_to_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_filtering_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    state: Mapped[str] = mapped_column(
        String(20),
        default=RouterFilteringState.PENDING.value,
        server_default=RouterFilteringState.PENDING.value,
        nullable=False,
    )
    # The router's own DoH settings before the platform first switched it
    # (wyfy_device_gateway.mikrotik_dns_filtering.DnsResolverSnapshot).
    # Written once, on the first successful switch, and kept across
    # re-pushes -- a re-push's "current state" is ours, not the original.
    dns_snapshot: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    routeros_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_push_status: Mapped[str] = mapped_column(
        String(20),
        default=DevicePushStatus.PENDING.value,
        server_default=DevicePushStatus.PENDING.value,
        nullable=False,
    )
    device_push_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Opt-in DoH/DoT bypass hardening (separate from the switch itself).
    bypass_hardening_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    bypass_hardening_status: Mapped[str] = mapped_column(
        String(20),
        default=BypassHardeningStatus.OFF.value,
        server_default=BypassHardeningStatus.OFF.value,
        nullable=False,
    )
    bypass_hardening_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Which bypass layers are on (constants.BypassLayer values). Empty while
    # bypass hardening is off. Written only after the device converged.
    bypass_layers: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb"), nullable=False
    )
    # The combined sha256 of the platform DoH lists last pushed to this
    # router, so the scheduled refresh only dials routers whose lists moved.
    bypass_lists_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bypass_lists_pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_dns_filtering_router_locations_router_id",
            "router_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index("ix_dns_filtering_router_locations_organization_id", "organization_id"),
        Index("ix_dns_filtering_router_locations_location_id", "location_id"),
        Index(
            "ix_dns_filtering_router_locations_applied_profile_id",
            "applied_profile_id",
        ),
        Index(
            "ix_dns_filtering_router_locations_switching_to_profile_id",
            "switching_to_profile_id",
        ),
    )


class DnsBypassBlocklist(BaseModel):
    """**Platform-owned.** The last *good* copy of one public DoH list
    (IPv4, IPv6 or hostnames), fetched once for the whole platform and
    pushed to every opted-in router from here -- never fetched per router.

    ``entries`` only ever holds validated literals (IP addresses or plain
    hostnames). A refresh that is refused (shrank by more than half, over
    the cap, empty) or fails leaves ``entries``/``sha256``/``fetched_at``
    untouched and records only ``last_status``/``last_error``.
    """

    __tablename__ = "dns_bypass_blocklists"

    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    entries: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_status: Mapped[str] = mapped_column(String(20), nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index(
            "uq_dns_bypass_blocklists_kind",
            "kind",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )


__all__ = [
    "DnsBypassBlocklist",
    "DnsFilteringPolicy",
    "DnsFilteringProfile",
    "DnsFilteringRouterLocation",
]
