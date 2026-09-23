"""ORM models for Cloudflare Gateway DNS filtering.

Three tables, because there are three different owners:

``dns_filtering_profiles`` -- **platform-owned.** One row per distinct set
of blocked categories, shared by every venue (in any organization) that
chose that set, and one Gateway DNS rule per row. Cloudflare allows 500 DNS
policies per account; one rule per venue would hit that at 500 venues,
while one rule per *distinct category set* grows with the number of
different choices, which is far smaller. A profile carries no tenant data:
its rule names only category ids and our own location ids, and a tenant
never reads a profile directly -- only its own policy.

``dns_filtering_policies`` -- **tenant-owned.** What an organization (as a
default, ``location_id IS NULL``) or one venue chose. A venue's own policy
overrides its organization's default.

``dns_filtering_router_locations`` -- **per router.** The router's Gateway
DNS location (id, DoH subdomain), which profile rule it is currently in, the
snapshot of the router's own DNS settings taken before the switch (what
disable restores), and the device-push record.
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
    """One distinct category set, and the one Gateway rule enforcing it."""

    __tablename__ = "dns_filtering_profiles"

    # sha256 of the sorted id list -- constants.profile_fingerprint.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    category_ids: Mapped[list[int]] = mapped_column(JSONB, nullable=False)
    # NULL while no router uses the profile: an empty-location rule is
    # deleted at Cloudflare to give the policy slot back.
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
    # constants.gateway_location_name(router_id) -- never tenant-derived.
    cf_location_name: Mapped[str] = mapped_column(String(100), nullable=False)
    cf_location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    doh_subdomain: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The profile whose rule currently lists this location, if any.
    applied_profile_id: Mapped[uuid.UUID | None] = mapped_column(
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
    )


__all__ = [
    "DnsFilteringPolicy",
    "DnsFilteringProfile",
    "DnsFilteringRouterLocation",
]
