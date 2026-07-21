"""SQLAlchemy ORM model for the Hotspot Settings domain.

One table -- ``HotspotProfile``. A row's own state *is* its current
state; there is no live device push in this pass to produce a history of
-- realized onto a device later by ``app.domains.network_config``'s own
provisioning pass, not this domain (mirrors ``app.domains.dhcp``/
``app.domains.vlan``/``app.domains.port_forwarding``'s own identical
"config resource, realized onto a device later" precedent).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.

## Scope: RouterOS ``/ip hotspot user profile`` + walled-garden, not the
## server bind itself

RouterOS's own ``/ip hotspot`` feature set spans several sub-menus: a
*server* (bound to an interface + address pool -- the same
interface/pool-provisioning concern ``DhcpPool`` already covers, not
duplicated here), a *server profile* (login page/method), a *user
profile* (session-timeout/idle-timeout/rate-limit -- exactly this
domain's own fields), and *walled-garden* entries (allowed hosts).
``HotspotProfile`` deliberately models only the user-profile/walled-garden
slice -- the part fully described by real, storable fields this domain
actually has -- rather than fabricate an interface/address-pool binding
this table has no data for. See ``docs/hotspot/FLOW.md`` for the full
reasoning.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class HotspotProfile(BaseModel):
    """One hotspot user-profile configuration a router serves -- see
    module docstring."""

    __tablename__ = "hotspot_profiles"

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
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # NULL means "no session limit" (RouterOS's own "0" convention for
    # unlimited), matching app.domains.guest.GuestSession
    # .session_timeout_minutes's identical nullable-means-unlimited shape.
    session_timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    idle_timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # rx-rate (client upload) / tx-rate (client download) -- see
    # app.domains.queue_management.service.format_mikrotik_rate_limit's
    # own identical rx=upload/tx=download convention, mirrored here for
    # RouterOS rate-limit rendering consistency.
    upload_limit_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    download_limit_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # A small, real list of allowed hostnames/IPs (RouterOS's own
    # walled-garden concept) -- JSONB for the same "real, structured, but
    # variably-shaped data" reason app.domains.captive_portal
    # .CaptivePortalConfig.social_login_providers already uses it; never a
    # comma-joined string column, which would make membership checks and
    # per-host validation awkward.
    walled_garden_hosts: Mapped[list[str]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_hotspot_profiles_router_id", "router_id"),
        Index("ix_hotspot_profiles_organization_id", "organization_id"),
        Index("ix_hotspot_profiles_location_id", "location_id"),
        Index("ix_hotspot_profiles_is_enabled", "is_enabled"),
    )

    def __repr__(self) -> str:
        return (
            f"<HotspotProfile(id={self.id}, router_id={self.router_id}, "
            f"name={self.name})>"
        )


__all__ = ["HotspotProfile"]
