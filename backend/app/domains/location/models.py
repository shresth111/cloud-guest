"""SQLAlchemy ORM model for the Location domain.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does --
Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all keep
working uniformly.

One model: :class:`Location` -- a physical site (an office, a retail
branch, a campus building) belonging to exactly one
:class:`app.domains.organization.models.Organization`, where Routers are
deployed and Guest WiFi is offered (CloudGuest hierarchy: Organization ->
Location -> Router -> Guest). The Router domain does not exist yet (a
future module), so this model does not reference or model routers in any
way.

No separate ``LocationMember`` table: unlike Organization (which needed
``OrganizationMember`` because tenant membership is meaningfully different
from RBAC role assignment), a user's relationship to a location is
adequately expressed by RBAC's existing ``user_roles`` scoped to that
``location_id`` -- see ``docs/location/LOCATION_ARCHITECTURE.md`` for the
full reasoning on why no gap was found that would require one.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Float, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .enums import LocationStatus


class Location(BaseModel):
    """A physical site belonging to exactly one organization."""

    __tablename__ = "locations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Unique per organization, not globally -- see LOCATION_ARCHITECTURE.md.
    slug: Mapped[str] = mapped_column(String(150), nullable=False)

    status: Mapped[str] = mapped_column(
        String(20), default=LocationStatus.ACTIVE.value, nullable=False
    )

    # -- physical address --------------------------------------------------
    address_line1: Mapped[str] = mapped_column(String(255), nullable=False)
    address_line2: Mapped[str | None] = mapped_column(String(255), nullable=True)
    city: Mapped[str] = mapped_column(String(100), nullable=False)
    state_province: Mapped[str] = mapped_column(String(100), nullable=False)
    postal_code: Mapped[str] = mapped_column(String(20), nullable=False)
    country: Mapped[str] = mapped_column(String(2), nullable=False)

    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)

    # Nullable: useful for a network-ops map view of site locations, but not
    # every location's coordinates will be known/entered up front.
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)

    # -- on-site contact -----------------------------------------------------
    contact_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    contact_phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Extension point: per-location config that does not warrant its own
    # column (e.g. captive-portal branding defaults, opening-hours notes).
    # Deliberately not modeled as individual columns -- same boundary
    # philosophy as ``Organization.settings``.
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "slug", name="uq_locations_organization_id_slug"
        ),
        Index("ix_locations_organization_id", "organization_id"),
        Index("ix_locations_slug", "slug"),
        Index("ix_locations_status", "status"),
        Index("ix_locations_name", "name"),
        Index("ix_locations_city", "city"),
    )

    def __repr__(self) -> str:
        return (
            f"<Location(id={self.id}, slug={self.slug}, "
            f"organization_id={self.organization_id})>"
        )

    def is_active(self) -> bool:
        return self.status == LocationStatus.ACTIVE.value
