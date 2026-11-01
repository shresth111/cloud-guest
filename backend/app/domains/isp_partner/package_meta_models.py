"""PKG-2: package type + connection type, keyed by ``package_id``.

Its own table so ``isp_packages`` is not altered. Labels for filtering and
reporting only: nothing is enforced from them.
"""

from __future__ import annotations

import uuid

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["CONNECTION_TYPES", "IspPackageMeta", "PACKAGE_TYPES"]

PACKAGE_TYPES = ("home", "commercial", "sme", "enterprise")
CONNECTION_TYPES = ("wireless", "fiber", "ethernet")


class IspPackageMeta(BaseModel):
    __tablename__ = "isp_package_meta"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    package_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_packages.id"), nullable=False
    )
    package_type: Mapped[str | None] = mapped_column(String(12), nullable=True)
    connection_type: Mapped[str | None] = mapped_column(String(12), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "package_type is null or package_type in "
            "('home','commercial','sme','enterprise')",
            name="package_type",
        ),
        CheckConstraint(
            "connection_type is null or connection_type in "
            "('wireless','fiber','ethernet')",
            name="connection_type",
        ),
        Index(
            "uq_isp_package_meta_package",
            "package_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index("ix_isp_package_meta_isp", "isp_organization_id"),
    )
