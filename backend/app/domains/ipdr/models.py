"""IPDR's Postgres index. The rows themselves live in the archive (S3, or a
local directory when unconfigured) as one gzip NDJSON object per
(organization, location, IST day); Postgres keeps only where each day is and
which subjects it contains. See DESIGN.md section 3."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base

__all__ = ["IpdrDayFile", "IpdrDaySubject"]


class IpdrDayFile(Base):
    """One archived IST day of one location. Rebuilt days point at the
    newest object; older objects stay in the (Object-Locked) archive."""

    __tablename__ = "ipdr_day_files"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
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
    #: The IST calendar day.
    day: Mapped[date] = mapped_column(Date, nullable=False)
    #: ``s3`` or ``local``.
    store: Mapped[str] = mapped_column(String(8), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    row_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    unknown_user_rows: Mapped[int] = mapped_column(BigInteger, nullable=False)
    derived_translation_rows: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: A router of the location hit the flow-record daily cap that day.
    records_incomplete: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    built_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("location_id", "day", name="uq_ipdr_day_files_location_day"),
        Index("ix_ipdr_day_files_org_day", "organization_id", "day"),
    )


class IpdrDaySubject(Base):
    """sha256 of one phone / user id / MAC / source IP seen in a day file:
    a pre-filter so a search for one subject opens only the days that
    contain it. Never the value itself."""

    __tablename__ = "ipdr_day_subjects"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    day_file_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("ipdr_day_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "day_file_id", "kind", "digest", name="uq_ipdr_day_subjects_key"
        ),
        Index("ix_ipdr_day_subjects_lookup", "kind", "digest"),
    )
