"""SQLAlchemy models for the Theme domain."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class Theme(BaseModel):
    """Represents full captive portal layout themes, styling, and text terms."""

    __tablename__ = "themes"

    branding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("branding.id"), unique=True, index=True, nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )

    # Visual Theme properties
    landing_page_theme: Mapped[str] = mapped_column(String(100), default="modern", nullable=False)
    bg_image_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ad_banner_url: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Custom Portal Injection styles & behaviour (Future Ready)
    custom_css: Mapped[str | None] = mapped_column(Text, nullable=True)
    custom_js: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Compliance content shown on the captive guest login portal
    terms_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    privacy_text: Mapped[str | None] = mapped_column(Text, nullable=True)
