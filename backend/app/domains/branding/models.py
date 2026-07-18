"""SQLAlchemy models for the Branding domain."""

from __future__ import annotations

import uuid

from sqlalchemy import String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class Branding(BaseModel):
    """Represents white-label UI customization options for tenant organizations and specific locations."""

    __tablename__ = "branding"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, index=True, nullable=False
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=True
    )

    company_name: Mapped[str] = mapped_column(String(100), nullable=False)
    
    # Brand Asset URLs
    logo_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dark_logo_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    light_logo_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    favicon_url: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Design Palettes
    primary_color: Mapped[str] = mapped_column(String(10), default="#4F46E5", nullable=False)
    secondary_color: Mapped[str] = mapped_column(String(10), default="#0F172A", nullable=False)
    typography: Mapped[str] = mapped_column(String(50), default="Inter", nullable=False)
    theme: Mapped[str] = mapped_column(String(20), default="light", nullable=False)  # light, dark, custom

    # Portal/Consent text
    footer_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Brand Contact channels
    support_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    support_phone: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Compliance and Help pointers
    privacy_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    terms_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    help_center_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
