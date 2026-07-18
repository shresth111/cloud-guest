"""SQLAlchemy models for the Custom Domains domain."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class CustomDomain(BaseModel):
    """Represents a custom white-label hostname mapped to the platform (e.g. portal.mycompany.com)."""

    __tablename__ = "custom_domains"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )

    domain_name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    
    # DNS TXT verification token
    verification_token: Mapped[str] = mapped_column(String(100), nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    dns_validation_status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)  # pending, valid, invalid
    
    # LetsEncrypt / SSL certificate status
    ssl_status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)  # pending, issuing, active, failed
    ssl_configured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
