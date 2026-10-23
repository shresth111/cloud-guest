"""ADDENDUM_04 §2: the Master-set add-on allowance per ISP (migration 0176).

One row per (ISP, add-on key). ``enabled`` = this ISP may switch the add-on on
for its customers; ``max_customers`` = an optional cap on how many of them may
have it on at once (NULL = no cap). No rows = the policy default
(``ISP_PARTNER_ADDON_DEFAULT_ALLOWANCE``, ``none`` until founder F1 is
answered).
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class IspAddonAllowance(BaseModel):
    __tablename__ = "isp_addon_allowances"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    feature_key: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    max_customers: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_addon_allowances_isp_key",
            "isp_organization_id",
            "feature_key",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )
