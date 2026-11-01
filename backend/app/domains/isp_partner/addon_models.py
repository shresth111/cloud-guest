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
    #: F1: an agreed price per customer per month, in paise. A RECORD only --
    #: the ISP pays Wyfy in cash; nothing bills from it (migration 0177).
    price_per_customer_paise: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_addon_allowances_isp_key",
            "isp_organization_id",
            "feature_key",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspParitySetting(BaseModel):
    """Per-ISP switches for founder questions F2/F3 (migration 0177).

    No row = the env defaults in ``policy.py``. Master owns
    ``pii_unmask_enabled``; the ISP owner/admin owns
    ``byo_customer_override_enabled``.
    """

    __tablename__ = "isp_parity_settings"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: F2: Master lets this ISP's owner/admin see unmasked guest identifiers
    #: and Traffic Lens flow records (every such view is audited).
    pii_unmask_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    #: F3: the ISP lets individual customers bring their own sender.
    byo_customer_override_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    __table_args__ = (
        Index(
            "uq_isp_parity_settings_isp",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspCustomerMessaging(BaseModel):
    """F3 per-customer override: this customer uses its own BYO sender
    instead of the ISP-level one (only when the ISP allows overrides)."""

    __tablename__ = "isp_customer_messaging"

    customer_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    own_sender: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    __table_args__ = (
        Index(
            "uq_isp_customer_messaging_customer",
            "customer_organization_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )
