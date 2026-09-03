"""SQLAlchemy ORM model for the Content Filtering domain.

One table -- ``ContentFilterRule``. A row's own state *is* its current
state; there is no history table. What the row does carry is whether it
has ever reached a real router -- the ``device_push_*`` trio below,
mirroring ``vlans``' and ``dhcp_pools``' own identical columns. Before
those existed there was no way to tell a blocked site from a row saying
blocked, and the dashboard showed the second as the first.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.

A router may not hold two non-deleted rules for the same
``(value_type, value)`` pair -- enforced by the partial unique index
below, mirroring ``app.domains.mac_authorization.models
.MacAuthorizationEntry``'s identical "avoid a redundant, device-
duplicating row" precedent (a duplicate DNS-sinkhole/address-list entry
would not itself break the device, but IS pointless bookkeeping this
domain's own service layer would rather reject up front than silently
accumulate).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import ContentFilterDevicePushStatus


class ContentFilterRule(BaseModel):
    """One content-filtering rule for a router -- either a domain to
    DNS-sinkhole or an IP/CIDR to address-list-and-drop. See
    ``constants.ContentFilterValueType``'s own docstring for why those
    are the only two real, honestly-implementable mechanisms this domain
    models (no Layer7, no web-proxy, no TLS interception -- see
    ``app.domains.network_config.renderers``'s own "Content Filtering"
    module-docstring section for the full scope write-up)."""

    __tablename__ = "content_filter_rules"

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
    # Purely organizational/reporting -- see
    # constants.ContentFilterCategory's own docstring for why this is
    # never itself a source of enforcement.
    category: Mapped[str | None] = mapped_column(String(30), nullable=True)
    # One of constants.ContentFilterValueType's values.
    value_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # A normalized domain (constants.ContentFilterValueType.DOMAIN) or
    # IP/CIDR (constants.ContentFilterValueType.IP_CIDR) -- normalized by
    # validators.normalize_rule_value before this row is ever written,
    # never stored in whatever casing/form the caller happened to submit.
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # -- device push ---------------------------------------------------------
    #
    # Whether this row has ever reached a real router, and what happened.
    # Deliberately independent of ``is_enabled`` (intent) and of
    # ``network_config``'s ``ConfigVersion`` status (a different, script-based
    # pipeline over a transport the fleet filters). Before these columns
    # existed the dashboard had no way to distinguish "blocked" from "a row
    # saying blocked" -- and it showed the second as the first.
    device_push_status: Mapped[str] = mapped_column(
        String(20),
        default=ContentFilterDevicePushStatus.PENDING.value,
        server_default=ContentFilterDevicePushStatus.PENDING.value,
        nullable=False,
    )
    # The raw ``str(exc)`` from the last failed push, shown to the customer
    # verbatim -- a device error is more useful unedited than summarized,
    # and summarizing device errors is how the previous silence started.
    device_push_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # NULL until the first successful push, truthfully: before one, this
    # platform has no claim about what any router carries for this rule.
    device_pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_content_filter_rules_router_id", "router_id"),
        Index("ix_content_filter_rules_organization_id", "organization_id"),
        Index("ix_content_filter_rules_location_id", "location_id"),
        Index("ix_content_filter_rules_value_type", "value_type"),
        Index("ix_content_filter_rules_is_enabled", "is_enabled"),
        Index(
            "uq_content_filter_rules_router_id_value_type_value",
            "router_id",
            "value_type",
            "value",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<ContentFilterRule(id={self.id}, router_id={self.router_id}, "
            f"value_type={self.value_type}, value={self.value})>"
        )


__all__ = ["ContentFilterRule"]
