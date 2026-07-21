"""SQLAlchemy ORM model for the ISP Routing domain.

One table -- ``IspRoutingRule``. Unlike ``app.domains.isp``'s own
``IspLink``/``IspHealthCheck`` split, there is no "current state + history"
concern here: a routing rule's own row *is* its current state (a matcher
plus a target uplink plus enable/disable plus priority), and there is no
live device push in this pass to produce a history of (see module
docstring -- realized onto a device later by Network Configuration
Management's own provisioning pass, not this domain).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class IspRoutingRule(BaseModel):
    """One traffic-steering rule -- see module docstring and
    ``constants.IspRoutingRuleType``'s own docstring for the
    one-match-field-per-``rule_type`` shape."""

    __tablename__ = "isp_routing_rules"

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
    # The WAN uplink matched traffic should route through -- must belong to
    # the same router_id (enforced at the service layer, see service.py's
    # own IspLinkLookupProtocol composition).
    isp_link_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_links.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_type: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Lower value tried first when more than one enabled rule could match
    # the same traffic -- mirrors IspLink.priority's own "lower tried
    # first" convention, the sibling domain this one composes with
    # directly (PolicyAssignment.priority's "higher wins" is the other
    # convention in this codebase, unrelated to this domain).
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # -- per-rule_type match fields -- exactly one is populated, enforced
    # by validators.validate_match_fields (see service.py's own docstring).
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    interface_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policies.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_isp_routing_rules_router_id", "router_id"),
        Index("ix_isp_routing_rules_organization_id", "organization_id"),
        Index("ix_isp_routing_rules_location_id", "location_id"),
        Index("ix_isp_routing_rules_isp_link_id", "isp_link_id"),
        Index("ix_isp_routing_rules_rule_type", "rule_type"),
        Index("ix_isp_routing_rules_is_enabled", "is_enabled"),
    )

    def __repr__(self) -> str:
        return (
            f"<IspRoutingRule(id={self.id}, name={self.name}, "
            f"rule_type={self.rule_type})>"
        )


__all__ = ["IspRoutingRule"]
