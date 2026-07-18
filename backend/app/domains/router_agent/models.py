"""SQLAlchemy ORM models for the Router Agent domain.

One model, extending ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

:class:`RouterAgentCredential` does not import
``app.domains.router.models.Router`` -- only FKs its table name
(``"routers.id"``), the same loose-coupling convention
``app.domains.router_provisioning.models`` already established for its own
``router_id`` columns.

## Why one table, not two

This row plays two roles for the same router, both strictly one-to-one with
it: (1) the persistent device-identity credential itself
(``credential_hash``/``issued_at``/``expires_at``/``revoked_at``/
``rotation_count``), and (2) the agent's most-recently-self-reported status
(``agent_software_version``/``capabilities``/``license_key``/
``license_status``/``last_status_report_at``). A genuine second table (e.g.
``RouterAgentStatus``) was considered and rejected: both halves share the
exact same cardinality (``router_id`` unique, one row per router) and the
exact same lifecycle (created once at credential issuance, then updated in
place on every subsequent call) -- splitting them would only add a mandatory
one-to-one join for no distinct query need, the same "don't split what has
no independent lifecycle" reasoning
``app.domains.router_provisioning.models.ConfigVersion.is_backup`` documents
for not being a separate ``RouterBackup`` table. ``capabilities``/
``license_key``/``license_status``/``agent_software_version`` are genuinely
new facts with no existing column anywhere in the schema; ``routeros_version``
(the one status fact that *does* already have a home) is deliberately never
duplicated here -- see ``service.py``'s ``report_status``, which updates
``Router.routeros_version`` via BE-008's own ``RouterService.update_router``
instead.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import AgentLicenseStatus


class RouterAgentCredential(BaseModel):
    """A persistent, hashed bearer credential authenticating every ongoing
    device-facing call this module exposes (heartbeat, config pull, status
    push, action poll/complete) -- distinct from, and issued only after,
    BE-008's one-time :class:`app.domains.router.models.RouterProvisioningToken`
    has already been consumed at check-in.

    Only ``credential_hash`` (a SHA-256 hex digest) is stored, never the
    plaintext -- the exact same posture ``RouterProvisioningToken.token_hash``
    already established, for the identical reason (a high-entropy,
    randomly-generated token has no need of a slow password hash like
    Argon2id).
    """

    __tablename__ = "router_agent_credentials"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    credential_hash: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Incremented every time this router's credential is reissued (e.g. a
    # factory-reset -> re-provision -> check-in cycle) rather than created
    # for the first time -- see ``service.py``'s ``issue_credential_for_router``.
    rotation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # -- latest agent-self-reported status (see module docstring) ---------------
    agent_software_version: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    capabilities: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    license_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    license_status: Mapped[str] = mapped_column(
        String(20), default=AgentLicenseStatus.UNKNOWN.value, nullable=False
    )
    last_status_report_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_router_agent_credentials_router_id", "router_id", unique=True),
        Index(
            "ix_router_agent_credentials_credential_hash",
            "credential_hash",
            unique=True,
        ),
        Index("ix_router_agent_credentials_expires_at", "expires_at"),
        Index("ix_router_agent_credentials_revoked_at", "revoked_at"),
    )

    def is_active(self, *, now: datetime) -> bool:
        return self.revoked_at is None and now <= self.expires_at

    def __repr__(self) -> str:
        return (
            f"<RouterAgentCredential(router_id={self.router_id}, "
            f"rotation_count={self.rotation_count})>"
        )


__all__ = ["RouterAgentCredential"]
