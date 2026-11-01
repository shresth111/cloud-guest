"""COMMS-2b: the rendered content of one sent message, kept beside the JAZE-4
log row (``isp_message_log`` is not altered). WhatsApp: the template name,
language and the positional body parameters exactly as they were sent, with
the variable each one fills."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["IspMessageContent"]


class IspMessageContent(BaseModel):
    __tablename__ = "isp_message_contents"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    message_log_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_message_log.id", ondelete="CASCADE"),
        nullable=False,
    )
    template_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    language: Mapped[str | None] = mapped_column(String(15), nullable=True)
    #: [{"position": 1, "variable": "name", "value": "..."}, ...]
    parameters: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )

    __table_args__ = (
        Index("uq_isp_message_contents_log", "message_log_id", unique=True),
    )
