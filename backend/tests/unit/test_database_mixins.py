import uuid
from datetime import datetime

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class DatabaseMixinWidget(BaseModel):
    __tablename__ = "database_mixin_widgets"

    name: Mapped[str] = mapped_column(String(120), nullable=False)


def test_base_model_mixins_define_enterprise_columns() -> None:
    columns = DatabaseMixinWidget.__table__.columns

    assert isinstance(columns["id"].type, UUID)
    assert columns["id"].primary_key is True
    assert "created_at" in columns
    assert "updated_at" in columns
    assert "deleted_at" in columns
    assert "is_deleted" in columns
    assert "created_by" in columns
    assert "updated_by" in columns
    assert "version" in columns


def test_soft_delete_and_restore_mutate_state() -> None:
    widget = DatabaseMixinWidget(name="Lobby WiFi")

    widget.mark_deleted()

    assert widget.is_deleted is True
    assert isinstance(widget.deleted_at, datetime)

    widget.restore_deleted()

    assert widget.is_deleted is False
    assert widget.deleted_at is None


def test_base_model_accepts_uuid_audit_fields() -> None:
    creator_id = uuid.uuid4()
    widget = DatabaseMixinWidget(name="Guest", created_by=creator_id)

    assert widget.created_by == creator_id

