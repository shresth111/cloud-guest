import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Integer, MetaData
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=convention)


class UUIDMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


class SoftDeleteMixin:
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )

    def mark_deleted(self) -> None:
        self.is_deleted = True
        self.deleted_at = datetime.now(UTC)

    def restore_deleted(self) -> None:
        self.is_deleted = False
        self.deleted_at = None


class AuditMixin:
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )


class VersionMixin:
    version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )


class BaseModel(
    UUIDMixin,
    TimestampMixin,
    SoftDeleteMixin,
    AuditMixin,
    VersionMixin,
    Base,
):
    __abstract__ = True

    @declared_attr.directive
    def __tablename__(cls) -> str:
        name = cls.__name__
        table_name = []
        for index, character in enumerate(name):
            if character.isupper() and index > 0:
                table_name.append("_")
            table_name.append(character.lower())
        return "".join(table_name)


UUIDPrimaryKeyMixin = UUIDMixin
