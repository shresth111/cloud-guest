"""System Settings persistence model.

``SystemSetting`` is the platform-wide (GLOBAL-scope) configuration store
the RBAC ``system_settings.*`` permission was reserved for but that had no
table behind it. Deliberately a **generic key/value store**, not one typed
column per setting:

* Each row is one setting: a unique ``key`` (drawn from
  ``constants.SystemSettingKey`` -- a closed, enumerated set, never
  free-form) and a JSONB ``value`` holding whatever that key's typed shape
  is (a plan id string, a list of feature-override objects, ...). Adding a
  new platform setting is a new enum member + a typed schema field, with no
  migration -- the same reason ``Organization.settings`` and
  ``brandings``' sibling JSONB fields exist, applied at platform scope.
* There is exactly zero or one row per key. The service reads the whole
  table into a ``{key: value}`` map and writes through an upsert, so a key
  that was never set simply reads as its schema default rather than needing
  a seeded row.

This is intentionally *not* modelled as a single wide "platform_config"
singleton row: a k/v table lets an unrelated future setting be added,
audited, and read without every writer racing on the same physical row.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class SystemSetting(BaseModel):
    """One platform-wide setting: ``key`` (unique) -> ``value`` (JSONB)."""

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True, index=True
    )

    # Nullable so "the key exists but is explicitly cleared" (e.g. the
    # default plan was unset) is representable distinctly from "no row" --
    # both resolve to the schema default at read time, but a writer can
    # store ``null`` to positively clear a value.
    value: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    def __repr__(self) -> str:
        return f"<SystemSetting(key={self.key!r})>"
