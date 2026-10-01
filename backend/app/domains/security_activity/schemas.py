"""Response schemas for ``GET /security/activity``."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

__all__ = [
    "SecurityActivityProtection",
    "SecurityActivityResponse",
    "SecurityActivityRuleCount",
    "SecurityStaffChange",
]


class SecurityActivityRuleCount(BaseModel):
    label: str
    count: int


class SecurityActivityProtection(BaseModel):
    """One protection's count for the window, and the sentence a venue owner
    reads. ``available=False`` with ``count=None`` means "we could not
    measure this", never zero. A protection that is not switched on (no rule
    read on any router in scope) is simply absent."""

    key: str
    label: str
    count: int | None
    available: bool
    unavailable_reason: str | None = None
    sentence: str | None = None
    source: str
    routers_reporting: int | None = None
    routers_total: int | None = None
    last_read_at: datetime | None = None
    top_rules: list[SecurityActivityRuleCount] = Field(default_factory=list)


class SecurityStaffChange(BaseModel):
    at: datetime
    action: str
    summary: str
    description: str | None = None


class SecurityActivityResponse(BaseModel):
    window: str
    since: datetime
    until: datetime
    protections: list[SecurityActivityProtection]
    staff_changes: list[SecurityStaffChange]
    routers_total: int
    semantics: str
    generated_at: datetime
