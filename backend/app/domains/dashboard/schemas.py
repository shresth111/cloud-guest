from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class SidebarNavItem(BaseModel):
    id: str
    label: str
    icon: str | None = None
    path: str | None = None
    module: str | None = None
    badge: str | None = None
    children: list[SidebarNavItem] | None = None


class WidgetConfig(BaseModel):
    id: str
    type: str
    title: str
    size: str = "medium"  # small, medium, large, full
    visible: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class ModuleInfo(BaseModel):
    id: str
    name: str
    description: str | None = None
    path: str | None = None
    icon: str | None = None
    enabled: bool = True
    locked: bool = False


class DashboardOverview(BaseModel):
    total_organizations: int = 0
    total_locations: int = 0
    total_routers: int = 0
    active_guests: int = 0
    alerts_active: int = 0
    revenue_mrr: float = 0.0
    platform_health: str = "healthy"


class DashboardResponse(BaseModel):
    overview: DashboardOverview
    widgets: list[WidgetConfig]
    modules: list[ModuleInfo]


class DashboardSidebarResponse(BaseModel):
    items: list[SidebarNavItem]


class DashboardWidgetsResponse(BaseModel):
    widgets: list[WidgetConfig]


class DashboardModulesResponse(BaseModel):
    modules: list[ModuleInfo]
