"""Dashboard configuration service.

Returns dynamic dashboard configuration (overview, widgets, sidebar, modules)
by composing existing analytics, monitoring, billing, RBAC, and organization
services — no new database tables.
"""

from __future__ import annotations

import logging
import uuid

from app.domains.analytics.dashboard_service import (
    DashboardService as AnalyticsDashboardService,
)
from app.domains.billing.service import SuperAdminBillingDashboardService
from app.domains.monitoring.service import PlatformDashboardService
from app.domains.organization.service import OrganizationService
from app.domains.rbac.service import RBACService

from .schemas import (
    DashboardModulesResponse,
    DashboardOverview,
    DashboardResponse,
    DashboardSidebarResponse,
    DashboardWidgetsResponse,
    ModuleInfo,
    SidebarNavItem,
    WidgetConfig,
)

logger = logging.getLogger(__name__)


class DashboardService:
    """Composes domain services into unified dashboard configuration."""

    def __init__(
        self,
        analytics_dashboard: AnalyticsDashboardService,
        platform_dashboard: PlatformDashboardService,
        billing_dashboard: SuperAdminBillingDashboardService,
        rbac_service: RBACService,
        organization_service: OrganizationService,
    ) -> None:
        self.analytics_dashboard = analytics_dashboard
        self.platform_dashboard = platform_dashboard
        self.billing_dashboard = billing_dashboard
        self.rbac_service = rbac_service
        self.organization_service = organization_service

    async def get_dashboard(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> DashboardResponse:
        overview = await self._get_overview(user_id, organization_id)
        widgets = await self._get_widgets(user_id, organization_id)
        modules = await self._get_modules(user_id, organization_id)
        return DashboardResponse(overview=overview, widgets=widgets, modules=modules)

    async def get_sidebar(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> DashboardSidebarResponse:
        permissions = await self.rbac_service.get_user_permissions(user_id)
        perm_set = set(permissions)

        items: list[SidebarNavItem] = [
            SidebarNavItem(
                id="dashboard",
                label="Dashboard",
                icon="layout-dashboard",
                path="/dashboard",
                module="dashboard",
            ),
            SidebarNavItem(
                id="locations",
                label="Locations",
                icon="map-pin",
                path="/locations",
                module="locations",
            ),
            SidebarNavItem(
                id="routers",
                label="Routers",
                icon="router",
                path="/routers",
                module="routers",
            ),
            SidebarNavItem(
                id="guests",
                label="Guests",
                icon="wifi",
                path="/guests",
                module="guest_wifi",
            ),
            SidebarNavItem(
                id="sessions",
                label="Live Sessions",
                icon="activity",
                path="/sessions",
                module="guest_sessions",
            ),
            SidebarNavItem(
                id="analytics",
                label="Analytics",
                icon="bar-chart-3",
                path="/analytics",
                module="analytics",
            ),
            SidebarNavItem(
                id="monitoring",
                label="Monitoring",
                icon="shield",
                path="/monitoring",
                module="monitoring",
            ),
            SidebarNavItem(
                id="billing",
                label="Billing",
                icon="credit-card",
                path="/billing",
                module="billing",
            ),
            SidebarNavItem(
                id="network",
                label="Network",
                icon="network",
                path="/network/vlan",
                module="dhcp",
                children=[
                    SidebarNavItem(
                        id="vlan",
                        label="VLAN",
                        path="/network/vlan",
                        module="vlan",
                    ),
                    SidebarNavItem(
                        id="dhcp",
                        label="DHCP",
                        path="/network/dhcp",
                        module="dhcp",
                    ),
                    SidebarNavItem(
                        id="dns",
                        label="DNS",
                        path="/network/dns",
                        module="dns",
                    ),
                    SidebarNavItem(
                        id="firewall",
                        label="Firewall",
                        path="/network/firewall",
                        module="firewall",
                    ),
                ],
            ),
            SidebarNavItem(
                id="policies",
                label="Policies",
                icon="shield-check",
                path="/policies/authentication",
                module="bandwidth",
            ),
            SidebarNavItem(
                id="portal",
                label="Portal",
                icon="palette",
                path="/portals",
                module="captive_portal",
            ),
            SidebarNavItem(
                id="rbac",
                label="Users & Roles",
                icon="users",
                path="/rbac",
                module="users",
            ),
            SidebarNavItem(
                id="settings",
                label="Settings",
                icon="settings",
                path="/settings",
                module="white_label",
            ),
        ]

        allowed: list[SidebarNavItem] = []
        for item in items:
            if (
                item.module
                and any(f"{item.module}." in p for p in perm_set)
                or item.module == "dashboard"
            ):
                allowed.append(item)

        return DashboardSidebarResponse(items=allowed)

    async def get_widgets(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> DashboardWidgetsResponse:
        widgets = await self._get_widgets(user_id, organization_id)
        return DashboardWidgetsResponse(widgets=widgets)

    async def get_modules(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> DashboardModulesResponse:
        modules = await self._get_modules(user_id, organization_id)
        return DashboardModulesResponse(modules=modules)

    async def _get_overview(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> DashboardOverview:
        """Composes the three headline counts from the services that already
        own them.

        Both reads below used to be wrapped in a bare ``except Exception: -> 0``.
        That is the wrong failure mode for a counter: an operator cannot tell
        "you genuinely have no routers" from "the query broke", and the second
        reading is the one that matters. Failures now propagate and surface as
        a 5xx, the same posture ``live_sessions`` was moved to.

        ``total_routers`` additionally read ``dash.total_routers_online`` and
        ``dash.total_routers_offline`` behind a ``hasattr`` guard. Neither
        attribute has ever existed on ``SuperAdminDashboardResponse`` -- the
        real fields are ``total_routers``/``routers_online``/``routers_offline``
        (``analytics.dashboard_schemas``) -- so the guard was permanently
        False and this endpoint reported **0 routers** for every account since
        it shipped, with the correct value one attribute away.
        """
        orgs = await self.organization_service.list_organizations(
            requesting_user_id=user_id, page=1, page_size=1
        )
        total_orgs = orgs[1].total_items if len(orgs) > 1 else 0

        dash = await self.analytics_dashboard.get_super_admin_dashboard(user_id)

        return DashboardOverview(
            total_organizations=total_orgs,
            total_locations=dash.total_locations,
            total_routers=dash.total_routers,
        )

    async def _get_widgets(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> list[WidgetConfig]:
        return [
            WidgetConfig(
                id="kpi-overview", type="kpi-grid", title="Overview", size="full"
            ),
            WidgetConfig(
                id="active-guests", type="stat", title="Active Guests", size="small"
            ),
            WidgetConfig(
                id="routers-online", type="stat", title="Routers Online", size="small"
            ),
            WidgetConfig(id="revenue-mrr", type="stat", title="MRR", size="small"),
            WidgetConfig(id="alerts", type="stat", title="Active Alerts", size="small"),
            WidgetConfig(
                id="guest-trend", type="chart", title="Guest Trend", size="medium"
            ),
            WidgetConfig(
                id="router-health", type="chart", title="Router Health", size="medium"
            ),
            WidgetConfig(
                id="recent-activity",
                type="table",
                title="Recent Activity",
                size="large",
            ),
        ]

    async def _get_modules(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> list[ModuleInfo]:
        permissions = await self.rbac_service.get_user_permissions(user_id)
        perm_set = set(permissions)

        all_modules = [
            ModuleInfo(id="dashboard", name="Dashboard", path="/dashboard"),
            ModuleInfo(id="locations", name="Locations", path="/locations"),
            ModuleInfo(id="routers", name="Routers", path="/routers"),
            ModuleInfo(id="guest_wifi", name="Guest WiFi", path="/guests"),
            ModuleInfo(id="guest_sessions", name="Live Sessions", path="/sessions"),
            ModuleInfo(id="analytics", name="Analytics", path="/analytics"),
            ModuleInfo(id="monitoring", name="Monitoring", path="/monitoring"),
            ModuleInfo(id="billing", name="Billing", path="/billing"),
            ModuleInfo(id="vlan", name="VLAN", path="/network/vlan"),
            ModuleInfo(id="dhcp", name="DHCP", path="/network/dhcp"),
            ModuleInfo(id="dns", name="DNS", path="/network/dns"),
            ModuleInfo(id="firewall", name="Firewall", path="/network/firewall"),
            ModuleInfo(id="captive_portal", name="Portal Builder", path="/portals"),
            ModuleInfo(id="voucher", name="Vouchers", path="/vouchers"),
            ModuleInfo(id="campaigns", name="Campaigns", path="/campaigns"),
            ModuleInfo(id="wireguard", name="WireGuard", path="/wireguard"),
            ModuleInfo(id="white_label", name="Branding", path="/branding"),
        ]

        result = []
        for mod in all_modules:
            if mod.id == "dashboard" or any(f"{mod.id}." in p for p in perm_set):
                result.append(mod)
            else:
                mod.enabled = False
                mod.locked = True
                result.append(mod)

        return result
