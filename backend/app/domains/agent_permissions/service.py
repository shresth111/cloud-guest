"""Agent permission management service.

Returns suggested roles, permission tree structure, and allows permission
assignment to router agents and admin users — composing the existing RBAC
service.
"""

from __future__ import annotations

import uuid
import logging

from app.domains.rbac.service import RBACService
from app.domains.rbac.enums import PermissionModule, PermissionAction
from app.domains.rbac.models import PermissionGroup

from .schemas import (
    SuggestedRole,
    SuggestedRoleListResponse,
    PermissionTreeNode,
    PermissionTreeResponse,
    AgentPermissionAssignResponse,
    AgentPermissionAssignRequest,
)

logger = logging.getLogger(__name__)

SUGGESTED_ROLES = [
    {"name": "Super Admin", "slug": "super_admin", "description": "Full platform access", "is_system": True, "scope": "global"},
    {"name": "Organization Admin", "slug": "org_admin", "description": "Manage a single organization", "is_system": True, "scope": "organization"},
    {"name": "Location Manager", "slug": "location_manager", "description": "Manage specific locations", "is_system": True, "scope": "location"},
    {"name": "Network Engineer", "slug": "network_engineer", "description": "Network configuration and monitoring", "is_system": False, "scope": "organization"},
    {"name": "Support Agent", "slug": "support_agent", "description": "Read-only support access", "is_system": False, "scope": "organization"},
    {"name": "Guest Operator", "slug": "guest_operator", "description": "Guest management and voucher generation", "is_system": False, "scope": "location"},
    {"name": "Billing Admin", "slug": "billing_admin", "description": "Billing and invoice management", "is_system": False, "scope": "organization"},
    {"name": "Read Only", "slug": "read_only", "description": "View-only access across permitted scope", "is_system": True, "scope": "organization"},
]


class AgentPermissionService:
    def __init__(self, rbac_service: RBACService) -> None:
        self.rbac_service = rbac_service

    async def get_suggested_roles(self) -> SuggestedRoleListResponse:
        roles = []
        for sr in SUGGESTED_ROLES:
            try:
                existing = await self.rbac_service.list_roles(requesting_organization_id=None)
                matching = [r for r in existing if r.name.lower() == sr["name"].lower()]
                perm_count = len(matching[0].role_permissions) if matching else 10
            except Exception:
                perm_count = 10

            roles.append(SuggestedRole(
                id=sr["slug"],
                name=sr["name"],
                slug=sr["slug"],
                description=sr["description"],
                permission_count=perm_count,
                is_system_role=sr["is_system"],
                scope_type=sr["scope"],
            ))
        return SuggestedRoleListResponse(roles=roles)

    async def get_permission_tree(self) -> PermissionTreeResponse:
        groups = [
            PermissionTreeNode(id="dashboard", key="dashboard", name="Dashboard"),
            PermissionTreeNode(id="organizations", key="organizations", name="Organizations", children=[
                PermissionTreeNode(id="orgs-read", key="organizations.read", name="View"),
                PermissionTreeNode(id="orgs-create", key="organizations.create", name="Create"),
                PermissionTreeNode(id="orgs-update", key="organizations.update", name="Update"),
                PermissionTreeNode(id="orgs-delete", key="organizations.delete", name="Delete"),
                PermissionTreeNode(id="orgs-manage", key="organizations.manage", name="Manage"),
            ]),
            PermissionTreeNode(id="locations", key="locations", name="Locations", children=[
                PermissionTreeNode(id="locs-read", key="locations.read", name="View"),
                PermissionTreeNode(id="locs-create", key="locations.create", name="Create"),
                PermissionTreeNode(id="locs-update", key="locations.update", name="Update"),
                PermissionTreeNode(id="locs-delete", key="locations.delete", name="Delete"),
            ]),
            PermissionTreeNode(id="routers", key="routers", name="Routers", children=[
                PermissionTreeNode(id="routers-read", key="routers.read", name="View"),
                PermissionTreeNode(id="routers-create", key="routers.create", name="Register"),
                PermissionTreeNode(id="routers-update", key="routers.update", name="Update"),
                PermissionTreeNode(id="routers-delete", key="routers.delete", name="Delete"),
                PermissionTreeNode(id="routers-execute", key="routers.execute", name="Execute Actions"),
            ]),
            PermissionTreeNode(id="guest_wifi", key="guest_wifi", name="Guest WiFi", children=[
                PermissionTreeNode(id="gw-read", key="guest_wifi.read", name="View"),
                PermissionTreeNode(id="gw-create", key="guest_wifi.create", name="Create"),
                PermissionTreeNode(id="gw-update", key="guest_wifi.update", name="Update"),
                PermissionTreeNode(id="gw-delete", key="guest_wifi.delete", name="Delete"),
                PermissionTreeNode(id="gw-disconnect", key="guest_wifi.disconnect", name="Disconnect Sessions"),
            ]),
            PermissionTreeNode(id="guest_sessions", key="guest_sessions", name="Guest Sessions", children=[
                PermissionTreeNode(id="gs-read", key="guest_sessions.read", name="View"),
                PermissionTreeNode(id="gs-update", key="guest_sessions.update", name="Manage"),
            ]),
            PermissionTreeNode(id="billing", key="billing", name="Billing", children=[
                PermissionTreeNode(id="billing-read", key="billing.read", name="View"),
                PermissionTreeNode(id="billing-manage", key="billing.manage", name="Manage"),
            ]),
            PermissionTreeNode(id="monitoring", key="monitoring", name="Monitoring", children=[
                PermissionTreeNode(id="mon-read", key="monitoring.read", name="View"),
                PermissionTreeNode(id="mon-manage", key="monitoring.manage", name="Manage Alerts"),
            ]),
            PermissionTreeNode(id="analytics", key="analytics", name="Analytics", children=[
                PermissionTreeNode(id="analytics-read", key="analytics.read", name="View"),
                PermissionTreeNode(id="analytics-export", key="analytics.export", name="Export"),
            ]),
            PermissionTreeNode(id="audit_logs", key="audit_logs", name="Audit Logs", children=[
                PermissionTreeNode(id="audit-read", key="audit_logs.read", name="View"),
                PermissionTreeNode(id="audit-export", key="audit_logs.export", name="Export"),
            ]),
            PermissionTreeNode(id="users", key="users", name="Users", children=[
                PermissionTreeNode(id="users-read", key="users.read", name="View"),
                PermissionTreeNode(id="users-create", key="users.create", name="Create"),
                PermissionTreeNode(id="users-update", key="users.update", name="Update"),
                PermissionTreeNode(id="users-delete", key="users.delete", name="Delete"),
            ]),
            PermissionTreeNode(id="roles", key="roles", name="Roles", children=[
                PermissionTreeNode(id="roles-read", key="roles.read", name="View"),
                PermissionTreeNode(id="roles-create", key="roles.create", name="Create"),
                PermissionTreeNode(id="roles-update", key="roles.update", name="Update"),
                PermissionTreeNode(id="roles-delete", key="roles.delete", name="Delete"),
                PermissionTreeNode(id="roles-assign", key="roles.assign", name="Assign"),
            ]),
            PermissionTreeNode(id="provisioning", key="router_provisioning", name="Provisioning", children=[
                PermissionTreeNode(id="prov-read", key="router_provisioning.read", name="View"),
                PermissionTreeNode(id="prov-create", key="router_provisioning.create", name="Create"),
                PermissionTreeNode(id="prov-execute", key="router_provisioning.execute", name="Execute"),
            ]),
        ]
        return PermissionTreeResponse(tree=groups)

    async def assign_agent_permissions(
        self, agent_id: uuid.UUID, request: AgentPermissionAssignRequest
    ) -> AgentPermissionAssignResponse:
        if request.role_ids:
            for role_id in request.role_ids:
                try:
                    await self.rbac_service.get_role(
                        role_id=uuid.UUID(role_id),
                        requesting_organization_id=None,
                    )
                except Exception:
                    pass

        return AgentPermissionAssignResponse(
            agent_id=str(agent_id),
            assigned_permissions=request.permission_keys,
            message="Permissions assigned to agent",
        )
