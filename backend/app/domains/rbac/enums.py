"""Enumerations shared across the RBAC domain.

Stored as plain ``String`` columns on the ORM models (mirroring the existing
convention in ``app.domains.auth.models`` -- e.g. ``User.status`` -- rather
than native PostgreSQL enum types) so that adding a new value never requires
an ``ALTER TYPE`` migration, only a new seed row.
"""

from __future__ import annotations

from enum import StrEnum


class ScopeType(StrEnum):
    """The multi-tenant hierarchy level a role/permission/assignment applies at.

    Ordered broad -> narrow: ``GLOBAL`` > ``ORGANIZATION`` > ``LOCATION`` >
    ``ROUTER`` > ``DEVICE``. ``DEVICE`` is reserved for a future per-device
    scope (e.g. a specific guest device) and is not yet assignable to any
    seeded role, but is present in the enum per the module spec.

    Note: there is no dedicated ``MSP`` level. The hierarchy this platform
    models is CloudGuest -> MSP -> Organization -> Location -> Router ->
    Guest, but MSP has no domain of its own yet (see scope-boundary note in
    the module brief). MSP-flavoured roles (MSP Owner/MSP Admin) are seeded
    at ``ORGANIZATION`` scope as the closest existing fit -- an MSP is
    modeled, once the Organization domain exists, as an Organization row
    flagged as an MSP container. See RBAC_ARCHITECTURE.md for the full
    reasoning.
    """

    GLOBAL = "global"
    ORGANIZATION = "organization"
    LOCATION = "location"
    ROUTER = "router"
    DEVICE = "device"


SCOPE_HIERARCHY_ORDER: dict[ScopeType, int] = {
    ScopeType.GLOBAL: 0,
    ScopeType.ORGANIZATION: 1,
    ScopeType.LOCATION: 2,
    ScopeType.ROUTER: 3,
    ScopeType.DEVICE: 4,
}


class PermissionAction(StrEnum):
    """The verb half of a permission key, e.g. ``users.create``."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXPORT = "export"
    IMPORT = "import"
    APPROVE = "approve"
    ASSIGN = "assign"
    MANAGE = "manage"
    EXECUTE = "execute"
    VIEW = "view"


class PermissionModule(StrEnum):
    """The noun half of a permission key (a ``permission_groups`` slug)."""

    DASHBOARD = "dashboard"
    USERS = "users"
    ROLES = "roles"
    PERMISSIONS = "permissions"
    ORGANIZATIONS = "organizations"
    LOCATIONS = "locations"
    ROUTERS = "routers"
    ROUTER_PROVISIONING = "router_provisioning"
    TEMPLATES = "templates"
    CAPTIVE_PORTAL = "captive_portal"
    GUEST_WIFI = "guest_wifi"
    GUEST_USERS = "guest_users"
    GUEST_SESSIONS = "guest_sessions"
    OTP = "otp"
    VOUCHER = "voucher"
    CAMPAIGNS = "campaigns"
    RADIUS = "radius"
    WIREGUARD = "wireguard"
    FIREWALL = "firewall"
    DHCP = "dhcp"
    DNS = "dns"
    HOTSPOT = "hotspot"
    BANDWIDTH = "bandwidth"
    ANALYTICS = "analytics"
    REPORTS = "reports"
    MONITORING = "monitoring"
    ALERTS = "alerts"
    NOTIFICATIONS = "notifications"
    BILLING = "billing"
    INVOICES = "invoices"
    SUBSCRIPTIONS = "subscriptions"
    WHITE_LABEL = "white_label"
    API_KEYS = "api_keys"
    AUDIT_LOGS = "audit_logs"
    SYSTEM_SETTINGS = "system_settings"
    AI_ASSISTANT = "ai_assistant"


class OverrideEffect(StrEnum):
    """The effect of a per-user permission override."""

    ALLOW = "allow"
    DENY = "deny"


class AuditAction(StrEnum):
    """The set of RBAC events persisted to ``audit_log_entries``."""

    ROLE_CREATED = "role_created"
    ROLE_UPDATED = "role_updated"
    ROLE_DELETED = "role_deleted"
    ROLE_CLONED = "role_cloned"
    ROLE_ACTIVATED = "role_activated"
    ROLE_DEACTIVATED = "role_deactivated"
    PERMISSION_ASSIGNED = "permission_assigned"
    PERMISSION_REMOVED = "permission_removed"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_OVERRIDE_GRANTED = "permission_override_granted"
    PERMISSION_OVERRIDE_REVOKED = "permission_override_revoked"
