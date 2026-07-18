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

    # Organization domain events (Module 005) -- written through this same
    # table by ``app.domains.organization.service.OrganizationService`` via
    # the ``AuditLogWriter`` protocol, per this table's documented "other
    # domains could plausibly reuse it" design (see ``AuditLogEntry``).
    ORGANIZATION_CREATED = "organization_created"
    ORGANIZATION_UPDATED = "organization_updated"
    ORGANIZATION_ARCHIVED = "organization_archived"
    ORGANIZATION_SUSPENDED = "organization_suspended"
    ORGANIZATION_ACTIVATED = "organization_activated"
    ORGANIZATION_MEMBER_INVITED = "organization_member_invited"
    ORGANIZATION_MEMBER_ACCEPTED = "organization_member_accepted"
    ORGANIZATION_MEMBER_REMOVED = "organization_member_removed"
    ORGANIZATION_MEMBER_STATUS_CHANGED = "organization_member_status_changed"

    # Location domain events (Module 006) -- written through this same table
    # by ``app.domains.location.service.LocationService`` via the same
    # narrow ``AuditLogWriter`` protocol shape ``OrganizationService`` uses
    # (see ``AuditLogEntry``'s "other domains could plausibly reuse it"
    # design).
    LOCATION_CREATED = "location_created"
    LOCATION_UPDATED = "location_updated"
    LOCATION_ARCHIVED = "location_archived"
    LOCATION_SUSPENDED = "location_suspended"
    LOCATION_ACTIVATED = "location_activated"

    # User management/aggregation events (Module 007) -- written through
    # this same table by ``app.domains.user.service.UserService`` via the
    # same narrow ``AuditLogWriter`` protocol shape ``OrganizationService``/
    # ``LocationService`` use (see ``AuditLogEntry``'s "other domains could
    # plausibly reuse it" design). Note this module never writes
    # ``ROLE_ASSIGNED``/organization-membership audit entries itself -- an
    # admin-time initial role assignment or organization membership grant
    # made during ``UserService.create_user`` is performed by *calling*
    # ``RBACService.assign_role_to_user`` / ``OrganizationService.
    # invite_member`` + ``accept_invite`` directly, so those domains' own
    # audit entries (``ROLE_ASSIGNED``, ``ORGANIZATION_MEMBER_INVITED``,
    # ``ORGANIZATION_MEMBER_ACCEPTED``) are what get recorded for that part
    # -- these four values cover only the identity-record lifecycle itself.
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DEACTIVATED = "user_deactivated"
    USER_REACTIVATED = "user_reactivated"

    # Router domain events (Module 008) -- written through this same table by
    # ``app.domains.router.service.RouterService`` via the same narrow
    # ``AuditLogWriter`` protocol shape ``OrganizationService``/
    # ``LocationService``/``UserService`` use (see ``AuditLogEntry``'s
    # "other domains could plausibly reuse it" design). Heartbeats are
    # deliberately not audited here -- see
    # ``docs/router/ROUTER_ARCHITECTURE.md`` §6.
    ROUTER_CREATED = "router_created"
    ROUTER_UPDATED = "router_updated"
    ROUTER_DECOMMISSIONED = "router_decommissioned"
    ROUTER_SUSPENDED = "router_suspended"
    ROUTER_REINSTATED = "router_reinstated"
    ROUTER_PROVISIONING_TOKEN_GENERATED = "router_provisioning_token_generated"
    ROUTER_PROVISIONED = "router_provisioned"

    # Router Provisioning domain events (Module 009) -- written through this
    # same table by
    # ``app.domains.router_provisioning.service.RouterProvisioningService``
    # via the same narrow ``AuditLogWriter`` protocol shape ``RouterService``/
    # ``LocationService``/``OrganizationService``/``UserService`` all use
    # (see ``AuditLogEntry``'s "other domains could plausibly reuse it"
    # design). ``ROUTER_FACTORY_RESET`` is used by BE-008's own
    # ``RouterService.reset_to_pending_provisioning`` (an additive method
    # Module 009 added to support its factory-reset workflow), not by
    # Module 009's service directly -- see
    # ``docs/router_provisioning/FLOW.md``. High-frequency device telemetry
    # (health snapshots, individual queue-job status ticks) is deliberately
    # **not** audited here -- see ``RouterEvent``'s module docstring in
    # ``app.domains.router_provisioning.models`` for why that lives in its
    # own, separate, higher-volume table instead.
    ROUTER_ENROLLMENT_SUBMITTED = "router_enrollment_submitted"
    ROUTER_ENROLLMENT_APPROVED = "router_enrollment_approved"
    ROUTER_ENROLLMENT_REJECTED = "router_enrollment_rejected"
    ROUTER_SECRET_ROTATED = "router_secret_rotated"
    ROUTER_FACTORY_RESET = "router_factory_reset"
    ROUTER_CONFIG_VERSION_APPLIED = "router_config_version_applied"
    ROUTER_CONFIG_VERSION_ROLLED_BACK = "router_config_version_rolled_back"
    ROUTER_BACKUP_CREATED = "router_backup_created"
    ROUTER_RESTORE_COMPLETED = "router_restore_completed"
