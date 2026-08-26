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
    # Staff impersonating a customer account to view their dashboard as
    # them (``users.impersonate``, USERS module only). Deliberately never
    # expanded into any generic ``GrantLevel`` (not even ``FULL``) --
    # ``app.domains.rbac.seed``'s own ``expand_grant_level``/
    # ``SystemRoleDefinition.extra_grants`` grant this action only to
    # Super Admin, explicitly, since it is materially more sensitive than
    # every other USERS action (it mints a real, working session as
    # another account) and must never silently ride along with an
    # otherwise-ordinary "full user management" grant held by Platform
    # Admin/MSP Owner/Organization Owner/etc. See seed.py's own comment
    # on ``expand_grant_level`` for the full reasoning.
    IMPERSONATE = "impersonate"


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
    GUEST_ACCESS = "guest_access"
    GUEST_TEAMS = "guest_teams"
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
    POLICY = "policy"
    PROVISIONING_ENGINE = "provisioning_engine"
    ISP = "isp"
    ISP_ROUTING = "isp_routing"
    VLAN = "vlan"
    MAC_AUTHORIZATION = "mac_authorization"
    CONNECTED_DEVICES = "connected_devices"
    DEVICE_SYNC = "device_sync"
    NETWORK_CONFIG = "network_config"
    QOS = "qos"
    NETWORK_DIAGNOSTICS = "network_diagnostics"
    NETWORK_DEVICE = "network_device"
    MONITORED_HARDWARE = "monitored_hardware"
    SUPPORT_TICKETS = "support_tickets"
    DEVICE_CONSOLE = "device_console"
    DEMO_REQUESTS = "demo_requests"
    # Content Filtering: per-router DNS-sinkhole/address-list blocking
    # rules -- see app.domains.content_filtering's own module docstring
    # for the full, honest RouterOS scope decision this module composes
    # into the network_config push pipeline.
    CONTENT_FILTERING = "content_filtering"
    # Sales quotations: a branded PDF quotation an operator generates and
    # emails to a prospective/existing client -- see
    # app.domains.quotation's own module docstring. GLOBAL-only, same
    # "belongs to no organization" profile as DEMO_REQUESTS above.
    QUOTATIONS = "quotations"
    # Router Readiness Checklist: per-router "is this ready to hand to a
    # customer" checklist -- see app.domains.readiness's own module
    # docstring. Read-only auto-detected items plus a manual-confirm
    # write path, mirroring NETWORK_DIAGNOSTICS's own "read + a real
    # device-facing action" shape.
    READINESS = "readiness"
    # Channel Partner onboarding: a Master console operator onboards a new
    # channel/reseller partner (name/phone/address/city/GSTIN) and the
    # system sends them a real welcome message in the same action. GLOBAL-
    # only, identical "belongs to no organization" profile as QUOTATIONS/
    # DEMO_REQUESTS above -- a channel partner is Wyfy Guest's own business
    # relationship, never scoped to a customer Organization.
    CHANNEL_PARTNERS = "channel_partners"


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
    ORGANIZATION_BRANDING_UPDATED = "organization_branding_updated"
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

    # Smart Location Provisioning (Module 006 extension) -- written through
    # this same table by
    # ``app.domains.location.provisioning_service.LocationProvisioningService``
    # via the same narrow ``AuditLogWriter`` protocol shape
    # ``LocationService`` itself already uses. Every composed step this
    # orchestration calls (organization/location/router/wireguard/plan/
    # subscription/captive-portal creation, role assignment) already writes
    # its *own* audit entry via its own existing service call -- this module
    # adds exactly one additional entry for the overall provisioning event
    # itself (see ``docs/location/FLOW.md`` "Audit logging" section), never
    # duplicating any of those. ``LOCATION_WELCOME_EMAIL_SENT`` covers both
    # the provisioning flow's own welcome email and the dedicated
    # "resend welcome email" endpoint.
    LOCATION_PROVISIONED = "location_provisioned"
    LOCATION_WELCOME_EMAIL_SENT = "location_welcome_email_sent"

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
    USER_FORCE_LOGGED_OUT = "user_force_logged_out"
    # A platform staff member (holding the Super-Admin-exclusive
    # ``users.impersonate`` permission) started a time-limited session
    # impersonating a customer account to view their dashboard as them --
    # see ``UserService.impersonate_user``. Always audited, on every
    # single start, regardless of outcome-of-session -- this is exactly
    # the "who accessed a customer's account, when, and why" trail this
    # genuinely sensitive capability exists to leave, the same
    # "operator explicitly triggers something with real side effects, so
    # every invocation is logged" posture ``ROUTER_CREDENTIALS_REVEALED``/
    # ``DEVICE_CONSOLE_COMMAND_EXECUTED`` already establish elsewhere in
    # this enum for other "a human deliberately did something powerful"
    # actions.
    IMPERSONATION_STARTED = "impersonation_started"

    # Router domain events (Module 008) -- written through this same table by
    # ``app.domains.router.service.RouterService`` via the same narrow
    # ``AuditLogWriter`` protocol shape ``OrganizationService``/
    # ``LocationService``/``UserService`` use (see ``AuditLogEntry``'s
    # "other domains could plausibly reuse it" design). Heartbeats are
    # deliberately not audited here -- see
    # ``docs/router/ROUTER_ARCHITECTURE.md`` §6.
    ROUTER_CREATED = "router_created"
    ROUTER_UPDATED = "router_updated"
    # A platform operator decrypted and viewed this router's stored RouterOS
    # API/WinBox credentials via Master Console's "Remote Access" panel
    # (app.domains.router.router's GET /routers/{id}/remote-access) --
    # audited because unlike every other ROUTER_* action here, this one
    # doesn't change any state, it exposes a secret, so "who saw this and
    # when" is the whole point of logging it.
    ROUTER_CREDENTIALS_REVEALED = "router_credentials_revealed"
    ROUTER_DECOMMISSIONED = "router_decommissioned"
    ROUTER_SUSPENDED = "router_suspended"
    ROUTER_REINSTATED = "router_reinstated"
    # THE MISSING WRITER. `OFFLINE` has always been documented as "was
    # previously ONLINE but missed its expected heartbeat window", and the
    # ONLINE -> OFFLINE edge has always been allowed -- but nothing ever
    # made that transition, so a router that stopped answering stayed
    # `online` for ever. Written only by the heartbeat sweep, and audited
    # with a null actor because no human performed it.
    ROUTER_MARKED_OFFLINE = "router_marked_offline"
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
    # A live (ONLINE/OFFLINE) router was rewound to PENDING_PROVISIONING by
    # the remote-mode bootstrap preview (RouterService
    # .preview_bootstrap_script with BootstrapMode.REMOTE) so a fresh
    # provisioning token could be minted for a scheduler-staged tunnel
    # cutover. Deliberately NOT reusing ROUTER_FACTORY_RESET: nothing was
    # wiped on the device -- the same "wrong semantics" concern
    # app.domains.router.router.regenerate_agent_credential's docstring
    # already documents for that action.
    ROUTER_REMOTE_REPROVISION_STARTED = "router_remote_reprovision_started"
    ROUTER_CONFIG_VERSION_APPLIED = "router_config_version_applied"
    ROUTER_CONFIG_VERSION_ROLLED_BACK = "router_config_version_rolled_back"
    ROUTER_BACKUP_CREATED = "router_backup_created"
    ROUTER_RESTORE_COMPLETED = "router_restore_completed"
    ROUTER_CONFIGURATION_PLAN_APPLIED = "router_configuration_plan_applied"
    ROUTER_CONFIGURATION_PLAN_FINAL_VERIFIED = (
        "router_configuration_plan_final_verified"
    )
    ROUTER_WAN_ROUTING_MODE_CHANGED = "router_wan_routing_mode_changed"

    # WireGuard domain events (Module 009 Part 3) -- written through this
    # same table by ``app.domains.wireguard.service.WireGuardService`` via
    # the same narrow ``AuditLogWriter`` protocol shape ``RouterService``/
    # ``RouterProvisioningService``/every other domain's own service uses
    # (see ``AuditLogEntry``'s "other domains could plausibly reuse it"
    # design). Handshake reports are deliberately **not** audited here --
    # they are frequent device telemetry, not an admin-driven event, the
    # identical reasoning BE-008 already documents for why heartbeats are
    # never audited either.
    WIREGUARD_TUNNEL_CREATED = "wireguard_tunnel_created"
    WIREGUARD_TUNNEL_ROTATED = "wireguard_tunnel_rotated"
    WIREGUARD_TUNNEL_REVOKED = "wireguard_tunnel_revoked"

    # OTP domain events (Module 010 Part 1) -- written through this same
    # table by ``app.domains.otp.service.OtpService`` via the same narrow
    # ``AuditLogWriter`` protocol shape every other domain's service uses
    # (see ``AuditLogEntry``'s "other domains could plausibly reuse it"
    # design). ``OTP_REQUESTED`` deliberately exists as a value but is
    # never actually written by ``OtpService.request_otp`` -- a guest-
    # facing, unauthenticated, high-volume action would flood this
    # moderate-volume, admin-reviewable table for no benefit; the value is
    # kept for forward-compatibility (a future decision to start auditing
    # it needs no migration). ``OTP_VERIFICATION_FAILED`` is likewise only
    # written for the two adversarially-relevant failure reasons (wrong
    # code, attempts exceeded) -- see ``app.domains.otp.service``'s module
    # docstring for the full audit-volume judgment call.
    OTP_REQUESTED = "otp_requested"
    OTP_VERIFIED = "otp_verified"
    OTP_VERIFICATION_FAILED = "otp_verification_failed"

    # Voucher domain events (Module 010 Part 2) -- written through this same
    # table by ``app.domains.voucher.service.VoucherService`` via the same
    # narrow ``AuditLogWriter`` protocol shape every other domain's service
    # uses (see ``AuditLogEntry``'s "other domains could plausibly reuse it"
    # design). Batch lifecycle events (created/submitted/approved/activated/
    # revoked) and pre-printed code imports are audited for the same reason
    # every other domain's own lifecycle events are (moderate-volume,
    # human-attributable, admin-reviewable). ``VOUCHER_REDEEMED`` is audited
    # on **every** successful redemption -- a deliberate departure from
    # OTP's own "don't audit the high-volume routine event" call, since a
    # voucher redemption (unlike an OTP *request*) is itself the moment real
    # network access is granted, standing in for a real monetary/access
    # transaction. ``VOUCHER_REDEMPTION_FAILED`` mirrors
    # ``OTP_VERIFICATION_FAILED``'s own tiering: only written for the two
    # adversarially-relevant reasons (attempted reuse of a ``revoked``/
    # ``exhausted`` voucher), never for routine not-found/expired/
    # not-yet-active churn -- see
    # ``app.domains.voucher.service``'s module docstring for the full
    # audit-volume judgment call.
    VOUCHER_BATCH_CREATED = "voucher_batch_created"
    VOUCHER_BATCH_SUBMITTED = "voucher_batch_submitted"
    VOUCHER_BATCH_APPROVED = "voucher_batch_approved"
    VOUCHER_BATCH_ACTIVATED = "voucher_batch_activated"
    VOUCHER_BATCH_REVOKED = "voucher_batch_revoked"
    VOUCHER_CODES_IMPORTED = "voucher_codes_imported"
    VOUCHER_REDEEMED = "voucher_redeemed"
    VOUCHER_REDEMPTION_FAILED = "voucher_redemption_failed"
    # Phase 1 BhaiFi-parity additions: VoucherPlan/VoucherSeries creation --
    # the identical "moderate-volume, human-attributable, admin-reviewable"
    # profile every lifecycle event above already carries.
    VOUCHER_PLAN_CREATED = "voucher_plan_created"
    VOUCHER_SERIES_CREATED = "voucher_series_created"

    # Captive Portal domain events (Module 010 Part 3) -- written through
    # this same table by
    # ``app.domains.captive_portal.service.CaptivePortalService`` via the
    # same narrow ``AuditLogWriter`` protocol shape every other domain's
    # service uses (see ``AuditLogEntry``'s "other domains could plausibly
    # reuse it" design). Unlike OTP/Voucher's careful volume-tiering for
    # high-frequency guest actions, **every** create/update/activate/
    # deactivate/delete is audited here -- this module's mutating actions
    # are low-volume, always-authenticated admin configuration changes (who
    # changed a tenant's guest WiFi login page branding/content/enabled
    # login methods, and when), not guest-facing traffic, so there is no
    # analogous volume problem to tier against. The guest-facing
    # ``resolve_portal_config`` read path is never audited (no state
    # change, mirrors every other domain's own "reads aren't audited"
    # convention).
    CAPTIVE_PORTAL_CONFIG_CREATED = "captive_portal_config_created"
    CAPTIVE_PORTAL_CONFIG_UPDATED = "captive_portal_config_updated"
    CAPTIVE_PORTAL_CONFIG_ACTIVATED = "captive_portal_config_activated"
    CAPTIVE_PORTAL_CONFIG_DEACTIVATED = "captive_portal_config_deactivated"
    CAPTIVE_PORTAL_CONFIG_DELETED = "captive_portal_config_deleted"
    # System-side counterpart to the ``powered_by_enabled`` white-label
    # write gate: a license downgrade to a plan without
    # ``PlanFeatureKey.WHITE_LABEL`` flips every ``powered_by_enabled=
    # False`` config in the organization back to ``True`` (see
    # ``app.domains.captive_portal.service
    # .PoweredByAttributionResetService``). Written with
    # ``actor_user_id=None`` when the downgrade itself was system-driven,
    # mirroring ``LICENSE_EXPIRED``'s "a real system-side event with no
    # human actor" convention -- deliberately *not* reusing
    # ``CAPTIVE_PORTAL_CONFIG_UPDATED``, so a tenant reading their audit
    # trail can tell an admin's edit from an entitlement-driven reset.
    CAPTIVE_PORTAL_POWERED_BY_RESTORED = "captive_portal_powered_by_restored"

    # Guest domain events (Module 010 Part 4, the final BE-010 module) --
    # written through this same table by
    # ``app.domains.guest.service.GuestService``/``RadiusService`` via the
    # same narrow ``AuditLogWriter`` protocol shape every other domain's
    # service uses (see ``AuditLogEntry``'s "other domains could plausibly
    # reuse it" design). Guest logins (``login_via_otp``/``login_via_voucher``)
    # are deliberately **not** audited here at all -- they are high-volume,
    # guest-facing traffic (the identical profile OTP's own *request*
    # tiering already establishes), and the composed calls those methods
    # make (``OtpService.verify_otp``, ``VoucherService.redeem_voucher``)
    # already write their own audit entries for the moments that matter
    # (``OTP_VERIFIED``/``VOUCHER_REDEEMED``) -- a second, guest-flavoured
    # audit row for the same event would be pure duplication. Every login
    # attempt is still recorded, at guest-module granularity, in
    # ``app.domains.guest.models.GuestLoginHistory`` (a purpose-built,
    # high-volume table, not this one -- mirrors
    # ``app.domains.router_provisioning.models.RouterEvent``'s identical
    # separation). ``GUEST_BLOCKED``/``GUEST_UNBLOCKED``/
    # ``GUEST_SESSION_TERMINATED`` are always audited (low-volume, always
    # admin-initiated). ``GUEST_SESSION_DISCONNECTED`` is audited only when
    # the disconnect was admin-initiated -- a system-initiated one (RADIUS
    # Accounting-Stop, timeout enforcement) is routine operational churn,
    # mirroring ``ROUTER_CREATED``'s heartbeat non-audit precedent.
    # ``RADIUS_NAS_REGISTERED`` is always audited (low-volume, admin-driven
    # infrastructure change).
    GUEST_BLOCKED = "guest_blocked"
    GUEST_UNBLOCKED = "guest_unblocked"
    GUEST_SESSION_DISCONNECTED = "guest_session_disconnected"
    GUEST_SESSION_TERMINATED = "guest_session_terminated"
    # Phase 1 BhaiFi-parity additions: Pause/Resume/Extend are always
    # admin-initiated (there is no system-driven equivalent, unlike
    # ``GUEST_SESSION_DISCONNECTED``'s dual system/admin origin), so all
    # three are always audited, the identical "always audited, low-volume,
    # admin-driven" profile ``GUEST_SESSION_TERMINATED`` already
    # established.
    GUEST_SESSION_PAUSED = "guest_session_paused"
    GUEST_SESSION_RESUMED = "guest_session_resumed"
    GUEST_SESSION_EXTENDED = "guest_session_extended"
    RADIUS_NAS_REGISTERED = "radius_nas_registered"
    # NAS lifecycle-management additions (NAS extension of RadiusNasClient)
    # -- the same "always audited, low-volume, admin-driven infrastructure
    # change" profile ``RADIUS_NAS_REGISTERED`` above already established.
    # ``resolve``/list/get reads are never audited, mirroring every other
    # domain's own read-vs-write audit posture.
    RADIUS_NAS_ACTIVATED = "radius_nas_activated"
    RADIUS_NAS_DISABLED = "radius_nas_disabled"
    RADIUS_NAS_SECRET_REGENERATED = "radius_nas_secret_regenerated"
    RADIUS_NAS_UPDATED = "radius_nas_updated"
    RADIUS_NAS_DELETED = "radius_nas_deleted"

    # Guest Access Control domain events (Phase 1) -- written through this
    # same table by
    # ``app.domains.guest_access.service.GuestAccessService`` via the same
    # narrow ``AuditLogWriter`` protocol shape every other domain above
    # uses. Rule create/delete are always audited (low-volume,
    # admin-initiated); deactivation (a reversible ``is_active`` toggle,
    # not a delete) is not audited on its own -- mirrors this table's
    # existing "state-changing writes get an audit row, a lighter-weight
    # flag flip doesn't need a dedicated one" judgment call.
    GUEST_ACCESS_RULE_CREATED = "guest_access_rule_created"
    GUEST_ACCESS_RULE_DELETED = "guest_access_rule_deleted"

    # Billing domain events (Module 013 Part 1: Plan + License + Usage Core)
    # -- written through this same table by
    # ``app.domains.billing.service.PlanService``/``LicenseService`` via the
    # same narrow ``AuditLogWriter`` protocol shape every other domain's
    # service uses (see ``AuditLogEntry``'s "other domains could plausibly
    # reuse it" design). Billing is a brand-new domain, not an extension of
    # an existing one -- the precedent followed here is the one every other
    # brand-new domain in this codebase's history has followed at its own
    # first Part (Organization/Module 005, Location/Module 006,
    # User/Module 007, Router/Module 008, Router Provisioning/Module 009,
    # WireGuard/Module 009 Part 3, OTP/Voucher/Captive Portal/Guest/Module
    # 010): add its own additive block of ``AuditAction`` values directly
    # here, never a domain-local constants shadow of this same enum. Every
    # Plan catalog mutation (create/update/deactivate) and every License
    # lifecycle transition (assign/activate/suspend/upgrade/downgrade/
    # expire/cancel) is audited -- the same moderate-volume,
    # admin-attributable event profile every prior domain's own additions
    # already cover this way. Usage recording/limit-check reads are never
    # audited (a pure read/recompute triggers no state change a human made,
    # mirroring every other domain's own "reads aren't audited" convention).
    PLAN_CREATED = "plan_created"
    PLAN_UPDATED = "plan_updated"
    PLAN_DEACTIVATED = "plan_deactivated"
    LICENSE_ASSIGNED = "license_assigned"
    LICENSE_ACTIVATED = "license_activated"
    LICENSE_SUSPENDED = "license_suspended"
    LICENSE_EXPIRED = "license_expired"
    LICENSE_CANCELLED = "license_cancelled"
    LICENSE_UPGRADED = "license_upgraded"
    LICENSE_DOWNGRADED = "license_downgraded"

    # Billing domain events (Module 013 Part 2: Subscription + Renewal +
    # Coupon Engines) -- written through this same table by
    # ``app.domains.billing.service.SubscriptionService``/``CouponService``/
    # ``app.domains.billing.renewal_service.RenewalService`` via the same
    # narrow ``AuditLogWriter`` protocol shape Part 1's own ``PlanService``/
    # ``LicenseService`` already use (see ``AuditLogEntry``'s "other domains
    # could plausibly reuse it" design) -- an existing domain's later Part
    # extending its own additive block, the same precedent BE-012's later
    # Parts (e.g. Part 5's ``REPORTS``) already followed for themselves.
    # Every Subscription lifecycle transition (create/cancel/reactivate/
    # pause/resume/renew/renewal-failed) and every Coupon catalog mutation/
    # application is audited -- the same moderate-volume, admin- or
    # billing-event-attributable profile Part 1's own License/Plan actions
    # already cover this way. Coupon *validation* (the no-side-effect
    # ``POST /coupons/validate`` check) and renewal reminder emails are
    # never audited (a pure read/notification triggers no billable state
    # change -- the same "reads aren't audited" convention every prior
    # domain's own additions already follow); both are still logged via the
    # structured logger for operational visibility.
    SUBSCRIPTION_CREATED = "subscription_created"
    SUBSCRIPTION_CANCELLED = "subscription_cancelled"
    SUBSCRIPTION_REACTIVATED = "subscription_reactivated"
    SUBSCRIPTION_PAUSED = "subscription_paused"
    SUBSCRIPTION_RESUMED = "subscription_resumed"
    SUBSCRIPTION_RENEWED = "subscription_renewed"
    SUBSCRIPTION_RENEWAL_FAILED = "subscription_renewal_failed"
    SUBSCRIPTION_EXPIRED_AFTER_GRACE_PERIOD = "subscription_expired_after_grace_period"
    COUPON_CREATED = "coupon_created"
    COUPON_UPDATED = "coupon_updated"
    COUPON_DEACTIVATED = "coupon_deactivated"
    COUPON_APPLIED = "coupon_applied"

    # Billing domain events (Module 013 Part 3: Payment Service + real
    # Stripe/Razorpay Integration + Webhooks) -- written through this same
    # table by ``app.domains.billing.service.PaymentService`` via the same
    # narrow ``AuditLogWriter`` protocol shape Part 1/2's own services
    # already use (see ``AuditLogEntry``'s "other domains could plausibly
    # reuse it" design) -- an existing domain's later Part extending its own
    # additive block, the same precedent Part 2 itself already followed for
    # Part 1. Every payment lifecycle transition a human/API-caller
    # initiated (initiate/refund/retry) and every PaymentMethod
    # registration/removal is audited -- the same moderate-volume,
    # admin- or billing-event-attributable profile Parts 1-2's own actions
    # already cover this way. A payment outcome *confirmed asynchronously by
    # a provider webhook* (PAYMENT_SUCCEEDED/PAYMENT_FAILED when the
    # triggering call was ``RenewalService``'s own automatic sweep, not a
    # human-initiated ``POST /payments``) is audited with ``actor_user_id=
    # None``, mirroring ``LICENSE_EXPIRED``'s identical "a real system-
    # attributed event, not a human one" precedent. Webhook signature
    # verification failures and successful-but-unhandled-event-type receipts
    # are logged via the structured logger only (see
    # ``webhooks.py``'s own module docstring) -- an adversarial/noise signal
    # a SOC/ops dashboard cares about, not a billable state change this
    # domain's own audit trail is for.
    PAYMENT_INITIATED = "payment_initiated"
    PAYMENT_SUCCEEDED = "payment_succeeded"
    PAYMENT_FAILED = "payment_failed"
    PAYMENT_REFUNDED = "payment_refunded"
    PAYMENT_RETRIED = "payment_retried"
    PAYMENT_METHOD_REGISTERED = "payment_method_registered"
    PAYMENT_METHOD_REMOVED = "payment_method_removed"

    # Billing domain events (Module 013 Part 4: Invoice Engine + Tax/GST) --
    # written through this same table by
    # ``app.domains.billing.service.InvoiceService``/``TaxRateService``/
    # ``BillingProfileService`` via the same narrow ``AuditLogWriter``
    # protocol shape every prior Part's own services already use (see
    # ``AuditLogEntry``'s "other domains could plausibly reuse it" design)
    # -- an existing domain's later Part extending its own additive block,
    # the same precedent Parts 2/3 themselves already followed for Part 1.
    # Every invoice lifecycle transition (generate/mark-paid/void/overdue)
    # and every credit/debit note issuance is audited -- the same
    # moderate-volume, billing-event-attributable profile Parts 1-3's own
    # actions already cover this way. ``INVOICE_MARKED_OVERDUE`` (a sweep-
    # driven, not human-initiated, transition) is audited with
    # ``actor_user_id=None``, mirroring ``LICENSE_EXPIRED``/
    # ``SUBSCRIPTION_EXPIRED_AFTER_GRACE_PERIOD``'s identical "a real
    # system-attributed event, not a human one" precedent.
    INVOICE_GENERATED = "invoice_generated"
    INVOICE_MARKED_PAID = "invoice_marked_paid"
    INVOICE_VOIDED = "invoice_voided"
    INVOICE_MARKED_OVERDUE = "invoice_marked_overdue"
    # A Master Console operator triggered the manual "generate & send"
    # flow (``POST /invoices/generate-and-send``) -- distinct from
    # ``INVOICE_GENERATED`` (which every invoice, automatic or manual,
    # already receives) because this one specifically records the
    # human-initiated email-dispatch attempt and its outcome (see
    # ``InvoiceService.record_invoice_emailed``'s own docstring).
    INVOICE_EMAILED = "invoice_emailed"
    CREDIT_NOTE_ISSUED = "credit_note_issued"
    DEBIT_NOTE_ISSUED = "debit_note_issued"
    TAX_RATE_CREATED = "tax_rate_created"
    TAX_RATE_UPDATED = "tax_rate_updated"
    BILLING_PROFILE_UPDATED = "billing_profile_updated"

    # Guest Teams domain events -- written through this same table by
    # ``app.domains.guest_teams.service.GuestTeamService`` via the same
    # narrow ``AuditLogWriter`` protocol shape every other domain's service
    # uses (see ``AuditLogEntry``'s "other domains could plausibly reuse it"
    # design). Guest Teams is a brand-new domain (an extension of
    # ``app.domains.guest``, composing its real ``GuestService`` rather than
    # sharing its module), not a later Part of an already-existing one -- the
    # precedent followed here is the one every brand-new domain in this
    # codebase's history has followed at its own first Part: add its own
    # additive block of ``AuditAction`` values directly here, never a
    # domain-local constants shadow of this same enum. Team lifecycle
    # (create/revoke) and individual member removal are always admin-
    # initiated, moderate-volume, human-attributable actions -- audited, the
    # same profile every other domain's own lifecycle events already meet.
    # ``join_team`` (a guest presenting a team's join code) is deliberately
    # **not** audited at all, and deliberately has no placeholder value here
    # either -- it is high-volume, guest-facing, unauthenticated traffic,
    # the identical profile ``app.domains.guest``'s own
    # ``login_via_otp``/``login_via_voucher`` already establish for guest
    # logins (which likewise have zero corresponding ``AuditAction`` values,
    # not even an unused placeholder -- see this enum's own "Guest domain
    # events" comment above). See ``app.domains.guest_teams.service``'s
    # module docstring for the full audit-volume judgment call.
    GUEST_TEAM_CREATED = "guest_team_created"
    GUEST_TEAM_MEMBER_REMOVED = "guest_team_member_removed"
    GUEST_TEAM_REVOKED = "guest_team_revoked"

    # Policy domain events -- written through this same table by
    # ``app.domains.policy.service.PolicyService`` via the same narrow
    # ``AuditLogWriter`` protocol shape every other domain's service uses.
    # Policy is a brand-new, additive domain (see
    # ``docs/ARCHITECTURE_DESIGN.md`` §6.1/§13) -- the same "add its own
    # additive block directly here" precedent every prior brand-new domain
    # in this codebase has followed at its own first Part. Every lifecycle
    # action here (create/deactivate a policy, publish a version, roll a
    # policy back, create/deactivate an assignment) is always admin-
    # initiated, moderate-volume, human-attributable -- audited, the same
    # profile every other domain's own lifecycle events already meet.
    # ``resolve_effective_policy`` (a read, potentially called at high
    # frequency by other domains/services) is deliberately **not** audited,
    # the identical "reads aren't audited, lifecycle writes are" posture
    # this table already applies everywhere else.
    POLICY_CREATED = "policy_created"
    POLICY_DEACTIVATED = "policy_deactivated"
    POLICY_VERSION_PUBLISHED = "policy_version_published"
    POLICY_ROLLED_BACK = "policy_rolled_back"
    POLICY_ASSIGNMENT_CREATED = "policy_assignment_created"
    POLICY_ASSIGNMENT_DEACTIVATED = "policy_assignment_deactivated"

    # Provisioning Engine domain events -- written through this same table
    # by ``app.domains.provisioning_engine.service.ProvisioningEngineService``
    # via the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses. Provisioning Engine is a brand-new, additive
    # domain (an orchestrator composing Router/Router Provisioning/Policy/
    # NAS, never duplicating their own lifecycle events) -- the same "add
    # its own additive block directly here" precedent every prior brand-new
    # domain has followed at its own first Part. Job creation/cancellation/
    # retry/rollback/terminal outcome are always either admin-initiated or
    # a genuinely job-defining state change -- audited, the same profile
    # every other domain's own lifecycle events already meet. Individual
    # step transitions and per-step logs are deliberately **not** audited
    # here -- high-frequency, non-human-attributable orchestration detail,
    # already fully captured in ``ProvisionStep``/``ProvisionLog`` (mirrors
    # ``RouterEvent``'s/``GuestLoginHistory``'s own identical "high-volume
    # detail lives in its own purpose-built table, not this one" split).
    PROVISION_JOB_CREATED = "provision_job_created"
    PROVISION_JOB_CANCELLED = "provision_job_cancelled"
    PROVISION_JOB_RETRIED = "provision_job_retried"
    PROVISION_JOB_ROLLED_BACK = "provision_job_rolled_back"
    PROVISION_JOB_SUCCEEDED = "provision_job_succeeded"
    PROVISION_JOB_FAILED = "provision_job_failed"

    # Device Console -- a raw RouterOS command run directly against a
    # device's real SSH connection (the Winbox-terminal-equivalent
    # capability), gated behind its own dedicated DEVICE_CONSOLE permission
    # module rather than reusing PROVISIONING_ENGINE's EXECUTE (see
    # ``seed.py``'s own comment on why: unlike every other PROVISIONING_ENGINE
    # action, this one has no bounded command shape -- always audited, every
    # single invocation, unlike this table's usual "only lifecycle events"
    # posture, precisely because there is no narrower per-command structure
    # to fall back on for after-the-fact reconstruction otherwise.
    DEVICE_CONSOLE_COMMAND_EXECUTED = "device_console_command_executed"

    # Queue Management Engine domain events -- written through this same
    # table by
    # ``app.domains.queue_management.service.QueueManagementService`` via
    # the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses. Queue Management is a brand-new, additive
    # domain (a vendor-agnostic bandwidth/QoS orchestrator composing
    # Router/Policy, never duplicating their own lifecycle events) -- the
    # same "add its own additive block directly here" precedent every
    # prior brand-new domain has followed at its own first Part. Every
    # value here matches the module brief's own named audit events
    # (Queue Created/Updated/Deleted/Applied/Removed/Expired/Assignment
    # Changed) exactly.
    QUEUE_PROFILE_CREATED = "queue_profile_created"
    QUEUE_PROFILE_UPDATED = "queue_profile_updated"
    QUEUE_PROFILE_DELETED = "queue_profile_deleted"
    QUEUE_ASSIGNMENT_CREATED = "queue_assignment_created"
    QUEUE_APPLIED = "queue_applied"
    QUEUE_REMOVED = "queue_removed"
    QUEUE_ASSIGNMENT_CHANGED = "queue_assignment_changed"
    QUEUE_ASSIGNMENT_EXPIRED = "queue_assignment_expired"

    # ISP Management domain events -- written through this same table by
    # ``app.domains.isp.service.IspService`` via the same narrow
    # ``AuditLogWriter`` protocol shape every other domain's service uses.
    # ISP Management is a brand-new, additive domain (a per-router WAN/ISP
    # uplink inventory with real health monitoring and failover, composing
    # Router, never duplicating its own lifecycle events) -- the same "add
    # its own additive block directly here" precedent every prior
    # brand-new domain has followed at its own first part. Link create/
    # update/delete are audited for the same "moderate-volume, admin-
    # relevant" reason every other domain's own lifecycle events are;
    # failover/failback are audited unconditionally (even when
    # system-triggered by the health-check sweep, not just admin-driven)
    # since a guest network's live uplink changing is always operationally
    # significant, mirroring ``GUEST_SESSION_TERMINATED``'s own "always
    # audited" profile rather than ``GUEST_SESSION_DISCONNECTED``'s
    # system-vs-admin split -- individual health-check *readings* are
    # deliberately not audited at all (see
    # ``app.domains.isp.service``'s own module docstring for the full
    # audit-volume judgment call).
    ISP_LINK_CREATED = "isp_link_created"
    ISP_LINK_UPDATED = "isp_link_updated"
    ISP_LINK_DELETED = "isp_link_deleted"
    ISP_FAILOVER_TRIGGERED = "isp_failover_triggered"
    ISP_FAILBACK_TRIGGERED = "isp_failback_triggered"
    # An admin's own manual override of a link's current status (the
    # "Internet Connection" dashboard view's one real write -- never a
    # device push). Always audited, the same "moderate-volume, admin-
    # relevant" profile ISP_LINK_UPDATED already carries.
    ISP_LINK_MANUAL_STATUS_SET = "isp_link_manual_status_set"
    # An operator explicitly triggering a real, on-demand download against
    # the router's own real WAN uplink to measure genuine throughput (the
    # "Run Speed Test" action) -- always audited, the same "operator
    # explicitly triggers something with real side effects" profile
    # ``RouterService.reveal_credentials``/router reboot actions already
    # carry elsewhere in this codebase, since this is real traffic
    # genuinely generated against a real, possibly metered ISP link, not a
    # passive read.
    ISP_LINK_SPEED_TEST_RUN = "isp_link_speed_test_run"

    # ISP Routing domain events -- written through this same table by
    # ``app.domains.isp_routing.service.IspRoutingService`` via the same
    # narrow ``AuditLogWriter`` protocol shape every other domain's service
    # uses. A pure rules/inventory domain (no live device push in this
    # pass -- see that module's own docstring), so create/update/delete are
    # its only lifecycle events; there is no failover/failback-style
    # execute action here.
    ISP_ROUTING_RULE_CREATED = "isp_routing_rule_created"
    ISP_ROUTING_RULE_UPDATED = "isp_routing_rule_updated"
    ISP_ROUTING_RULE_DELETED = "isp_routing_rule_deleted"

    # VLAN Management domain events -- written through this same table by
    # ``app.domains.vlan.service.VlanService`` via the same narrow
    # ``AuditLogWriter`` protocol shape every other domain's service uses.
    # A pure rules/inventory domain (no live device push in this pass --
    # see that module's own docstring), so create/update/delete are its
    # only lifecycle events.
    VLAN_CREATED = "vlan_created"
    VLAN_UPDATED = "vlan_updated"
    VLAN_DELETED = "vlan_deleted"

    # DHCP Pool Management domain events -- written through this same
    # table by ``app.domains.dhcp.service.DhcpService`` via the same
    # narrow ``AuditLogWriter`` protocol shape every other domain's
    # service uses. A pure rules/inventory domain (no live device push in
    # this pass -- see that module's own docstring), so create/update/
    # delete are its only lifecycle events.
    DHCP_POOL_CREATED = "dhcp_pool_created"
    DHCP_POOL_UPDATED = "dhcp_pool_updated"
    DHCP_POOL_DELETED = "dhcp_pool_deleted"

    # Port Forwarding Management domain events -- written through this
    # same table by
    # ``app.domains.port_forwarding.service.PortForwardingService`` via
    # the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses. A pure rules/inventory domain (no live
    # device push in this pass -- see that module's own docstring), so
    # create/update/delete are its only lifecycle events.
    PORT_FORWARDING_RULE_CREATED = "port_forwarding_rule_created"
    PORT_FORWARDING_RULE_UPDATED = "port_forwarding_rule_updated"
    PORT_FORWARDING_RULE_DELETED = "port_forwarding_rule_deleted"

    # MAC Authorization domain events -- written through this same table
    # by
    # ``app.domains.mac_authorization.service.MacAuthorizationService``
    # via the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses.
    MAC_AUTHORIZATION_ENTRY_CREATED = "mac_authorization_entry_created"
    MAC_AUTHORIZATION_ENTRY_UPDATED = "mac_authorization_entry_updated"
    MAC_AUTHORIZATION_ENTRY_DELETED = "mac_authorization_entry_deleted"

    # Connected Device Management domain events -- written through this
    # same table by
    # ``app.domains.connected_devices.service.ConnectedDeviceService``
    # via the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses. Routine sync discovery/updates are
    # deliberately not audited (high-volume, platform-wide) -- only real
    # admin-initiated actions are (see that module's own module
    # docstring for the full audit-volume judgment call).
    CONNECTED_DEVICE_DISCONNECTED = "connected_device_disconnected"
    CONNECTED_DEVICE_DELETED = "connected_device_deleted"
    CONNECTED_DEVICE_COMMENT_ADDED = "connected_device_comment_added"
    CONNECTED_DEVICE_BLOCKED = "connected_device_blocked"
    CONNECTED_DEVICE_UNBLOCKED = "connected_device_unblocked"
    CONNECTED_DEVICE_WHITELISTED = "connected_device_whitelisted"

    # Device Synchronization domain events -- written through this same
    # table by ``app.domains.device_sync.service.DeviceSyncService`` via
    # the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses. Always audited, even when every component
    # succeeds -- a router-wide sync is always an admin-triggered,
    # operationally significant action.
    DEVICE_SYNC_RUN_COMPLETED = "device_sync_run_completed"

    # Hotspot Settings domain events -- written through this same table by
    # ``app.domains.hotspot.service.HotspotService`` via the same narrow
    # ``AuditLogWriter`` protocol shape every other domain's service uses.
    # A pure rules/inventory domain (no live device push in this pass --
    # see that module's own docstring), so create/update/delete are its
    # only lifecycle events.
    HOTSPOT_PROFILE_CREATED = "hotspot_profile_created"
    HOTSPOT_PROFILE_UPDATED = "hotspot_profile_updated"
    HOTSPOT_PROFILE_DELETED = "hotspot_profile_deleted"

    # QoS & VOIP Priority domain events -- written through this same
    # table by ``app.domains.qos.service.QosService`` via the same narrow
    # ``AuditLogWriter`` protocol shape every other domain's service uses.
    # QOS_TRAFFIC_RULE_PUSHED is the real device-push event (a paired
    # ``/queue tree`` entry actually applied to the router) -- see
    # ``service.py::push_rule_to_device``'s own docstring.
    QOS_TRAFFIC_RULE_CREATED = "qos_traffic_rule_created"
    QOS_TRAFFIC_RULE_UPDATED = "qos_traffic_rule_updated"
    QOS_TRAFFIC_RULE_DELETED = "qos_traffic_rule_deleted"
    QOS_TRAFFIC_RULE_PUSHED = "qos_traffic_rule_pushed"

    # Network Diagnostics domain events -- written through this same
    # table by ``app.domains.network_diagnostics.service
    # .NetworkDiagnosticsService`` via the same narrow ``AuditLogWriter``
    # protocol shape every other domain's service uses. Always audited,
    # even when the diagnostic itself fails -- mirrors
    # ``DEVICE_SYNC_RUN_COMPLETED``'s identical "an admin-triggered,
    # operationally significant action" posture.
    NETWORK_DIAGNOSTIC_RUN_COMPLETED = "network_diagnostic_run_completed"

    # PII masking bypass -- written by ``app.middleware.request_context
    # .RequestContextMiddleware`` itself (not a domain service), once per
    # request, only when a caller with ``User.data_masking_enabled=False``
    # actually caused a ``Masked*`` field to serialize unmasked (see
    # ``app.common.masking``'s own module docstring). One row per request
    # summarizing every distinct PII kind unmasked (``mobile``/``email``/
    # ``name``/``mac``) -- never one row per field, to avoid a
    # multi-hundred-row explosion on a single guest-list page view.
    PII_VIEWED_UNMASKED = "pii_viewed_unmasked"

    # Campaigns domain events -- written through this same table by
    # ``app.domains.campaigns.service.CampaignsService`` via the same
    # narrow ``AuditLogWriter`` protocol shape every other domain's
    # service uses. Status transitions get their own action distinct
    # from a plain field update since they are the operationally
    # significant moment (a campaign going live/ending), mirroring
    # ``app.domains.router_provisioning``'s own config-version-status
    # audit split.
    CAMPAIGN_CREATED = "campaign_created"
    CAMPAIGN_UPDATED = "campaign_updated"
    CAMPAIGN_STATUS_CHANGED = "campaign_status_changed"
    CAMPAIGN_DELETED = "campaign_deleted"
    CAMPAIGN_CLONED = "campaign_cloned"

    # DNS Management domain events -- written through this same table by
    # ``app.domains.dns.service.DnsService`` via the same narrow
    # ``AuditLogWriter`` protocol shape every other domain's service
    # uses. A pure rules/inventory domain (no live device push in this
    # pass -- see that module's own docstring), so create/update/delete
    # are its only lifecycle events.
    DNS_RECORD_CREATED = "dns_record_created"
    DNS_RECORD_UPDATED = "dns_record_updated"
    DNS_RECORD_DELETED = "dns_record_deleted"

    # Firewall Rule Management domain events -- written through this
    # same table by ``app.domains.firewall.service.FirewallService`` via
    # the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses. A pure rules/inventory domain (no live
    # device push in this pass -- see that module's own docstring), so
    # create/update/delete are its only lifecycle events.
    FIREWALL_RULE_CREATED = "firewall_rule_created"
    FIREWALL_RULE_UPDATED = "firewall_rule_updated"
    FIREWALL_RULE_DELETED = "firewall_rule_deleted"

    # Network Device (NAC) domain events -- written through this same
    # table by ``app.domains.network_device.service.NetworkDeviceService``
    # via the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses. Compliance-status changes get their own
    # action distinct from a plain field update since they are the
    # operationally significant moment (feeds guest_access as an input
    # signal) -- mirrors app.domains.campaigns's own status-change-vs-
    # plain-update split.
    NETWORK_DEVICE_CREATED = "network_device_created"
    NETWORK_DEVICE_UPDATED = "network_device_updated"
    NETWORK_DEVICE_COMPLIANCE_STATUS_CHANGED = (
        "network_device_compliance_status_changed"
    )
    NETWORK_DEVICE_DELETED = "network_device_deleted"

    # Monitored Hardware domain events -- admin-registered venue hardware
    # (Access Points, Printers, Routers, Cameras, Other) tracked for
    # presence, distinct from NETWORK_DEVICE's NAC/compliance registry.
    # No UPDATED action -- registration fields are immutable after
    # creation in this first pass (delete + re-register covers edits),
    # mirroring how narrow some of this codebase's other CRUD domains
    # deliberately start.
    MONITORED_HARDWARE_CREATED = "monitored_hardware_created"
    MONITORED_HARDWARE_DELETED = "monitored_hardware_deleted"

    # Content Filtering domain events -- written through this same table
    # by ``app.domains.content_filtering.service.ContentFilterService``
    # via the same narrow ``AuditLogWriter`` protocol shape every other
    # domain's service uses. A pure rules/inventory domain (no live
    # device push in this pass -- see that module's own docstring), so
    # create/update/delete are its only lifecycle events, mirroring
    # FIREWALL_RULE_CREATED/_UPDATED/_DELETED's identical shape above.
    CONTENT_FILTER_RULE_CREATED = "content_filter_rule_created"
    CONTENT_FILTER_RULE_UPDATED = "content_filter_rule_updated"
    CONTENT_FILTER_RULE_DELETED = "content_filter_rule_deleted"

    # Support Tickets domain events -- written through this same table by
    # ``app.domains.support_tickets.service.TicketService`` via the same
    # narrow ``AuditLogWriter`` protocol shape every other domain's service
    # uses. Support Tickets is a brand-new, additive domain (customers raise
    # tickets from their own org dashboard; platform admins triage/resolve
    # across every organization on the Master dashboard) -- the same "add
    # its own additive block directly here" precedent every prior brand-new
    # domain in this codebase's history has followed at its own first Part.
    # Both create and any admin update (status/priority/assignment/
    # resolution) are audited -- a support ticket's whole lifecycle is
    # low-volume and always human-attributable, the same profile every
    # other domain's own lifecycle events already meet; there is no
    # separate "resolved"/"assigned" action distinct from a plain update
    # since, unlike e.g. ``app.domains.campaigns``'s own status-vs-update
    # split, a ticket's status/assignment/resolution are all just fields on
    # the same ``PATCH`` a caller may set together in one call.
    SUPPORT_TICKET_CREATED = "support_ticket_created"
    SUPPORT_TICKET_UPDATED = "support_ticket_updated"
    # Added alongside the real-time reply-thread pass: a reply is its own
    # distinct, human-authored event on the ticket (not a field the
    # existing PATCH-driven SUPPORT_TICKET_UPDATED already covers), from
    # either side (the ticket-owning organization's own member or a
    # platform support agent) -- see
    # app.domains.support_tickets.service.TicketService.add_reply.
    SUPPORT_TICKET_REPLY_ADDED = "support_ticket_reply_added"

    # Channel Partner domain events -- written through this same table by
    # ``app.domains.channel_partner.service.ChannelPartnerService`` via the
    # same narrow ``AuditLogWriter`` protocol shape
    # ``OrganizationService``/``VoucherService`` use (see
    # ``AuditLogEntry``'s "other domains could plausibly reuse it" design).
    # Onboarding itself is not audited (mirrors ``QuotationService``'s own
    # "creation is reconstructable from the row's own created_at/created_by"
    # judgment call) -- only the later, destructive-ish status transition
    # is, the same "the mutation an operator can undo/needs a trail for" bar
    # ``ORGANIZATION_SUSPENDED``/``VOUCHER_BATCH_REVOKED`` are held to.
    #
    # ``CHANNEL_PARTNER_WELCOME_RESENT`` is the second such mutation: a
    # deliberate operator-triggered re-delivery of the welcome message,
    # which puts a real SMS/email in front of a third party (and, for SMS,
    # spends money) -- exactly the bar above, and the same call
    # ``LOCATION_WELCOME_EMAIL_SENT`` already makes for the location
    # domain's own "resend welcome email" endpoint. Written whether or not
    # the send actually succeeded: the *attempt* is what an operator
    # chasing "did anyone already re-poke this partner?" needs the trail
    # for, and the per-channel outcome rides along in ``event_metadata``.
    CHANNEL_PARTNER_REVOKED = "channel_partner_revoked"
    CHANNEL_PARTNER_WELCOME_RESENT = "channel_partner_welcome_resent"


# Actions that must never surface on an organization-scoped audit query --
# concretely, the customer dashboard's own Admin Logs -> "Account Activity"
# section (``app.domains.audit.router.search_audit_log_entries``, the only
# org-scoped caller of ``RBACRepository.search_audit_log_entries``).
#
# WireGuard tunnel lifecycle events are platform/backend infrastructure --
# the tunnel between this platform and a router -- never a concept the
# product exposes to a customer anywhere else in the dashboard (there is no
# "WireGuard"/"tunnel" UI on the customer side at all, by design). Surfacing
# raw entries like "WireGuard tunnel created for router 'X'" in a small
# business owner's own activity log is both meaningless jargon to that
# audience and a leak of backend implementation detail the rest of the
# product deliberately keeps master-console-only.
#
# A platform-level caller (``organization_id is None``, the master console
# reviewing the full cross-tenant trail) is unaffected -- this constant is
# only consulted when an organization scope is present, see
# ``RBACRepository.search_audit_log_entries``.
CUSTOMER_HIDDEN_AUDIT_ACTIONS: frozenset[str] = frozenset(
    {
        AuditAction.WIREGUARD_TUNNEL_CREATED,
        AuditAction.WIREGUARD_TUNNEL_ROTATED,
        AuditAction.WIREGUARD_TUNNEL_REVOKED,
    }
)
