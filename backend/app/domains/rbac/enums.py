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
