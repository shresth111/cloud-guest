"""Constants for the ISP partner domain: permission keys, role slugs, audit
actions and the few policy switches the founder has not decided yet."""

from __future__ import annotations

from enum import StrEnum

# -- permission keys (API_CONTRACT §1.1) -------------------------------------
ISP_PARTNER_READ = "isp_partner.read"
ISP_PARTNER_CREATE = "isp_partner.create"
ISP_PARTNER_UPDATE = "isp_partner.update"
ISP_PARTNER_MANAGE = "isp_partner.manage"
ISP_PARTNER_EXECUTE = "isp_partner.execute"
ISP_PARTNER_EXPORT = "isp_partner.export"
ISP_PARTNER_ASSIGN = "isp_partner.assign"
ISP_LOGS_READ = "isp_logs.read"
ISP_LOGS_EXPORT = "isp_logs.export"
ISP_IPDR_READ = "isp_ipdr.read"
ISP_IPDR_EXPORT = "isp_ipdr.export"
TR069_READ = "tr069.read"
TR069_EXECUTE = "tr069.execute"
TR069_MANAGE = "tr069.manage"

#: The four permission groups this feature owns. Every key above belongs to
#: exactly one of them (the part before the dot).
ISP_PERMISSION_GROUPS: tuple[str, ...] = (
    "isp_partner",
    "isp_logs",
    "isp_ipdr",
    "tr069",
)


class IspRole(StrEnum):
    OWNER = "isp-owner"
    ADMIN = "isp-admin"
    NOC = "isp-noc"
    TECHNICIAN = "isp-technician"
    VIEWER = "isp-viewer"
    BILLING = "isp-billing"


ISP_ROLE_SLUGS: frozenset[str] = frozenset(r.value for r in IspRole)
# isp-billing (1b) is confinable like noc/technician/viewer.
#: Roles that may never be confined to a customer list (API_CONTRACT §1.3).
UNCONFINABLE_ROLES: frozenset[str] = frozenset({IspRole.OWNER, IspRole.ADMIN})
#: Roles only an ``isp-owner`` may grant.
OWNER_GRANTED_ROLES: frozenset[str] = frozenset({IspRole.OWNER, IspRole.ADMIN})


class IspProfileStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


# -- audit actions ----------------------------------------------------------
AUDIT_ISP_CUSTOMER_CREATED = "isp_customer_created"
AUDIT_ISP_CUSTOMER_UPDATED = "isp_customer_updated"
AUDIT_ISP_CUSTOMER_SUSPENDED = "isp_customer_suspended"
AUDIT_ISP_CUSTOMER_ACTIVATED = "isp_customer_activated"
AUDIT_ISP_ROUTER_SETUP_PREFIX = "isp_router_setup_"
AUDIT_ISP_USER_CREATED = "isp_user_created"
AUDIT_ROLE_ASSIGNED = "role_assigned"
AUDIT_ISP_USER_SCOPE_CHANGED = "isp_user_customer_scope_changed"
AUDIT_ISP_USER_PASSWORD_RESET = "isp_user_password_reset"
AUDIT_ISP_REPORT_EXPORTED = "isp_report_exported"

# -- limits -----------------------------------------------------------------
REPORT_MAX_RANGE_DAYS = 92
ATTENTION_CAP = 50
#: PRD §4.2: an offline router is "needs attention" after 15 minutes, a
#: pending one after 24 hours.
ATTENTION_ROUTER_OFFLINE_MINUTES = 15
ATTENTION_ROUTER_PENDING_HOURS = 24
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100

# -- undecided founder questions (STATUS Q2, Q4) -----------------------------
#
# Each is isolated here so flipping it is one line, and each defaults to the
# conservative choice.

#: Q2 (answered yes, 2026-10-22). Roles that may run the router setup twins,
#: whose script carries the router's management-tunnel key. Technicians are
#: included; IspScope still limits them to the customers they are confined
#: to, and every generation writes an ``isp_router_setup_*`` audit row.
SETUP_SCRIPT_ROLES: frozenset[str] = frozenset(
    {IspRole.OWNER, IspRole.ADMIN, IspRole.TECHNICIAN}
)

#: Q4 (answered 2026-10-22, D14): suspending an ISP customer cuts its
#: internet -- see ``service_control``. TR-069 credentials stay enabled.
SUSPEND_CUTS_GUEST_WIFI = True

# -- Phase 1b: service control (ADDENDUM_01 §A) ------------------------------
from datetime import timedelta as _td  # noqa: E402

AUDIT_ISP_SERVICE_SUSPENDED = "isp_customer_service_suspended"
AUDIT_ISP_SERVICE_RESUMED = "isp_customer_service_resumed"
AUDIT_ISP_AUTO_SUSPENDED = "isp_customer_auto_suspended"
SUSPEND_REASONS: frozenset[str] = frozenset(
    {"non_payment", "customer_request", "abuse", "other"}
)
#: Lazy retries run at most this often per customer.
SERVICE_RETRY_MIN_INTERVAL = _td(seconds=60)
#: Kick steps stop retrying after this; sessions end at their own timeout.
SERVICE_RETRY_GIVE_UP = _td(hours=24)

# -- Phase 1b: billing keys --------------------------------------------------
ISP_BILLING_READ = "isp_billing.read"
ISP_BILLING_CREATE = "isp_billing.create"
ISP_BILLING_UPDATE = "isp_billing.update"
ISP_BILLING_EXECUTE = "isp_billing.execute"
ISP_BILLING_EXPORT = "isp_billing.export"
ISP_BILLING_MANAGE = "isp_billing.manage"
ISP_INVOICES_READ = "isp_invoices.read"
ISP_INVOICES_CREATE = "isp_invoices.create"
ISP_INVOICES_EXECUTE = "isp_invoices.execute"
ISP_INVOICES_EXPORT = "isp_invoices.export"
ISP_INVOICES_MANAGE = "isp_invoices.manage"
ISP_ZONES_READ = "isp_zones.read"
ISP_ZONES_MANAGE = "isp_zones.manage"

# -- Phase 2c: venue twins (the customer dashboard's own feature set) ---------
#
# One group per customer domain the ISP manages on a customer's venue. The
# keys are the ISP-side gate for the ``/isp/venue/*`` twins in ``twins_venue``:
# a twin checks one of these on the ISP org, then calls the customer handler
# with ``requesting_organization_id=<the customer>``. No customer key
# (``dhcp.read``, ``vlan.read``, ...) is ever granted to an ISP role.
ISP_NETWORK_READ = "isp_network.read"
ISP_NETWORK_CREATE = "isp_network.create"
ISP_NETWORK_UPDATE = "isp_network.update"
ISP_NETWORK_DELETE = "isp_network.delete"
ISP_NETWORK_EXECUTE = "isp_network.execute"

#: The customer app's Access & Policy screens: access rules (policies), the
#: guest allow-list, trusted devices (MAC authorization) and open hours.
ISP_ACCESS_READ = "isp_access.read"
ISP_ACCESS_CREATE = "isp_access.create"
ISP_ACCESS_UPDATE = "isp_access.update"
ISP_ACCESS_DELETE = "isp_access.delete"
ISP_ACCESS_EXECUTE = "isp_access.execute"

# -- ADDENDUM_04 §4: the rest of the customer dashboard (parity batches) -----
#
# Same rule as the two groups above: one group per customer surface, checked
# on the ISP org by a twin or an ISP wrapper; no customer key is ever granted.
#: Engagement: Login Page Offers writes, venue voucher batches, Guest Messaging.
ISP_ENGAGE_READ = "isp_engage.read"
ISP_ENGAGE_CREATE = "isp_engage.create"
ISP_ENGAGE_UPDATE = "isp_engage.update"
ISP_ENGAGE_DELETE = "isp_engage.delete"
ISP_ENGAGE_MANAGE = "isp_engage.manage"
#: Security: Security Score, Block Websites, the customer's own firewall rules
#: (never the Wyfy firewall band, which stays GLOBAL and Master-only).
ISP_SECURITY_READ = "isp_security.read"
ISP_SECURITY_CREATE = "isp_security.create"
ISP_SECURITY_UPDATE = "isp_security.update"
ISP_SECURITY_DELETE = "isp_security.delete"
ISP_SECURITY_EXECUTE = "isp_security.execute"
#: Operations: Fix a Problem (diagnostics run on the venue's router).
ISP_OPS_EXECUTE = "isp_ops.execute"
#: Monitoring: alerts, connected clients, monitored hardware.
ISP_MONITOR_READ = "isp_monitor.read"
ISP_MONITOR_UPDATE = "isp_monitor.update"
#: Support: ISP -> Wyfy support tickets.
ISP_SUPPORT_READ = "isp_support.read"
ISP_SUPPORT_CREATE = "isp_support.create"
