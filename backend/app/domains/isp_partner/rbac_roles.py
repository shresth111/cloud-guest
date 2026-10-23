"""The ISP partner RBAC data (API_CONTRACT §1.1, §1.3), as plain data.

Seeded by ``app.domains.isp_partner.seed`` -- never by ``rbac/seed.py``, and
``rbac/enums.py`` is not edited. Keys are plain string rows in
``permissions``; no existing role is touched, so no existing role (Super
Admin, MSP Owner, Organization Owner ...) ever holds one of these keys.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.domains.rbac.enums import ScopeType

from .constants import IspRole


@dataclass(frozen=True)
class IspPermissionGroup:
    key: str
    name: str
    actions: tuple[str, ...]
    sort_order: int


@dataclass(frozen=True)
class IspRoleDefinition:
    slug: str
    name: str
    description: str
    permission_keys: tuple[str, ...]


#: Groups and their actions. Every key is allowed at ORGANIZATION scope only:
#: GLOBAL is deliberately not an allowed scope (platform staff use the Master
#: endpoints instead).
PERMISSION_GROUPS: tuple[IspPermissionGroup, ...] = (
    IspPermissionGroup(
        key="isp_partner",
        name="ISP Partner",
        actions=("read", "create", "update", "manage", "execute", "export", "assign"),
        sort_order=1000,
    ),
    IspPermissionGroup(
        key="isp_logs", name="ISP Logs", actions=("read", "export"), sort_order=1001
    ),
    IspPermissionGroup(
        key="isp_ipdr", name="ISP IPDR", actions=("read", "export"), sort_order=1002
    ),
    IspPermissionGroup(
        key="tr069",
        name="TR-069",
        actions=("read", "execute", "manage"),
        sort_order=1003,
    ),
    # Phase 1b (ADDENDUM_01 §B.3, ADDENDUM_03 §11): added by the same
    # seeder, as new rows only.
    IspPermissionGroup(
        key="isp_billing",
        name="ISP Billing",
        actions=("read", "create", "update", "execute", "export", "manage"),
        sort_order=1004,
    ),
    IspPermissionGroup(
        key="isp_invoices",
        name="ISP Invoices",
        actions=("read", "create", "execute", "export", "manage"),
        sort_order=1005,
    ),
    IspPermissionGroup(
        key="isp_zones", name="ISP Zones", actions=("read", "manage"), sort_order=1006
    ),
    # Phase 2a (ADDENDUM_02 §7)
    IspPermissionGroup(
        key="isp_plans",
        name="ISP Plans",
        actions=("read", "create", "update", "delete"),
        sort_order=1007,
    ),
    IspPermissionGroup(
        key="isp_coupons",
        name="ISP Coupons",
        actions=("read", "create", "export", "update"),
        sort_order=1008,
    ),
    IspPermissionGroup(
        key="isp_subscribers",
        name="ISP Subscribers",
        actions=("read", "update"),
        sort_order=1009,
    ),
    # Phase 2c: the venue twins. One group covers the customer network/QoS
    # domains the ISP runs on a customer's venue (DHCP pools, VLANs, port
    # forwarding, QoS). Adding another customer domain means adding its own
    # group here, not widening this one -- the keys are the audit surface.
    IspPermissionGroup(
        key="isp_network",
        name="ISP Venue Network",
        actions=("read", "create", "update", "delete", "execute"),
        sort_order=1010,
    ),
    # The venue twins' Access & Policy surface: access rules, the guest
    # allow-list, trusted devices and open hours.
    IspPermissionGroup(
        key="isp_access",
        name="ISP Venue Access",
        actions=("read", "create", "update", "delete", "execute"),
        sort_order=1011,
    ),
    # ADDENDUM_04 §4: the remaining customer-dashboard surfaces.
    IspPermissionGroup(
        key="isp_engage",
        name="ISP Venue Engagement",
        actions=("read", "create", "update", "delete", "manage"),
        sort_order=1012,
    ),
    IspPermissionGroup(
        key="isp_security",
        name="ISP Venue Security",
        actions=("read", "create", "update", "delete", "execute"),
        sort_order=1013,
    ),
    IspPermissionGroup(
        key="isp_ops",
        name="ISP Venue Operations",
        actions=("execute",),
        sort_order=1014,
    ),
    IspPermissionGroup(
        key="isp_monitor",
        name="ISP Venue Monitoring",
        actions=("read", "update"),
        sort_order=1015,
    ),
    IspPermissionGroup(
        key="isp_support",
        name="ISP Support",
        actions=("read", "create"),
        sort_order=1016,
    ),
)

ALLOWED_SCOPE_TYPES: tuple[ScopeType, ...] = (ScopeType.ORGANIZATION,)
ROLE_SCOPE_TYPE = ScopeType.ORGANIZATION


def all_permission_keys() -> tuple[str, ...]:
    return tuple(f"{g.key}.{a}" for g in PERMISSION_GROUPS for a in g.actions)


def _keys(**groups: str) -> tuple[str, ...]:
    out: list[str] = []
    for group, actions in groups.items():
        out.extend(f"{group}.{action}" for action in actions.split())
    return tuple(out)


_FULL = "read create update manage execute export assign"

_BILLING_FULL = "read create update execute export manage"
_INVOICES_FULL = "read create execute export manage"

ROLES: tuple[IspRoleDefinition, ...] = (
    IspRoleDefinition(
        slug=IspRole.OWNER.value,
        name="ISP Owner",
        description="Runs the ISP partner account. Created by Wyfy Master.",
        permission_keys=_keys(
            isp_partner=_FULL,
            isp_logs="read export",
            isp_ipdr="read export",
            tr069="read execute manage",
            isp_billing=_BILLING_FULL,
            isp_invoices=_INVOICES_FULL,
            isp_zones="read manage",
            isp_plans="read create update delete",
            isp_coupons="read create export update",
            isp_subscribers="read update",
            isp_network="read create update delete execute",
            isp_access="read create update delete execute",
            isp_engage="read create update delete manage",
            isp_security="read create update delete execute",
            isp_ops="execute",
            isp_monitor="read update",
            isp_support="read create",
        ),
    ),
    IspRoleDefinition(
        slug=IspRole.ADMIN.value,
        name="ISP Admin",
        description="ISP operations manager. Cannot change or disable an owner.",
        permission_keys=_keys(
            isp_partner=_FULL,
            isp_logs="read export",
            isp_ipdr="read export",
            tr069="read execute manage",
            isp_billing=_BILLING_FULL,
            isp_invoices=_INVOICES_FULL,
            isp_zones="read manage",
            isp_plans="read create update delete",
            isp_coupons="read create export update",
            isp_subscribers="read update",
            isp_network="read create update delete execute",
            isp_access="read create update delete execute",
            isp_engage="read create update delete manage",
            isp_security="read create update delete execute",
            isp_ops="execute",
            isp_monitor="read update",
            isp_support="read create",
        ),
    ),
    IspRoleDefinition(
        slug=IspRole.NOC.value,
        name="ISP NOC Operator",
        description="Watches routers and CPEs, reads logs, reboots CPEs.",
        permission_keys=_keys(
            isp_partner="read export",
            isp_logs="read export",
            tr069="read execute",
            isp_invoices="read",
            isp_zones="read",
            isp_plans="read",
            isp_coupons="read",
            isp_subscribers="read",
            isp_network="read execute",
            isp_access="read",
            isp_engage="read",
            isp_security="read",
            isp_ops="execute",
            isp_monitor="read update",
            isp_support="read create",
        ),
    ),
    IspRoleDefinition(
        slug=IspRole.TECHNICIAN.value,
        name="ISP Technician",
        description="Field installer: locations, routers, CPE assignment.",
        permission_keys=_keys(
            isp_partner="read create update execute",
            isp_logs="read",
            tr069="read execute manage",
            isp_zones="read",
            isp_plans="read",
            isp_coupons="read export",
            isp_subscribers="read",
            isp_network="read create update execute",
            isp_access="read create update",
            isp_engage="read",
            isp_security="read create update execute",
            isp_ops="execute",
            isp_monitor="read update",
            isp_support="read create",
        ),
    ),
    IspRoleDefinition(
        slug=IspRole.VIEWER.value,
        name="ISP Viewer",
        description="Read-only reports and exports.",
        permission_keys=_keys(
            isp_partner="read export",
            tr069="read",
            isp_billing="read",
            isp_invoices="read export",
            isp_zones="read",
            isp_plans="read",
            isp_coupons="read",
            isp_subscribers="read",
            isp_network="read",
            isp_access="read",
            isp_engage="read",
            isp_security="read",
            isp_monitor="read",
            isp_support="read",
        ),
    ),
    IspRoleDefinition(
        slug=IspRole.BILLING.value,
        name="ISP Billing",
        description="Accounts: invoices, payments, dues. Can be confined.",
        permission_keys=_keys(
            isp_partner="read",
            isp_billing="read create update execute export",
            isp_invoices=_INVOICES_FULL,
            isp_zones="read",
            isp_plans="read",
            isp_coupons="read create export update",
            isp_subscribers="read update",
            isp_engage="read",
            isp_monitor="read",
            isp_support="read create",
        ),
    ),
)

ROLES_BY_SLUG: dict[str, IspRoleDefinition] = {r.slug: r for r in ROLES}
