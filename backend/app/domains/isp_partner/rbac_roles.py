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
        ),
    ),
)

ROLES_BY_SLUG: dict[str, IspRoleDefinition] = {r.slug: r for r in ROLES}
