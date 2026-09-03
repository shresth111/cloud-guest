"""FastAPI dependencies for the VLAN Management domain.

Composes ``app.domains.router`` entirely through its own existing,
already-wired FastAPI dependency function (``get_router_service``) --
exactly the same real service graph the live API already builds for that
domain, never a second, parallel construction path. Mirrors
``app.domains.isp_routing.dependencies``'s identical shape.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.dhcp.repository import DhcpRepository
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import VlanRepository, VlanRepositoryProtocol
from .service import DhcpPoolLookupProtocol, VlanService


def get_dhcp_pool_lookup(
    db: AsyncSession = Depends(get_db_session),
) -> DhcpPoolLookupProtocol:
    """The DHCP repository, constructed here rather than imported from
    ``app.domains.dhcp.dependencies``.

    The two domains compose each other -- this service refuses a captive
    portal on an interface a DHCP pool serves, and ``DhcpService`` refuses
    the mirror image -- so importing that module would make the two
    ``dependencies`` modules import each other at load time, which Python
    fails outright. The *repositories* have no such problem: each depends
    on the session and nothing else, which is the whole reason the conflict
    rule is enforced at that layer.
    """
    return DhcpRepository(db)


def get_vlan_repository(
    db: AsyncSession = Depends(get_db_session),
) -> VlanRepositoryProtocol:
    return VlanRepository(db)


def get_vlan_service(
    repository: VlanRepositoryProtocol = Depends(get_vlan_repository),
    router_service: RouterService = Depends(get_router_service),
    dhcp_pool_lookup: DhcpPoolLookupProtocol = Depends(get_dhcp_pool_lookup),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> VlanService:
    # The DHCP *repository*, not ``DhcpService``. The DHCP service composes
    # this domain back the other way (its push refuses a pool on an
    # interface a captive portal owns), and two services depending on each
    # other is a FastAPI dependency cycle that never resolves. Repositories
    # depend on nothing but the session, so both directions of the
    # captive-portal/DHCP conflict rule can be enforced without either
    # domain owning the other.
    return VlanService(
        repository,
        router_service,
        dhcp_pool_lookup=dhcp_pool_lookup,
        audit_writer=audit_repository,
    )


__all__ = ["get_dhcp_pool_lookup", "get_vlan_repository", "get_vlan_service"]
