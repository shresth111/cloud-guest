"""FastAPI dependencies for the Guest Access Control domain.

Wires the repository/service layer, composing with RBAC (for audit
logging) rather than duplicating it.

## The one place this domain is allowed to know about ``app.domains.guest``

``service.py``'s module docstring states the invariant: this domain has no
dependency on ``app.domains.guest`` -- the dependency runs guest ->
guest_access (``app.domains.guest.dependencies.get_guest_service`` wires
``GuestAccessService.check_access`` in as ``GuestService``'s own
access-control hook), and reversing it would close a cycle FastAPI's
dependency resolution cannot unwind.

Ending a blocked guest's live session needs facts from that domain --
which sessions they hold, and what status a terminated session takes -- so
the invariant is kept where it matters and relaxed exactly here:

* ``service.py`` and ``enforcement.py`` know only ``Protocol``\\ s. Neither
  imports anything from ``app.domains.guest`` at all.
* This module imports ``app.domains.guest.repository`` and
  ``app.domains.guest.constants``. Both are leaves -- the repository
  depends on the DB session and its own models, the constants module
  imports nothing but ``enum`` -- so neither can import this domain back,
  and no cycle exists to close. The *service* modules, which are the ones
  that could, still do not.

This is the same shape ``app.domains.vlan.dependencies`` already uses to
reach the DHCP domain: compose the other domain's **repository**, never
its service, because two services depending on each other is the cycle.

The router side is different and needs no such care: ``RouterService`` is
composed through its own already-wired ``get_router_service``, exactly as
the VLAN domain does, so the live API builds one real router service graph
rather than a second parallel one.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.repository import GuestRepository
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .enforcement import BlocklistEnforcer
from .repository import GuestAccessRepository, GuestAccessRepositoryProtocol
from .service import BlockEnforcerProtocol, GuestAccessService


def get_guest_access_repository(
    db: AsyncSession = Depends(get_db_session),
) -> GuestAccessRepositoryProtocol:
    return GuestAccessRepository(db)


def get_block_enforcer(
    db: AsyncSession = Depends(get_db_session),
    router_service: RouterService = Depends(get_router_service),
) -> BlockEnforcerProtocol:
    """The thing that makes "Blocked" true on the router.

    ``GuestRepository`` is constructed directly on the request's own
    session rather than pulled from ``app.domains.guest.dependencies`` --
    that module imports this one (for the access-control hook), so
    importing it back is the cycle. Constructing the repository here costs
    one object and keeps the import graph acyclic; both objects share the
    same ``AsyncSession``, so the session terminations this enforcer
    writes commit in the same transaction as the rule row.

    ``TERMINATED`` rather than ``DISCONNECTED``: a block is admin-driven,
    punitive and immediate, which is exactly the distinction
    ``GuestSessionStatus`` draws between the two (``DISCONNECTED`` is an
    ordinary end of use the guest may immediately follow with a fresh
    login). It also carries the reconnect cooldown
    ``SessionTerminationCooldownError`` enforces, which is the correct
    behaviour for someone who was just blocked.
    """
    return BlocklistEnforcer(
        session_lookup=GuestRepository(db),
        router_lookup=router_service,
        terminated_session_status=GuestSessionStatus.TERMINATED.value,
    )


def get_guest_access_service(
    repository: GuestAccessRepositoryProtocol = Depends(get_guest_access_repository),
    block_enforcer: BlockEnforcerProtocol = Depends(get_block_enforcer),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> GuestAccessService:
    return GuestAccessService(
        repository,
        block_enforcer=block_enforcer,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_block_enforcer",
    "get_guest_access_repository",
    "get_guest_access_service",
]
