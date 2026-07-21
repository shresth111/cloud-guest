"""FastAPI dependencies for the audit domain.

Composes with ``app.domains.rbac``'s existing repository (see
``service.py``'s own module docstring for why this domain owns no
repository/model of its own).
"""

from __future__ import annotations

from fastapi import Depends

from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .service import AuditService


def get_audit_service(
    repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> AuditService:
    return AuditService(repository)


__all__ = ["get_audit_service"]
