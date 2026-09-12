"""FastAPI dependencies for the System Settings domain.

Wires the repository/service layer, composing with:

* ``app.domains.billing.dependencies.get_plan_repository`` -- the same real
  ``PlanRepository`` the billing console uses, so plan-id validation goes
  through one source of truth for "does this plan exist".
* ``app.domains.rbac.dependencies.get_rbac_repository`` -- reused purely as
  the ``AuditLogWriter`` (its ``create_audit_log_entry``), the identical
  pattern ``app.domains.channel_partner.dependencies`` follows.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.billing.dependencies import get_plan_repository
from app.domains.billing.repository import PlanRepositoryProtocol
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import SystemSettingsRepository, SystemSettingsRepositoryProtocol
from .service import SystemSettingsService


def get_system_settings_repository(
    db: AsyncSession = Depends(get_db_session),
) -> SystemSettingsRepositoryProtocol:
    return SystemSettingsRepository(db)


def get_system_settings_service(
    repository: SystemSettingsRepositoryProtocol = Depends(
        get_system_settings_repository
    ),
    plan_repository: PlanRepositoryProtocol = Depends(get_plan_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> SystemSettingsService:
    return SystemSettingsService(
        repository,
        plan_reader=plan_repository,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_system_settings_repository",
    "get_system_settings_service",
]
