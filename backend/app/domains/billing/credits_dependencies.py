"""FastAPI wiring for the prepaid-credits routes."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .credits_repository import CreditRepository
from .credits_service import CreditsService, CreditWalletService
from .dependencies import get_invoice_service
from .service import InvoiceService


def get_credits_service(
    db: AsyncSession = Depends(get_db_session),
    invoice_service: InvoiceService = Depends(get_invoice_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> CreditsService:
    repository = CreditRepository(db)
    return CreditsService(
        repository=repository,
        wallets=CreditWalletService(repository),
        invoices=invoice_service,
        audit_writer=audit_repository,
        committer=db,
    )


__all__ = ["get_credits_service"]
