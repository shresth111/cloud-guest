"""FastAPI wiring for the prepaid-credits routes."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .credits_notifications import LowBalanceNotifier
from .credits_repository import CreditRepository
from .credits_service import CreditsService, CreditWalletService
from .dependencies import get_invoice_service
from .service import InvoiceService

PricingLookup = Callable[[uuid.UUID, bool], Awaitable[tuple[dict[str, Any], list[str]]]]


def get_marketing_pricing(
    db: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
    redis: Redis = Depends(get_redis_client),
) -> PricingLookup:
    """``(organization_id, platform) -> (prices, byo_channels)`` from the
    marketing price book and the §12.1 provider resolution. Imported lazily:
    marketing already depends on billing, not the other way round."""

    async def _lookup(
        organization_id: uuid.UUID, platform: bool
    ) -> tuple[dict[str, Any], list[str]]:
        from app.domains.billing.constants import PlanFeatureKey
        from app.domains.marketing.credits import PriceBook, PriceRepository
        from app.domains.marketing.dependencies import build_entitlement_check
        from app.domains.marketing.repository import MarketingRepository
        from app.domains.marketing.senders import resolve_marketing_senders
        from app.domains.marketing.service import MarketingService

        prices = await PriceBook(PriceRepository(db)).prices(
            organization_id, platform=platform
        )
        marketing = MarketingService(
            MarketingRepository(db),
            settings=settings,
            senders=resolve_marketing_senders(settings),
            redis=redis,
            byo_entitlement_check=build_entitlement_check(
                db, redis, PlanFeatureKey.GUEST_MARKETING_BYO
            ),
        )
        resolutions = await marketing.resolve_providers(organization_id)
        byo = [channel.value for channel, r in resolutions.items() if r.own]
        return prices, byo

    return _lookup


def get_credits_service(
    db: AsyncSession = Depends(get_db_session),
    invoice_service: InvoiceService = Depends(get_invoice_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    pricing: PricingLookup = Depends(get_marketing_pricing),
) -> CreditsService:
    repository = CreditRepository(db)
    return CreditsService(
        repository=repository,
        wallets=CreditWalletService(
            repository, low_balance_hook=LowBalanceNotifier(db)
        ),
        invoices=invoice_service,
        audit_writer=audit_repository,
        committer=db,
        pricing=pricing,
    )


__all__ = ["get_credits_service", "get_marketing_pricing"]
