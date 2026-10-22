"""Exception X1 (founder-approved, ADDENDUM_02 §4): a transparent decorator
around ``RadiusService``'s ``queue_lookup`` hook.

For an ISP coupon session it answers ``Mikrotik-Rate-Limit`` with the
package's speed-group rate, so RouterOS builds the guest's dynamic hotspot
queue from it (inserted first, removed at logout). For **everything else**
-- the flag off, a non-ISP organization, a session without an ISP coupon, a
disabled subscriber, or any exception -- it returns exactly what the wrapped
``QueueManagementService`` returns, called with the identical arguments.
``tests/unit/test_isp_rate_limit.py`` pins that identity.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from .config import get_isp_partner_settings

logger = logging.getLogger(__name__)

_CACHE_TTL_S = 60.0
#: {organization_id: (is_isp_customer, expires_monotonic)}
_isp_customer_cache: dict[uuid.UUID, tuple[bool, float]] = {}


class IspRateLimitLookup:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        # Everything we do not define is the inner hook's, unchanged.
        return getattr(self._inner, name)

    def _session(self) -> Any:
        repository = getattr(self._inner, "repository", None)
        return getattr(repository, "session", None)

    async def _is_isp_customer(self, session: Any, organization_id: uuid.UUID) -> bool:
        now = time.monotonic()
        hit = _isp_customer_cache.get(organization_id)
        if hit is not None and hit[1] > now:
            return hit[0]
        from sqlalchemy import select

        from .models import IspCustomerProfile

        found = (
            await session.execute(
                select(IspCustomerProfile.id)
                .where(
                    IspCustomerProfile.customer_organization_id == organization_id,
                    IspCustomerProfile.is_deleted.is_(False),
                )
                .limit(1)
            )
        ).first() is not None
        _isp_customer_cache[organization_id] = (found, now + _CACHE_TTL_S)
        return found

    async def _isp_rate(
        self, session: Any, session_id: uuid.UUID, organization_id: uuid.UUID
    ) -> tuple[bool, str | None]:
        """(handled, rate). ``handled`` False means "not ours: delegate"."""
        from sqlalchemy import select

        from app.domains.guest.models import GuestSession
        from app.domains.queue_management.models import QueueProfile
        from app.domains.queue_management.service import format_mikrotik_rate_limit
        from app.domains.voucher.models import Voucher

        from .plans_models import (
            IspCouponBatch,
            IspCouponBatchPart,
            IspPackage,
            IspPackageMaterialization,
            IspSubscriber,
        )

        gs = await session.get(GuestSession, session_id)
        if gs is None or gs.voucher_id is None or gs.organization_id != organization_id:
            return False, None
        row = (
            await session.execute(
                select(IspCouponBatch, Voucher)
                .join(
                    IspCouponBatchPart,
                    IspCouponBatchPart.coupon_batch_id == IspCouponBatch.id,
                )
                .join(Voucher, Voucher.batch_id == IspCouponBatchPart.voucher_batch_id)
                .where(
                    Voucher.id == gs.voucher_id,
                    IspCouponBatch.customer_organization_id == organization_id,
                )
            )
        ).first()
        if row is None:
            return False, None
        batch, voucher = row
        if voucher.redeemed_identifier:
            sub = (
                await session.execute(
                    select(IspSubscriber.status).where(
                        IspSubscriber.customer_organization_id == organization_id,
                        IspSubscriber.identifier == voucher.redeemed_identifier,
                        IspSubscriber.is_deleted.is_(False),
                    )
                )
            ).scalar_one_or_none()
            if sub == "disabled":
                return False, None
        profile = (
            (
                await session.execute(
                    select(QueueProfile)
                    .join(
                        IspPackageMaterialization,
                        IspPackageMaterialization.queue_profile_id == QueueProfile.id,
                    )
                    .join(
                        IspPackage,
                        IspPackage.id == IspPackageMaterialization.package_id,
                    )
                    .where(
                        IspPackageMaterialization.package_id == batch.package_id,
                        IspPackageMaterialization.customer_organization_id
                        == organization_id,
                    )
                )
            )
            .scalars()
            .first()
        )
        if profile is None:
            return False, None
        if not profile.download_rate_kbps and not profile.upload_rate_kbps:
            return True, None  # 0/0 = unlimited, matching existing semantics
        return True, format_mikrotik_rate_limit(profile)

    async def rate_limit_reply_for_authorize(
        self, session_id: uuid.UUID, **kwargs: Any
    ) -> str | None:
        organization_id = kwargs.get("organization_id")
        try:
            if get_isp_partner_settings().enabled and organization_id is not None:
                session = self._session()
                if session is not None:
                    # A SAVEPOINT: a failure here can never poison the
                    # authorize request's own transaction.
                    async with session.begin_nested():
                        if await self._is_isp_customer(session, organization_id):
                            handled, rate = await self._isp_rate(
                                session, session_id, organization_id
                            )
                            if handled:
                                return rate
        except Exception as exc:  # noqa: BLE001 -- never raises; fall back to today
            logger.warning(
                "isp_rate_limit_lookup_failed", extra={"error": str(exc)[:200]}
            )
        return await self._inner.rate_limit_reply_for_authorize(session_id, **kwargs)


__all__ = ["IspRateLimitLookup"]
