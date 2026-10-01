"""FastAPI dependencies for security activity."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.dns_filtering.cloudflare_client import CloudflareGatewayClient
from app.domains.dns_filtering.dependencies import get_cloudflare_gateway_client

from .repository import SecurityActivityRepository
from .service import SecurityActivityService


def get_security_activity_service(
    db: AsyncSession = Depends(get_db_session),
    gateway: CloudflareGatewayClient | None = Depends(get_cloudflare_gateway_client),
) -> SecurityActivityService:
    """The Cloudflare client is the shared per-request one (built from
    settings, closed after the request); ``None`` when the platform has no
    token configured, which the view reports as unavailable."""
    counter = None
    if gateway is not None:

        async def counter(location_ids, start, end):  # noqa: ANN001, ANN202
            return await gateway.gateway_blocked_query_counts(
                location_ids=location_ids, start=start, end=end
            )

    return SecurityActivityService(
        SecurityActivityRepository(db),
        cloudflare_counter=counter,
        cloudflare_unavailable_reason=(
            None
            if gateway is not None
            else "Cloudflare is not connected on this platform."
        ),
    )


__all__ = ["get_security_activity_service"]
