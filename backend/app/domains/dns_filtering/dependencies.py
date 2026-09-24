"""FastAPI dependencies for DNS filtering.

The Cloudflare client is built per request from settings and closed after
it; ``None`` when no token/account id is configured, which the service turns
into a 503 on exactly the calls that need Cloudflare.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import get_db_session
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.location_scope import CallerLocationScope, LocationScope
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .cloudflare_client import CloudflareGatewayClient
from .repository import DnsFilteringRepository, DnsFilteringRepositoryProtocol
from .service import DnsFilteringService


def get_dns_filtering_repository(
    db: AsyncSession = Depends(get_db_session),
) -> DnsFilteringRepositoryProtocol:
    return DnsFilteringRepository(db)


async def get_cloudflare_gateway_client() -> (
    AsyncIterator[CloudflareGatewayClient | None]
):
    settings = get_settings()
    token = settings.cloudflare_api_token
    if not token.get_secret_value() or not settings.cloudflare_account_id:
        yield None
        return
    client = CloudflareGatewayClient(
        api_token=token,
        account_id=settings.cloudflare_account_id,
        base_url=settings.cloudflare_api_base_url,
        timeout_seconds=settings.cloudflare_timeout_seconds,
    )
    try:
        yield client
    finally:
        await client.aclose()


def get_dns_filtering_service(
    repository: DnsFilteringRepositoryProtocol = Depends(get_dns_filtering_repository),
    router_service: RouterService = Depends(get_router_service),
    location_service: LocationService = Depends(get_location_service),
    gateway: CloudflareGatewayClient | None = Depends(get_cloudflare_gateway_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    caller_location_scope: LocationScope = Depends(CallerLocationScope),
) -> DnsFilteringService:
    settings = get_settings()
    return DnsFilteringService(
        repository,
        router_service,
        location_service,
        gateway=gateway,
        audit_writer=audit_repository,
        caller_location_scope=caller_location_scope,
        max_locations=settings.cloudflare_gateway_max_locations,
        max_dns_rules=settings.cloudflare_gateway_max_dns_rules,
        probe_hostname=settings.dns_filtering_probe_hostname,
        ip_exclusions=tuple(settings.dns_bypass_ip_exclusions),
        hostname_exclusions=tuple(settings.dns_bypass_hostname_exclusions),
        list_max_entries=settings.dns_bypass_list_max_entries,
    )


__all__ = [
    "get_cloudflare_gateway_client",
    "get_dns_filtering_repository",
    "get_dns_filtering_service",
]
