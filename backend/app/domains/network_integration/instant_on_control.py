"""Mid-session control of an Aruba Instant On venue, through Instant On's
cloud (the only thing that can reach an AP behind the venue's NAT).

Wired into the existing paths, not beside them:

* **Session end** (timeout / daily limit / Open Hours sweeps, data cap and FUP
  in ``GuestService.record_usage``, the operator's Terminate, a block's live
  half) -> ``LiveSessionTerminator.end_on_router`` -> for a NAS-only router,
  ``client_hooks``' terminator ``.end_nas_only`` -> :func:`end_nas_only_session`.
  A *disconnect* is a block that this module created, followed after
  ``Settings.instant_on_disconnect_hold_seconds`` by a timed unblock (Celery),
  because Instant On has no deauthorize verb. The guest's next attempt lands
  on the portal, which decides (refused at data cap / blocklist / Open Hours,
  allowed to sign in again after a plain timeout -- as on every other vendor).
* **Admin block** (``BlocklistEnforcer.block_devices``) ->
  ``client_hooks._DeviceBlocker`` falls back here when the venue has no Omada
  controller -> a *persistent* Instant On block, released by the stored-row
  release path on unblock.

## Transient vs persistent blocks

A disconnect must never undo an admin's block. The timed unblock only runs if
the disconnect itself created the entry, and only while a Redis marker it set
is still there; a persistent block of the same MAC deletes the marker, so the
pending unblock finds nothing and leaves the block alone.

## Gates

Nothing here does anything unless ``Settings.instant_on_cloud_control_enabled``
is true **and** the router is in ``instant_on_cloud_control_router_ids``
**and** a write account ARN is configured for it **and** an
``instant_on_sites`` row (tenant-scoped in the query) maps it to a site. Any
gate closed -> "not available", which every caller already treats as the
pre-existing NAS-only behaviour.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import Settings, get_settings
from app.core.logging import get_logger

from .constants import TASK_INSTANT_ON_RELEASE_TRANSIENT_BLOCK
from .models import InstantOnSite
from .providers.aruba_instant_on_client import InstantOnError
from .providers.aruba_instant_on_control import (
    InstantOnControlClient,
    normalize_instant_on_mac,
)

logger = get_logger(__name__)

__all__ = [
    "ControlTarget",
    "build_live_control_client",
    "cloud_control_allowed",
    "end_nas_only_session",
    "instant_on_block_device",
    "instant_on_release_device",
    "release_transient_block",
    "resolve_control_target",
    "transient_marker_key",
]

_TRANSIENT_PREFIX = "instant_on:transient_block"


@dataclass(frozen=True, slots=True)
class ControlTarget:
    router_id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    site_id: str
    secret_arn: str


def cloud_control_allowed(router_id: uuid.UUID | None, settings: Settings) -> bool:
    return bool(
        router_id is not None
        and settings.instant_on_cloud_control_enabled
        and router_id in settings.instant_on_cloud_control_router_id_set
        and settings.instant_on_control_secret_arn_for(router_id)
    )


async def resolve_control_target(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID | None,
    router_id: uuid.UUID | None = None,
    location_id: uuid.UUID | None = None,
    settings: Settings | None = None,
) -> ControlTarget | None:
    """The venue's Instant On site, or ``None`` (any gate closed).

    Tenant-scoped in the WHERE clause: the caller's organization is always
    part of the query, so another tenant's router or location resolves to
    nothing. The site written to comes from the row, never from a caller."""
    settings = settings or get_settings()
    if organization_id is None or not settings.instant_on_cloud_control_enabled:
        return None
    if router_id is None and location_id is None:
        return None
    statement = select(InstantOnSite).where(
        InstantOnSite.organization_id == organization_id,
        InstantOnSite.is_deleted.is_(False),
    )
    if router_id is not None:
        statement = statement.where(InstantOnSite.router_id == router_id)
    if location_id is not None:
        statement = statement.where(InstantOnSite.location_id == location_id)
    statement = statement.order_by(InstantOnSite.created_at.asc())
    rows = list((await session.execute(statement)).scalars().all())
    for site in rows:
        if cloud_control_allowed(site.router_id, settings):
            return ControlTarget(
                router_id=site.router_id,
                organization_id=site.organization_id,
                location_id=site.location_id,
                site_id=site.site_id,
                secret_arn=settings.instant_on_control_secret_arn_for(site.router_id),
            )
    return None


def build_live_control_client(
    http: Any, settings: Settings, *, secret_arn: str
) -> InstantOnControlClient:
    """Same token machinery as the poller (DB token row keyed by the ARN,
    Redis single-flight refresh, Secrets Manager credentials), for the write
    account named by ``secret_arn``."""
    from app.database.redis import redis_client
    from app.database.session import SessionLocal

    from .instant_on_repository import DbInstantOnTokenStore, account_key_for
    from .providers.aruba_instant_on_client import (
        InstantOnAuthConfig,
        InstantOnNotConfiguredError,
        InstantOnTokenManager,
        RedisRefreshLock,
        SecretsManagerCredentialSource,
    )

    if settings.uses_public_network_integration_key():
        raise InstantOnNotConfiguredError(
            "CLOUDGUEST_NETWORK_INTEGRATION_ENCRYPTION_KEY is not set",
            reason="encryption_key_not_configured",
        )
    account_key = account_key_for(secret_arn)
    tokens = InstantOnTokenManager(
        http=http,
        store=DbInstantOnTokenStore(SessionLocal, account_key=account_key),
        lock=RedisRefreshLock(
            redis_client, key=f"instant_on:token_refresh_lock:{account_key[:16]}"
        ),
        credentials=SecretsManagerCredentialSource(
            secret_arn=secret_arn, region_name=settings.instant_on_secrets_region
        ),
        config=InstantOnAuthConfig(
            api_base_url=settings.instant_on_api_base_url,
            sso_base_url=settings.instant_on_sso_base_url,
            client_id=settings.instant_on_sso_client_id,
            redirect_uri=settings.instant_on_sso_redirect_uri,
            auth_failure_cooldown_seconds=(
                settings.instant_on_auth_failure_cooldown_seconds
            ),
        ),
    )
    return InstantOnControlClient(
        http=http,
        tokens=tokens,
        api_base_url=settings.instant_on_api_base_url,
        api_version=settings.instant_on_api_version,
    )


def transient_marker_key(site_id: str, mac: str) -> str:
    return f"{_TRANSIENT_PREFIX}:{site_id}:{mac}"


# -- seams the tests replace -------------------------------------------------


async def _with_client(target: ControlTarget, settings: Settings, action):  # noqa: ANN001, ANN202
    import httpx

    async with httpx.AsyncClient(
        timeout=settings.instant_on_http_timeout_seconds
    ) as http:
        client = build_live_control_client(http, settings, secret_arn=target.secret_arn)
        return await action(client)


def _redis():  # noqa: ANN202
    from app.database.redis import redis_client

    return redis_client


def _schedule_release(
    target: ControlTarget, mac: str, token: str, countdown: int
) -> None:
    release_transient_block_task.apply_async(
        kwargs={
            "organization_id": str(target.organization_id),
            "router_id": str(target.router_id),
            "mac": mac,
            "token": token,
        },
        countdown=countdown,
    )


# -- session end -------------------------------------------------------------


async def end_nas_only_session(
    session: AsyncSession,
    *,
    router_id: uuid.UUID,
    organization_id: uuid.UUID | None,
    client_mac: str,
    settings: Settings | None = None,
) -> bool:
    """Take ``client_mac`` off the venue now. ``True`` only when Instant On's
    blocked list, read back, shows the device (the AP then drops it). Never
    raises: ``False`` means "could not", and the caller keeps the NAS-only
    behaviour it had before this existed."""
    settings = settings or get_settings()
    target = await resolve_control_target(
        session,
        organization_id=organization_id,
        router_id=router_id,
        settings=settings,
    )
    if target is None:
        return False
    try:
        mac = normalize_instant_on_mac(client_mac)
    except ValueError:
        return False
    try:
        result = await _with_client(
            target, settings, lambda client: client.block_client(target.site_id, mac)
        )
    except InstantOnError as error:
        logger.warning(
            "instant_on_disconnect_failed",
            extra={
                "router_id": str(router_id),
                "error_code": error.code,
                "reason": error.reason,
                "enforcement_delivered": False,
            },
        )
        return False

    if result.created:
        token = uuid.uuid4().hex
        hold = settings.instant_on_disconnect_hold_seconds
        try:
            await _redis().set(
                transient_marker_key(target.site_id, mac), token, ex=hold + 3600
            )
            _schedule_release(target, mac, token, hold)
        except Exception:  # noqa: BLE001 -- the block landed; say so loudly
            logger.error(
                "instant_on_disconnect_release_not_scheduled",
                extra={"router_id": str(router_id)},
            )
    logger.info(
        "instant_on_disconnect_enforced",
        extra={
            "router_id": str(router_id),
            "created": result.created,
            "enforcement_delivered": True,
        },
    )
    return True


async def release_transient_block(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    router_id: uuid.UUID,
    mac: str,
    token: str,
    settings: Settings | None = None,
) -> str:
    """The timed unblock after a disconnect. Unblocks only while the marker
    this disconnect set is still ours (a persistent block deletes it)."""
    settings = settings or get_settings()
    target = await resolve_control_target(
        session, organization_id=organization_id, router_id=router_id, settings=settings
    )
    if target is None:
        return "not_available"
    key = transient_marker_key(target.site_id, mac)
    redis = _redis()
    current = await redis.get(key)
    if isinstance(current, bytes):
        current = current.decode()
    if current != token:
        return "superseded"
    try:
        await _with_client(
            target, settings, lambda client: client.unblock_client(target.site_id, mac)
        )
    except InstantOnError as error:
        logger.error(
            "instant_on_transient_unblock_failed",
            extra={"router_id": str(router_id), "error_code": error.code},
        )
        raise
    await redis.delete(key)
    return "released"


# -- admin block (persistent) ------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceWriteOutcome:
    status: str  # enforced | failed | unavailable
    error_code: str | None = None
    error_message: str | None = None


async def instant_on_block_device(
    session: AsyncSession,
    *,
    location_id: uuid.UUID,
    organization_id: uuid.UUID | None,
    client_mac: str,
    settings: Settings | None = None,
) -> DeviceWriteOutcome:
    settings = settings or get_settings()
    target = await resolve_control_target(
        session,
        organization_id=organization_id,
        location_id=location_id,
        settings=settings,
    )
    if target is None:
        return DeviceWriteOutcome(status="unavailable")
    try:
        mac = normalize_instant_on_mac(client_mac)
    except ValueError as exc:
        return DeviceWriteOutcome(status="failed", error_message=str(exc))
    try:
        await _with_client(
            target, settings, lambda client: client.block_client(target.site_id, mac)
        )
    except InstantOnError as error:
        return DeviceWriteOutcome(
            status="failed", error_code=error.code, error_message=str(error)
        )
    # Now persistent: a pending timed unblock must not undo it.
    try:
        await _redis().delete(transient_marker_key(target.site_id, mac))
    except Exception:  # noqa: BLE001
        logger.error(
            "instant_on_transient_marker_not_cleared",
            extra={"router_id": str(target.router_id)},
        )
        return DeviceWriteOutcome(
            status="failed",
            error_message=(
                "Blocked on Instant On, but a pending timed release could not "
                "be cancelled."
            ),
        )
    return DeviceWriteOutcome(status="enforced")


async def instant_on_release_device(
    session: AsyncSession,
    *,
    location_id: uuid.UUID,
    organization_id: uuid.UUID | None,
    client_mac: str,
    settings: Settings | None = None,
) -> DeviceWriteOutcome:
    settings = settings or get_settings()
    target = await resolve_control_target(
        session,
        organization_id=organization_id,
        location_id=location_id,
        settings=settings,
    )
    if target is None:
        return DeviceWriteOutcome(status="unavailable")
    try:
        mac = normalize_instant_on_mac(client_mac)
    except ValueError as exc:
        return DeviceWriteOutcome(status="failed", error_message=str(exc))
    try:
        await _with_client(
            target, settings, lambda client: client.unblock_client(target.site_id, mac)
        )
    except InstantOnError as error:
        return DeviceWriteOutcome(
            status="failed", error_code=error.code, error_message=str(error)
        )
    return DeviceWriteOutcome(status="enforced")


async def instant_on_control_present(
    session: AsyncSession,
    *,
    location_id: uuid.UUID,
    organization_id: uuid.UUID | None,
) -> bool:
    return (
        await resolve_control_target(
            session, organization_id=organization_id, location_id=location_id
        )
        is not None
    )


# -- Celery ------------------------------------------------------------------


async def _release_async(**kwargs: str) -> str:
    from app.database.session import SessionLocal

    async with SessionLocal() as session:
        return await release_transient_block(
            session,
            organization_id=uuid.UUID(kwargs["organization_id"]),
            router_id=uuid.UUID(kwargs["router_id"]),
            mac=kwargs["mac"],
            token=kwargs["token"],
        )


@celery_app.task(
    name=TASK_INSTANT_ON_RELEASE_TRANSIENT_BLOCK,
    autoretry_for=(InstantOnError,),
    retry_backoff=30,
    max_retries=5,
)
def release_transient_block_task(
    *, organization_id: str, router_id: str, mac: str, token: str
) -> str:
    result = run_celery_task(
        _release_async(
            organization_id=organization_id, router_id=router_id, mac=mac, token=token
        )
    )
    logger.info("instant_on_transient_unblock", extra={"result": result})
    return result
