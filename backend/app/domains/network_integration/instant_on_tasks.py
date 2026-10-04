"""Celery Beat task: the read-only Aruba Instant On poller.

Modelled on ``usage_tasks.py`` (Beat entry, ``DEVICE_IO_QUEUE_NAME``,
per-venue failure isolation, counts returned, never raises per venue), with
one deliberate difference: **it writes nothing to guest sessions.** RADIUS
accounting is the source of truth for guests at an Instant On venue and
already feeds ``GuestService.record_usage``; a second producer on that sink
would double-count. Instant On data lands only in ``instant_on_snapshots``.

## Cadence (REAL_DATA_SPIKE section 7)

Beat wakes the sweep every ``INSTANT_ON_POLL_SWEEP_INTERVAL_SECONDS`` (60 s).
Each site is then read only for the kinds whose own period has elapsed
since that kind's last attempt:

* ``instant_on_fast_poll_seconds`` (60): ``inventory`` -> access_points,
  ``clientSummary`` -> clients
* ``instant_on_health_poll_seconds`` (300): ``systemHealth`` -> health,
  ``networksSummary`` -> ssids, ``alerts`` -> alerts
* ``instant_on_usage_poll_seconds`` (900): 24 h per-client usage

That is about 3 requests/minute per site, roughly a tenth of one open portal
tab (which polls every 10 s).

## Failure handling

* Per kind: a failure is recorded on that kind's snapshot (the last good
  payload stays but is never served as current -- see
  ``instant_on_service.build_view``).
* Per site: ``not_invited`` (403/404) and ``upstream_error`` stop the
  site's remaining kinds for this tick; drift on one resource does not stop
  the others (shapes can drift one resource at a time).
* Account-wide: ``auth_failed`` / ``not_configured`` concern the one service
  account, so the remaining sites are marked with the same failure **without
  any further network call**. ``rate_limited`` (a 429 whose Retry-After was
  too long to wait inline) backs the site off until Retry-After and ends the
  tick: the limit is almost certainly per account.
* Gated twice: ``Settings.instant_on_poller_enabled`` (global) and
  ``instant_on_sites.poll_enabled`` (per venue). With either off, nothing is
  contacted.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import Settings, get_settings
from app.core.logging import get_logger

from .constants import TASK_RUN_INSTANT_ON_POLL_SWEEP
from .instant_on_repository import InstantOnRepositoryProtocol
from .instant_on_service import InstantOnKind, poll_period_seconds
from .models import InstantOnSite, InstantOnSnapshot
from .providers.aruba_instant_on import ArubaInstantOnProvider, to_jsonable
from .providers.aruba_instant_on_client import (
    InstantOnApiDriftError,
    InstantOnAuthError,
    InstantOnError,
    InstantOnForbiddenError,
    InstantOnNotConfiguredError,
    InstantOnRateLimitedError,
    InstantOnUpstreamError,
)

#: ``(site, access_points payload, now)`` -> the multi-AP registry upsert.
ApSync = Callable[[InstantOnSite, Any, datetime], Awaitable[None]]

logger = get_logger(__name__)

__all__ = [
    "InstantOnPollSummary",
    "build_live_provider",
    "due_kinds",
    "poll_site",
    "run_instant_on_poll",
    "run_instant_on_poll_sweep",
]

# Order matters only for which kinds a site-stopping error skips: the
# cheap, most-wanted reads go first.
_KIND_ORDER: tuple[InstantOnKind, ...] = (
    InstantOnKind.ACCESS_POINTS,
    InstantOnKind.CLIENTS,
    InstantOnKind.HEALTH,
    InstantOnKind.SSIDS,
    InstantOnKind.ALERTS,
    InstantOnKind.CLIENT_USAGE,
)

# A tick that lands a few seconds early must still count as due, or a
# 60 s kind on a 60 s Beat would be polled every other tick.
_DUE_SLACK_SECONDS = 5


async def _read(
    provider: ArubaInstantOnProvider, kind: InstantOnKind, site_id: str
) -> list[dict[str, Any]]:
    if kind == InstantOnKind.ACCESS_POINTS:
        records: list[Any] = await provider.read_access_points(site_id)
    elif kind == InstantOnKind.CLIENTS:
        records = await provider.read_clients(site_id)
    elif kind == InstantOnKind.SSIDS:
        records = await provider.read_networks(site_id)
    elif kind == InstantOnKind.ALERTS:
        records = await provider.read_alerts(site_id)
    elif kind == InstantOnKind.HEALTH:
        records = [await provider.read_health(site_id)]
    else:
        records = await provider.read_client_usage_24h(site_id)
    return [to_jsonable(r) for r in records]


def due_kinds(
    snapshots: Mapping[str, InstantOnSnapshot],
    *,
    now: datetime,
    settings: Settings,
) -> list[InstantOnKind]:
    due: list[InstantOnKind] = []
    for kind in _KIND_ORDER:
        snapshot = snapshots.get(kind.value)
        last = snapshot.last_attempt_at if snapshot is not None else None
        period = poll_period_seconds(kind, settings) - _DUE_SLACK_SECONDS
        if last is None or (now - last).total_seconds() >= period:
            due.append(kind)
    return due


def _payload_hash(payload: list[dict[str, Any]]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class InstantOnPollSummary:
    skipped_reason: str | None = None
    sites_considered: int = 0
    sites_ok: int = 0
    sites_failed: int = 0
    sites_skipped: int = 0
    kinds_read: int = 0
    kinds_failed: int = 0
    error_codes: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "skipped_reason": self.skipped_reason,
            "sites_considered": self.sites_considered,
            "sites_ok": self.sites_ok,
            "sites_failed": self.sites_failed,
            "sites_skipped": self.sites_skipped,
            "kinds_read": self.kinds_read,
            "kinds_failed": self.kinds_failed,
            "error_codes": dict(self.error_codes),
        }


class _AccountWideFailure(Exception):
    def __init__(self, error: InstantOnError) -> None:
        super().__init__(str(error))
        self.error = error


class _StopSweep(Exception):
    pass


# Severity order for the site's api_state when several kinds failed.
_STATE_PRIORITY = (
    "auth_failed",
    "not_configured",
    "not_invited",
    "incompatible",
    "rate_limited",
    "upstream_error",
    "internal_error",
)


async def _record_failures(
    repository: InstantOnRepositoryProtocol,
    site: InstantOnSite,
    kinds: list[InstantOnKind],
    *,
    code: str,
    message: str,
    at: datetime,
) -> None:
    for kind in kinds:
        await repository.record_snapshot_failure(
            site, kind=kind.value, error_code=code, error_message=message, at=at
        )


async def poll_site(
    *,
    site: InstantOnSite,
    provider: ArubaInstantOnProvider,
    repository: InstantOnRepositoryProtocol,
    settings: Settings,
    now: datetime,
    summary: InstantOnPollSummary,
    ap_sync: ApSync | None = None,
) -> None:
    """Poll one site's due kinds and record the outcome. ``ap_sync``, when
    given, receives every successfully read ``access_points`` payload (the
    multi-AP registry upsert); its failure is logged and changes nothing
    about the poll's own outcome. Raises
    :class:`_AccountWideFailure` / :class:`_StopSweep` for the sweep to act
    on; everything else is contained here."""
    snapshots = await repository.get_snapshots(site)
    kinds = due_kinds(snapshots, now=now, settings=settings)
    if not kinds:
        summary.sites_skipped += 1
        return

    failures: dict[str, str] = {}
    last_message = ""
    stop_sweep = False
    account_error: InstantOnError | None = None
    for index, kind in enumerate(kinds):
        try:
            payload = await _read(provider, kind, site.site_id)
        except (InstantOnAuthError, InstantOnNotConfiguredError) as error:
            await _record_failures(
                repository,
                site,
                kinds[index:],
                code=error.code,
                message=str(error),
                at=now,
            )
            failures[kind.value] = error.code
            last_message = str(error)
            account_error = error
            break
        except InstantOnRateLimitedError as error:
            await _record_failures(
                repository, site, [kind], code=error.code, message=str(error), at=now
            )
            failures[kind.value] = error.code
            last_message = str(error)
            await repository.update_site(
                site,
                {"backoff_until": now + timedelta(seconds=error.retry_after_seconds)},
            )
            stop_sweep = True
            break
        except (InstantOnForbiddenError, InstantOnUpstreamError) as error:
            await _record_failures(
                repository,
                site,
                kinds[index:],
                code=error.code,
                message=str(error),
                at=now,
            )
            failures[kind.value] = error.code
            last_message = str(error)
            break
        except InstantOnApiDriftError as error:
            await _record_failures(
                repository, site, [kind], code=error.code, message=str(error), at=now
            )
            failures[kind.value] = error.code
            last_message = str(error)
            continue
        except Exception:  # noqa: BLE001 -- one kind must not stop the site
            logger.exception(
                "instant_on_poll_kind_failed",
                extra={"instant_on_site_id": str(site.id), "kind": kind.value},
            )
            await _record_failures(
                repository,
                site,
                [kind],
                code="internal_error",
                message="Unexpected error while reading Instant On",
                at=now,
            )
            failures[kind.value] = "internal_error"
            last_message = "Unexpected error while reading Instant On"
            continue
        await repository.record_snapshot_success(
            site,
            kind=kind.value,
            payload=payload,
            payload_hash=_payload_hash(payload),
            at=now,
        )
        summary.kinds_read += 1
        if ap_sync is not None and kind == InstantOnKind.ACCESS_POINTS:
            try:
                await ap_sync(site, payload, now)
            except Exception:  # noqa: BLE001 -- see docstring
                logger.exception(
                    "instant_on_ap_registry_sync_failed",
                    extra={"instant_on_site_id": str(site.id)},
                )

    summary.kinds_failed += len(failures)
    if failures:
        codes = set(failures.values())
        state = next((c for c in _STATE_PRIORITY if c in codes), "upstream_error")
        for code in codes:
            summary.error_codes[code] = summary.error_codes.get(code, 0) + 1
        await repository.update_site(
            site,
            {
                "api_state": state,
                "last_poll_at": now,
                "last_error_code": state,
                "last_error_message": last_message[:500],
                "last_error_at": now,
                "consecutive_failures": (site.consecutive_failures or 0) + 1,
            },
        )
        summary.sites_failed += 1
    else:
        await repository.update_site(
            site,
            {
                "api_state": "ok",
                "last_poll_at": now,
                "last_success_at": now,
                "consecutive_failures": 0,
                "backoff_until": None,
            },
        )
        summary.sites_ok += 1

    if account_error is not None:
        raise _AccountWideFailure(account_error)
    if stop_sweep:
        raise _StopSweep()


async def _mark_account_failure(
    *,
    site: InstantOnSite,
    repository: InstantOnRepositoryProtocol,
    settings: Settings,
    now: datetime,
    error: InstantOnError,
    summary: InstantOnPollSummary,
) -> None:
    snapshots = await repository.get_snapshots(site)
    kinds = due_kinds(snapshots, now=now, settings=settings)
    if not kinds:
        summary.sites_skipped += 1
        return
    await _record_failures(
        repository, site, kinds, code=error.code, message=str(error), at=now
    )
    await repository.update_site(
        site,
        {
            "api_state": error.code,
            "last_poll_at": now,
            "last_error_code": error.code,
            "last_error_message": str(error)[:500],
            "last_error_at": now,
            "consecutive_failures": (site.consecutive_failures or 0) + 1,
        },
    )
    summary.sites_failed += 1
    summary.kinds_failed += len(kinds)
    summary.error_codes[error.code] = summary.error_codes.get(error.code, 0) + 1


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def run_instant_on_poll(
    *,
    repository: InstantOnRepositoryProtocol,
    provider_factory: Callable[[], ArubaInstantOnProvider],
    settings: Settings,
    commit: Callable[[], Awaitable[None]],
    rollback: Callable[[], Awaitable[None]],
    clock: Callable[[], datetime] = _utcnow,
    ap_sync: ApSync | None = None,
) -> InstantOnPollSummary:
    """One sweep. Commits after every site so one venue's failure (or a DB
    error while recording it) cannot roll back another's results."""
    summary = InstantOnPollSummary()
    if not settings.instant_on_poller_enabled:
        summary.skipped_reason = "poller_disabled"
        return summary
    sites = await repository.list_pollable_sites(
        limit=settings.instant_on_max_sites_per_run
    )
    summary.sites_considered = len(sites)
    if not sites:
        return summary

    provider: ArubaInstantOnProvider | None = None
    account_error: InstantOnError | None = None
    for site in sites:
        now = clock()
        try:
            if account_error is not None:
                await _mark_account_failure(
                    site=site,
                    repository=repository,
                    settings=settings,
                    now=now,
                    error=account_error,
                    summary=summary,
                )
                await commit()
                continue
            if site.backoff_until is not None and site.backoff_until > now:
                summary.sites_skipped += 1
                continue
            if provider is None:
                try:
                    provider = provider_factory()
                except InstantOnError as error:
                    # Nothing can be read for anybody (no encryption key for
                    # the token store, ...): an account-wide failure.
                    account_error = error
                    await _mark_account_failure(
                        site=site,
                        repository=repository,
                        settings=settings,
                        now=now,
                        error=error,
                        summary=summary,
                    )
                    await commit()
                    continue
            await poll_site(
                site=site,
                provider=provider,
                repository=repository,
                settings=settings,
                now=now,
                summary=summary,
                ap_sync=ap_sync,
            )
            await commit()
        except _AccountWideFailure as failure:
            await commit()
            account_error = failure.error
            logger.warning(
                "instant_on_account_failure",
                extra={"code": failure.error.code, "reason": failure.error.reason},
            )
        except _StopSweep:
            await commit()
            logger.warning("instant_on_rate_limited_sweep_stopped")
            break
        except Exception:  # noqa: BLE001 -- one venue must not stop the sweep
            logger.exception(
                "instant_on_poll_site_failed",
                extra={"instant_on_site_id": str(site.id)},
            )
            await rollback()
            summary.sites_failed += 1
    return summary


# ============================================================================
# Celery wiring
# ============================================================================

_SWEEP_LOCK_KEY = "instant_on:poll_sweep_lock"


def build_live_provider(http: Any, settings: Settings) -> ArubaInstantOnProvider:
    """The production wiring: DB-backed shared token store, Redis
    single-flight lock, Secrets Manager credentials. Used by the sweep and by
    the Master "which sites can the service account see" read."""
    from app.database.redis import redis_client
    from app.database.session import SessionLocal

    from .instant_on_repository import DbInstantOnTokenStore, account_key_for
    from .providers.aruba_instant_on_client import (
        InstantOnAuthConfig,
        InstantOnClient,
        InstantOnTokenManager,
        RedisRefreshLock,
        SecretsManagerCredentialSource,
    )

    if settings.uses_public_network_integration_key():
        # The token store encrypts under network_integration_encryption_key
        # and refuses the public default outside a dev machine. Refuse here,
        # before any SSO call: a rotated refresh token that cannot be saved
        # is a lost one.
        raise InstantOnNotConfiguredError(
            "CLOUDGUEST_NETWORK_INTEGRATION_ENCRYPTION_KEY is not set",
            reason="encryption_key_not_configured",
        )
    account_key = account_key_for(settings.instant_on_service_account_secret_arn)
    tokens = InstantOnTokenManager(
        http=http,
        store=DbInstantOnTokenStore(SessionLocal, account_key=account_key),
        lock=RedisRefreshLock(
            redis_client, key=f"instant_on:token_refresh_lock:{account_key[:16]}"
        ),
        credentials=SecretsManagerCredentialSource(
            secret_arn=settings.instant_on_service_account_secret_arn,
            region_name=settings.instant_on_secrets_region,
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
    client = InstantOnClient(
        http=http,
        tokens=tokens,
        api_base_url=settings.instant_on_api_base_url,
        api_version=settings.instant_on_api_version,
    )
    return ArubaInstantOnProvider(client)


def _ap_registry_sync(session: Any) -> ApSync:
    """Upsert the polled inventory into ``aruba_access_points`` in a
    SAVEPOINT, so a failure there cannot roll back the snapshot."""
    from .aruba_access_points import sync_from_instant_on_inventory

    async def sync(site: InstantOnSite, payload: Any, now: datetime) -> None:
        async with session.begin_nested():
            await sync_from_instant_on_inventory(
                session, site=site, access_points=payload or [], now=now
            )

    return sync


async def _run_instant_on_poll_async() -> InstantOnPollSummary:
    import httpx

    from app.database.redis import redis_client
    from app.database.session import SessionLocal

    from .instant_on_repository import InstantOnRepository

    settings = get_settings()
    if not settings.instant_on_poller_enabled:
        return InstantOnPollSummary(skipped_reason="poller_disabled")

    # Overlapping ticks would double the request rate against the account;
    # a tick that finds the previous one still running steps aside.
    if not await redis_client.set(_SWEEP_LOCK_KEY, "1", nx=True, ex=55):
        return InstantOnPollSummary(skipped_reason="previous_sweep_running")

    try:
        async with (
            httpx.AsyncClient(timeout=settings.instant_on_http_timeout_seconds) as http,
            SessionLocal() as session,
        ):
            return await run_instant_on_poll(
                repository=InstantOnRepository(session),
                provider_factory=lambda: build_live_provider(http, settings),
                settings=settings,
                commit=session.commit,
                rollback=session.rollback,
                ap_sync=_ap_registry_sync(session),
            )
    finally:
        try:
            await redis_client.delete(_SWEEP_LOCK_KEY)
        except Exception:  # noqa: BLE001 -- the TTL releases it anyway
            logger.warning("instant_on_sweep_lock_release_failed")


@celery_app.task(name=TASK_RUN_INSTANT_ON_POLL_SWEEP)
def run_instant_on_poll_sweep() -> dict[str, Any]:
    """Beat-scheduled (``app.core.celery_app``). Reads Instant On for every
    enabled venue; writes only ``instant_on_*`` tables."""
    summary = run_celery_task(_run_instant_on_poll_async())
    result = summary.as_dict()
    logger.info("instant_on_poll_sweep_completed", extra=result)
    return result
