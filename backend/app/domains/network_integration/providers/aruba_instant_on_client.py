"""Read-only HTTP client for the Aruba Instant On portal API.

## What this talks to, and on what terms

Instant On has **no public API** (HPE's own position: the portal API is
undocumented, unsupported and may change or be revoked). This client speaks
the private REST API the portal web app itself uses
(``https://portal.instant-on.hpe.com/api/``), authenticated as a dedicated
Wyfy *service account* that a venue owner invites to their site as a
**Viewer**. The owner accepted that risk explicitly; the design consequence
is that every value read here is treated as untrustworthy in shape, and any
departure from the shapes we have seen is reported as drift rather than
guessed around. Field names come from
``wyfy-ops/aruba-ap21/REAL_DATA_SPIKE.md`` (bundle + live reads, 2026-10-02).

## Read-only, structurally

:class:`InstantOnClient` has no method that issues anything but ``GET``
against the portal API, and its single request primitive hard-codes the
verb. The only ``POST``\\ s in this module go to the **SSO** token endpoints
(login and refresh) inside :class:`InstantOnTokenManager`, which is
authentication, not a change to anybody's network. A test asserts both
properties by recording every request every public method makes.

## Tokens (SPIKE section 3)

* OAuth2 public client (no secret). Refresh = ``POST {sso}/as/token.oauth2``
  with ``grant_type=refresh_token, client_id, refresh_token``.
* The refresh response carries a new refresh token and the old one is
  presumed dead (rotation, INFERRED). Two refreshers racing on one rotating
  token break each other -- the portal itself guards this with a cross-tab
  lock -- so refresh is **single-flight**: an in-process ``asyncio.Lock``
  plus a cross-process lock (Redis in production), a re-read of the stored
  state after the lock is taken, and the rotated refresh token is
  **persisted before** the new access token is handed to anybody.
* Access token lifetime ~1800 s; renewed when under
  :data:`ACCESS_TOKEN_RENEW_MARGIN_SECONDS` remain.
* Initial auth: a scripted PKCE login with the service account's username
  and password, fetched from AWS Secrets Manager by ARN at login time and
  never stored in this repo, in config defaults, or in a log line. A failed
  login sets a cooldown so this platform never retries somebody else's SSO
  in a tight loop, and never tries to get past a challenge (MFA, captcha):
  an unexpected answer is ``auth_failed``, full stop.

## Errors

Every failure is one of the :class:`InstantOnError` subclasses, each with a
stable ``code`` the poller stores and the Master console renders:
``not_configured``, ``auth_failed``, ``not_invited``, ``rate_limited``,
``upstream_error`` and ``incompatible`` (version/shape drift, logged as
``instant_on_api_drift`` at ERROR so it can be alerted on).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import re
import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "ACCESS_TOKEN_RENEW_MARGIN_SECONDS",
    "InstantOnApiDriftError",
    "InstantOnAuthConfig",
    "InstantOnAuthError",
    "InstantOnClient",
    "InstantOnCredentialSource",
    "InstantOnError",
    "InstantOnForbiddenError",
    "InstantOnNotConfiguredError",
    "InstantOnRateLimitedError",
    "InstantOnRefreshLock",
    "InstantOnTokenManager",
    "InstantOnTokenState",
    "InstantOnTokenStore",
    "InstantOnUpstreamError",
    "RedisRefreshLock",
    "SecretsManagerCredentialSource",
    "validate_site_id",
]

ACCESS_TOKEN_RENEW_MARGIN_SECONDS = 300
DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS = 1800
# A Retry-After at or under this is waited out inline, once; anything longer
# is handed back to the poller as rate_limited so it can back the site off
# without holding a worker.
INLINE_RETRY_AFTER_MAX_SECONDS = 5.0
DEFAULT_RETRY_AFTER_SECONDS = 60
MAX_RETRY_AFTER_SECONDS = 900
TRANSIENT_RETRY_DELAY_SECONDS = 1.0

_SITE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


# ============================================================================
# Errors
# ============================================================================


class InstantOnError(Exception):
    """Base class. ``code`` is stable and is what gets stored/rendered;
    ``str(error)`` is operator-facing and never contains a secret."""

    code = "upstream_error"

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason or self.code


class InstantOnNotConfiguredError(InstantOnError):
    """No service-account secret ARN (or an unusable secret). No network
    call was made."""

    code = "not_configured"


class InstantOnAuthError(InstantOnError):
    """The service account could not authenticate: login rejected, a
    challenge we will not answer (MFA/captcha), a refresh token that died and
    a login that failed, or an access token the API refused twice."""

    code = "auth_failed"


class InstantOnForbiddenError(InstantOnError):
    """403/404 on a site resource: the service account has not been invited
    to this site (or was removed, or the site id is wrong)."""

    code = "not_invited"


class InstantOnRateLimitedError(InstantOnError):
    code = "rate_limited"

    def __init__(self, message: str, *, retry_after_seconds: int) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class InstantOnUpstreamError(InstantOnError):
    """5xx, timeout, connection failure, or lock contention. Transient."""

    code = "upstream_error"


class InstantOnApiDriftError(InstantOnError):
    """The API answered in a way we have not seen: a GET we have made before
    refused as a bad request, a non-JSON body, or a body missing the fields
    the mapping depends on. Usually means ``x-ion-api-version`` or the
    resource shape moved. Never guessed around."""

    code = "incompatible"

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message, reason=reason)
        # One stable event name, at ERROR, so a log-based alarm can fire on it.
        logger.error(
            "instant_on_api_drift",
            extra={"reason": self.reason, "detail": message[:200]},
        )


def validate_site_id(site_id: str) -> str:
    """An Instant On site id is interpolated into a URL path, so it must be a
    plain token (the live one is a UUID). Raises ``ValueError`` otherwise."""
    candidate = (site_id or "").strip()
    if not _SITE_ID_RE.match(candidate):
        raise ValueError("Not a valid Instant On site id")
    return candidate


# ============================================================================
# Token state, storage, locking, credentials
# ============================================================================


@dataclass(frozen=True, slots=True)
class InstantOnTokenState:
    """Everything the token manager persists. Secrets are ``repr=False``."""

    access_token: str | None = field(default=None, repr=False)
    access_expires_at: datetime | None = None
    refresh_token: str | None = field(default=None, repr=False)
    refresh_obtained_at: datetime | None = None
    auth_state: str = "never"  # never | ok | auth_failed
    auth_error_code: str | None = None
    login_blocked_until: datetime | None = None


class InstantOnTokenStore(Protocol):
    """Durable, shared-across-processes token storage. ``save`` must be
    committed by the time it returns: the rotated refresh token is the only
    copy in existence."""

    async def load(self) -> InstantOnTokenState: ...

    async def save(self, state: InstantOnTokenState) -> None: ...


class InstantOnRefreshLock(Protocol):
    """Cross-process mutual exclusion for the refresh/login critical
    section. ``hold()`` raises :class:`InstantOnUpstreamError` when it cannot
    get the lock in time -- never proceeds without it."""

    def hold(self) -> contextlib.AbstractAsyncContextManager[None]: ...


class InstantOnCredentialSource(Protocol):
    async def get(self) -> tuple[str, str]:
        """(username, password). Raises InstantOnNotConfiguredError."""
        ...


_RELEASE_LOCK_SCRIPT = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


class RedisRefreshLock:
    """``SET NX PX`` lock with an owner token, released compare-and-delete so
    a lock that expired and was taken by someone else is never deleted by
    the late original owner."""

    def __init__(
        self,
        redis: Any,
        *,
        key: str = "instant_on:token_refresh_lock",
        # Longer than the slowest login (four SSO round trips at the HTTP
        # timeout), so the lock cannot lapse while a rotation is in flight.
        ttl_seconds: float = 120.0,
        wait_seconds: float = 25.0,
        poll_seconds: float = 0.2,
    ) -> None:
        self._redis = redis
        self._key = key
        self._ttl_ms = int(ttl_seconds * 1000)
        self._wait_seconds = wait_seconds
        self._poll_seconds = poll_seconds

    @contextlib.asynccontextmanager
    async def hold(self) -> AsyncIterator[None]:
        owner = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._wait_seconds
        while True:
            if await self._redis.set(self._key, owner, nx=True, px=self._ttl_ms):
                break
            if loop.time() >= deadline:
                raise InstantOnUpstreamError(
                    "Another worker is renewing the Instant On token",
                    reason="token_refresh_contended",
                )
            await asyncio.sleep(self._poll_seconds)
        try:
            yield
        finally:
            try:
                await self._redis.eval(_RELEASE_LOCK_SCRIPT, 1, self._key, owner)
            except Exception:  # noqa: BLE001 -- the TTL releases it anyway
                logger.warning("instant_on_refresh_lock_release_failed")


class SecretsManagerCredentialSource:
    """Reads ``{"username": ..., "password": ...}`` from AWS Secrets Manager.

    Called only when a full login is needed (first start, or the refresh
    token died) -- not on every poll. Values are returned to the caller and
    never logged; errors name the failure, not the secret.
    """

    def __init__(self, *, secret_arn: str, region_name: str) -> None:
        self._secret_arn = secret_arn
        self._region_name = region_name

    async def get(self) -> tuple[str, str]:
        if not self._secret_arn:
            raise InstantOnNotConfiguredError(
                "No Instant On service-account secret ARN is configured",
                reason="secret_arn_missing",
            )
        try:
            raw = await asyncio.to_thread(self._fetch)
        except Exception as exc:  # noqa: BLE001 -- boto raises many types
            raise InstantOnNotConfiguredError(
                "The Instant On service-account secret could not be read "
                f"({type(exc).__name__})",
                reason="secret_unreadable",
            ) from None
        return _parse_credential_secret(raw)

    def _fetch(self) -> str:
        import boto3

        client = boto3.client("secretsmanager", region_name=self._region_name)
        response = client.get_secret_value(SecretId=self._secret_arn)
        return str(response.get("SecretString") or "")


def _parse_credential_secret(raw: str) -> tuple[str, str]:
    try:
        decoded = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        decoded = None
    if not isinstance(decoded, dict):
        raise InstantOnNotConfiguredError(
            "The Instant On service-account secret is not a JSON object",
            reason="secret_malformed",
        )
    username = decoded.get("username") or decoded.get("email")
    password = decoded.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise InstantOnNotConfiguredError(
            "The Instant On service-account secret lacks username/password",
            reason="secret_malformed",
        )
    if not username or not password:
        raise InstantOnNotConfiguredError(
            "The Instant On service-account secret has an empty field",
            reason="secret_malformed",
        )
    return username, password


# ============================================================================
# Token manager
# ============================================================================


@dataclass(frozen=True, slots=True)
class InstantOnAuthConfig:
    api_base_url: str
    sso_base_url: str
    client_id: str = ""
    redirect_uri: str = "https://portal.instant-on.hpe.com"
    auth_failure_cooldown_seconds: int = 1800

    @property
    def portal_root(self) -> str:
        base = self.api_base_url.rstrip("/")
        return base[: -len("/api")] if base.endswith("/api") else base


@dataclass(frozen=True, slots=True)
class _TokenResponse:
    access_token: str = field(repr=False)
    expires_in: int
    refresh_token: str | None = field(default=None, repr=False)


class _RefreshRejected(Exception):
    pass


def _utcnow() -> datetime:
    return datetime.now(UTC)


class InstantOnTokenManager:
    """Hands out a valid access token, renewing it single-flight."""

    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        store: InstantOnTokenStore,
        lock: InstantOnRefreshLock,
        credentials: InstantOnCredentialSource,
        config: InstantOnAuthConfig,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._http = http
        self._store = store
        self._lock = lock
        self._credentials = credentials
        self._config = config
        self._clock = clock
        self._local_lock = asyncio.Lock()
        self._client_id: str | None = config.client_id or None

    # -- public ----------------------------------------------------------

    async def get_access_token(self) -> str:
        state = await self._store.load()
        if self._usable(state):
            assert state.access_token is not None
            return state.access_token
        return await self._renew(rejected_token=None)

    async def force_refresh(self, *, rejected_token: str) -> str:
        """Called after the API answered 401 to ``rejected_token``. If some
        other worker already replaced it, that replacement is returned
        without a second refresh."""
        return await self._renew(rejected_token=rejected_token)

    async def mark_auth_failed(self, reason: str) -> None:
        """The API refused a freshly renewed token. Drop both tokens (they
        are no use) and block logins for the cooldown: something about the
        account is wrong and hammering the SSO will not fix it."""
        async with self._local_lock, self._lock.hold():
            await self._store.save(self._failed_state(reason))

    # -- internals -------------------------------------------------------

    def _usable(self, state: InstantOnTokenState) -> bool:
        if not state.access_token or state.access_expires_at is None:
            return False
        remaining = (state.access_expires_at - self._clock()).total_seconds()
        return remaining > ACCESS_TOKEN_RENEW_MARGIN_SECONDS

    def _failed_state(self, reason: str) -> InstantOnTokenState:
        return InstantOnTokenState(
            auth_state="auth_failed",
            auth_error_code=reason,
            login_blocked_until=self._clock()
            + timedelta(seconds=self._config.auth_failure_cooldown_seconds),
        )

    async def _renew(self, *, rejected_token: str | None) -> str:
        async with self._local_lock, self._lock.hold():
            # Double-checked: whoever held the lock before us may already
            # have renewed. Re-read from the store, never from memory.
            state = await self._store.load()
            if self._usable(state) and (
                rejected_token is None or state.access_token != rejected_token
            ):
                assert state.access_token is not None
                return state.access_token

            now = self._clock()
            if (
                state.login_blocked_until is not None
                and state.login_blocked_until > now
            ):
                raise InstantOnAuthError(
                    "Instant On sign-in is cooling down after a failure",
                    reason=state.auth_error_code or "login_cooldown",
                )

            if state.refresh_token:
                try:
                    tokens = await self._refresh_grant(state.refresh_token)
                except _RefreshRejected:
                    logger.warning("instant_on_refresh_token_rejected")
                    # Dead either way; forget it so the next attempt does not
                    # spend another SSO round trip on it.
                    state = replace(state, refresh_token=None, access_token=None)
                    await self._store.save(state)
                else:
                    return await self._persist(tokens, previous=state)

            try:
                tokens = await self._login()
            except InstantOnAuthError as error:
                await self._store.save(self._failed_state(error.reason))
                logger.warning(
                    "instant_on_login_failed", extra={"reason": error.reason}
                )
                raise
            return await self._persist(tokens, previous=state)

    async def _persist(
        self, tokens: _TokenResponse, *, previous: InstantOnTokenState
    ) -> str:
        now = self._clock()
        rotated = tokens.refresh_token is not None
        state = replace(
            previous,
            access_token=tokens.access_token,
            access_expires_at=now + timedelta(seconds=tokens.expires_in),
            refresh_token=tokens.refresh_token or previous.refresh_token,
            refresh_obtained_at=now if rotated else previous.refresh_obtained_at,
            auth_state="ok",
            auth_error_code=None,
            login_blocked_until=None,
        )
        # Persist BEFORE the access token is used: if this process dies after
        # the SSO rotated the refresh token, the new one must already be on
        # disk or the account is locked out until a full login.
        await self._store.save(state)
        return tokens.access_token

    async def _resolve_client_id(self) -> str:
        if self._client_id:
            return self._client_id
        url = f"{self._config.portal_root}/settings.json"
        response = await self._send("GET", url)
        if response.status_code != 200:
            raise _status_error(response, "portal settings.json")
        payload = _json_body(response, "portal settings.json")
        client_id = (
            payload.get("ssoClientIdAuthZ") if isinstance(payload, dict) else None
        )
        if not isinstance(client_id, str) or not client_id:
            raise InstantOnApiDriftError(
                "Portal settings.json has no ssoClientIdAuthZ",
                reason="settings_shape",
            )
        self._client_id = client_id
        return client_id

    async def _refresh_grant(self, refresh_token: str) -> _TokenResponse:
        client_id = await self._resolve_client_id()
        response = await self._send(
            "POST",
            f"{self._config.sso_base_url.rstrip('/')}/as/token.oauth2",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
        )
        if response.status_code in (400, 401):
            raise _RefreshRejected()
        if response.status_code != 200:
            raise _status_error(response, "token refresh")
        return _parse_token_response(response)

    async def _login(self) -> _TokenResponse:
        """Scripted PKCE login (SPIKE section 3; flow DOCUMENTED by
        puddle.town/mspp.io, UNVERIFIED here until hardware check H2)."""
        username, password = await self._credentials.get()
        client_id = await self._resolve_client_id()
        sso = self._config.sso_base_url.rstrip("/")

        response = await self._send(
            "POST",
            f"{sso}/aio/api/v1/mfa/validate/full",
            data={"username": username, "password": password},
        )
        if response.status_code in (400, 401, 403):
            raise InstantOnAuthError(
                "Instant On rejected the service-account sign-in",
                reason="login_rejected",
            )
        if response.status_code != 200:
            raise _status_error(response, "sign-in")
        body = _json_body(response, "sign-in")
        session_token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(session_token, str) or not session_token:
            # MFA prompt, captcha, or anything else we do not recognise. We
            # do not try to get past a challenge.
            raise InstantOnAuthError(
                "Instant On sign-in did not complete (challenge or unknown "
                "answer); the service account needs MFA off and no captcha",
                reason="login_challenge",
            )

        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        state = secrets.token_urlsafe(16)
        response = await self._send(
            "GET",
            f"{sso}/as/authorization.oauth2",
            params={
                "client_id": client_id,
                "redirect_uri": self._config.redirect_uri,
                "response_type": "code",
                "scope": "profile openid",
                "state": state,
                "code_challenge_method": "S256",
                "code_challenge": challenge,
                "sessionToken": session_token,
            },
        )
        location = (
            response.headers.get("location", "")
            if response.status_code in (301, 302, 303, 307, 308)
            else ""
        )
        query = parse_qs(urlsplit(location).query) if location else {}
        code = (query.get("code") or [None])[0]
        returned_state = (query.get("state") or [None])[0]
        if not code or returned_state != state:
            raise InstantOnAuthError(
                "Instant On did not issue an authorization code",
                reason="authorization_code_missing",
            )

        response = await self._send(
            "POST",
            f"{sso}/as/token.oauth2",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "redirect_uri": self._config.redirect_uri,
                "code": code,
                "code_verifier": verifier,
            },
        )
        if response.status_code in (400, 401):
            raise InstantOnAuthError(
                "Instant On refused the authorization code",
                reason="code_exchange_rejected",
            )
        if response.status_code != 200:
            raise _status_error(response, "code exchange")
        return _parse_token_response(response)

    async def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            return await self._http.request(
                method, url, follow_redirects=False, **kwargs
            )
        except httpx.TimeoutException:
            raise InstantOnUpstreamError(
                "Instant On SSO timed out", reason="timeout"
            ) from None
        except httpx.HTTPError as exc:
            raise InstantOnUpstreamError(
                f"Instant On SSO unreachable ({type(exc).__name__})",
                reason="connection_failed",
            ) from None


def _parse_token_response(response: httpx.Response) -> _TokenResponse:
    body = _json_body(response, "token response")
    access = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(access, str) or not access:
        raise InstantOnApiDriftError(
            "Token response has no access_token", reason="token_shape"
        )
    refresh = body.get("refresh_token")
    expires = _as_int(body.get("expires_in")) or DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS
    return _TokenResponse(
        access_token=access,
        expires_in=max(60, expires),
        refresh_token=refresh if isinstance(refresh, str) and refresh else None,
    )


def _json_body(response: httpx.Response, what: str) -> Any:
    try:
        return response.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise InstantOnApiDriftError(
            f"Instant On {what} was not JSON", reason="non_json"
        ) from None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _retry_after_seconds(response: httpx.Response, now: datetime) -> int:
    raw = response.headers.get("retry-after")
    seconds: float | None = None
    if raw:
        raw = raw.strip()
        if raw.isdigit():
            seconds = float(raw)
        else:
            try:
                when = parsedate_to_datetime(raw)
            except (TypeError, ValueError):
                when = None
            if when is not None:
                if when.tzinfo is None:
                    when = when.replace(tzinfo=UTC)
                seconds = (when - now).total_seconds()
    if seconds is None:
        seconds = DEFAULT_RETRY_AFTER_SECONDS
    return int(min(max(seconds, 1), MAX_RETRY_AFTER_SECONDS))


def _status_error(response: httpx.Response, what: str) -> InstantOnError:
    status = response.status_code
    if status == 429:
        return InstantOnRateLimitedError(
            f"Instant On rate-limited the {what}",
            retry_after_seconds=_retry_after_seconds(response, _utcnow()),
        )
    if status >= 500:
        return InstantOnUpstreamError(
            f"Instant On {what} failed with HTTP {status}", reason=f"http_{status}"
        )
    return InstantOnApiDriftError(
        f"Instant On {what} answered HTTP {status}", reason=f"http_{status}"
    )


# ============================================================================
# The portal API client -- GET only
# ============================================================================


class InstantOnClient:
    """GET-only client for ``/api/sites`` and ``/api/sites/{site}/...``.

    Every public method is a read. There is deliberately no generic
    ``request``/``post``/``put``/``delete`` here, and :meth:`_get_json` --
    the only thing that touches the API -- has no ``method`` parameter.
    """

    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        tokens: InstantOnTokenManager,
        api_base_url: str,
        api_version: int,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._http = http
        self._tokens = tokens
        self._api_base_url = api_base_url.rstrip("/")
        self._api_version = str(api_version)
        self._sleep = sleep
        self._clock = clock

    # -- resources (SPIKE section 2.2) --------------------------------------

    async def list_sites(self) -> list[dict[str, Any]]:
        return _elements(await self._get_json("sites"), "sites")

    async def get_inventory(self, site_id: str) -> list[dict[str, Any]]:
        return _elements(await self._site_get(site_id, "inventory"), "inventory")

    async def get_client_summary(self, site_id: str) -> list[dict[str, Any]]:
        return _elements(
            await self._site_get(site_id, "clientSummary"), "clientSummary"
        )

    async def get_networks_summary(self, site_id: str) -> list[dict[str, Any]]:
        return _elements(
            await self._site_get(site_id, "networksSummary"), "networksSummary"
        )

    async def get_alerts(self, site_id: str) -> list[dict[str, Any]]:
        return _elements(await self._site_get(site_id, "alerts"), "alerts")

    async def get_system_health(self, site_id: str) -> dict[str, Any]:
        payload = await self._site_get(site_id, "systemHealth")
        if not isinstance(payload, dict):
            raise InstantOnApiDriftError(
                "systemHealth is not an object", reason="shape_systemHealth"
            )
        return payload

    async def get_client_usage_24h(self, site_id: str) -> list[dict[str, Any]]:
        return _elements(
            await self._site_get(
                site_id,
                "stats/allNetworks/client/usage",
                params={"appCategory": "allAppCategories"},
            ),
            "client usage",
        )

    # -- the one request primitive ----------------------------------------

    async def _site_get(
        self, site_id: str, resource: str, *, params: dict[str, str] | None = None
    ) -> Any:
        return await self._get_json(
            f"sites/{validate_site_id(site_id)}/{resource}", params=params
        )

    async def _get_json(
        self, path: str, *, params: dict[str, str] | None = None
    ) -> Any:
        url = f"{self._api_base_url}/{path}"
        token = await self._tokens.get_access_token()
        refreshed = False
        transient_retried = False
        rate_limit_waited = False
        while True:
            try:
                response = await self._http.get(
                    url,
                    params=params,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "x-ion-api-version": self._api_version,
                        "Accept": "application/json",
                    },
                    follow_redirects=False,
                )
            except httpx.TimeoutException:
                if not transient_retried:
                    transient_retried = True
                    await self._sleep(TRANSIENT_RETRY_DELAY_SECONDS)
                    continue
                raise InstantOnUpstreamError(
                    "Instant On API timed out", reason="timeout"
                ) from None
            except httpx.HTTPError as exc:
                if not transient_retried:
                    transient_retried = True
                    await self._sleep(TRANSIENT_RETRY_DELAY_SECONDS)
                    continue
                raise InstantOnUpstreamError(
                    f"Instant On API unreachable ({type(exc).__name__})",
                    reason="connection_failed",
                ) from None

            status = response.status_code
            if status == 200:
                return _json_body(response, path.rsplit("/", 1)[-1])
            if status == 401:
                if refreshed:
                    await self._tokens.mark_auth_failed("api_rejected_token")
                    raise InstantOnAuthError(
                        "Instant On rejected a freshly renewed token",
                        reason="api_rejected_token",
                    )
                refreshed = True
                token = await self._tokens.force_refresh(rejected_token=token)
                continue
            if status in (403, 404):
                raise InstantOnForbiddenError(
                    "The service account cannot read this Instant On site "
                    f"(HTTP {status}); has the venue invited it as Viewer?",
                    reason=f"http_{status}",
                )
            if status == 429:
                retry_after = _retry_after_seconds(response, self._clock())
                if (
                    not rate_limit_waited
                    and retry_after <= INLINE_RETRY_AFTER_MAX_SECONDS
                ):
                    rate_limit_waited = True
                    await self._sleep(retry_after)
                    continue
                raise InstantOnRateLimitedError(
                    "Instant On rate-limited this account",
                    retry_after_seconds=retry_after,
                )
            if status >= 500:
                if not transient_retried:
                    transient_retried = True
                    await self._sleep(TRANSIENT_RETRY_DELAY_SECONDS)
                    continue
                raise InstantOnUpstreamError(
                    f"Instant On API failed with HTTP {status}",
                    reason=f"http_{status}",
                )
            # Any other status on a GET we know works -- 400, 406, 410, 412,
            # 415, 422, a redirect -- is the API telling us our request no
            # longer matches it. That is drift, not a transient.
            raise InstantOnApiDriftError(
                f"Instant On API answered HTTP {status} to a known read "
                f"(api version {self._api_version})",
                reason=f"http_{status}",
            )


def _elements(payload: Any, resource: str) -> list[dict[str, Any]]:
    """List resources answer ``{"elements": [...]}`` (MEASURED on inventory,
    networksSummary, clientSummary). Anything else is drift."""
    reason = "shape_" + resource.replace(" ", "_")
    if not isinstance(payload, dict):
        raise InstantOnApiDriftError(f"{resource} is not an object", reason=reason)
    elements = payload.get("elements")
    if not isinstance(elements, list) or not all(isinstance(e, dict) for e in elements):
        raise InstantOnApiDriftError(f"{resource} has no elements list", reason=reason)
    return elements
