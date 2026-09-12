"""The HTTP transport: timeouts, bounded retry, re-login, redacted logging.

Everything in this package that touches the network goes through
``OmadaHttpClient``. Resource modules (``sites``/``devices``/``clients``/
``portal``) never see ``httpx``; they call ``client.request(...)`` and get a
parsed, already-error-checked envelope back.

## errorCode 0 is the only success

Both Omada APIs answer HTTP 200 with a failure inside the body. A client that
trusts the status line reports "connected" for wrong credentials. So the
success test here is always ``errorCode == 0`` (see ``types.parse_envelope``),
and the HTTP status is used only for the things a status code genuinely
carries: 401/403, 429, 5xx, and transport failures.

## Retry policy, and what is deliberately *not* retried

At most ``MAX_ATTEMPTS`` (3) attempts, with exponential backoff plus full
jitter between them. Retried: timeouts, connection failures, HTTP 5xx, and
HTTP 429. Never retried: any authentication failure. Hammering a controller
with credentials it just rejected is how an integration gets an operator
account locked out, and no amount of retrying will make a wrong password
right.

Jitter is *full* jitter (``uniform(0, base * 2**n)``) rather than a fixed
delay, because the realistic concurrency here is a Celery sweep waking up and
polling every integration on one controller at once (contract section 7). A
fixed backoff would resynchronize those into a second simultaneous burst
against a controller that is already struggling.

## Session expiry gets exactly one re-login

On a session-expired signal the cached session is dropped, a new one is
established, and the request is replayed **once**. If that also comes back
expired we stop and raise, rather than looping: a controller that rejects a
session it issued moments ago is not going to be fixed by a third attempt,
and the loop would be indistinguishable from a credential problem while
generating unbounded load.

## A fresh HTTP client per call, on purpose

``httpx.AsyncClient`` is created and closed per adapter call rather than
pooled. A pooled client would be faster, but it would also be a long-lived
holder of session cookies for many tenants' controllers inside one worker
process, and cross-tenant leakage through a shared cookie jar is exactly the
class of bug this platform has already been bitten by. The session *material*
is cached deliberately and explicitly (``auth.SessionCache``, keyed on a
credential fingerprint); the connection is not. Callers are Celery tasks on
the ``device_io`` queue (PRD section 2.4), where a TLS handshake per call is
not a meaningful cost.

## Logging

Every log line goes through ``_log``, which redacts its ``extra`` payload via
``redaction.redact_mapping``. Response bodies are never logged, not even at
debug level -- a body is the single most likely place for a token to appear,
and "we only log it at debug" is not a control, because production debug
logging happens.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from ..controller_contract import ControllerCredentials, ControllerTlsMode
from .auth import (
    EnvelopeSender,
    RawResult,
    SessionCache,
    SessionState,
    establish_session,
    session_key,
)
from .errors import (
    OmadaAuthError,
    OmadaAuthorizationError,
    OmadaConnectionError,
    OmadaInvalidControllerError,
    OmadaPermissionDeniedError,
    OmadaRateLimitedError,
    OmadaSessionExpiredError,
    OmadaTimeoutError,
    OmadaTlsTrustError,
    OmadaUnsupportedApiError,
)
from .redaction import redact_mapping, sanitize_detail
from .tls import (
    PinVerifyingTransport,
    assert_peer_certificate_matches,
    is_certificate_verification_failure,
    require_pin,
    ssl_verify_argument,
)
from .types import (
    OPENAPI_ERROR_CONTROLLER_ID_NOT_FOUND,
    SESSION_EXPIRED_ERROR_CODES,
    OmadaEnvelope,
    coerce_str,
    extract_page,
    extract_total_rows,
    parse_envelope,
)

logger = logging.getLogger(__name__)

#: Total attempts per request, including the first. Contract section 2.
MAX_ATTEMPTS = 3
#: First backoff step; doubles per attempt, then full-jittered.
BACKOFF_BASE_SECONDS = 0.5
#: Ceiling on any single sleep, so a 3rd attempt cannot stall a Celery task.
BACKOFF_MAX_SECONDS = 8.0

#: Rows per page when walking a paginated Open API list endpoint.
DEFAULT_PAGE_SIZE = 100
#: Hard cap on pages walked, so a controller with an inconsistent
#: ``totalRows`` cannot spin a sync task forever. 100 pages x 100 rows is far
#: beyond any realistic single-site fleet or guest population.
MAX_PAGES = 100

#: VERIFIED on hardware 2026-09-11, still not in any TP-Link document.
#: ``GET /api/info`` is the unauthenticated controller-identity endpoint used
#: universally by community tooling. Against Omada Software Controller
#: 5.15.24.19 it answers::
#:
#:     {"errorCode":0,"msg":"Success.","result":{"controllerVer":"5.15.24.19",
#:      "apiVer":"3","configured":false,"type":1,"supportApp":true,
#:      "omadacId":"24eaf8e5c95e88902a966e69763cfb0d","registeredRoot":false,
#:      "omadacCategory":"advanced","mspMode":false,
#:      "omadaCloudUrl":"https://omada.tplinkcloud.com"}}
#:
#: It is the only path that can *discover* ``omadacId``, which is why it is
#: tried first and why the id-scoped path below cannot replace it.
CONTROLLER_INFO_PATH = "/api/info"


def controller_info_path(omadac_id: str) -> str:
    """The id-scoped identity path, ``GET /{omadacId}/api/info``.

    **VERIFIED on hardware 2026-09-11 against two real controllers**, and it
    is the fix for the cloud-managed case:

    * TP-Link's cloud edge (``https://aps1-api-omada-controller.tplinkcloud
      .com``) answers **404 with an empty body** on the unscoped
      ``/api/info`` -- there is no controller to identify until you say which
      one -- but answers the *scoped* path with the full identity payload,
      ``omadacId`` and ``controllerVer`` included.
    * A direct controller answers **both** paths with the identical payload.

    So this is not a cloud-only path; it is the same endpoint namespaced the
    way every other v5.0.15+ route already is (``/{omadacId}/api/v2/...``). A
    wrong id returns Omada ``-7131``, so a mistyped Omada ID is reported as a
    mistyped Omada ID rather than as an unreachable controller.
    """
    return f"/{omadac_id}/api/info"


#: What to tell an operator when neither identity path can be used: the host
#: does not serve the unscoped path and we were given no id to scope with.
#: Composed from constants only (see ``errors.py``).
_NO_IDENTITY_PATH_MESSAGE = (
    "This address did not answer at /api/info, which is how a controller is "
    "identified when no Omada ID is stored. Cloud-managed controllers never "
    "answer it -- their address fronts many controllers at once. Enter the "
    "Omada ID (Settings > Controller Settings, or the long identifier in the "
    "controller's own web address) and try again."
)

SleepFn = Callable[[float], Awaitable[None]]


class OmadaHttpClient:
    """One controller, one call's worth of HTTP.

    Construct inside ``async with``; the underlying ``httpx.AsyncClient`` is
    created on entry and closed on exit.

    ``transport``, ``sleep`` and ``rng`` are injection points for tests: a
    ``httpx.MockTransport`` removes the network, a no-op ``sleep`` removes
    real backoff delays, and a seeded ``rng`` makes jitter deterministic so
    the backoff bounds can actually be asserted.
    """

    def __init__(
        self,
        creds: ControllerCredentials,
        *,
        cache: SessionCache,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: SleepFn | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self._creds = creds
        self._cache = cache
        self._transport = transport
        self._sleep: SleepFn = sleep or asyncio.sleep
        self._rng = rng or random.Random()
        self._http: httpx.AsyncClient | None = None
        self._omadac_id: str | None = creds.omadac_id or None

    # -- lifecycle --------------------------------------------------------

    async def __aenter__(self) -> OmadaHttpClient:
        timeout = httpx.Timeout(
            connect=self._creds.timeout_seconds,
            read=self._creds.timeout_seconds,
            write=self._creds.timeout_seconds,
            pool=self._creds.timeout_seconds,
        )
        verify = ssl_verify_argument(self._creds)
        transport = self._transport
        if self._creds.tls_mode is ControllerTlsMode.PINNED:
            pin = require_pin(self._creds)
            if transport is None:
                # The preflight is what keeps a credential off the wire when
                # the certificate is wrong -- see ``tls.py``. It is skipped
                # when a transport was injected because there is then no real
                # socket to preflight; the injector owns the network.
                await assert_peer_certificate_matches(self._creds, pin)
                transport = httpx.AsyncHTTPTransport(verify=verify)
            transport = PinVerifyingTransport(transport, pin)
        self._http = httpx.AsyncClient(
            base_url=self._creds.base_url.rstrip("/"),
            timeout=timeout,
            verify=verify,
            transport=transport,
            # Redirects are not followed. The caller SSRF-validated one
            # specific host (contract section 6); letting the controller
            # redirect us to a different one would route around that check
            # entirely, and a legitimate Omada API never needs it.
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # -- logging ----------------------------------------------------------

    def _log(self, level: int, event: str, **fields: Any) -> None:
        """Emit one structured, redacted log line.

        Mirrors the ``logger.info("event_name", extra={...})`` style the
        MikroTik adapter already uses. ``redact_mapping`` runs on the way out
        so a caller cannot leak a secret by passing one in -- the guarantee
        does not depend on every call site remembering.
        """
        logger.log(level, event, extra=redact_mapping(fields))

    # -- low-level send ---------------------------------------------------

    async def _send_raw(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        is_auth_request: bool = False,
    ) -> RawResult:
        """Send one request and parse the envelope. Raises normalized errors.

        Every ``httpx`` exception type is translated here so that nothing
        below this line ever sees a transport-library exception -- which
        matters because ``httpx``'s messages embed the full request URL, and
        a URL can carry a query string we would rather not surface.
        """
        if self._http is None:  # pragma: no cover - guarded by context manager
            raise RuntimeError("OmadaHttpClient must be used inside `async with`.")

        request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            request_headers.update(headers)

        if cookies:
            # Set on the client instance rather than per-request: httpx
            # deprecated the per-request form because cookie-persistence
            # semantics were ambiguous. Safe here precisely because this
            # client is built fresh per adapter call and never shared across
            # tenants (see the module docstring).
            self._http.cookies.update(cookies)

        try:
            response = await self._http.request(
                method,
                path,
                json=json,
                params=params,
                headers=request_headers,
            )
        except httpx.TimeoutException as exc:
            self._log(logging.WARNING, "omada_request_timeout", path=path, method=method)
            raise OmadaTimeoutError() from exc
        except httpx.TransportError as exc:
            # Covers connect errors, DNS failures, TLS handshake failures and
            # read errors -- but NOT all of them equally. A rejected
            # certificate is a different problem from an unreachable address
            # and gets its own code: see ``OmadaTlsTrustError``. Everything
            # else really is "we could not complete a conversation with the
            # controller", which is one actionable thing to a user.
            if is_certificate_verification_failure(exc):
                self._log(
                    logging.WARNING,
                    "omada_request_tls_untrusted",
                    path=path,
                    method=method,
                    error_type=type(exc).__name__,
                )
                raise OmadaTlsTrustError() from exc
            self._log(
                logging.WARNING,
                "omada_request_transport_error",
                path=path,
                method=method,
                error_type=type(exc).__name__,
            )
            raise OmadaConnectionError() from exc
        except httpx.HTTPError as exc:  # pragma: no cover - defensive catch-all
            raise OmadaConnectionError() from exc

        self._log(
            logging.DEBUG,
            "omada_response",
            path=path,
            method=method,
            status_code=response.status_code,
        )

        self._raise_for_status(response, path=path, is_auth_request=is_auth_request)

        try:
            payload = response.json()
        except ValueError as exc:
            # HTTP 200 with a non-JSON body: almost always a proxy or a
            # login page rather than the controller API.
            self._log(logging.WARNING, "omada_response_not_json", path=path)
            raise OmadaInvalidControllerError() from exc

        envelope = parse_envelope(payload)
        return RawResult(envelope=envelope, cookies=dict(response.cookies))

    def _raise_for_status(
        self, response: httpx.Response, *, path: str, is_auth_request: bool
    ) -> None:
        """Translate an HTTP status into a normalized error, or return."""
        status = response.status_code
        if status < 400:
            return

        if status in (401, 403):
            # On a login/token request this is a credential problem and must
            # never be retried. On any other request it means our session is
            # no longer good, which is a recoverable, re-loginable condition.
            if is_auth_request:
                raise OmadaAuthError()
            raise OmadaSessionExpiredError()
        if status == 404:
            # The endpoint is not present on this controller -- typically an
            # Open API path on a controller older than v5.13, or Open API
            # switched off. "Unsupported" is both true and actionable.
            raise OmadaUnsupportedApiError()
        if status == 429:
            raise OmadaRateLimitedError()
        if status >= 500:
            self._log(
                logging.WARNING, "omada_server_error", path=path, status_code=status
            )
            raise OmadaConnectionError(
                "The Omada controller returned a server error. It may be "
                "restarting or overloaded."
            )
        raise OmadaInvalidControllerError()

    # -- session ----------------------------------------------------------

    def _auth_sender(self) -> EnvelopeSender:
        """A sender bound for auth use: unauthenticated, non-retrying, and
        flagged so a 401 becomes ``OmadaAuthError`` rather than a re-login
        loop."""

        async def _send(
            method: str,
            path: str,
            *,
            json: dict[str, Any] | None = None,
            params: dict[str, Any] | None = None,
            headers: dict[str, str] | None = None,
            cookies: dict[str, str] | None = None,
        ) -> RawResult:
            return await self._send_raw(
                method,
                path,
                json=json,
                params=params,
                headers=headers,
                cookies=cookies,
                is_auth_request=True,
            )

        return _send

    async def resolve_omadac_id(self) -> str:
        """The controller id, from ``creds`` or discovered via ``/api/info``."""
        if self._omadac_id:
            return self._omadac_id
        info = await self.fetch_controller_info()
        omadac_id = coerce_str(info.get("omadacId"))
        if not omadac_id:
            raise OmadaInvalidControllerError(
                "The controller did not report its controller ID. Enter it "
                "manually -- it is the long identifier in the controller's "
                "own web address."
            )
        self._omadac_id = omadac_id
        return omadac_id

    async def fetch_controller_info(self) -> dict[str, Any]:
        """Raw controller-identity result. Unauthenticated by design.

        Tries the unscoped ``GET /api/info`` first and, if the host does not
        serve it (HTTP 404, which ``_raise_for_status`` turns into
        ``OmadaUnsupportedApiError``), retries at the id-scoped
        ``GET /{omadacId}/api/info`` when an ``omadacId`` is known.

        ## Why a fallback rather than a configured ``direct``/``cloud`` mode

        The cloud-northbound assessment proposed a ``controller_access``
        column to record that a controller is reached through TP-Link's cloud
        edge, and to skip discovery on that basis. Hardware says the
        behaviour does not need declaring, because the request itself answers
        the question better than a column could:

        * **A column can be wrong; a 404 cannot.** An operator who picks
          ``direct`` for a cloud controller reproduces exactly the defect this
          fixes, and one who picks ``cloud`` for a direct controller loses
          discovery for no reason. The failure mode of a self-declared enum is
          a support ticket that looks identical to the bug.
        * **It is not a cloud-only condition.** Any controller behind a
          reverse proxy that does not forward the unscoped path lands here
          too, and the fallback fixes that case for free.
        * **The unscoped path is still required**, so the "cloud" branch could
          never have been a clean fork: it is the only way to *discover* an
          ``omadacId``, and the scoped path is the only way to identify a
          controller once discovery is impossible. Both paths exist in both
          worlds; which one works is a property of the host, not of the row.
        * **Discovery is genuinely unnecessary on the cloud host anyway.** The
          Omada ID is handed to the operator with the credentials and TP-Link's
          own console puts it in the URL bar, so requiring it there costs
          nothing -- which is why the "no id, no unscoped path" case raises a
          message naming that field instead of degrading silently.

        The cost is one wasted 404 round trip per *identity* call on a cloud
        host. It is not paid on the hot path: ``resolve_omadac_id`` returns the
        configured id without any request at all, so sync and portal
        authorization never reach this method.
        """
        try:
            return await self._fetch_controller_info_at(CONTROLLER_INFO_PATH)
        except OmadaUnsupportedApiError:
            scoped_id = self._omadac_id

        if not scoped_id:
            # Nothing left to try: this host does not publish identity
            # unscoped, and we have no id to scope the request with.
            raise OmadaInvalidControllerError(_NO_IDENTITY_PATH_MESSAGE) from None

        self._log(
            logging.INFO,
            "omada_controller_info_scoped_fallback",
            path=CONTROLLER_INFO_PATH,
        )
        return await self._fetch_controller_info_at(controller_info_path(scoped_id))

    async def _fetch_controller_info_at(self, path: str) -> dict[str, Any]:
        """One identity request, envelope-checked. Raises, never returns None."""
        result = await self._send_raw("GET", path)
        if not result.envelope.ok:
            if result.envelope.error_code == OPENAPI_ERROR_CONTROLLER_ID_NOT_FOUND:
                # VERIFIED on hardware: both a direct controller and the cloud
                # edge answer the scoped path with -7131 for an id they do not
                # hold. The default "does not look like an Omada controller"
                # would be false here and would send the operator to check the
                # URL, which is the one field that is right.
                raise OmadaInvalidControllerError(
                    "The Omada controller does not recognise that controller "
                    "ID. Check the identifier in the controller's own web "
                    "address.",
                    provider_code=result.envelope.error_code,
                )
            detail = sanitize_detail(result.envelope.msg)
            raise OmadaInvalidControllerError(
                f"{OmadaInvalidControllerError.default_message} Controller said: {detail}"
                if detail
                else None,
                provider_code=result.envelope.error_code,
            )
        if not isinstance(result.envelope.result, dict):
            raise OmadaInvalidControllerError()
        return result.envelope.result

    async def _ensure_session(self, *, force_new: bool = False) -> SessionState:
        omadac_id = await self.resolve_omadac_id()
        key = session_key(self._creds, omadac_id)
        previous = self._cache.get(key)
        if previous is not None and not force_new:
            return previous
        if force_new:
            self._cache.invalidate(key)
        state = await establish_session(
            self._auth_sender(), self._creds, omadac_id, previous=previous
        )
        self._cache.set(key, state)
        self._log(
            logging.INFO,
            "omada_session_established",
            auth_mode=str(self._creds.auth_mode),
            reused=False,
        )
        return state

    async def ensure_authenticated(self) -> SessionState:
        """Force a real login, bypassing any cached session.

        Public because ``test_connection`` needs exactly this and nothing
        else: proof that the stored credentials are accepted *right now*.
        Reusing a cached session there would mean the second press of "Test
        connection" validated nothing.
        """
        return await self._ensure_session(force_new=True)

    def invalidate_session(self) -> None:
        if self._omadac_id:
            self._cache.invalidate(session_key(self._creds, self._omadac_id))

    # -- retry / backoff --------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        """Full-jittered exponential backoff for ``attempt`` (1-based)."""
        ceiling = min(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)), BACKOFF_MAX_SECONDS)
        return self._rng.uniform(0.0, ceiling)

    # -- public request ---------------------------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        authenticated: bool = True,
        retry_on_transport_error: bool = True,
    ) -> OmadaEnvelope:
        """Send a request, retrying and re-logging-in per the policy above.

        Returns the envelope only on ``errorCode == 0``; every other outcome
        raises one of the normalized errors.

        ``retry_on_transport_error=False`` is for requests that are not safe
        to repeat -- a ``POST`` that *creates* something. A timeout or a
        dropped connection leaves it unknowable whether the controller acted,
        and replaying a create is how one click becomes two portals or two
        operator accounts. Such a request is sent once and a transport
        failure is raised to the caller, which is expected to re-read state
        before trying again. HTTP 429 is still retried: it is the controller
        saying it did *not* process the request. Re-login on an expired
        session is still performed for the same reason -- a 401 or a token
        error is a request the controller refused before acting on it.
        """
        relogin_used = False
        last_error: Exception | None = None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            session: SessionState | None = None
            try:
                if authenticated:
                    session = await self._ensure_session()
                result = await self._send_raw(
                    method,
                    path,
                    json=json,
                    params=params,
                    headers=session.headers if session else None,
                    cookies=session.cookies if session else None,
                )
                envelope = result.envelope
            except OmadaSessionExpiredError as exc:
                # HTTP-level expiry (401/403 on an authenticated call).
                last_error = exc
                if not authenticated or relogin_used:
                    raise
                relogin_used = True
                self._log(logging.INFO, "omada_session_expired_relogin", path=path)
                await self._ensure_session(force_new=True)
                continue
            except (OmadaTimeoutError, OmadaConnectionError, OmadaRateLimitedError) as exc:
                last_error = exc
                if attempt >= MAX_ATTEMPTS:
                    raise
                if not retry_on_transport_error and not isinstance(
                    exc, OmadaRateLimitedError
                ):
                    raise
                delay = self._backoff_delay(attempt)
                self._log(
                    logging.INFO,
                    "omada_request_retry",
                    path=path,
                    attempt=attempt,
                    delay_seconds=round(delay, 3),
                    reason=type(exc).__name__,
                )
                await self._sleep(delay)
                continue

            if envelope.ok:
                return envelope

            # errorCode-level session expiry.
            if (
                authenticated
                and envelope.error_code in SESSION_EXPIRED_ERROR_CODES
                and not relogin_used
            ):
                relogin_used = True
                self._log(
                    logging.INFO,
                    "omada_session_expired_relogin",
                    path=path,
                    provider_code=envelope.error_code,
                )
                await self._ensure_session(force_new=True)
                continue

            raise self.translate_envelope_error(envelope)

        # Only reachable if the final iteration was a `continue` -- i.e. the
        # re-login path consumed the last attempt.
        if isinstance(last_error, Exception):
            raise last_error
        raise OmadaSessionExpiredError()  # pragma: no cover - defensive

    async def get_all_pages(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> list[dict[str, Any]]:
        """Walk an Open API list endpoint and return every row.

        Open API paginates with ``page`` (1-based) and ``pageSize`` query
        parameters and replies ``{"data": [...], "totalRows": n,
        "currentPage": p, "currentSize": s}``.

        Termination does not rely on ``totalRows`` alone. A page that comes
        back empty ends the walk regardless of what ``totalRows`` claims, and
        ``MAX_PAGES`` caps the whole thing. Both guards exist because a
        controller whose ``totalRows`` disagrees with the rows it actually
        serves -- a real possibility when clients connect and disconnect
        mid-walk -- would otherwise spin forever inside a Celery task.
        """
        rows: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            page_params = dict(params or {})
            page_params.update({"page": page, "pageSize": page_size})
            envelope = await self.request("GET", path, params=page_params)
            batch = extract_page(envelope.result)
            rows.extend(batch)
            if not batch:
                break
            total = extract_total_rows(envelope.result)
            if total is not None and len(rows) >= total:
                break
            if len(batch) < page_size:
                # A short page means there is nothing after it, whatever
                # `totalRows` says.
                break
        else:
            self._log(
                logging.WARNING,
                "omada_pagination_cap_reached",
                path=path,
                max_pages=MAX_PAGES,
            )
        return rows

    @staticmethod
    def translate_envelope_error(envelope: OmadaEnvelope) -> Exception:
        """Map a non-zero ``errorCode`` onto a normalized exception.

        Deliberately coarse. We have a reliable published meaning for very
        few Omada error codes, so rather than invent a large lookup table
        that would be wrong in ways nobody could audit, unknown codes become
        a generic ``OmadaError`` subclass carrying the raw integer in
        ``provider_code``. The integer is what an engineer needs for
        diagnosis; a fabricated human string would only mislead.
        """
        from .errors import OmadaError  # local import: avoids a cycle at import time
        from .types import (
            OPENAPI_ERROR_CONTROLLER_ID_NOT_FOUND,
            OPENAPI_ERROR_OPERATION_UNSUPPORTED,
            PERMISSION_DENIED_ERROR_CODES,
            PORTAL_AUTHORIZATION_ERROR_CODES,
        )

        code = envelope.error_code
        detail = sanitize_detail(envelope.msg)

        if code in SESSION_EXPIRED_ERROR_CODES:
            return OmadaSessionExpiredError(provider_code=code)
        if code in PORTAL_AUTHORIZATION_ERROR_CODES:
            # The controller answered and refused. Without this branch both
            # codes fell through to the generic ``OmadaError`` below, whose
            # ``OMADA_ERROR`` is absent from the backend's code table and so
            # became ``OMADA_CONNECTION_FAILED`` -- "could not reach the
            # network controller" about a controller that had just replied.
            # The raw integer still rides along in ``provider_code``, which is
            # what keeps -41500 distinguishable from -41501.
            return OmadaAuthorizationError(
                f"{OmadaAuthorizationError.default_message} "
                f"Controller said: {detail}"
                if detail
                else None,
                provider_code=code,
            )
        if code == OPENAPI_ERROR_CONTROLLER_ID_NOT_FOUND:
            return OmadaInvalidControllerError(
                "The Omada controller does not recognise that controller ID. "
                "Check the identifier in the controller's own web address.",
                provider_code=code,
            )
        if code == OPENAPI_ERROR_OPERATION_UNSUPPORTED:
            return OmadaUnsupportedApiError(provider_code=code)
        if code in PERMISSION_DENIED_ERROR_CODES:
            # The controller answered and named the problem: this credential
            # may not do that. Without this branch it fell through to the
            # generic ``OmadaError``, which the backend reports as "could not
            # reach the network controller". The message is a constant -- the
            # fix is always the app's role -- so no controller text is needed.
            return OmadaPermissionDeniedError(provider_code=code)

        message = (
            f"{OmadaError.default_message} Controller said: {detail}" if detail else None
        )
        return OmadaError(message, provider_code=code)


__all__ = [
    "BACKOFF_BASE_SECONDS",
    "BACKOFF_MAX_SECONDS",
    "CONTROLLER_INFO_PATH",
    "DEFAULT_PAGE_SIZE",
    "MAX_ATTEMPTS",
    "MAX_PAGES",
    "OmadaHttpClient",
    "controller_info_path",
]
