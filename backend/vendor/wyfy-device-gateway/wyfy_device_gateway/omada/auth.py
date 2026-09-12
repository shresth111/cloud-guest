"""Obtaining a session, and caching it -- the two auth modes, side by side.

## The endpoint transposition, resolved (contract section 1a's blocking question)

**Verdict: operator login is ``POST /{omadacId}/api/v2/hotspot/login``;
client authorization is ``POST /{omadacId}/api/v2/hotspot/extPortal/auth``.**

This needed settling because TP-Link's own current documentation contradicts
itself. In *API and Code Sample for External Portal Server (Omada Controller
v5.0.15 to v6.2.0)*,
<https://support.omadanetworks.com/us/document/13080/>, the prose says:

    "First, it must log in Controller by sending an HTTP POST request. The
    request's URL should be https://CONTROLLER:PORT/CONTROLLER_ID/api/v2/hotspot/login"

    "After successful login, Portal can send the client authentication result
    to https://CONTROLLER:PORT/CONTROLLER_ID/api/v2/hotspot/extPortal/auth"

but the PHP sample code on that same page has the two URLs **swapped** --
its ``login()`` posts to ``extPortal/auth`` and its ``authorize()`` posts to
``hotspot/login``. That is a genuine defect in TP-Link's sample, and it is
almost certainly what produced the transposed extraction the contract flagged.

Three independent checks resolve it in favour of the prose:

1. **The older doc agrees, in both prose *and* code.** *API and Code Sample
   for External Portal Server (Omada Controller 4.1.5 to 4.4.6)*,
   <https://support.omadanetworks.com/us/document/13023/>, states "The calling
   interface is POST /api/v2/hotspot/login" for the operator login and sends
   the client result to ``/api/v2/hotspot/extPortal/auth?token=CSRFToken`` --
   and its PHP sample uses those same two URLs the same way round. The v5 doc
   introduced the ``CONTROLLER_ID`` path segment, and the swap appears to have
   been introduced in that same edit.
2. **The newest doc still says the same thing.** *API and Code Samples for
   External Portal Server (Omada Controller v6.2.10 or Above)*,
   <https://support.omadanetworks.com/en/document/132060/>, repeats the prose
   verbatim ("Steps 10 and 11. Portal logs in to the Controller ...
   /CONTROLLER_ID/api/v2/hotspot/login", "Steps 12 and 13. Authorize the
   client ... /CONTROLLER_ID/api/v2/hotspot/extPortal/auth") -- while
   inheriting the identical swapped PHP sample, which is what a copy-pasted
   defect looks like.
3. **The payloads only fit one way round.** The login response carries
   ``result.token``, the CSRF token that the *authorize* call must then send
   in its ``Csrf-Token`` header. Ordering forces login first, and only the
   login body (``{"name", "password"}``) matches an operator credential.

Note the older API also accepted the CSRF token as a ``?token=`` query
parameter; v5+ moved it to the ``Csrf-Token`` header. This package targets
v5.0.15+ and sends the header only.

## Legacy mode is a *hotspot operator* login, not a controller admin login

The credentials here are the operator account created under the controller's
Hotspot Manager -- explicitly "rather than the account and password for the
controller account" (doc 13080). That distinction sets a hard capability
ceiling that shapes this whole package: an operator can authorize portal
clients and nothing else. It cannot enumerate sites, devices, SSIDs or
clients, because those live behind the controller's own admin API, which this
credential does not open. ``adapter.py`` therefore refuses inventory calls in
legacy mode rather than sending a request we know will fail. See
``omada/__init__.py`` for the full capability matrix.

## Open API mode

Token: ``POST /openapi/authorize/token?grant_type=client_credentials`` with a
JSON body of ``{"omadacId", "client_id", "client_secret"}``; refresh with the
same URL but ``grant_type=refresh_token`` and a body of
``{"client_id", "client_secret", "refresh_token"}``. The reply is the standard
envelope with ``result.accessToken`` / ``result.refreshToken`` /
``result.expiresIn``. Subsequent calls carry ``Authorization:
AccessToken=<token>``.

The header spelling is the one part of this that has a **primary** source:
TP-Link's *How to Create Site in Omada Controller via Open API*,
<https://support.omadanetworks.com/uk/document/109315/>, states outright
"The prefix in the Authorization header must be AccessToken=". This is worth
being precise about because ``Bearer`` is the natural guess for an OAuth-style
client-credentials flow, it is what at least one user tried on TP-Link's own
forum, and it does not work.

Sourcing, revised 2026-09-12. This used to be tagged wholly CORROBORATED. It
now splits three ways:

* **VERIFIED -- the token path, and ``grant_type`` being a *query* parameter.**
  TP-Link runs the Open API northbound gateway for its own cloud controllers
  at ``use1-omada-northbound.tplinkcloud.com``, and it answers this call
  unauthenticated with structured Omada error envelopes. Probed directly:

      POST /openapi/authorize/token?grant_type=client_credentials
      {"omadacId":"x","client_id":"x","client_secret":"x"}
        -> {"errorCode":-7131,"msg":"Controller ID not exist."}

  i.e. the body was parsed and ``omadacId`` was reached and rejected on its
  value. Drop the query parameter, move it into the body, or give it a
  nonsense value, and the same request instead fails before the body is
  looked at, with ``{"errorCode":-44116,"msg":"Open API Authorized failed,
  please check whether the input parameters are legal."}``. So ``grant_type``
  belongs in the query string, not the body -- and ``?grant_type=refresh_token``
  is likewise a recognised grant (it reaches ``-1001 "Invalid request
  parameters."`` on a bogus token, rather than -44116), while passing the
  refresh fields as query parameters instead of a JSON body gives
  ``-1004 "Invalid request type."``.

* **VERIFIED -- the ``AccessToken=`` header prefix.** TP-Link's *How to
  Create Site in Omada Controller via Open API*,
  <https://support.omadanetworks.com/uk/document/109315/>: "The prefix in the
  Authorization header must be AccessToken=".

* **CORROBORATED, still not primary -- the response envelope's field names**
  (``result.accessToken`` / ``result.refreshToken`` / ``result.expiresIn``)
  and the exact body key spellings ``client_id`` / ``client_secret``. The
  probe above cannot separate these from their camelCase alternatives,
  because ``omadacId`` is validated first and short-circuits the rest. They
  come from the open-source client at
  <https://github.com/bullitt186/ha-omada-open-api> (``custom_components/
  omada_open_api/auth.py``, ``const.py``) and from TP-Link forum threads.
  Note that the token endpoint is genuinely absent from TP-Link's published
  OpenAPI 3.0.1 document (1,918 paths, none under ``/openapi/authorize``);
  the authoritative text is the "Online API Document" a running controller
  serves at ``/doc.html``, which is not publicly reachable. Settle it on the
  first controller: ``OMADA_HARDWARE_VERIFICATION.md`` test 2.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..controller_contract import ControllerAuthMode, ControllerCredentials
from .errors import OmadaAuthError, OmadaUnsupportedApiError
from .redaction import credential_fingerprint, sanitize_detail
from .types import OmadaEnvelope, coerce_int, coerce_str

# --- endpoint paths (see this module's docstring for the sourcing) --------

#: VERIFIED (TP-Link docs 13080 / 132060, prose). Operator login.
LEGACY_LOGIN_PATH = "/{omadac_id}/api/v2/hotspot/login"
#: VERIFIED (TP-Link docs 13080 / 132060, prose; and 13023 in both prose and
#: sample code). Client authorization.
LEGACY_AUTHORIZE_PATH = "/{omadac_id}/api/v2/hotspot/extPortal/auth"
#: VERIFIED: probed against TP-Link's own Open API northbound gateway, which
#: parses the body and validates ``omadacId`` on this exact path with
#: ``?grant_type=client_credentials``. The response *envelope* field names
#: remain CORROBORATED only -- see this module's docstring.
OPENAPI_TOKEN_PATH = "/openapi/authorize/token"

#: VERIFIED (TP-Link docs 13080 / 132060): the CSRF header name, whose value
#: is the login response's ``result.token``.
CSRF_HEADER = "Csrf-Token"

#: VERIFIED (TP-Link docs 13080 / 132060): "For Controller versions earlier
#: than v5.11, the cookie name is TPEAP_SESSIONID. For v5.11 and later, the
#: cookie name is TPOMADA_SESSIONID." We do not branch on version -- we keep
#: whichever the controller actually set, which is strictly more robust than
#: predicting it from a version string we may not even have.
LEGACY_COOKIE_NAMES: tuple[str, ...] = ("TPOMADA_SESSIONID", "TPEAP_SESSIONID")

# INFERRED, unverified: TP-Link documents no lifetime for the hotspot
# operator session. The controller's web session idle timeout is commonly
# ~30 minutes, so 10 minutes is a deliberately conservative cache TTL -- long
# enough that a burst of portal authorizations reuses one login, short enough
# that we re-login well before any plausible server-side expiry. Being wrong
# in the "too short" direction costs one extra login; the session-expiry
# retry path covers the other direction.
LEGACY_SESSION_TTL_SECONDS = 600.0

#: Refresh this many seconds before an Open API token's stated expiry, so a
#: request in flight cannot straddle the boundary.
TOKEN_EXPIRY_BUFFER_SECONDS = 60.0

# INFERRED, unverified: used only when the token response omits ``expiresIn``.
# Observed Omada access tokens last 2 hours; 30 minutes is a safe under-guess.
DEFAULT_TOKEN_TTL_SECONDS = 1800.0


@dataclass(frozen=True, slots=True)
class RawResult:
    """One completed HTTP exchange, already envelope-parsed.

    ``cookies`` is carried separately because the legacy flow's session lives
    in a ``Set-Cookie`` header rather than in the JSON body, and this package
    builds a fresh HTTP client per call rather than relying on a long-lived
    cookie jar (see ``client.py`` on why).
    """

    envelope: OmadaEnvelope
    cookies: dict[str, str] = field(default_factory=dict)


class EnvelopeSender(Protocol):
    """The low-level send primitive ``client.py`` hands to this module.

    Auth needs to make HTTP calls, and the HTTP layer needs auth -- so rather
    than have the two import each other, ``client.py`` passes in a bound
    sender. This module never imports ``httpx`` at all, which also makes the
    login flows trivially testable with a plain function.
    """

    async def __call__(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> RawResult: ...


@dataclass(frozen=True, slots=True)
class SessionState:
    """Everything needed to authenticate a subsequent request.

    Deliberately holds only *derived* material -- a CSRF token, a session
    cookie, an access token -- never the originating password or client
    secret. Anything that reaches the cache is therefore already one step
    removed from the customer's stored credential.
    """

    headers: dict[str, str]
    cookies: dict[str, str]
    expires_at: float  # monotonic clock deadline
    omadac_id: str
    refresh_token: str | None = None

    def is_fresh(self, *, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) < self.expires_at


SessionKey = tuple[str, str, str, str]


def session_key(creds: ControllerCredentials, omadac_id: str) -> SessionKey:
    """Cache key: ``(base_url, omadac_id, auth_mode, credential fingerprint)``.

    The fingerprint is a one-way hash (``redaction.credential_fingerprint``),
    never the secret. Including it is what makes credential rotation correct:
    change the password and the key changes, so the session cached under the
    old password is not handed to the new one. Without it, a rotation would
    keep silently working off a stale session until it expired, and the
    "test connection" button would report success for credentials that were
    never actually tried.
    """
    return (
        creds.base_url.rstrip("/"),
        omadac_id,
        str(creds.auth_mode),
        credential_fingerprint(
            creds.auth_mode,
            creds.username,
            creds.password,
            creds.client_id,
            creds.client_secret,
        ),
    )


class SessionCache:
    """A tiny TTL cache of ``SessionState`` keyed by ``session_key``.

    Not thread-safe and intentionally not locked. Callers are asyncio tasks
    in one event loop, and the worst case under concurrency is two coroutines
    both logging in and one overwriting the other -- two logins instead of
    one, with a correct result either way. A lock here would add a failure
    mode (a login that hangs also blocks every other caller for that
    controller) in exchange for saving a redundant request, which is a bad
    trade for an operation that already tolerates retries.
    """

    def __init__(self) -> None:
        self._entries: dict[SessionKey, SessionState] = {}

    def get(self, key: SessionKey) -> SessionState | None:
        state = self._entries.get(key)
        if state is None:
            return None
        if not state.is_fresh():
            # Expired by our own clock: drop it rather than hand back
            # something we already know the controller will reject.
            self._entries.pop(key, None)
            return None
        return state

    def set(self, key: SessionKey, state: SessionState) -> None:
        self._entries[key] = state

    def invalidate(self, key: SessionKey) -> None:
        self._entries.pop(key, None)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


def _auth_error_from(envelope: OmadaEnvelope) -> OmadaAuthError:
    """Build an auth error, folding in the controller's ``msg`` only if it
    survives ``sanitize_detail`` (short, prose-shaped, nothing secret in it).

    Omada's auth messages are genuinely helpful -- "Controller ID not exist."
    tells an operator exactly what to fix -- so it is worth passing through,
    but only through the fail-closed filter.
    """
    detail = sanitize_detail(envelope.msg)
    message = (
        f"{OmadaAuthError.default_message} Controller said: {detail}"
        if detail
        else None
    )
    return OmadaAuthError(message, provider_code=envelope.error_code)


async def legacy_login(
    send: EnvelopeSender,
    creds: ControllerCredentials,
    omadac_id: str,
    *,
    now: float | None = None,
) -> SessionState:
    """Log in as a hotspot operator and capture the CSRF token + cookie.

    VERIFIED against TP-Link docs 13080 / 132060: ``POST
    /{omadacId}/api/v2/hotspot/login`` with ``{"name", "password"}``, replying
    ``{"errorCode": 0, "msg": "Hotspot log in successfully.",
    "result": {"token": "..."}}``.
    """
    if not creds.username or not creds.password:
        raise OmadaAuthError(
            "This Omada integration is set to operator login but no operator "
            "username and password are stored for it."
        )

    result = await send(
        "POST",
        LEGACY_LOGIN_PATH.format(omadac_id=omadac_id),
        json={"name": creds.username, "password": creds.password},
    )
    envelope = result.envelope
    if not envelope.ok:
        raise _auth_error_from(envelope)

    token = None
    if isinstance(envelope.result, dict):
        token = coerce_str(envelope.result.get("token"))
    if not token:
        # errorCode 0 but no CSRF token: the authorize call cannot be made
        # without it, so treat it as an auth failure now with a clear
        # message rather than as a confusing 403 one request later.
        raise OmadaAuthError(
            "The Omada controller accepted the operator login but did not "
            "return a session token."
        )

    cookies = {
        name: value
        for name, value in result.cookies.items()
        if name in LEGACY_COOKIE_NAMES
    }
    # Keep any other cookie the controller set too -- a future firmware may
    # rename the session cookie again (it already did once, at v5.11), and
    # echoing back everything it gave us is strictly safer than filtering to
    # a hardcoded allowlist and silently dropping the one that mattered.
    cookies.update(result.cookies)

    return SessionState(
        headers={CSRF_HEADER: token},
        cookies=cookies,
        expires_at=(now if now is not None else time.monotonic())
        + LEGACY_SESSION_TTL_SECONDS,
        omadac_id=omadac_id,
    )


def _session_from_token_result(
    envelope: OmadaEnvelope, omadac_id: str, *, now: float | None = None
) -> SessionState:
    """Turn a token response's ``result`` into a ``SessionState``."""
    result = envelope.result if isinstance(envelope.result, dict) else {}
    access_token = coerce_str(result.get("accessToken"))
    if not access_token:
        raise OmadaAuthError(
            "The Omada controller accepted the Open API credentials but did "
            "not return an access token."
        )
    expires_in = coerce_int(result.get("expiresIn"))
    ttl = float(expires_in) if expires_in and expires_in > 0 else DEFAULT_TOKEN_TTL_SECONDS
    # Never let the buffer drive the deadline negative on a very short token.
    ttl = max(ttl - TOKEN_EXPIRY_BUFFER_SECONDS, 1.0)
    return SessionState(
        # VERIFIED (TP-Link doc 109315): "The prefix in the Authorization
        # header must be AccessToken=". Not "Bearer".
        headers={"Authorization": f"AccessToken={access_token}"},
        cookies={},
        expires_at=(now if now is not None else time.monotonic()) + ttl,
        omadac_id=omadac_id,
        refresh_token=coerce_str(result.get("refreshToken")),
    )


async def openapi_login(
    send: EnvelopeSender,
    creds: ControllerCredentials,
    omadac_id: str,
    *,
    now: float | None = None,
) -> SessionState:
    """Get a fresh access token via the client-credentials grant.

    CORROBORATED, not primary: URL, query parameter and body field names come
    from the community client and forum threads (see module docstring).
    """
    if not creds.client_id or not creds.client_secret:
        raise OmadaAuthError(
            "This Omada integration is set to Open API but no client ID and "
            "client secret are stored for it."
        )

    result = await send(
        "POST",
        OPENAPI_TOKEN_PATH,
        params={"grant_type": "client_credentials"},
        json={
            "omadacId": omadac_id,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
        },
    )
    if not result.envelope.ok:
        raise _auth_error_from(result.envelope)
    return _session_from_token_result(result.envelope, omadac_id, now=now)


async def openapi_refresh(
    send: EnvelopeSender,
    creds: ControllerCredentials,
    omadac_id: str,
    refresh_token: str,
    *,
    now: float | None = None,
) -> SessionState:
    """Exchange a refresh token for a new access token.

    Falls back to a full client-credentials login on *any* failure. We hold
    the client id and secret permanently, so a refresh is purely an
    optimisation -- there is no state we could lose by starting over, and
    treating a refresh failure as fatal would turn a routine token rollover
    into a customer-visible outage.
    """
    try:
        result = await send(
            "POST",
            OPENAPI_TOKEN_PATH,
            params={"grant_type": "refresh_token"},
            json={
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "refresh_token": refresh_token,
            },
        )
        if result.envelope.ok:
            return _session_from_token_result(result.envelope, omadac_id, now=now)
    except OmadaAuthError:
        pass
    return await openapi_login(send, creds, omadac_id, now=now)


async def establish_session(
    send: EnvelopeSender,
    creds: ControllerCredentials,
    omadac_id: str,
    *,
    previous: SessionState | None = None,
    now: float | None = None,
) -> SessionState:
    """Obtain a session for whichever ``auth_mode`` this integration uses.

    ``previous`` lets Open API take the cheap path: if we still hold a
    refresh token from an expired session, spend that instead of a full
    client-credentials round trip.
    """
    if creds.auth_mode == ControllerAuthMode.LEGACY:
        return await legacy_login(send, creds, omadac_id, now=now)
    if creds.auth_mode == ControllerAuthMode.OPENAPI:
        if previous is not None and previous.refresh_token:
            return await openapi_refresh(
                send, creds, omadac_id, previous.refresh_token, now=now
            )
        return await openapi_login(send, creds, omadac_id, now=now)
    raise OmadaUnsupportedApiError(
        f"Unknown Omada authentication mode: {creds.auth_mode!s}"
    )


__all__ = [
    "CSRF_HEADER",
    "DEFAULT_TOKEN_TTL_SECONDS",
    "LEGACY_AUTHORIZE_PATH",
    "LEGACY_COOKIE_NAMES",
    "LEGACY_LOGIN_PATH",
    "LEGACY_SESSION_TTL_SECONDS",
    "OPENAPI_TOKEN_PATH",
    "TOKEN_EXPIRY_BUFFER_SECONDS",
    "EnvelopeSender",
    "RawResult",
    "SessionCache",
    "SessionKey",
    "SessionState",
    "establish_session",
    "legacy_login",
    "openapi_login",
    "openapi_refresh",
    "session_key",
]
