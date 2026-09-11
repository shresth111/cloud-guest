"""Normalized Omada errors -- one class per code the backend can map to copy.

## The one rule this module exists to enforce

``str(exc)`` is shown to a human. It is rendered into the customer dashboard,
written to ``network_integration_events.message``, and returned in API error
payloads. Therefore it must never contain a password, a client secret, a
session cookie, a CSRF token, an access token, or a raw controller response
body -- the last one because Omada echoes request context into ``msg`` on
some failures, and a response body is exactly the kind of thing that quietly
grows a credential in it two firmware versions from now.

The mechanism is deliberately blunt: **exception messages are composed only
from constants defined in this package plus values the caller already knew.**
No exception below ever formats a controller response into its message. When
a controller-supplied string genuinely helps a human (Omada's ``msg`` field is
often decent, e.g. "Controller ID not exist."), it is passed through
``sanitize_detail`` from ``redaction.py``, which strips anything
secret-shaped, caps the length, and drops it entirely if it looks like a
serialized body rather than a sentence.

``.code`` is the stable, machine-readable half and is what the backend
switches on. The human half may be reworded freely; the code may not change
without a contract revision.
"""

from __future__ import annotations


class OmadaError(Exception):
    """Base for every error this package raises.

    Carries a stable ``.code`` (see the table in contract section 2) and an
    optional ``.provider_code``: the raw Omada ``errorCode`` integer, kept as
    a *number* for diagnostics. It is safe to store and log -- an integer
    cannot smuggle a credential -- and it is the only piece of the raw
    controller response that survives into the exception at all.
    """

    code: str = "OMADA_ERROR"
    #: Default human-readable message. Subclasses override; callers may pass
    #: a more specific one, but only ever built from constants + sanitized
    #: detail, never from a raw response body.
    default_message: str = "The Omada controller request failed."

    def __init__(
        self,
        message: str | None = None,
        *,
        provider_code: int | None = None,
    ) -> None:
        self.provider_code = provider_code
        super().__init__(message or self.default_message)

    def __repr__(self) -> str:
        # repr() shows up in logs and tracebacks too, so it gets the same
        # treatment as str(): code + already-safe message, nothing else. The
        # default dataclass-ish repr would re-expose whatever was passed in.
        return f"{type(self).__name__}(code={self.code!r}, message={str(self)!r})"


class OmadaAuthError(OmadaError):
    code = "OMADA_AUTH_FAILED"
    default_message = (
        "The Omada controller rejected the stored credentials. "
        "Check the operator account or Open API client credentials and try again."
    )


class OmadaConnectionError(OmadaError):
    code = "OMADA_CONNECTION_FAILED"
    default_message = (
        "Could not reach the Omada controller. Check that the controller URL "
        "and port are correct and that the controller is reachable from the server."
    )


class OmadaTlsTrustError(OmadaError):
    """The handshake happened; we refused the certificate at the other end.

    Kept apart from :class:`OmadaConnectionError` because the two send an
    operator to opposite ends of the building. ``OMADA_CONNECTION_FAILED``
    says "check the URL, the port, the firewall"; every one of those is
    already correct here -- the address answered, on the right port, with a
    working TLS stack. The only thing wrong is that nothing this platform
    trusts vouches for the certificate, which is the *normal* state of a
    self-hosted Omada controller and is fixed by pinning it, not by editing
    the URL.

    Reporting this as a connectivity failure is the defect this class was
    added for: no operator was ever going to diagnose a self-signed
    certificate from "check that the controller is reachable from the
    server."
    """

    code = "OMADA_TLS_UNTRUSTED"
    default_message = (
        "The Omada controller answered, but its HTTPS certificate is not "
        "trusted by this platform -- which is normal for a self-hosted "
        "controller, because they ship a self-signed certificate. The URL "
        "and port are fine. Run Test Connection to see the controller's "
        "certificate fingerprint and pin it, or install a certificate from "
        "a public certificate authority on the controller."
    )


class OmadaTlsPinMismatchError(OmadaError):
    """The controller presented a certificate other than the pinned one.

    A separate code from :class:`OmadaTlsTrustError` because it means
    something different and rarer: this integration has already recorded
    which certificate it expects, and the box in front of it is not
    presenting that certificate. That is either a certificate the venue
    legitimately reissued, or somebody is in the middle. The platform cannot
    tell those apart, so it refuses and says both.

    It deliberately does NOT fall back to connecting anyway. A pin that
    yields under pressure is decoration.
    """

    code = "OMADA_TLS_PIN_MISMATCH"
    default_message = (
        "The Omada controller presented a different HTTPS certificate than "
        "the one pinned to this integration. If the controller's certificate "
        "was recently replaced, run Test Connection to review the new "
        "fingerprint and pin it. If it was not, stop: something is "
        "intercepting the connection to the controller."
    )


class OmadaTimeoutError(OmadaError):
    code = "OMADA_TIMEOUT"
    default_message = "The Omada controller did not respond in time."


class OmadaRateLimitedError(OmadaError):
    code = "OMADA_RATE_LIMITED"
    default_message = (
        "The Omada controller is rate limiting requests. Try again in a few moments."
    )


class OmadaInvalidControllerError(OmadaError):
    code = "OMADA_INVALID_CONTROLLER"
    default_message = (
        "The address responded, but it does not look like an Omada controller."
    )


class OmadaSiteNotFoundError(OmadaError):
    code = "OMADA_SITE_NOT_FOUND"
    default_message = "That site no longer exists on the Omada controller."


class OmadaClientNotFoundError(OmadaError):
    code = "OMADA_CLIENT_NOT_FOUND"
    default_message = "That client is not currently connected to this Omada site."


class OmadaAuthorizationError(OmadaError):
    code = "OMADA_AUTHORIZATION_FAILED"
    default_message = (
        "The Omada controller refused to authorize this guest for network access."
    )


class OmadaUnsupportedApiError(OmadaError):
    code = "OMADA_API_UNSUPPORTED"
    default_message = (
        "This Omada controller does not support the requested operation."
    )


class OmadaSessionExpiredError(OmadaError):
    """Internal-ish: the client catches this to trigger exactly one re-login.

    It reaches the caller only when the re-login itself also produced an
    expired session -- i.e. we are looping -- at which point it is a real,
    reportable condition rather than a transient one.
    """

    code = "OMADA_SESSION_EXPIRED"
    default_message = (
        "The Omada controller session expired and could not be re-established."
    )


#: Every error class, for the exhaustiveness test and for the backend's
#: code -> copy mapping. Keep in sync with contract section 2's table.
ALL_ERRORS: tuple[type[OmadaError], ...] = (
    OmadaAuthError,
    OmadaConnectionError,
    OmadaTlsTrustError,
    OmadaTlsPinMismatchError,
    OmadaTimeoutError,
    OmadaRateLimitedError,
    OmadaInvalidControllerError,
    OmadaSiteNotFoundError,
    OmadaClientNotFoundError,
    OmadaAuthorizationError,
    OmadaUnsupportedApiError,
    OmadaSessionExpiredError,
)


__all__ = [
    "ALL_ERRORS",
    "OmadaAuthError",
    "OmadaAuthorizationError",
    "OmadaClientNotFoundError",
    "OmadaConnectionError",
    "OmadaError",
    "OmadaInvalidControllerError",
    "OmadaRateLimitedError",
    "OmadaSessionExpiredError",
    "OmadaSiteNotFoundError",
    "OmadaTimeoutError",
    "OmadaTlsPinMismatchError",
    "OmadaTlsTrustError",
    "OmadaUnsupportedApiError",
]
