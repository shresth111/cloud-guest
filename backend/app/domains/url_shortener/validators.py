"""Pure, side-effect-free validation helpers for the URL Shortener domain.

``validate_target_url``: syntactic only, no network calls, by design.

This endpoint never fetches ``target_url`` server-side -- it only stores and
redirects (see ``models.ShortLink``'s own docstring). Because there is no
outbound request to defend, this validator's job is narrower than a full
SSRF defense: reject a scheme that would make the visitor's own browser do
something dangerous when redirected (``javascript:``, ``data:``, ``file:``,
or no scheme at all), and reject a hostname that is obviously pointed at an
internal network as a basic guard against a link that -- if some future
caller ever did resolve it server-side, or if a misconfigured internal tool
follows it -- would reach a private/loopback/link-local address. Both
checks are purely string/``ipaddress`` parsing against the literal
``target_url`` the caller supplied; nothing here ever performs a DNS lookup
or opens a network connection, so a caller who supplies a public hostname
that itself resolves to a private address at request time is not, and
cannot be, caught here (that would require the network call this module's
whole design deliberately avoids). This is a basic, documented guard, not a
claim of complete SSRF immunity.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from .exceptions import BlockedTargetHostError, InvalidTargetUrlSchemeError

# Only http/https may ever be redirected to -- every other scheme either
# executes in the visitor's browser context (javascript:), risks exposing
# local files (file:), or embeds arbitrary content directly (data:), none
# of which "redirect the visitor's browser to a URL" was ever meant to do.
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Exact hostnames (case-insensitive) treated as obviously-internal targets,
# beyond what a literal IP's own is_private/is_loopback/is_link_local/
# is_reserved/is_multicast check already covers below.
_BLOCKED_EXACT_HOSTNAMES = frozenset({"localhost", "0.0.0.0"})  # noqa: S104
# Hostname suffixes treated the same way -- ".localhost" is IANA-reserved
# (RFC 6761) to always resolve loopback; ".internal"/".local" are common
# organizational/mDNS conventions for private-network-only names.
_BLOCKED_HOSTNAME_SUFFIXES = (".localhost", ".internal", ".local")


def _is_blocked_ip_literal(hostname: str) -> bool:
    """``True`` if ``hostname`` parses as a literal IPv4/IPv6 address
    falling in a private/loopback/link-local/reserved/multicast/unspecified
    range -- stdlib ``ipaddress``, no DNS resolution (a hostname that is
    *not* a literal IP address returns ``False`` here and falls through to
    the exact-name/suffix checks above instead)."""
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def validate_target_url(raw_url: str) -> str:
    """Validates ``raw_url`` is a plausible http(s) redirect target and
    returns it unchanged (never mutates/normalizes the caller's own URL --
    a short link redirects to *exactly* what was submitted).

    Raises :class:`~.exceptions.InvalidTargetUrlSchemeError` for a missing/
    disallowed scheme, :class:`~.exceptions.BlockedTargetHostError` for an
    obviously-internal hostname/IP literal. See module docstring for the
    full "syntactic only, no network calls" scope note."""
    parsed = urlsplit(raw_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidTargetUrlSchemeError(scheme or "(none)")

    hostname = parsed.hostname
    if not hostname:
        raise BlockedTargetHostError("(empty)")
    hostname = hostname.lower()

    if hostname in _BLOCKED_EXACT_HOSTNAMES:
        raise BlockedTargetHostError(hostname)
    if any(hostname.endswith(suffix) for suffix in _BLOCKED_HOSTNAME_SUFFIXES):
        raise BlockedTargetHostError(hostname)
    if _is_blocked_ip_literal(hostname):
        raise BlockedTargetHostError(hostname)

    return raw_url.strip()


__all__ = ["ALLOWED_SCHEMES", "validate_target_url"]
