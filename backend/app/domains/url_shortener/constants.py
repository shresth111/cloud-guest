"""Enumerations and small constants for the URL Shortener domain.

Stored as plain ``String`` columns on the ORM model (``ShortLink.source``),
never a native PostgreSQL enum type -- the same reason every other domain in
this codebase documents (``app.domains.otp.constants``,
``app.domains.voucher.constants``): adding a new source value never
requires an ``ALTER TYPE`` migration, only a new additive ``StrEnum``
member.
"""

from __future__ import annotations

from enum import StrEnum


class ShortLinkSource(StrEnum):
    """Which surface created a given :class:`~.models.ShortLink`.

    * ``PUBLIC_SITE`` -- the anonymous, unauthenticated marketing-site tool
      (``POST /api/v1/public/short-links``). No ``organization_id``/
      ``created_by_user_id`` -- see ``models.ShortLink``'s own docstring.
    * ``CUSTOMER`` -- the authenticated customer dashboard, org-scoped
      (``POST /api/v1/short-links``).
    * ``MASTER`` -- created directly by a platform operator from the Master
      console. Distinct from a customer-created link a master operator later
      *moderates* (``PATCH /api/v1/master/short-links/{id}``, which never
      changes ``source``) -- this value is only ever set at creation time by
      a real Master-console create flow, should one exist in a later pass.
    """

    PUBLIC_SITE = "public_site"
    CUSTOMER = "customer"
    MASTER = "master"


# ============================================================================
# Code generation (~7-char base62, collision-checked -- see
# service.ShortLinkService._generate_code)
# ============================================================================

# Base62: 0-9, A-Z, a-z -- the conventional URL-shortener alphabet (every
# character is URL-safe with no percent-encoding, unlike voucher's own
# print-friendly-but-narrower VOUCHER_CODE_ALPHABET, which deliberately
# excludes ambiguous characters for a human reading a printed card; a short
# link's code is only ever copy-pasted/clicked, never dictated aloud, so
# that narrowing has no reason to apply here).
SHORT_LINK_CODE_ALPHABET = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
SHORT_LINK_CODE_LENGTH = 7

# Bound on how many (generate, then DB-existence-check) rounds
# ShortLinkService._generate_code will attempt before giving up and raising
# ShortLinkCodeGenerationExhaustedError -- mirrors
# app.domains.voucher.constants.CODE_GENERATION_MAX_ROUNDS's identical
# defensive-backstop role. 62^7 (~3.5 trillion) codes means a collision on
# any single attempt is already vanishingly unlikely; this bound exists only
# to fail loudly instead of looping forever in the pathological case.
CODE_GENERATION_MAX_ROUNDS = 10

# ============================================================================
# Guest-facing (public-create + redirect) rate limiting -- Redis, mirrors
# app.domains.voucher.service.VoucherRedemptionRateLimiter's/
# app.domains.otp.service.OtpRateLimiter's identical INCR+EXPIRE+TTL shape.
# ============================================================================

# Scoped by ``source`` (the presumed caller IP address, supplied by
# router.py from the request) -- same "protect against one source hammering
# this endpoint" reasoning as VOUCHER_REDEMPTION_RATE_LIMIT_KEY_TEMPLATE.
# Public *creation* and the *redirect* endpoint are rate-limited under
# separate keys/budgets (creation is the higher-value action worth spamming;
# redirect is a read, but still worth bounding against link-existence
# probing) -- see service.py's module docstring.
SHORT_LINK_CREATE_RATE_LIMIT_KEY_TEMPLATE = "url_shortener:create_attempts:{source}"
SHORT_LINK_REDIRECT_RATE_LIMIT_KEY_TEMPLATE = "url_shortener:redirect_attempts:{source}"

DEFAULT_CREATE_MAX_ATTEMPTS_PER_WINDOW = 20
DEFAULT_CREATE_WINDOW_MINUTES = 1

# More generous than creation -- a redirect is a plain read with no write
# amplification, and legitimate traffic to a popular short link can burst
# well above a creation-sized budget (mirrors
# app.domains.voucher.constants.DEFAULT_REDEMPTION_MAX_ATTEMPTS_PER_WINDOW's
# identical "generous enough for real front-line traffic" reasoning).
DEFAULT_REDIRECT_MAX_ATTEMPTS_PER_WINDOW = 60
DEFAULT_REDIRECT_WINDOW_MINUTES = 1

__all__ = [
    "ShortLinkSource",
    "SHORT_LINK_CODE_ALPHABET",
    "SHORT_LINK_CODE_LENGTH",
    "CODE_GENERATION_MAX_ROUNDS",
    "SHORT_LINK_CREATE_RATE_LIMIT_KEY_TEMPLATE",
    "SHORT_LINK_REDIRECT_RATE_LIMIT_KEY_TEMPLATE",
    "DEFAULT_CREATE_MAX_ATTEMPTS_PER_WINDOW",
    "DEFAULT_CREATE_WINDOW_MINUTES",
    "DEFAULT_REDIRECT_MAX_ATTEMPTS_PER_WINDOW",
    "DEFAULT_REDIRECT_WINDOW_MINUTES",
]
