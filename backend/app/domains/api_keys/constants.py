"""Shared constants for the API Keys domain."""

from __future__ import annotations

# Prepended to every generated key so a leaked credential is instantly
# recognizable in logs/scanners as a CloudGuest API key (the same real-
# world convention Stripe/GitHub/etc. use for their own token prefixes).
API_KEY_PREFIX = "cgst_"

# secrets.token_urlsafe(N) byte count for the random portion of the key --
# 32 bytes (256 bits) is comfortably high-entropy for a bearer credential
# with no brute-force-relevant keyspace concern, the same bar
# app.domains.router_agent.service.hash_credential's own high-entropy
# bearer token already sets.
API_KEY_SECRET_BYTES = 32

# How many leading characters of the full plaintext key are persisted as
# `ApiKey.display_prefix` for UI display ("cgst_AbCdEfGh...") after
# creation -- short enough that it never meaningfully narrows the
# brute-force search space, long enough to help an operator recognize
# which key is which without ever storing/returning the full secret again.
API_KEY_DISPLAY_PREFIX_LENGTH = 12

__all__ = [
    "API_KEY_PREFIX",
    "API_KEY_SECRET_BYTES",
    "API_KEY_DISPLAY_PREFIX_LENGTH",
]
