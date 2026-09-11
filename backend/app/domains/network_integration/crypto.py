"""Symmetric encryption for third-party network controller credentials.

A near-exact mirror of ``app.domains.router.crypto`` -- same library
(``cryptography``'s ``Fernet``: AES-128-CBC + HMAC-SHA256, authenticated),
same shape, same honest admission that this is application-level key
material and not a KMS. Read that module's docstring for the full
write-up of why a decryptable secret (rather than an Argon2 hash) is
unavoidable here: this platform has to open a real, authenticated session
against a customer's Omada controller, which needs the plaintext
``client_secret``/operator password back out again.

## Why a separate key, and not ``router_encryption_key``

It would have been one fewer setting to reuse the existing key, and that
is exactly what makes it worth arguing against:

1. **Different blast radius.** ``router_encryption_key`` opens RouterOS
   API credentials for every router this platform manages -- devices *we*
   provisioned, on *our* WireGuard hub. This key opens credentials for
   *customer-owned third-party infrastructure* the platform does not
   manage and cannot re-provision. Compromising one should not
   automatically compromise the other, and sharing a key guarantees it
   does.
2. **Different rotation cost.** Rotating ``router_encryption_key`` means
   re-encrypting the ``routers`` table -- rows this platform wrote and can
   regenerate credentials for. Rotating this one means re-encrypting rows
   whose plaintext, if lost, can only be recovered by asking every venue
   owner to go back into their controller UI and mint a new API client. A
   shared key forces both migrations to happen at once, at the cost of the
   more painful one.
3. **Different lifecycle.** These integrations are new and optional; the
   router key is load-bearing for the entire fleet. A key that can be
   rotated on a whim without touching the fleet is worth more than one
   saved environment variable.

Same interim status, same eventual fix: a real KMS issuing per-tenant data
keys. Until then, the ciphertext column
(``NetworkIntegration.credentials_encrypted``) at least ensures the secret
is never at rest in the clear, and this key can be rotated independently
of the router fleet's.

## The plaintext is a JSON blob, not a single string

``app.domains.router.crypto`` encrypts one string because a RouterOS
connection needs one secret. A controller integration needs a *set* --
``client_id`` + ``client_secret`` for Open API, ``username`` +
``password`` for legacy, and both are per-integration. Encrypting a JSON
object keeps that a single ciphertext column and a single Fernet
operation, rather than four nullable encrypted columns three of which are
always empty. ``encrypt_credentials``/``decrypt_credentials`` are the only
two functions that know the encoding, so the column's contents are never
constructed or parsed anywhere else.

## Refusing the public default key

``network_integration_encryption_key`` defaults to a value committed to a
public repository. Outside a developer machine, ``encrypt_credentials``
refuses to use it (``NetworkIntegrationEncryptionKeyNotConfiguredError``),
so no new secret is ever written under a key everyone has.

``decrypt_credentials`` does *not* refuse it, and that asymmetry is
deliberate. A row that already exists was already written under the public
key; refusing to read it un-leaks nothing, and it would take a live venue's
guest WiFi down until somebody re-enters credentials -- which, until a real
key is set, they could not do anyway. So a read works and logs CRITICAL,
once per process. Setting a real key is what ends the exposure; after that,
any such row fails to decrypt and surfaces as "re-enter credentials", which
is the correct remedy for a secret that was never protected.
"""

from __future__ import annotations

import json
import logging

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings, get_settings

from .exceptions import NetworkIntegrationEncryptionKeyNotConfiguredError

logger = logging.getLogger(__name__)

# One CRITICAL per process for reads under the public key, not one per
# sync tick per integration -- the startup line already names the env var.
_warned_public_key_decrypt = False

__all__ = [
    "NetworkIntegrationCredentialDecryptionError",
    "decrypt_credentials",
    "encrypt_credentials",
]


class NetworkIntegrationCredentialDecryptionError(Exception):
    """Raised when stored ciphertext cannot be decrypted with the configured
    ``network_integration_encryption_key`` -- e.g. the key was rotated
    without re-encrypting existing rows, or the ciphertext was
    corrupted/tampered with.

    Deliberately not a ``CloudGuestError``: a caller must never be handed
    this as an HTTP response body, because "your stored secret cannot be
    decrypted" is a statement about *this platform's* key management, not
    about the customer's request. ``service.py`` catches it and surfaces
    ``ProviderAuthFailedError`` -- which is also the honest answer, since
    the practical consequence is identical to the controller rejecting the
    credentials: this integration cannot authenticate until somebody
    re-enters them.
    """


def _fernet(settings: Settings | None = None) -> Fernet:
    app_settings = settings or get_settings()
    return Fernet(app_settings.network_integration_encryption_key.encode("utf-8"))


def encrypt_credentials(
    credentials: dict[str, str], *, settings: Settings | None = None
) -> str:
    """Encrypt a controller credential set, returning an opaque,
    urlsafe-base64 ciphertext string safe to store directly in
    ``NetworkIntegration.credentials_encrypted``.

    Keys with a ``None``/empty value are dropped rather than stored as
    ``null``, so a legacy-mode integration's ciphertext contains no
    ``client_secret`` key at all and an Open-API one contains no
    ``password``. That keeps ``has_credentials``-style reasoning honest:
    the presence of a key means a real value.

    Raises ``NetworkIntegrationEncryptionKeyNotConfiguredError`` outside a
    developer machine when the configured key is the public default --
    before anything is encrypted, so every caller refuses before it writes.
    """
    app_settings = settings or get_settings()
    if app_settings.uses_public_network_integration_key():
        logger.critical(
            "network_integration_credentials_refused_public_key",
            extra={
                "env_var": "CLOUDGUEST_NETWORK_INTEGRATION_ENCRYPTION_KEY",
                "environment": app_settings.environment,
            },
        )
        raise NetworkIntegrationEncryptionKeyNotConfiguredError()
    payload = {k: v for k, v in credentials.items() if v}
    token = _fernet(app_settings).encrypt(json.dumps(payload).encode("utf-8"))
    return token.decode("utf-8")


def decrypt_credentials(
    ciphertext: str, *, settings: Settings | None = None
) -> dict[str, str]:
    """Decrypt a ciphertext previously produced by ``encrypt_credentials``.

    Raises ``NetworkIntegrationCredentialDecryptionError`` if the
    ciphertext is invalid, was tampered with, was encrypted under a
    different key, or does not decode to a JSON object of strings.

    The error message never contains the ciphertext or any part of the
    plaintext -- it is written to logs on a failure path, and a "helpful"
    excerpt of either would be the exact leak this module exists to
    prevent.

    Works under the public default key too -- see the module docstring for
    why reads are not refused -- but says so, once per process.
    """
    global _warned_public_key_decrypt
    app_settings = settings or get_settings()
    if (
        app_settings.uses_public_network_integration_key()
        and not _warned_public_key_decrypt
    ):
        _warned_public_key_decrypt = True
        logger.critical(
            "network_integration_credentials_read_under_public_key",
            extra={
                "env_var": "CLOUDGUEST_NETWORK_INTEGRATION_ENCRYPTION_KEY",
                "environment": app_settings.environment,
            },
        )
    try:
        plaintext = _fernet(app_settings).decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise NetworkIntegrationCredentialDecryptionError(
            "Stored network integration credentials could not be decrypted -- "
            "the ciphertext is invalid, corrupted, or was encrypted under a "
            "different network_integration_encryption_key"
        ) from exc
    try:
        decoded = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkIntegrationCredentialDecryptionError(
            "Stored network integration credentials decrypted but are not a "
            "JSON object -- the row predates this encoding or was written by "
            "something other than encrypt_credentials"
        ) from exc
    if not isinstance(decoded, dict):
        raise NetworkIntegrationCredentialDecryptionError(
            "Stored network integration credentials decrypted to a "
            f"{type(decoded).__name__}, not an object"
        )
    return {str(k): str(v) for k, v in decoded.items()}
