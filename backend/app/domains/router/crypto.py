"""Symmetric encryption for Router API connection credentials.

**Interim design, documented as such** (see
``docs/router/ROUTER_ARCHITECTURE.md`` §3 for the full write-up): this is
the first genuinely-decryptable secret this codebase stores. Every existing
secret (``app.domains.auth.password.PasswordManager``) is one-way Argon2id
hashing -- correct for a user's login password, which the platform never
needs to recover, but useless here: this platform must be able to open a
live RouterOS API connection to the physical device, which requires the
plaintext username/password (or API key) back out again, not just a
yes/no comparison.

Uses ``cryptography``'s ``Fernet`` (AES-128-CBC + HMAC-SHA256, authenticated
symmetric encryption) with a single application-level key read from
``Settings.router_encryption_key``. This is **not** a real secrets-manager/
KMS integration -- the key lives in application config (an env var in every
real deployment), not a dedicated key-management service with rotation,
access auditing, or envelope encryption. A production hardening pass should
replace this with a real KMS (AWS KMS, HashiCorp Vault, GCP Secret Manager,
etc.) issuing per-tenant or per-router data keys; until then, the ciphertext
column (``Router.api_credentials_encrypted``) at least ensures the secret is
never stored in the clear in the database, and rotating
``router_encryption_key`` is a single-key, single-environment operation
(re-encrypt every row with the new key), not yet automated.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings, get_settings


class RouterCredentialDecryptionError(Exception):
    """Raised when stored ciphertext cannot be decrypted with the
    configured ``router_encryption_key`` -- e.g. the key was rotated without
    re-encrypting existing rows, or the ciphertext was corrupted/tampered
    with."""


def _fernet(settings: Settings | None = None) -> Fernet:
    app_settings = settings or get_settings()
    return Fernet(app_settings.router_encryption_key.encode("utf-8"))


def encrypt_secret(plaintext: str, *, settings: Settings | None = None) -> str:
    """Encrypt ``plaintext`` (a RouterOS API password or API key), returning
    an opaque, urlsafe-base64 ciphertext string safe to store directly in
    ``Router.api_credentials_encrypted``."""
    token = _fernet(settings).encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(ciphertext: str, *, settings: Settings | None = None) -> str:
    """Decrypt a ciphertext string previously produced by ``encrypt_secret``,
    returning the original plaintext. Raises
    ``RouterCredentialDecryptionError`` if the ciphertext is invalid, was
    tampered with, or was encrypted under a different key."""
    try:
        plaintext = _fernet(settings).decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise RouterCredentialDecryptionError(
            "Stored router API credential could not be decrypted -- the "
            "ciphertext is invalid, corrupted, or was encrypted under a "
            "different router_encryption_key"
        ) from exc
    return plaintext.decode("utf-8")


__all__ = [
    "RouterCredentialDecryptionError",
    "encrypt_secret",
    "decrypt_secret",
]
