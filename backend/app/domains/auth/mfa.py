"""TOTP (RFC 6238) multi-factor authentication: secret generation/
encryption, code verification, and recovery codes.

Uses ``pyotp`` for the real TOTP algorithm (deterministic given a shared
secret + the current time -- no network call, no fabrication). The secret
itself is encrypted at rest with ``cryptography``'s ``Fernet`` under
``Settings.mfa_encryption_key`` -- the identical interim-design pattern
``app.domains.router.crypto`` already established for RouterOS credentials
(see that module's own docstring for the full "not a real KMS yet" write-
up), but under its **own**, separate key: an MFA secret and a router
credential are unrelated secret classes, so they never share a key.

Recovery codes are hashed with SHA-256, not Argon2id -- the same "high-
entropy, randomly-generated bearer credential, not a human password"
reasoning ``app.domains.router_agent.models.RouterAgentCredential`` and
this codebase's OTP codes already establish, mirrored exactly.
"""

from __future__ import annotations

import hashlib
import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings, get_settings

_ISSUER_NAME = "CloudGuest"
_RECOVERY_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_RECOVERY_CODE_LENGTH = 10


class MfaSecretDecryptionError(Exception):
    """Raised when a stored, encrypted TOTP secret cannot be decrypted with
    the configured ``mfa_encryption_key`` -- e.g. the key was rotated
    without re-encrypting existing rows, or the ciphertext was corrupted/
    tampered with."""


def _fernet(settings: Settings | None = None) -> Fernet:
    app_settings = settings or get_settings()
    return Fernet(app_settings.mfa_encryption_key.encode("utf-8"))


def generate_secret() -> str:
    """A new, random base32 TOTP secret (``pyotp``'s own recommended
    generator -- 160 bits, the RFC 4226/6238-recommended length)."""
    return pyotp.random_base32()


def encrypt_secret(secret: str, *, settings: Settings | None = None) -> str:
    token = _fernet(settings).encrypt(secret.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(ciphertext: str, *, settings: Settings | None = None) -> str:
    try:
        plaintext = _fernet(settings).decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise MfaSecretDecryptionError(
            "Stored MFA secret could not be decrypted -- the ciphertext is "
            "invalid, corrupted, or was encrypted under a different "
            "mfa_encryption_key"
        ) from exc
    return plaintext.decode("utf-8")


def get_provisioning_uri(secret: str, *, account_name: str) -> str:
    """The ``otpauth://`` URI an authenticator app (Google Authenticator,
    1Password, Authy, ...) scans/imports to enroll this secret -- real,
    standard TOTP provisioning, per RFC 6238's own companion "Key URI
    Format" convention ``pyotp`` implements."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=account_name, issuer_name=_ISSUER_NAME
    )


def verify_code(secret: str, code: str) -> bool:
    """Verifies a 6-digit TOTP code against ``secret`` at the current time.
    ``valid_window=1`` tolerates the code from one 30-second step before/
    after now -- real clock drift between server and authenticator app,
    not a security weakening (each window is still a single real,
    time-bound code)."""
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)


def generate_recovery_codes(count: int) -> list[str]:
    """``count`` new single-use recovery codes, e.g. ``"7K4M-2Q8X9C"`` --
    an unambiguous alphabet (no ``0``/``O``/``1``/``I``) since these are
    meant to be transcribed by hand as a last resort when the
    authenticator app itself is unavailable."""
    codes = []
    for _ in range(count):
        raw = "".join(
            secrets.choice(_RECOVERY_CODE_ALPHABET)
            for _ in range(_RECOVERY_CODE_LENGTH)
        )
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_recovery_code(code: str) -> str:
    """SHA-256 hex digest -- see module docstring for why this, not
    Argon2id, is the right hash for a high-entropy, randomly-generated
    recovery code."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


__all__ = [
    "MfaSecretDecryptionError",
    "generate_secret",
    "encrypt_secret",
    "decrypt_secret",
    "get_provisioning_uri",
    "verify_code",
    "generate_recovery_codes",
    "hash_recovery_code",
]
