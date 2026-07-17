"""Password hashing and strength validation using Argon2id.

Ported from the old ``password_hasher.py``. Configuration is kept as
class-level constants (rather than pulled from ``Settings``) since Argon2
cost parameters are a hashing-format concern, not deployment config -
changing them would invalidate already-stored hashes.
"""

from __future__ import annotations

import re

from argon2 import PasswordHasher as _Argon2Hasher
from argon2.exceptions import HashingError, InvalidHash, VerificationError

_COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "password123",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "princess",
    "qazwsx",
    "123123",
    "654321",
    "superman",
    "iloveyou",
    "trustno1",
}

_SPECIAL_CHARS_RE = re.compile(r"[!@#$%^&*\-_=+]")


class PasswordError(Exception):
    """Base exception for password handling errors."""


class PasswordStrengthError(PasswordError):
    """Password does not meet the minimum strength requirements."""


class PasswordVerificationError(PasswordError):
    """Password verification failed unexpectedly (not a simple mismatch)."""


class PasswordManager:
    """Static facade over Argon2id hashing, verification, and strength checks."""

    MIN_LENGTH = 12
    MAX_LENGTH = 128

    _hasher = _Argon2Hasher(
        time_cost=2,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )

    @staticmethod
    def validate_strength(password: str) -> None:
        """Raise ``PasswordStrengthError`` if ``password`` is too weak."""
        if len(password) < PasswordManager.MIN_LENGTH:
            raise PasswordStrengthError(
                f"Password must be at least {PasswordManager.MIN_LENGTH} characters"
            )
        if len(password) > PasswordManager.MAX_LENGTH:
            raise PasswordStrengthError(
                f"Password must not exceed {PasswordManager.MAX_LENGTH} characters"
            )
        if not re.search(r"[A-Z]", password):
            raise PasswordStrengthError(
                "Password must contain at least one uppercase letter"
            )
        if not re.search(r"[a-z]", password):
            raise PasswordStrengthError(
                "Password must contain at least one lowercase letter"
            )
        if not re.search(r"\d", password):
            raise PasswordStrengthError("Password must contain at least one digit")
        if not _SPECIAL_CHARS_RE.search(password):
            raise PasswordStrengthError(
                "Password must contain at least one special character (!@#$%^&*-_=+)"
            )
        if password.lower() in _COMMON_PASSWORDS:
            raise PasswordStrengthError(
                "Password is too common. Please choose a stronger password"
            )

    @staticmethod
    def hash(password: str) -> str:
        """Validate strength, then hash ``password`` with Argon2id."""
        PasswordManager.validate_strength(password)
        try:
            return PasswordManager._hasher.hash(password)
        except HashingError as exc:
            raise PasswordError(f"Failed to hash password: {exc}") from exc

    @staticmethod
    def verify(password: str, hashed_password: str) -> bool:
        """Return ``True`` if ``password`` matches ``hashed_password``."""
        try:
            PasswordManager._hasher.verify(hashed_password, password)
            return True
        except VerificationError:
            return False
        except InvalidHash as exc:
            raise PasswordVerificationError(
                f"Failed to verify password: {exc}"
            ) from exc

    @staticmethod
    def needs_rehash(hashed_password: str) -> bool:
        """Return ``True`` if ``hashed_password`` should be rehashed."""
        try:
            return PasswordManager._hasher.check_needs_rehash(hashed_password)
        except InvalidHash:
            return True

    @staticmethod
    def strength_score(password: str) -> int:
        """Return a heuristic strength score from 0 (very weak) to 100 (very strong)."""
        score = 0
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        if len(password) >= 20:
            score += 10
        if re.search(r"[a-z]", password):
            score += 15
        if re.search(r"[A-Z]", password):
            score += 15
        if re.search(r"\d", password):
            score += 15
        if _SPECIAL_CHARS_RE.search(password):
            score += 20
        if re.search(r"(.)\1{2,}", password):
            score -= 10
        if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde)", password):
            score -= 10
        return max(0, min(100, score))
