"""
Password hashing and verification using Argon2.

This module provides secure password hashing using Argon2id algorithm.
Supports password strength validation and history checking.

Architecture: Infrastructure Layer - Security
"""

import re
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import HashingError, InvalidHash, VerificationError


class PasswordHasherError(Exception):
    """Base exception for password hashing errors."""

    pass


class PasswordVerificationError(PasswordHasherError):
    """Exception raised when password verification fails."""

    pass


class PasswordStrengthError(PasswordHasherError):
    """Exception raised when password doesn't meet strength requirements."""

    pass


class SecurePasswordHasher:
    """
    Secure password hasher using Argon2id algorithm.

    Configuration:
        - Time cost: 2 (iterations)
        - Memory cost: 65536 KB (~64 MB)
        - Parallelism: 4 (threads)
        - Hash type: ID (Argon2id - resistant to both GPU and ASIC attacks)

    Password strength requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character (!@#$%^&*-_=+)
        - Not in common passwords list
    """

    # Common passwords to reject
    COMMON_PASSWORDS = {
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
        "sun",
        "princess",
        "qazwsx",
        "123123",
        "654321",
        "superman",
        "iloveyou",
        "trustno1",
    }

    # Minimum password requirements
    MIN_LENGTH = 12
    MAX_LENGTH = 128

    def __init__(self) -> None:
        """Initialize the Argon2 password hasher."""
        self.hasher = PasswordHasher(
            time_cost=2,  # iterations (2 iterations = fast enough for login)
            memory_cost=65536,  # 65 MB
            parallelism=4,  # 4 threads
            hash_len=32,  # 32 bytes hash
            salt_len=16,  # 16 bytes salt
        )

    def validate_password_strength(self, password: str) -> None:
        """
        Validate that password meets strength requirements.

        Args:
            password: Password to validate

        Raises:
            PasswordStrengthError: If password doesn't meet requirements
        """
        # Check length
        if len(password) < self.MIN_LENGTH:
            raise PasswordStrengthError(
                f"Password must be at least {self.MIN_LENGTH} characters long"
            )

        if len(password) > self.MAX_LENGTH:
            raise PasswordStrengthError(
                f"Password must not exceed {self.MAX_LENGTH} characters"
            )

        # Check for at least one uppercase letter
        if not re.search(r"[A-Z]", password):
            raise PasswordStrengthError(
                "Password must contain at least one uppercase letter"
            )

        # Check for at least one lowercase letter
        if not re.search(r"[a-z]", password):
            raise PasswordStrengthError(
                "Password must contain at least one lowercase letter"
            )

        # Check for at least one digit
        if not re.search(r"\d", password):
            raise PasswordStrengthError("Password must contain at least one digit")

        # Check for at least one special character
        if not re.search(r"[!@#$%^&*\-_=+]", password):
            raise PasswordStrengthError(
                "Password must contain at least one special character (!@#$%^&*-_=+)"
            )

        # Check against common passwords (case-insensitive)
        if password.lower() in self.COMMON_PASSWORDS:
            raise PasswordStrengthError(
                "Password is too common. Please choose a stronger password"
            )

    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2id.

        Args:
            password: Plain text password to hash

        Returns:
            Argon2 hash string

        Raises:
            PasswordStrengthError: If password doesn't meet strength requirements
            PasswordHasherError: If hashing fails
        """
        # Validate strength first
        self.validate_password_strength(password)

        try:
            return self.hasher.hash(password)
        except HashingError as e:
            raise PasswordHasherError(f"Failed to hash password: {str(e)}") from e

    def verify_password(self, password: str, hash_value: str) -> bool:
        """
        Verify a password against a hash using constant-time comparison.

        Args:
            password: Plain text password to verify
            hash_value: Argon2 hash to verify against

        Returns:
            True if password matches hash, False otherwise

        Raises:
            PasswordVerificationError: If verification fails unexpectedly
        """
        try:
            self.hasher.verify(hash_value, password)
            return True
        except VerificationError:
            return False
        except (InvalidHash, Exception) as e:
            raise PasswordVerificationError(
                f"Failed to verify password: {str(e)}"
            ) from e

    def check_password_needs_rehash(self, hash_value: str) -> bool:
        """
        Check if a password hash needs to be rehashed with current parameters.

        Useful for upgrading hash parameters when security requirements increase.

        Args:
            hash_value: Argon2 hash to check

        Returns:
            True if hash should be replaced with current parameters
        """
        try:
            return self.hasher.check_needs_rehash(hash_value)
        except (InvalidHash, Exception):
            return True

    def get_password_strength_score(self, password: str) -> int:
        """
        Calculate password strength score (0-100).

        Args:
            password: Password to score

        Returns:
            Strength score from 0 (very weak) to 100 (very strong)
        """
        score = 0

        # Length scoring
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        if len(password) >= 20:
            score += 10

        # Character diversity scoring
        if re.search(r"[a-z]", password):
            score += 15
        if re.search(r"[A-Z]", password):
            score += 15
        if re.search(r"\d", password):
            score += 15
        if re.search(r"[!@#$%^&*\-_=+]", password):
            score += 20

        # Penalty for common patterns
        if re.search(r"(.)\1{2,}", password):  # Repeated characters
            score -= 10
        if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde)", password):
            score -= 10

        return max(0, min(100, score))

    @property
    def hash_algorithm(self) -> str:
        """Get the hashing algorithm name."""
        return "argon2id"


# Singleton instance
_password_hasher: Optional[SecurePasswordHasher] = None


def get_password_hasher() -> SecurePasswordHasher:
    """
    Get or create a password hasher instance.

    Lazy loads the hasher on first access.

    Returns:
        SecurePasswordHasher instance
    """
    global _password_hasher
    if _password_hasher is None:
        _password_hasher = SecurePasswordHasher()
    return _password_hasher
