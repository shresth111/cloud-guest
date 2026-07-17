from __future__ import annotations

from typing import Any


class AuthSecurity:
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        raise NotImplementedError("Password verification logic must be implemented.")

    @staticmethod
    def hash_password(password: str) -> str:
        raise NotImplementedError("Password hashing logic must be implemented.")

    @staticmethod
    def create_token(subject: str, **claims: Any) -> str:
        raise NotImplementedError("Token creation logic must be implemented.")

    @staticmethod
    def decode_token(token: str) -> dict[str, Any]:
        raise NotImplementedError("Token decoding logic must be implemented.")
