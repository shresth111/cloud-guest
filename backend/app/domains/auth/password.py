from __future__ import annotations


class PasswordManager:
    @staticmethod
    def hash(password: str) -> str:
        raise NotImplementedError("Password hashing logic must be implemented.")

    @staticmethod
    def verify(password: str, hashed_password: str) -> bool:
        raise NotImplementedError("Password verification logic must be implemented.")
