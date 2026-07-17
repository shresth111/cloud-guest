from __future__ import annotations

from typing import Protocol


class AuthRepositoryProtocol(Protocol):
    def get_user_by_email(self, email: str):
        ...

    def create_refresh_token(self, user_id: str, token: str) -> None:
        ...

    def revoke_refresh_token(self, token: str) -> None:
        ...


class AuthRepository:
    def get_user_by_email(self, email: str):
        raise NotImplementedError

    def create_refresh_token(self, user_id: str, token: str) -> None:
        raise NotImplementedError

    def revoke_refresh_token(self, token: str) -> None:
        raise NotImplementedError
