from __future__ import annotations

from .models import AuthUser, TokenPair
from .repository import AuthRepository


class AuthService:
    def __init__(self, repository: AuthRepository | None = None):
        self.repository = repository or AuthRepository()

    def login(self, email: str, password: str) -> TokenPair:
        raise NotImplementedError("Authentication logic must be implemented.")

    def refresh(self, refresh_token: str) -> TokenPair:
        raise NotImplementedError("Refresh token logic must be implemented.")

    def get_user(self, user_id: str) -> AuthUser | None:
        raise NotImplementedError("User lookup logic must be implemented.")
