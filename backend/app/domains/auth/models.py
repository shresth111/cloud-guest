from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class AuthUser:
    id: str
    email: str
    is_active: bool = True
    is_superuser: bool = False


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
