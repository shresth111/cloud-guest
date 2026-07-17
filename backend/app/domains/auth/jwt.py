from __future__ import annotations

from typing import Any


class JWTManager:
    @staticmethod
    def encode(payload: dict[str, Any]) -> str:
        raise NotImplementedError("JWT encoding logic must be implemented.")

    @staticmethod
    def decode(token: str) -> dict[str, Any]:
        raise NotImplementedError("JWT decoding logic must be implemented.")
