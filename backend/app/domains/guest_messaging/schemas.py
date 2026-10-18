"""Request bodies. ``extra="forbid"`` everywhere: a wrong request shape is a
422, never a silent 2xx that stored nothing."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ChannelParam = Literal["whatsapp", "sms"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginProviderPutRequest(_Strict):
    provider_type: str | None = Field(default=None, max_length=20)
    # Per-adapter fields are validated by registry.normalize_config, which
    # refuses unknown keys for the chosen adapter. Values are scalars except
    # the Custom HTTP adapter's ``headers`` list.
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool | None = None


class VerifyStartRequest(_Strict):
    to: str = Field(min_length=8, max_length=24)


class VerifyConfirmRequest(_Strict):
    code: str = Field(pattern=r"^\s*\d{4,8}\s*$")
