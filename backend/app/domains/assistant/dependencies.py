"""FastAPI dependencies for the Assistant domain.

``build_assistant_provider`` mirrors
``app.domains.billing.dependencies.build_payment_gateway``'s exact "one
plain, FastAPI-DI-framework-free function decides real vs. logging"
pattern: picks :class:`~.service.AnthropicAssistantProvider` when
``Settings.anthropic_api_key`` is actually set, or
:class:`~.service.LoggingAssistantProvider` (this deployment's real,
honest default -- see ``service.py``'s module docstring) otherwise.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session

from .repository import AssistantRepository, AssistantRepositoryProtocol
from .service import (
    AnthropicAssistantProvider,
    AssistantProviderProtocol,
    AssistantService,
    LoggingAssistantProvider,
)


def get_assistant_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AssistantRepositoryProtocol:
    return AssistantRepository(db)


def build_assistant_provider(*, settings: Settings) -> AssistantProviderProtocol:
    """Plain, FastAPI-DI-framework-free constructor for the real
    provider selection -- mirrors
    ``app.domains.billing.dependencies.build_payment_gateway`` exactly.

    No real Anthropic API key is configured in this deployment, so this
    function's real, observed behavior today is always
    :class:`~.service.LoggingAssistantProvider` -- the identical
    "the real provider's code is present and correct, just unreachable
    without a credential" posture ``build_payment_gateway`` itself
    documents for Stripe/Razorpay. Setting
    ``CLOUDGUEST_ANTHROPIC_API_KEY`` in a real deployment is the entire
    "wire it in for real" step; nothing else changes.
    """
    if settings.anthropic_api_key:
        return AnthropicAssistantProvider(api_key=settings.anthropic_api_key)
    return LoggingAssistantProvider()


def get_assistant_provider(
    settings: Settings = Depends(get_settings),
) -> AssistantProviderProtocol:
    return build_assistant_provider(settings=settings)


def get_assistant_service(
    repository: AssistantRepositoryProtocol = Depends(get_assistant_repository),
    provider: AssistantProviderProtocol = Depends(get_assistant_provider),
) -> AssistantService:
    return AssistantService(repository, provider=provider)


__all__ = [
    "get_assistant_repository",
    "build_assistant_provider",
    "get_assistant_provider",
    "get_assistant_service",
]
