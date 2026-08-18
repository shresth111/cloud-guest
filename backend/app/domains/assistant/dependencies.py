"""FastAPI dependencies for the Assistant domain.

``build_assistant_provider`` mirrors
``app.domains.billing.dependencies.build_payment_gateway``'s exact "one
plain, FastAPI-DI-framework-free function decides real vs. logging"
pattern, extended to the multi-provider selector shape
``app.domains.otp.service.get_configured_email_provider``/
``get_configured_sms_provider``/``get_configured_whatsapp_provider``
already establish for that domain: it picks
:class:`~.service.LiteLLMAssistantProvider` -- constructed for whichever
real provider is actually configured -- or
:class:`~.service.LoggingAssistantProvider` (this deployment's real,
honest default -- see ``service.py``'s module docstring) when nothing
real is configured.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session

from .repository import AssistantRepository, AssistantRepositoryProtocol
from .service import (
    AssistantProviderProtocol,
    AssistantService,
    LiteLLMAssistantProvider,
    LoggingAssistantProvider,
)

# Sarvam's current flagship chat-completions model (Sarvam-M/24B was
# deprecated by Sarvam in favor of this one -- see
# https://docs.sarvam.ai/api-reference-docs/chat-completion/models for the
# current model list). litellm routes on the "sarvam/" prefix per its own
# provider-routing convention (https://docs.litellm.ai/docs/providers/sarvam)
# -- the same convention LiteLLMAssistantProvider.__init__ already applies
# for the "anthropic/" prefix, just spelled out explicitly here since
# "sarvam" isn't the module's default-prefix fallback.
_SARVAM_DEFAULT_MODEL = "sarvam/sarvam-105b"


def get_assistant_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AssistantRepositoryProtocol:
    return AssistantRepository(db)


def build_assistant_provider(*, settings: Settings) -> AssistantProviderProtocol:
    """Plain, FastAPI-DI-framework-free constructor for the real
    provider selection -- mirrors
    ``app.domains.billing.dependencies.build_payment_gateway`` and
    ``app.domains.otp.service``'s ``get_configured_*_provider`` factories.

    ``assistant_provider='sarvam'`` is checked first and is strictly
    gated on ``sarvam_api_key`` -- selecting it with that key still empty
    falls back to :class:`~.service.LoggingAssistantProvider` rather than
    silently reusing a configured Anthropic key instead, so a
    misconfigured Sarvam selection can never surprise-route to a
    different provider.

    Everything else falls through to the original, unconditional
    ``anthropic_api_key`` check this function shipped with before Sarvam
    existed as an option -- deliberately preserved as-is (not folded into
    an ``assistant_provider == 'anthropic'`` gate) so an existing
    deployment that already set only ``CLOUDGUEST_ANTHROPIC_API_KEY``, with
    ``CLOUDGUEST_ASSISTANT_PROVIDER`` left at its 'logging' default, keeps
    working with zero migration. No real API key is configured for either
    provider in this sandbox, so this function's real, observed behavior
    today is always :class:`~.service.LoggingAssistantProvider` -- the
    identical "the real provider's code is present and correct, just
    unreachable without a credential" posture ``build_payment_gateway``
    itself documents for Stripe/Razorpay.
    """
    if settings.assistant_provider.lower() == "sarvam":
        if settings.sarvam_api_key:
            return LiteLLMAssistantProvider(
                api_key=settings.sarvam_api_key, model=_SARVAM_DEFAULT_MODEL
            )
        return LoggingAssistantProvider()
    if settings.anthropic_api_key:
        return LiteLLMAssistantProvider(api_key=settings.anthropic_api_key)
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
