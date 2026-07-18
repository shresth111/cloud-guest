"""Service layer for the Theme domain."""

from __future__ import annotations

import uuid
from .exceptions import ThemeNotFoundError
from .models import Theme
from .repository import ThemeRepositoryProtocol


class ThemeService:
    def __init__(self, repository: ThemeRepositoryProtocol) -> None:
        self.repository = repository

    async def get_theme_by_branding(
        self, branding_id: uuid.UUID, organization_id: uuid.UUID
    ) -> Theme:
        theme = await self.repository.get_by_branding_id(branding_id)
        if not theme:
            # Create a default guest captive portal theme
            data = {
                "branding_id": branding_id,
                "organization_id": organization_id,
                "landing_page_theme": "modern",
                "terms_text": "By connecting, you agree to our Terms of Service.",
                "privacy_text": "We value your privacy and protect your data.",
            }
            theme = await self.repository.create_theme(data)
        return theme

    async def update_theme(self, branding_id: uuid.UUID, data: dict) -> Theme:
        theme = await self.repository.get_by_branding_id(branding_id)
        if not theme:
            raise ThemeNotFoundError(str(branding_id))

        return await self.repository.update_theme(theme, data)
