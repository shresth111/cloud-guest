"""Service layer for the License domain."""

from __future__ import annotations

import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta
from typing import Sequence

from .constants import LicenseStatus
from .exceptions import (
    LicenseAlreadyActivatedError,
    LicenseBindingMismatchError,
    LicenseExpiredError,
    LicenseNotFoundError,
)
from .models import License
from .repository import LicenseRepositoryProtocol


class LicenseService:
    def __init__(self, repository: LicenseRepositoryProtocol) -> None:
        self.repository = repository

    def _generate_key(self) -> str:
        """Generates a secure 16-character license key formatted as XXXX-XXXX-XXXX-XXXX."""
        chars = string.ascii_uppercase + string.digits
        blocks = []
        for _ in range(4):
            blocks.append("".join(secrets.choice(chars) for _ in range(4)))
        return "-".join(blocks)

    async def generate_license(
        self, organization_id: uuid.UUID, tier: str, duration_days: int = 365
    ) -> License:
        key = self._generate_key()
        now = datetime.now(UTC)
        expires = now + timedelta(days=duration_days)

        data = {
            "organization_id": organization_id,
            "router_id": None,
            "license_key": key,
            "status": LicenseStatus.ISSUED.value,
            "tier": tier,
            "issued_at": now,
            "expires_at": expires,
        }

        return await self.repository.create_license(data)

    async def activate_license(self, key: str, router_id: uuid.UUID) -> License:
        license_obj = await self.repository.get_by_key(key)
        if not license_obj:
            raise LicenseNotFoundError(key)

        if license_obj.status == LicenseStatus.ACTIVATED.value:
            raise LicenseAlreadyActivatedError(key)

        now = datetime.now(UTC)
        if license_obj.expires_at and license_obj.expires_at < now:
            raise LicenseExpiredError(key)

        update_data = {
            "router_id": router_id,
            "status": LicenseStatus.ACTIVATED.value,
            "activated_at": now,
            "last_validated_at": now,
        }

        return await self.repository.update_license(license_obj, update_data)

    async def deactivate_license(self, key: str) -> License:
        license_obj = await self.repository.get_by_key(key)
        if not license_obj:
            raise LicenseNotFoundError(key)

        update_data = {
            "status": LicenseStatus.DEACTIVATED.value,
            "deallocated_at": datetime.now(UTC),
        }

        return await self.repository.update_license(license_obj, update_data)

    async def validate_license(
        self, key: str, router_id: uuid.UUID, organization_id: uuid.UUID
    ) -> License:
        license_obj = await self.repository.get_by_key(key)
        if not license_obj:
            raise LicenseNotFoundError(key)

        if license_obj.organization_id != organization_id:
            raise LicenseBindingMismatchError("License belongs to another organization.")

        if license_obj.router_id and license_obj.router_id != router_id:
            raise LicenseBindingMismatchError("License bound to a different router.")

        now = datetime.now(UTC)
        if license_obj.expires_at and license_obj.expires_at < now:
            await self.repository.update_license(
                license_obj, {"status": LicenseStatus.EXPIRED.value}
            )
            raise LicenseExpiredError(key)

        update_data = {"last_validated_at": now}
        return await self.repository.update_license(license_obj, update_data)

    async def list_organization_licenses(
        self, organization_id: uuid.UUID
    ) -> Sequence[License]:
        return await self.repository.list_by_organization(organization_id)

    async def renew_license(self, key: str, extension_days: int) -> License:
        license_obj = await self.repository.get_by_key(key)
        if not license_obj:
            raise LicenseNotFoundError(key)

        base_time = max(license_obj.expires_at, datetime.now(UTC)) if license_obj.expires_at else datetime.now(UTC)
        new_expires = base_time + timedelta(days=extension_days)

        update_data = {
            "expires_at": new_expires,
            "status": LicenseStatus.ACTIVATED.value if license_obj.activated_at else LicenseStatus.ISSUED.value,
        }

        return await self.repository.update_license(license_obj, update_data)
