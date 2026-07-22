from __future__ import annotations

from app.common.exceptions import CloudGuestError


class BrandingNotFoundError(CloudGuestError):
    def __init__(self, organization_id: object) -> None:
        super().__init__(
            message=f"Branding not found for organization {organization_id}",
            code="branding_not_found",
            status_code=404,
        )


class BrandingOrganizationMismatchError(CloudGuestError):
    def __init__(self) -> None:
        super().__init__(
            message="Branding organization mismatch",
            code="branding_organization_mismatch",
            status_code=403,
        )
