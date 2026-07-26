from __future__ import annotations

from app.common.exceptions import CloudGuestError


class BrandingNotFoundError(CloudGuestError):
    def __init__(self, organization_id: object) -> None:
        # NOTE: CloudGuestError (app.common.exceptions) takes no ``code``
        # kwarg -- a prior version of this call passed one and would have
        # raised TypeError the instant this was actually constructed.
        super().__init__(
            message=f"Branding not found for organization {organization_id}",
            status_code=404,
        )


class BrandingOrganizationMismatchError(CloudGuestError):
    def __init__(self) -> None:
        super().__init__(
            message="Branding organization mismatch",
            status_code=403,
        )


class InvalidBackgroundImageError(CloudGuestError):
    """Raised when an uploaded background image fails content-type or
    size validation in ``BrandingService.upload_background_image``."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            message=f"Invalid background image: {reason}",
            status_code=400,
        )


class BrandingStorageNotConfiguredError(CloudGuestError):
    """Raised if BrandingService.upload/delete_background_image is called
    on a service instance built without an object_storage backend --
    mirrors app.domains.voucher.exceptions.
    VoucherEmailDeliveryNotConfiguredError's identical defensive shape."""

    def __init__(self) -> None:
        super().__init__(
            message="Background image storage is not configured",
            status_code=503,
        )


class BackgroundImageNotFoundError(CloudGuestError):
    """Raised by BrandingService.get_background_image_bytes when the
    organization has no background image set -- the proxy endpoint
    (GET /branding/background-image/raw) 404s rather than serving an
    empty/placeholder image."""

    def __init__(self, organization_id: object) -> None:
        super().__init__(
            message=f"No background image set for organization {organization_id}",
            status_code=404,
        )
