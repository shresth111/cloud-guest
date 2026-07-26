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


class InvalidLogoError(CloudGuestError):
    """Raised when an uploaded logo fails content-type or size validation
    in ``BrandingService.upload_logo`` -- mirrors
    InvalidBackgroundImageError exactly."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            message=f"Invalid logo: {reason}",
            status_code=400,
        )


class BrandingStorageNotConfiguredError(CloudGuestError):
    """Raised if BrandingService.upload/delete_background_image or
    upload/delete_logo is called on a service instance built without an
    object_storage backend -- mirrors
    app.domains.voucher.exceptions.VoucherEmailDeliveryNotConfiguredError's
    identical defensive shape."""

    def __init__(self, asset: str = "Background image") -> None:
        super().__init__(
            message=f"{asset} storage is not configured",
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


class LogoNotFoundError(CloudGuestError):
    """Raised by BrandingService.get_logo_bytes when the organization has
    no uploaded logo -- mirrors BackgroundImageNotFoundError exactly."""

    def __init__(self, organization_id: object) -> None:
        super().__init__(
            message=f"No logo set for organization {organization_id}",
            status_code=404,
        )
