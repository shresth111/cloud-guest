"""DNS filtering exceptions. All subclass ``CloudGuestError`` so they reach
the app-wide handler as real non-2xx responses -- never ``200 {"success":
false}``, which the frontend interceptor reads as success."""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "BypassLayerInvalidError",
    "CategoryNotSelectableError",
    "CategorySetLimitError",
    "CloudflareGatewayCeilingError",
    "CloudflareNotConfiguredError",
    "CloudflareSyncError",
    "CrossLocationDnsFilteringAccessError",
    "DnsFilteringDeviceConnectionError",
    "DnsFilteringDeviceOperationError",
    "DnsFilteringError",
    "DnsFilteringMissingCredentialsError",
    "DnsFilteringNotEnabledError",
    "DnsFilteringNoCategoriesError",
    "DnsFilteringRoutersStillEnabledError",
    "UnknownCategoryError",
    "UnsupportedDnsFilteringVendorError",
]


class DnsFilteringError(CloudGuestError):
    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class CloudflareNotConfiguredError(DnsFilteringError):
    """No token/account id on this deployment. 503, not 500: the platform is
    fine, a prerequisite is missing, and nothing was written."""

    def __init__(self) -> None:
        super().__init__(
            "Category filtering is not configured on this platform yet "
            "(no Cloudflare Gateway account is connected).",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class CloudflareSyncError(DnsFilteringError):
    """Cloudflare refused or could not be reached. The message is already
    redacted by the client."""

    def __init__(self, message: str) -> None:
        super().__init__(
            f"Cloudflare Gateway: {message}", status_code=status.HTTP_502_BAD_GATEWAY
        )


class CloudflareGatewayCeilingError(DnsFilteringError):
    """The platform's Cloudflare account is at a per-account limit that is
    not the location cap (today: DNS policies). 409 and a sentence an
    operator can act on."""

    def __init__(self, *, resource: str, limit: int) -> None:
        super().__init__(
            f"The platform's Cloudflare Gateway account is at its limit of "
            f"{limit} {resource}. Category filtering cannot use another "
            "category set until Cloudflare raises the limit.",
            status_code=status.HTTP_409_CONFLICT,
            data={"resource": resource, "limit": limit},
        )


class CategorySetLimitError(DnsFilteringError):
    """A **new distinct** category set would need a Gateway DNS location the
    platform's plan does not have.

    Locations are allocated per category set (profile), and the cap is a
    setting (``cloudflare_gateway_max_locations``) because the Cloudflare
    plan's allowance is not published for Free and is 25 on Standard. 409,
    and never a silent merge into another set: the detail names the nearest
    set already in use so the venue can choose it deliberately. Only
    category ids are disclosed -- a profile holds no tenant data.
    """

    def __init__(
        self,
        *,
        limit: int,
        in_use: int,
        requested_category_ids: list[int],
        nearest_category_ids: list[int] | None,
        nearest_adds: list[int],
        nearest_removes: list[int],
        nearest_label: str | None,
    ) -> None:
        message = (
            f"Category filtering can run at most {limit} different category "
            f"selections at once on this platform, and {in_use} are in use. "
            "This selection is new, so it cannot be applied as it stands."
        )
        if nearest_label:
            message += f" The closest selection already in use {nearest_label}."
        super().__init__(
            message,
            status_code=status.HTTP_409_CONFLICT,
            data={
                "resource": "DNS locations",
                "limit": limit,
                "in_use": in_use,
                "requested_category_ids": requested_category_ids,
                "nearest_category_ids": nearest_category_ids,
                "nearest_adds": nearest_adds,
                "nearest_removes": nearest_removes,
            },
        )


class DnsFilteringRoutersStillEnabledError(DnsFilteringError):
    """Clearing a policy to "block nothing" while routers still point at a
    category set's DoH endpoint. There is no endpoint for "nothing", so the
    routers would have to be switched back first -- refused rather than
    silently turning filtering off on live routers."""

    def __init__(self, count: int) -> None:
        super().__init__(
            f"Category filtering is still on for {count} router(s) that would "
            "block nothing under this change. Turn category filtering off on "
            "those routers first, or keep at least one category.",
            status_code=status.HTTP_409_CONFLICT,
            data={"routers": count},
        )


class UnknownCategoryError(DnsFilteringError):
    def __init__(self, ids: list[int]) -> None:
        super().__init__(
            f"Unknown Cloudflare Gateway category id(s): {ids}",
            status_code=status.HTTP_400_BAD_REQUEST,
            data={"category_ids": ids},
        )


class CategoryNotSelectableError(DnsFilteringError):
    def __init__(self, ids: list[int]) -> None:
        super().__init__(
            f"Cloudflare does not allow blocking category id(s) {ids}.",
            status_code=status.HTTP_400_BAD_REQUEST,
            data={"category_ids": ids},
        )


class DnsFilteringNoCategoriesError(DnsFilteringError):
    def __init__(self) -> None:
        super().__init__(
            "Choose at least one category to block for this venue before "
            "turning on category filtering.",
            status_code=status.HTTP_409_CONFLICT,
        )


class DnsFilteringNotEnabledError(DnsFilteringError):
    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Category filtering is not enabled on router {router_id}.",
            status_code=status.HTTP_409_CONFLICT,
        )


class CrossLocationDnsFilteringAccessError(DnsFilteringError):
    def __init__(self) -> None:
        super().__init__(
            "You do not have access to this venue.",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class DnsFilteringMissingCredentialsError(DnsFilteringError):
    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials",
            status_code=status.HTTP_409_CONFLICT,
        )


class UnsupportedDnsFilteringVendorError(DnsFilteringError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class DnsFilteringDeviceConnectionError(DnsFilteringError):
    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to router {host}: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class DnsFilteringDeviceOperationError(DnsFilteringError):
    """The router refused, or the switch was rolled back. ``data`` carries
    the gateway's stable ``code`` and, for a probe failure, whether the
    rollback read back clean."""

    def __init__(
        self,
        operation: str,
        detail: str,
        *,
        code: str | None = None,
        rolled_back: bool | None = None,
        status_code: int = status.HTTP_502_BAD_GATEWAY,
    ) -> None:
        data: dict[str, object] = {"operation": operation}
        if code is not None:
            data["code"] = code
        if rolled_back is not None:
            data["rolled_back"] = rolled_back
        super().__init__(
            f"Router {operation} failed: {detail}", status_code=status_code, data=data
        )
        # Set by device_adapters for a failed DoH switch: the pre-switch DNS
        # settings, kept server-side (never in the response) so a router
        # whose rollback failed can still be restored by a later disable.
        self.snapshot: dict[str, object] | None = None


class BypassLayerInvalidError(DnsFilteringError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)
