"""ISP partner error codes (API_CONTRACT §9). Every one carries its machine
code in ``data.code``. The TR-069 codes live in ``app.domains.tr069``."""

from __future__ import annotations

from fastapi import status

from app.common.exceptions import CloudGuestError


class IspError(CloudGuestError):
    code = "ISP_ERROR"
    status_code_default = status.HTTP_400_BAD_REQUEST
    default_message = "ISP partner request failed"

    def __init__(self, message: str | None = None, **data: object) -> None:
        super().__init__(
            message or self.default_message,
            status_code=self.status_code_default,
            data={"code": self.code, **data},
        )


# -- 403 ---------------------------------------------------------------------
class IspPartnerRequiredError(IspError):
    code = "ISP_PARTNER_REQUIRED"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = "This account is not an ISP partner account"


class IspPartnerSuspendedError(IspError):
    code = "ISP_PARTNER_SUSPENDED"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = "This ISP partner account is suspended. Contact Wyfy support."


class IspRoleRequiredError(IspError):
    code = "ISP_ROLE_REQUIRED"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = "An ISP role on this organization is required"


class IspRoleEscalationError(IspError):
    code = "ISP_ROLE_ESCALATION"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = "You cannot grant or change that role"


class IspSetupNotAllowedError(IspError):
    """A role that holds ``isp_partner.execute`` but is not on the setup
    allow-list (``constants.SETUP_SCRIPT_ROLES``, STATUS Q2)."""

    code = "ISP_ROLE_ESCALATION"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = "Only an ISP owner or admin can generate a router setup script"


# -- 400 ---------------------------------------------------------------------
class IspScopeHeadersNotAllowedError(IspError):
    code = "ISP_SCOPE_HEADERS_NOT_ALLOWED"
    status_code_default = status.HTTP_400_BAD_REQUEST
    default_message = "X-Location-Id and X-Router-Id are not accepted on /isp"


# -- 404 ---------------------------------------------------------------------
class IspCustomerNotFoundError(IspError):
    code = "ISP_CUSTOMER_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "Customer not found"


class IspLocationNotFoundError(IspError):
    code = "ISP_LOCATION_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "Location not found"


class IspRouterNotFoundError(IspError):
    code = "ISP_ROUTER_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "Router not found"


class IspPortalConfigNotFoundError(IspError):
    code = "ISP_PORTAL_CONFIG_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "Captive portal config not found"


class IspUserNotFoundError(IspError):
    code = "ISP_USER_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "User not found"


class IspPartnerNotFoundError(IspError):
    code = "ISP_PARTNER_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "ISP partner not found"


# -- 409 ---------------------------------------------------------------------
class IspCustomerLimitError(IspError):
    code = "ISP_CUSTOMER_LIMIT"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "This ISP has reached its customer limit"


class IspCustomerSlugTakenError(IspError):
    code = "ISP_CUSTOMER_SLUG_TAKEN"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "That slug is already taken"


class IspExternalRefTakenError(IspError):
    code = "ISP_EXTERNAL_REF_TAKEN"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "Another customer already uses that external reference"


class IspLastOwnerError(IspError):
    code = "ISP_LAST_OWNER"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "The last active ISP owner cannot be disabled or demoted"


class IspSlugTakenError(IspError):
    code = "ISP_SLUG_TAKEN"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "That slug is already taken"


class UserEmailTakenError(IspError):
    code = "USER_EMAIL_TAKEN"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "A user with that email already exists"


# -- 422 ---------------------------------------------------------------------
class IspRoleInvalidError(IspError):
    code = "ISP_ROLE_INVALID"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Role must be one of the ISP roles"


class IspConfinementNotAllowedError(IspError):
    code = "ISP_CONFINEMENT_NOT_ALLOWED"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Owners and admins cannot be confined to customers"


class IspCustomerRequiredError(IspError):
    code = "ISP_CUSTOMER_REQUIRED"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Choose a customer"


class IspRangeTooLongError(IspError):
    code = "ISP_RANGE_TOO_LONG"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "The date range can be at most 92 days"


class IspVendorNotSupportedError(IspError):
    code = "ISP_VENDOR_NOT_SUPPORTED"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Only MikroTik routers can be added in this release"


class IspForceNotAllowedError(IspError):
    code = "ISP_FORCE_NOT_ALLOWED"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "force=true is not available to ISP partners"


class IspImmutableFieldError(IspError):
    """A body named a field that exists but may not change (``slug`` on
    PATCH). Same 422 family as ``extra="forbid"``."""

    code = "ISP_FIELD_IMMUTABLE"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "That field cannot be changed"


class IspBadRequestError(IspError):
    code = "ISP_BAD_REQUEST"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Invalid request"


class PlanNotFoundError(IspError):
    code = "PLAN_NOT_FOUND"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Plan not found"
