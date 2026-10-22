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


# -- Phase 1b: service control ------------------------------------------------
class IspServiceTransitionInProgressError(IspError):
    code = "ISP_SERVICE_TRANSITION_IN_PROGRESS"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "Another suspend or resume for this customer is running"


class IspCustomerSuspendedError(IspError):
    code = "ISP_CUSTOMER_SUSPENDED"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "Not available while this customer is suspended"


class IspSuspendReasonInvalidError(IspError):
    code = "ISP_SUSPEND_REASON_INVALID"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Reason must be non_payment, customer_request, abuse or other"


class IspScopeViolation(IspError):
    """A suspension step named a row outside the ISP's customers. Must never
    happen; aborts the transaction (A.9)."""

    code = "ISP_SCOPE_VIOLATION"
    status_code_default = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_message = "Internal scope check failed"


# -- Phase 1b: billing --------------------------------------------------------
def _err(name: str, code: str, http: int, message: str) -> type[IspError]:
    return type(
        name,
        (IspError,),
        {"code": code, "status_code_default": http, "default_message": message},
    )


IspBillingNotConfiguredError = _err(
    "IspBillingNotConfiguredError",
    "ISP_BILLING_NOT_CONFIGURED",
    409,
    "Set up billing (legal name, state, prefixes) first",
)
IspInvoiceNotFoundError = _err(
    "IspInvoiceNotFoundError", "ISP_INVOICE_NOT_FOUND", 404, "Invoice not found"
)
IspPaymentNotFoundError = _err(
    "IspPaymentNotFoundError", "ISP_PAYMENT_NOT_FOUND", 404, "Payment not found"
)
IspInvoiceVoidError = _err(
    "IspInvoiceVoidError", "ISP_INVOICE_VOID", 409, "This invoice is cancelled"
)
IspInvoiceCancelledError = _err(
    "IspInvoiceCancelledError",
    "ISP_INVOICE_CANCELLED",
    409,
    "This invoice is cancelled",
)
IspInvoicePaidError = _err(
    "IspInvoicePaidError", "ISP_INVOICE_PAID", 409, "This invoice is already paid"
)
IspPaymentModeInvalidError = _err(
    "IspPaymentModeInvalidError",
    "ISP_PAYMENT_MODE_INVALID",
    422,
    "Mode must be cash, upi, bank_transfer or online",
)
IspPaymentReferenceRequiredError = _err(
    "IspPaymentReferenceRequiredError",
    "ISP_PAYMENT_REFERENCE_REQUIRED",
    422,
    "A reference (UTR) is required for UPI and bank transfers",
)
IspCreditExceedsBalanceError = _err(
    "IspCreditExceedsBalanceError",
    "ISP_CREDIT_EXCEEDS_BALANCE",
    422,
    "The credit note is larger than the invoice balance",
)
IspInvoicePrefixTooLongError = _err(
    "IspInvoicePrefixTooLongError",
    "ISP_INVOICE_PREFIX_TOO_LONG",
    422,
    "Prefix must be 1-4 characters A-Z or 0-9",
)
IspInvoiceDateOutOfRangeError = _err(
    "IspInvoiceDateOutOfRangeError",
    "ISP_INVOICE_DATE_OUT_OF_RANGE",
    422,
    "Invoice date must be within the last 7 days and in the current financial year",
)
IspBuyerGstinInvalidError = _err(
    "IspBuyerGstinInvalidError", "ISP_BUYER_GSTIN_INVALID", 422, "GSTIN is not valid"
)
IspZoneInUseError = _err(
    "IspZoneInUseError", "ISP_ZONE_IN_USE", 409, "The zone is still assigned"
)
IspZoneNotFoundError = _err(
    "IspZoneNotFoundError", "ISP_ZONE_NOT_FOUND", 404, "Zone not found"
)
IspBulkTooLargeError = _err(
    "IspBulkTooLargeError", "ISP_BULK_TOO_LARGE", 422, "At most 500 invoices at once"
)
IspInvoiceNumberOverflowError = _err(
    "IspInvoiceNumberOverflowError",
    "ISP_INVOICE_NUMBER_OVERFLOW",
    500,
    "Invoice number would exceed 16 characters",
)
IspNoDuesError = _err(
    "IspNoDuesError",
    "ISP_NO_OVERDUE_INVOICES",
    409,
    "This customer has no overdue invoices",
)
