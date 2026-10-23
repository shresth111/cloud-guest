"""TR-069 error codes (API_CONTRACT §9)."""

from __future__ import annotations

from fastapi import status

from app.domains.isp_partner.exceptions import IspError


class Tr069NotEnabledError(IspError):
    code = "TR069_NOT_ENABLED"
    status_code_default = status.HTTP_503_SERVICE_UNAVAILABLE
    default_message = "TR-069 management is not enabled on this platform yet"


class Tr069DeviceNotFoundError(IspError):
    code = "TR069_DEVICE_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "Device not found"


class Tr069DisabledForCustomerError(IspError):
    code = "TR069_DISABLED_FOR_CUSTOMER"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "TR-069 is disabled for this customer"


class Tr069DisabledForLocationError(IspError):
    code = "TR069_DISABLED_FOR_LOCATION"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "TR-069 is disabled for this device's location"


class Tr069TaskPendingError(IspError):
    code = "TR069_TASK_PENDING"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "A task of this kind is already queued for this device"


class Tr069AcsUnavailableError(IspError):
    code = "TR069_ACS_UNAVAILABLE"
    status_code_default = status.HTTP_502_BAD_GATEWAY
    default_message = "The ACS could not be reached. Try again shortly."
