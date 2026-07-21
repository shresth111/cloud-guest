"""DNS Management domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "DnsError",
    "DnsRecordNotFoundError",
    "CrossOrganizationDnsRecordAccessError",
    "InvalidDnsAddressError",
    "InvalidDnsNameError",
]


class DnsError(CloudGuestError):
    """Base exception for DNS Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class DnsRecordNotFoundError(DnsError):
    def __init__(self, record_id: uuid.UUID | str) -> None:
        super().__init__(
            f"DNS record not found: {record_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationDnsRecordAccessError(DnsError):
    """Mirrors ``app.domains.dhcp.exceptions
    .CrossOrganizationDhcpPoolAccessError``'s identical shape."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a DNS record belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidDnsAddressError(DnsError):
    """Raised when an ``A``/``AAAA`` record's ``address`` is not a real,
    parseable IPv4/IPv6 address of the matching family."""

    def __init__(self, record_type: str, value: str) -> None:
        super().__init__(
            f"Invalid address for {record_type} record: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidDnsNameError(DnsError):
    """Raised when ``name``/a ``CNAME`` record's ``address`` (a hostname,
    not an IP) fails a basic hostname-shape check."""

    def __init__(self, field_name: str, value: str) -> None:
        super().__init__(
            f"Invalid {field_name}: '{value}' is not a valid hostname",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
