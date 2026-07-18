"""Constants for the Custom Domains module."""

from enum import Enum

class DNSValidationStatus(str, Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"

class SSLStatus(str, Enum):
    PENDING = "pending"
    ISSUING = "issuing"
    ACTIVE = "active"
    FAILED = "failed"
