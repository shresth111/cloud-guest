"""Constants for the License domain."""

from enum import Enum

class LicenseStatus(str, Enum):
    ISSUED = "issued"
    ACTIVATED = "activated"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
