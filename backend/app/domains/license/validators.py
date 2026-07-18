"""Validators for checking license format and integrity."""

import re

LICENSE_KEY_PATTERN = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")

def validate_license_key_format(key: str) -> bool:
    """Validate license key format (XXXX-XXXX-XXXX-XXXX)."""
    return bool(LICENSE_KEY_PATTERN.match(key))
