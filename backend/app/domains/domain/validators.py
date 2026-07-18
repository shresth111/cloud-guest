"""Validators for custom domain names."""

import re

DOMAIN_REGEX = re.compile(r"^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}$")

def validate_domain_name_format(domain_name: str) -> bool:
    """Validate format of domain name."""
    return bool(DOMAIN_REGEX.match(domain_name.lower().strip()))
