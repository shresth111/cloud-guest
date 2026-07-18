"""Validators for the Branding domain."""

import re

HEX_COLOR_PATTERN = re.compile(r"^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")

def validate_hex_color(color: str) -> bool:
    """Ensure color code is a valid hex code."""
    return bool(HEX_COLOR_PATTERN.match(color))
