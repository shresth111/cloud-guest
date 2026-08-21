"""Managed comment and secret-placeholder conventions (Wave 1 Step 10).

New resources emit ``WYFYGUEST-*`` comments. Discovery and conflict analysis
continue to recognize legacy ``cloudguest-*`` tags without re-tagging live
devices (dual-recognize, single-emit).
"""

from __future__ import annotations

EMIT_COMMENT_PREFIX = "WYFYGUEST-"
RECOGNIZE_COMMENT_PREFIXES: tuple[str, ...] = (
    EMIT_COMMENT_PREFIX,
    "cloudguest-",
)
SECRET_PLACEHOLDER_PREFIX = "{{WYFYGUEST_SECRET:"


def wyfy_comment(domain: str, slug: str) -> str:
    """Build a new managed comment tag (always ``WYFYGUEST-*``)."""
    return f"{EMIT_COMMENT_PREFIX}{domain}-{slug}"


def is_managed_comment(comment: str | None) -> bool:
    if not comment:
        return False
    return any(comment.startswith(prefix) for prefix in RECOGNIZE_COMMENT_PREFIXES)


def secret_placeholder(ref: str) -> str:
    """Placeholder stored in ``config_versions.rendered_content`` until push."""
    return SECRET_PLACEHOLDER_PREFIX + ref + "}}"


def escape_routeros_string(value: str) -> str:
    """Escape a value for interpolation inside a double-quoted RouterOS string.

    Shared rather than re-declared per module. Three renderer modules already
    carry a private ``_escape_routeros_string`` with this exact body
    (``wan/renderers.py``, ``profiles/guest.py``, ``profiles/safety_net.py``);
    new modules import this one instead of adding a fourth copy. The existing
    three are deliberately left alone -- they are working, pushed code, and
    re-pointing them is a separate change with its own review.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


__all__ = [
    "EMIT_COMMENT_PREFIX",
    "RECOGNIZE_COMMENT_PREFIXES",
    "SECRET_PLACEHOLDER_PREFIX",
    "wyfy_comment",
    "is_managed_comment",
    "secret_placeholder",
    "escape_routeros_string",
]
