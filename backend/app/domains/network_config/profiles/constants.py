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

    Escapes every character RouterOS interprets inside a quoted string,
    from its own scripting escape table: ``\\`` and ``"`` (string syntax),
    ``$`` (variable substitution, so ``$var`` and ``$[...]`` would otherwise
    run), ``?`` (console help), and newline/CR/tab plus any other control
    character (which would end the line, and the command, early). A value
    containing none of these comes back unchanged, so rendered output for
    ordinary names is byte-for-byte what it always was.
    """
    out: list[str] = []
    for ch in value:
        if ch in _ROUTEROS_STRING_ESCAPES:
            out.append(_ROUTEROS_STRING_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\{ord(ch):02X}")
        else:
            out.append(ch)
    return "".join(out)


_ROUTEROS_STRING_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "$": "\\$",
    "?": "\\?",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

# Characters a bare (unquoted) RouterOS argument value may contain without
# being quoted. Anything else is quoted and escaped by
# :func:`routeros_value`.
_BARE_VALUE_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/*@"
)


def routeros_value(value: str) -> str:
    """A user-supplied value for an unquoted ``key=value`` position.

    Returned as-is when it holds only characters that cannot end or extend
    the argument (hostnames, IPs, ``*.domain`` wildcards), so existing
    rendered config is unchanged; otherwise quoted and escaped, so a space,
    ``;`` or ``[`` cannot start a second command."""
    if value and all(ch in _BARE_VALUE_SAFE for ch in value):
        return value
    return f'"{escape_routeros_string(value)}"'


__all__ = [
    "EMIT_COMMENT_PREFIX",
    "routeros_value",
    "RECOGNIZE_COMMENT_PREFIXES",
    "SECRET_PLACEHOLDER_PREFIX",
    "wyfy_comment",
    "is_managed_comment",
    "secret_placeholder",
    "escape_routeros_string",
]
