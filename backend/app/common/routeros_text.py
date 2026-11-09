"""Request-field types for free text that ends up in a RouterOS script.

Names and comments a venue types (a port-forward rule called "CCTV", a DNS
record's note) are rendered into ``.rsc`` config that the router imports.
The renderers escape them (``network_config.profiles.constants
.escape_routeros_string``); these types are the second layer, refusing at the
API the characters RouterOS gives meaning to, so a name cannot carry script
in the first place.

Deliberately a denylist, not an ASCII allowlist: venue staff write names like
"Cafe 2nd floor (CCTV) #2" or in Hindi, and all of that stays valid. Refused
are only characters with no business in a label: ``"`` ``\\`` ``$`` ``[``
``]`` ``{`` ``}`` ``;`` ``?`` ``` ` ``` and control characters (newlines
included).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator

ROUTEROS_FORBIDDEN_CHARACTERS = frozenset('"\\$[]{};?`')


def _check_routeros_safe(value: str | None) -> str | None:
    if value is None:
        return value
    for ch in value:
        if ch in ROUTEROS_FORBIDDEN_CHARACTERS or ord(ch) < 0x20 or ord(ch) == 0x7F:
            shown = repr(ch) if ord(ch) < 0x20 or ord(ch) == 0x7F else ch
            raise ValueError(
                f"must not contain {shown} -- use letters, numbers, spaces "
                "and ordinary punctuation"
            )
    return value


RouterOSSafeText = Annotated[str, AfterValidator(_check_routeros_safe)]

__all__ = ["ROUTEROS_FORBIDDEN_CHARACTERS", "RouterOSSafeText"]
