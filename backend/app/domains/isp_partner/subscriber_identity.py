"""How a subscriber's identifier is shown to ISP staff (QA-014).

``mask_identifier`` is the venue-guest masker: anything that is not an e-mail
is treated as a phone number and reduced to its digits, so the ISP's own
usernames (``rahul.sharma.9288``, ``user9288``) both became ``9288`` and two
subscribers looked the same, while the same detail response showed the
ISP-entered phone and e-mail in clear.

The rule now:
- a subscriber the ISP created (``source="manual"``) is the ISP's own record:
  the identifier is shown exactly as entered;
- a subscriber derived from a coupon redemption (``source="coupon"``) carries
  the identifier the GUEST typed at the captive portal -- a venue guest's
  phone or e-mail -- so it stays masked (F2), but only when it actually looks
  like a phone number or an e-mail; a username-style code is shown as is.
"""

from __future__ import annotations

import re

from app.common.masking import mask_identifier

__all__ = ["looks_like_contact", "subscriber_identifier"]

_PHONE = re.compile(r"^\+?[\d\s\-().]{6,}$")


def looks_like_contact(value: str) -> bool:
    v = value.strip()
    return "@" in v or bool(_PHONE.match(v))


def subscriber_identifier(identifier: str | None, source: str | None) -> str | None:
    if not identifier:
        return identifier
    if source == "manual" or not looks_like_contact(identifier):
        return identifier
    return mask_identifier(identifier)
