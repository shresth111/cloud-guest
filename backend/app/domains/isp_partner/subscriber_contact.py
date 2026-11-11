"""DEFAULT-LOGS follow-up (founder "hn", 2026-11-11): first name and mobile
are required when the ISP console creates or edits a subscriber.

``ISP_SUBSCRIBER_CONTACT_REQUIRED`` (default OFF; on on the testbox). While
off nothing changes. While on, the checks run ONLY on the console's own
write routes:

* ``POST  /isp/subscribers``            (Plans "Assign a package by hand")
* ``POST  /isp/subscribers/onboard``    (directory "Quick add")
* ``POST  /isp/onboarding``             (the Onboard page)
* ``PATCH /isp/subscribers/{subscriber_id}`` -- only the keys sent: clearing
  the first name, or setting a blank / malformed mobile, is refused; an
  update that does not touch them passes even on a row that has neither.

Owners, admins and franchisees use the same routes, so all of them are
covered. Not touched: coupon / voucher subscribers (``sync_subscribers``
builds rows directly), hotspot OTP guests, lead conversion and every
non-ISP path, and reads of existing rows without a name.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import _err

__all__ = [
    "IspSubscriberFirstNameRequiredError",
    "IspSubscriberMobileRequiredError",
    "check_contact_on_create",
    "check_contact_on_patch",
    "get_subscriber_contact_settings",
    "is_mobile",
]


class IspSubscriberContactSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    subscriber_contact_required: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_subscriber_contact_settings() -> IspSubscriberContactSettings:
    return IspSubscriberContactSettings()


IspSubscriberFirstNameRequiredError = _err(
    "IspSubscriberFirstNameRequiredError",
    "ISP_SUBSCRIBER_FIRST_NAME_REQUIRED",
    422,
    "Enter the subscriber's first name.",
)
IspSubscriberMobileRequiredError = _err(
    "IspSubscriberMobileRequiredError",
    "ISP_SUBSCRIBER_MOBILE_REQUIRED",
    422,
    "Enter the subscriber's mobile number: 10 digits, e.g. 9876543210.",
)

#: 10 digits starting 6-9, optionally +91 / 91 / 0 in front; spaces and
#: dashes ignored. Same rule as the console (``lib/isp-partner/onboarding``).
_MOBILE = re.compile(r"^(\+?91|0)?[6-9]\d{9}$")


def is_mobile(value: str | None) -> bool:
    return bool(value) and bool(_MOBILE.match(re.sub(r"[\s-]", "", value or "")))


def _on() -> bool:
    return get_subscriber_contact_settings().subscriber_contact_required


def check_contact_on_create(data: dict[str, Any]) -> None:
    if not _on():
        return
    if not (data.get("first_name") or "").strip():
        raise IspSubscriberFirstNameRequiredError()
    if not is_mobile(data.get("phone")):
        raise IspSubscriberMobileRequiredError()


def check_contact_on_patch(data: dict[str, Any]) -> None:
    if not _on():
        return
    if "first_name" in data and not (data["first_name"] or "").strip():
        raise IspSubscriberFirstNameRequiredError()
    if "phone" in data and not is_mobile(data["phone"]):
        raise IspSubscriberMobileRequiredError()
