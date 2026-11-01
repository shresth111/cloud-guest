"""QA-006: ISP customer create/patch and location create/patch accept only
IANA time zones (422 otherwise)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.domains.isp_partner.schemas import (
    CustomerCreateRequest,
    CustomerUpdateRequest,
    IspLocationCreateRequest,
    IspLocationUpdateRequest,
)

CUSTOMER = {"name": "Cafe", "contact_email": "cafe@example.com"}
LOCATION = {
    "name": "Cafe Sector 18",
    "address_line1": "Test Rd",
    "city": "Noida",
    "state_province": "UP",
    "postal_code": "201301",
}
BAD = ["Not/AZone", "Mars/Base", "", "IST", "asia/kolkata ", "../etc/passwd"]
GOOD = ["Asia/Kolkata", "UTC", "Europe/London", "America/New_York"]


@pytest.mark.parametrize("tz", BAD)
def test_invalid_zone_is_rejected_everywhere(tz) -> None:
    for model, base in (
        (CustomerCreateRequest, CUSTOMER),
        (CustomerUpdateRequest, {}),
        (IspLocationCreateRequest, LOCATION),
        (IspLocationUpdateRequest, {}),
    ):
        with pytest.raises(ValidationError):
            model(**base, timezone=tz)


@pytest.mark.parametrize("tz", GOOD)
def test_iana_zones_are_accepted(tz) -> None:
    assert CustomerCreateRequest(**CUSTOMER, timezone=tz).timezone == tz
    assert CustomerUpdateRequest(timezone=tz).timezone == tz
    assert IspLocationCreateRequest(**LOCATION, timezone=tz).timezone == tz
    assert IspLocationUpdateRequest(timezone=tz).timezone == tz


def test_defaults_and_omitted_still_work() -> None:
    assert CustomerCreateRequest(**CUSTOMER).timezone == "Asia/Kolkata"
    assert IspLocationCreateRequest(**LOCATION).timezone == "Asia/Kolkata"
    assert CustomerUpdateRequest().timezone is None
    assert IspLocationUpdateRequest().timezone is None
