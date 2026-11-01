"""QA-006, Master side: POST/PATCH /platform/isp-partners accept only IANA
time zones (422 otherwise)."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.domains.isp_partner.platform_schemas import (
    IspPartnerCreateRequest,
    IspPartnerUpdateRequest,
)

CREATE = {
    "name": "QA ISP",
    "slug": "qa-isp",
    "contact_email": "ops@example.com",
    "default_customer_plan_id": str(uuid.uuid4()),
    "owner": {"first_name": "Q", "last_name": "A", "email": "owner@example.com"},
}


@pytest.mark.parametrize("tz", ["Not/AZone", "Mars/Base", "IST", " ", "../etc/passwd"])
def test_invalid_zone_is_rejected(tz) -> None:
    with pytest.raises(ValidationError):
        IspPartnerCreateRequest(**CREATE, timezone=tz)
    with pytest.raises(ValidationError):
        IspPartnerUpdateRequest(timezone=tz)


@pytest.mark.parametrize("tz", ["Asia/Kolkata", "UTC", "Asia/Dubai"])
def test_iana_zone_is_accepted(tz) -> None:
    assert IspPartnerCreateRequest(**CREATE, timezone=tz).timezone == tz
    assert IspPartnerUpdateRequest(timezone=tz).timezone == tz


def test_default_and_omitted() -> None:
    assert IspPartnerCreateRequest(**CREATE).timezone == "Asia/Kolkata"
    assert IspPartnerUpdateRequest().timezone is None
