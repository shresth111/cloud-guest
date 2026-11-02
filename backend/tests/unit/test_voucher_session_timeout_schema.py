"""Voucher batch session timeout: positive, optional, never above the validity."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.domains.voucher.schemas import VoucherBatchCreate


def _payload(**over: object) -> VoucherBatchCreate:
    return VoucherBatchCreate(
        name="Lobby",
        organization_id=uuid.uuid4(),
        quantity=1,
        validity_minutes=120,
        **over,
    )


def test_optional() -> None:
    assert _payload().session_timeout_minutes is None


@pytest.mark.parametrize("minutes", [1, 60, 120])
def test_accepts_up_to_the_validity(minutes: int) -> None:
    assert _payload(session_timeout_minutes=minutes).session_timeout_minutes == minutes


@pytest.mark.parametrize("minutes", [0, -5, 121])
def test_refuses_zero_negative_and_above_the_validity(minutes: int) -> None:
    with pytest.raises(ValidationError):
        _payload(session_timeout_minutes=minutes)
