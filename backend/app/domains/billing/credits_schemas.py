"""Request schemas for the prepaid-credits routes (§13.7).

``extra="forbid"`` everywhere: an unknown field is a 422, never silently
dropped. No request carries an ``organization_id`` -- customer routes take it
from ``CurrentOrganization``, Master routes from a GLOBAL-pinned path.
Amounts are ``int`` in minor units; a float or a numeric string is refused
(``strict``), so ``12.5`` can never be read as 12.
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .credits_constants import (
    MAX_CLIENT_IDEMPOTENCY_KEY_LENGTH,
    MAX_ENTRY_AMOUNT_MINOR,
    MAX_LOW_BALANCE_THRESHOLD_MINOR,
    NOTE_MAX_LENGTH,
    NOTE_MIN_LENGTH,
    REFERENCE_MAX_LENGTH,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreditAdjustmentCreate(_Strict):
    entry_type: Literal["topup", "adjustment", "refund"]
    amount_minor: int = Field(
        strict=True, ge=-MAX_ENTRY_AMOUNT_MINOR, le=MAX_ENTRY_AMOUNT_MINOR
    )
    note: str = Field(min_length=NOTE_MIN_LENGTH, max_length=NOTE_MAX_LENGTH)
    reference: str | None = Field(default=None, max_length=REFERENCE_MAX_LENGTH)
    campaign_id: uuid.UUID | None = None
    issue_invoice: bool = False
    amount_paid_minor_inr: int | None = Field(
        default=None, strict=True, gt=0, le=MAX_ENTRY_AMOUNT_MINOR
    )
    idempotency_key: str = Field(
        min_length=8,
        max_length=MAX_CLIENT_IDEMPOTENCY_KEY_LENGTH,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )

    @model_validator(mode="after")
    def _rules(self) -> CreditAdjustmentCreate:
        self.note = self.note.strip()
        if len(self.note) < NOTE_MIN_LENGTH:
            raise ValueError(f"note must be at least {NOTE_MIN_LENGTH} characters")
        if self.reference is not None:
            self.reference = self.reference.strip() or None
        if self.entry_type == "adjustment":
            if self.amount_minor == 0:
                raise ValueError("an adjustment amount must not be 0")
        elif self.amount_minor <= 0:
            raise ValueError(f"a {self.entry_type} amount must be greater than 0")
        if self.campaign_id is not None and self.entry_type != "refund":
            raise ValueError("campaign_id is only allowed on a refund")
        if self.issue_invoice and self.entry_type != "topup":
            raise ValueError("issue_invoice is only allowed on a topup")
        if self.issue_invoice and self.amount_paid_minor_inr is None:
            raise ValueError("amount_paid_minor_inr is required when issue_invoice")
        if not self.issue_invoice and self.amount_paid_minor_inr is not None:
            raise ValueError("amount_paid_minor_inr is only used with issue_invoice")
        return self


class CreditSettingsUpdate(_Strict):
    low_balance_threshold_minor: int = Field(
        strict=True, ge=0, le=MAX_LOW_BALANCE_THRESHOLD_MINOR
    )


__all__ = ["CreditAdjustmentCreate", "CreditSettingsUpdate"]
