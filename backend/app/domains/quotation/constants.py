"""Enumerations and fixed branding constants for the Quotation domain.

``QuotationStatus`` is stored as a plain ``String`` column, never a native
PostgreSQL enum type -- the same reason every other domain in this codebase
documents (see e.g. ``app.domains.demo_request.constants``): adding a new
status never requires an ``ALTER TYPE`` migration, only a code change.

## Branding constants: hardcoded, not ``Settings``-driven

``QUOTATION_COMPANY_LEGAL_NAME``/``QUOTATION_PRODUCT_NAME`` are literal,
fixed strings, not new ``Settings`` fields the way
``platform_legal_business_name`` is for GST invoices. Two reasons:

1. This is exact, non-negotiable legal/brand copy the feature spec calls
   for verbatim ("Infovertias Technologies Pvt Ltd" / "WyfyGuest") -- unlike
   an invoice's seller line (which legitimately varies per deployment/
   white-label), a sales quotation for *this* platform is never issued
   under a different legal entity or product name per environment.
2. There is real precedent for exactly this choice already in this
   codebase: ``app.domains.billing.router.generate_and_send_invoice``'s own
   email body hardcodes ``"Wyfy Guest"`` directly in the message text
   (``f"Your Wyfy Guest invoice {invoice.invoice_number}"`` /
   ``"Thank you for using Wyfy Guest."``) rather than sourcing it from
   ``Settings`` -- this module follows that same established convention for
   the identical kind of copy, one place (here) instead of a third
   ad-hoc hardcoded occurrence.
"""

from __future__ import annotations

from enum import StrEnum

QUOTATION_COMPANY_LEGAL_NAME = "Infovertias Technologies Pvt Ltd"
QUOTATION_PRODUCT_NAME = "WyfyGuest"
# Corporate Identification Number -- India's MCA-issued registration number
# for QUOTATION_COMPANY_LEGAL_NAME, same "exact, non-negotiable legal copy"
# reasoning as the two constants above (see module docstring).
QUOTATION_COMPANY_CIN = "U58201DL2024PTC437197"

# Prefix for the human-readable quotation_number shown on the PDF/UI --
# derived from the row's own UUID id (see models.py), never a separate
# atomic-counter table like app.domains.billing.number_generator's
# INV-/CN-/DN- sequences: a sales quotation is not a legally sequential
# financial document (unlike a GST invoice), so there is no compliance
# requirement for a gapless sequence, and reusing/duplicating the invoice
# counter machinery here would be needless cross-domain coupling for a
# property this domain does not actually need.
QUOTATION_NUMBER_PREFIX = "QUO"


class QuotationStatus(StrEnum):
    """Lifecycle of a generated quotation."""

    DRAFT = "draft"
    SENT = "sent"
    FAILED = "failed"


__all__ = [
    "QUOTATION_COMPANY_LEGAL_NAME",
    "QUOTATION_PRODUCT_NAME",
    "QUOTATION_COMPANY_CIN",
    "QUOTATION_NUMBER_PREFIX",
    "QuotationStatus",
]
