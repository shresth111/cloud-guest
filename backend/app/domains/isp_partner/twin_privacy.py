"""PII handling for ISP twins (ADDENDUM_04 F2 default: masked).

A venue owner may switch masking off for themselves (``User.
data_masking_enabled``); the customer app's ``Masked*`` serializers then show
raw phone numbers and emails. ISP staff are not the venue: founder question F2
is open, and its default is **masked**, with the IPDR export as the legal route
to raw identifiers.

Two layers, both applied by ``build_twin``:

1. ``force_masking()`` turns the request's masking context ON before the
   original handler serializes, whatever the ISP user's own flag says. Every
   ``MaskedIdentifier``/``MaskedName``/... field in the original response is
   therefore masked exactly as the customer app masks it for a masked user.
2. Some originals return identifiers as plain ``str`` (``GuestSessionResponse.
   guest_identifier``, ``OtpRequestAdminResponse.identifier``,
   ``VoucherRedemptionEntryResponse.redeemed_identifier``). A row lists those
   keys in ``TwinSpec.redact_fields`` and ``redact()`` masks them in the body
   with the same ``mask_identifier`` the serializers use.

**Flip:** ``ISP_PARTNER_PII_UNMASKED=true`` (``IspPartnerPolicy.pii_unmasked``)
turns both layers off, so ISP users get exactly what the original returns for
their own masking flag. Default false.
"""

from __future__ import annotations

from typing import Any

from app.common.masking import mask_identifier
from app.middleware.request_context import get_masking_context

from .policy import get_isp_partner_policy

__all__ = ["force_masking", "redact"]


def force_masking() -> None:
    if get_isp_partner_policy().pii_unmasked:
        return
    get_masking_context().masking_enabled = True


def _walk(node: Any, keys: frozenset[str]) -> Any:
    if isinstance(node, dict):
        return {
            k: (
                mask_identifier(v)
                if k in keys and isinstance(v, str)
                else _walk(v, keys)
            )
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [_walk(item, keys) for item in node]
    return node


def redact(body: Any, fields: tuple[str, ...]) -> Any:
    """Mask the named keys anywhere in a JSON-shaped body (dicts only)."""
    if not fields or get_isp_partner_policy().pii_unmasked:
        return body
    if not isinstance(body, dict | list):
        return body
    return _walk(body, frozenset(fields))
