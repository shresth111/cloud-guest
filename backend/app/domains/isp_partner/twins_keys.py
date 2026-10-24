"""ISP key alignment for venue twins (QA-016).

ADDENDUM_04 §3/§4: Login Page Offers and venue Vouchers are Engagement, read
with ``isp_engage.read`` (every ISP role holds it; ``isp-billing`` too). The
cherry-picked report rows read campaigns and voucher batches with
``isp_access.read``, which ``isp-billing`` does not hold, so the shell showed
billing those items (their nav ``anyOf`` includes ``isp_engage.read``) and the
page then 403'd. The rows stay where they are; this maps their READ key.
"""

from __future__ import annotations

from dataclasses import replace

from .constants import ISP_ENGAGE_READ
from .twins import TwinSpec

__all__ = ["ENGAGE_READ_PATHS", "with_aligned_key"]

ENGAGE_READ_PATHS: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/venue/campaigns"),
        ("GET", "/venue/campaigns/{campaign_id}/results"),
        ("GET", "/venue/voucher-batches"),
        ("GET", "/venue/voucher-batches/{batch_id}/stats"),
    }
)


def with_aligned_key(spec: TwinSpec) -> TwinSpec:
    if (spec.method, spec.path) in ENGAGE_READ_PATHS:
        return replace(spec, permission_key=ISP_ENGAGE_READ)
    return spec
