"""F2 per ISP, applied by ``build_twin`` (ADDENDUM_04, coordinator default).

Masked unless Master enabled unmasking for THIS ISP and the caller is its
``isp-owner``/``isp-admin`` (``parity_settings.pii_unmasked_for``). When a
request is served unmasked and the row returns guest identifiers, one
``isp_pii_unmasked_view`` audit row is written in the ISP org -- Staff
Activity shows it.
"""

from __future__ import annotations

from typing import Any

from app.middleware.request_context import get_masking_context

from .twin_privacy import force_masking

__all__ = ["PII_PATH_PREFIXES", "apply_pii_policy", "is_pii_spec", "audit_if_pii"]

#: Twins whose bodies carry guest identifiers (phone / email / MAC / IP).
PII_PATH_PREFIXES: tuple[str, ...] = (
    "/venue/guests",
    "/venue/guest-sessions",
    "/venue/otp",
    "/venue/analytics/voucher-redemptions",
    "/venue/voucher-redemptions",
    "/venue/guest-login-history",
    "/venue/connected-devices",
    "/venue/mac-authorization",
    "/venue/marketing/contacts",
    "/venue/marketing/deliveries",
    "/venue/marketing/campaigns/{campaign_id}/recipients",
    "/venue/traffic-flow/locations/{isp_location_id}/flows",
)


def is_pii_spec(spec: Any) -> bool:
    return bool(spec.redact_fields) or spec.path.startswith(PII_PATH_PREFIXES)


async def apply_pii_policy(isp: Any) -> bool:
    """Set the request's masking context; True when this request is unmasked."""
    from .parity_settings import pii_unmasked_for

    session = getattr(getattr(isp, "repository", None), "session", None)
    unmasked = bool(session is not None and await pii_unmasked_for(session, isp))
    if unmasked:
        get_masking_context().masking_enabled = False
    else:
        force_masking()
    return unmasked


async def audit_if_pii(
    spec: Any, isp: Any, resolved: tuple[Any, Any, Any, Any]
) -> None:
    if not is_pii_spec(spec):
        return
    from .parity_settings import record_unmasked_view

    await record_unmasked_view(
        isp.repository.session,
        isp,
        what=f"{spec.method} {spec.path}",
        customer_org_id=resolved[1],
        location_id=resolved[2],
    )
