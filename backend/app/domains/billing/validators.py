"""Pure, side-effect-free validation for the Billing domain.

Mirrors ``app.domains.otp.validators``/``app.domains.wireguard.validators``'s
identical discipline: no I/O, just "is this a legal input" checks the
service layer can call before touching the database.
"""

from __future__ import annotations

from decimal import Decimal

from .constants import FEATURE_KEY_TYPE, PlanFeatureKey, PlanFeatureType, SupportTier
from .exceptions import InvalidPlanFeatureValueError


def normalize_slug(slug: str) -> str:
    return slug.strip().lower()


def expected_feature_type(feature_key: PlanFeatureKey) -> PlanFeatureType:
    """The one legal ``feature_type`` for a given ``feature_key`` -- see
    ``constants.FEATURE_KEY_TYPE``."""
    return FEATURE_KEY_TYPE[feature_key]


def validate_feature_value(
    *,
    feature_key: PlanFeatureKey,
    feature_type: PlanFeatureType,
    limit_value: Decimal | None,
    is_enabled: bool | None,
    tier_value: str | None,
) -> None:
    """Raises ``InvalidPlanFeatureValueError`` unless ``feature_type`` is the
    one legal type for ``feature_key`` (per
    ``constants.FEATURE_KEY_TYPE``) and exactly the matching typed column is
    populated -- see ``models.PlanFeature``'s docstring for why this module
    uses three typed columns rather than one JSONB blob."""
    required_type = expected_feature_type(feature_key)
    if feature_type != required_type:
        raise InvalidPlanFeatureValueError(
            f"Feature '{feature_key.value}' must use feature_type "
            f"'{required_type.value}', not '{feature_type.value}'"
        )

    if feature_type == PlanFeatureType.LIMIT:
        if limit_value is None:
            raise InvalidPlanFeatureValueError(
                f"Feature '{feature_key.value}' is LIMIT-typed and requires "
                "limit_value"
            )
        if limit_value < 0:
            raise InvalidPlanFeatureValueError("limit_value cannot be negative")
        if is_enabled is not None or tier_value is not None:
            raise InvalidPlanFeatureValueError(
                "LIMIT-typed features must not set is_enabled/tier_value"
            )
    elif feature_type == PlanFeatureType.BOOLEAN:
        if is_enabled is None:
            raise InvalidPlanFeatureValueError(
                f"Feature '{feature_key.value}' is BOOLEAN-typed and requires "
                "is_enabled"
            )
        if limit_value is not None or tier_value is not None:
            raise InvalidPlanFeatureValueError(
                "BOOLEAN-typed features must not set limit_value/tier_value"
            )
    else:  # TIER
        if tier_value is None:
            raise InvalidPlanFeatureValueError(
                f"Feature '{feature_key.value}' is TIER-typed and requires "
                "tier_value"
            )
        if tier_value not in {tier.value for tier in SupportTier}:
            raise InvalidPlanFeatureValueError(
                f"'{tier_value}' is not a legal tier_value "
                f"({', '.join(tier.value for tier in SupportTier)})"
            )
        if limit_value is not None or is_enabled is not None:
            raise InvalidPlanFeatureValueError(
                "TIER-typed features must not set limit_value/is_enabled"
            )


__all__ = ["normalize_slug", "expected_feature_type", "validate_feature_value"]
