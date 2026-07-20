"""Pure, side-effect-free validation for the Guest Access Control domain.

Mirrors ``app.domains.guest.validators``'s identical discipline: no I/O,
just "is this a legal input" checks the service layer calls before
touching the database. Reuses ``app.domains.guest.validators
.normalize_mac_address``/``normalize_identifier`` directly rather than
duplicating them -- both are pure, stateless functions with no
``guest``-specific dependency, the same "import a pure validator from
another domain" precedent ``app.domains.router_agent.service`` already
establishes for ``app.domains.router_provisioning.validators
.validate_job_belongs_to_router``.
"""

from __future__ import annotations

from datetime import datetime

from app.domains.guest.validators import normalize_identifier, normalize_mac_address

from .constants import AccessRuleType
from .exceptions import InvalidRuleExpiryError, TemporaryRuleRequiresExpiryError

__all__ = [
    "normalize_identifier",
    "normalize_mac_address",
    "validate_rule_expiry",
    "is_rule_expired",
]


def validate_rule_expiry(
    *, rule_type: AccessRuleType, expires_at: datetime | None, now: datetime
) -> None:
    """Raises if ``expires_at`` is missing for a ``TEMPORARY`` rule, or is
    not in the future for any rule type that supplies one. A
    ``WHITELIST``/``BLOCKLIST``/``VIP`` rule may still carry an
    ``expires_at`` (e.g. a time-bound blocklist entry) -- only ``TEMPORARY``
    *requires* one."""
    if rule_type == AccessRuleType.TEMPORARY and expires_at is None:
        raise TemporaryRuleRequiresExpiryError()
    if expires_at is not None and expires_at <= now:
        raise InvalidRuleExpiryError()


def is_rule_expired(expires_at: datetime | None, *, now: datetime) -> bool:
    """Whether a rule's own ``expires_at`` has already passed ``now``.
    Returns ``False`` for a permanent rule (``expires_at is None``)."""
    if expires_at is None:
        return False
    return expires_at <= now
