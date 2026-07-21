"""Pure, side-effect-free validation for the Policy domain.

Mirrors ``app.domains.guest_teams.validators``'s identical discipline: no
I/O, just "is this a legal input or transition" checks the service layer
calls before touching the database.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from app.domains.rbac.enums import ScopeType

from .constants import (
    POLICY_VERSION_STATUS_TRANSITIONS,
    PolicyAssignmentTargetType,
    PolicyType,
    PolicyVersionStatus,
)
from .exceptions import (
    InvalidPolicyAssignmentScopeTypeError,
    InvalidPolicyAssignmentTargetTypeError,
    InvalidPolicyVersionStatusTransitionError,
    PolicyAssignmentScopeIdNotAllowedError,
    PolicyAssignmentScopeIdRequiredError,
    PolicyAssignmentTargetIdNotAllowedError,
    PolicyAssignmentTargetIdRequiredError,
    PolicyRulesValidationError,
)
from .schemas import POLICY_RULE_SCHEMAS


def validate_rules(policy_type: PolicyType, rules: dict[str, Any]) -> dict[str, Any]:
    """Validates ``rules`` against the Pydantic schema registered for
    ``policy_type`` in ``schemas.POLICY_RULE_SCHEMAS``, returning the
    normalized (schema-validated) payload to persist. Raises
    ``PolicyRulesValidationError`` on any shape mismatch -- see that
    registry's own docstring for which types have a concrete schema vs. the
    generic passthrough."""
    schema = POLICY_RULE_SCHEMAS[policy_type]
    try:
        validated = schema.model_validate(rules)
    except ValidationError as exc:
        raise PolicyRulesValidationError(policy_type.value, str(exc)) from exc
    return validated.model_dump()


def validate_version_status_transition(
    *, current: PolicyVersionStatus, target: PolicyVersionStatus
) -> None:
    """Consults the exhaustive ``POLICY_VERSION_STATUS_TRANSITIONS`` graph.
    Deliberately has no "same status is a no-op" shortcut -- publishing an
    already-published version must raise, mirroring
    ``app.domains.guest_teams.validators.validate_team_status_transition``'s
    identical discipline."""
    legal_targets = POLICY_VERSION_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidPolicyVersionStatusTransitionError(current.value, target.value)


def validate_assignment_scope(*, scope_type: str, scope_id: object | None) -> None:
    """``scope_type`` must be one of ``app.domains.rbac.enums.ScopeType``'s
    values. A ``global`` assignment must have no ``scope_id``; every other
    scope type requires one -- see ``models.PolicyAssignment``'s own
    docstring for why ``scope_id`` cannot be a real, single-table foreign
    key."""
    try:
        resolved_scope_type = ScopeType(scope_type)
    except ValueError as exc:
        raise InvalidPolicyAssignmentScopeTypeError(scope_type) from exc
    if resolved_scope_type == ScopeType.GLOBAL:
        if scope_id is not None:
            raise PolicyAssignmentScopeIdNotAllowedError()
    elif scope_id is None:
        raise PolicyAssignmentScopeIdRequiredError(scope_type)


def validate_assignment_target(*, target_type: str, target_id: object | None) -> None:
    """``target_type`` must be one of
    ``constants.PolicyAssignmentTargetType``'s values. A ``none`` target
    must have no ``target_id``; ``user``/``role`` requires one -- the
    identical shape ``validate_assignment_scope`` already establishes for
    the WHERE axis, applied to the new, orthogonal WHO axis (Enterprise
    SaaS Phase F)."""
    try:
        resolved_target_type = PolicyAssignmentTargetType(target_type)
    except ValueError as exc:
        raise InvalidPolicyAssignmentTargetTypeError(target_type) from exc
    if resolved_target_type == PolicyAssignmentTargetType.NONE:
        if target_id is not None:
            raise PolicyAssignmentTargetIdNotAllowedError()
    elif target_id is None:
        raise PolicyAssignmentTargetIdRequiredError(target_type)


__all__ = [
    "validate_rules",
    "validate_version_status_transition",
    "validate_assignment_scope",
    "validate_assignment_target",
]
