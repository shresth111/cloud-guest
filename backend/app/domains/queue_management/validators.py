"""Pure, side-effect-free validation logic for the Queue Management Engine
domain -- mirrors ``app.domains.policy.validators``/
``app.domains.router_provisioning.validators``'s own identical "no I/O, no
repository access, just shape/transition checks" convention.
"""

from __future__ import annotations

import uuid

from .constants import (
    DEVICE_BOUND_TARGET_TYPES,
    QUEUE_STATUS_TRANSITIONS,
    QueueStatus,
    QueueTargetType,
)
from .exceptions import (
    InvalidQueueStatusTransitionError,
    QueueTargetIdNotAllowedError,
    QueueTargetIdRequiredError,
    QueueTargetRouterRequiredError,
)


def validate_target(
    *,
    target_type: QueueTargetType,
    target_id: uuid.UUID | None,
    router_id: uuid.UUID | None,
) -> None:
    """Enforces ``constants.QueueTargetType``'s own polymorphic shape rule
    (mirrors ``app.domains.policy.validators``'s identical
    ``PolicyAssignment.scope_id`` nullability check): ``target_id`` is
    required for every target type except ``ORGANIZATION``, and forbidden
    for ``ORGANIZATION`` itself; ``router_id`` is required for every
    device-bound target type (see
    ``constants.DEVICE_BOUND_TARGET_TYPES``)."""
    if target_type == QueueTargetType.ORGANIZATION:
        if target_id is not None:
            raise QueueTargetIdNotAllowedError()
    elif target_id is None:
        raise QueueTargetIdRequiredError(target_type.value)

    if target_type in DEVICE_BOUND_TARGET_TYPES and router_id is None:
        raise QueueTargetRouterRequiredError(target_type.value)


def validate_status_transition(*, current: QueueStatus, target: QueueStatus) -> None:
    """Consults the exhaustive ``QUEUE_STATUS_TRANSITIONS`` graph.
    Deliberately has no "same status is a no-op" shortcut -- mirrors every
    other domain's identical status-machine discipline in this codebase."""
    legal_targets = QUEUE_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidQueueStatusTransitionError(current.value, target.value)


__all__ = ["validate_target", "validate_status_transition"]
