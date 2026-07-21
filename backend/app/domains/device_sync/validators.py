"""Pure helpers for the Device Synchronization domain -- no I/O, easy to
unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

from .constants import SyncComponentStatus, SyncRunStatus


def compute_overall_status(
    component_results: dict[str, dict[str, object]],
) -> SyncRunStatus:
    """Computes the overall run status from each component's own result.
    Components reported ``NOT_PROVISIONED`` (see
    ``constants.UNPROVISIONED_COMPONENTS``) are excluded entirely --
    they never had a real operation to succeed or fail at, so they can
    never drag an otherwise-clean run down to ``PARTIAL``. Among the
    remaining, real components: all succeeded (or ``NO_JOBS``, itself
    not a failure) -> ``SUCCESS``; all failed -> ``FAILED``; a mix ->
    ``PARTIAL``. A run with no real components counted at all (should
    not happen in practice -- see module docstring's own three
    always-attempted components) is treated as ``SUCCESS``, not a
    fabricated failure."""
    counted = [
        result["status"]
        for result in component_results.values()
        if result["status"] != SyncComponentStatus.NOT_PROVISIONED.value
    ]
    if not counted:
        return SyncRunStatus.SUCCESS
    failures = sum(
        1 for status in counted if status == SyncComponentStatus.FAILED.value
    )
    if failures == 0:
        return SyncRunStatus.SUCCESS
    if failures == len(counted):
        return SyncRunStatus.FAILED
    return SyncRunStatus.PARTIAL


__all__ = ["compute_overall_status"]
