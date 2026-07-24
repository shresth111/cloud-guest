"""Celery Beat task wiring for the Router domain.

Every other domain in this codebase that owns a Beat-scheduled sweep keeps
its task name/interval constants in a dedicated ``constants.py`` (see
``app.domains.guest.constants``, ``app.domains.isp.constants``,
``app.domains.connected_devices.constants``, ...) -- this module's own
enum-shaped values already live in ``enums.py`` (``RouterStatus``/
``ROUTER_STATUS_TRANSITIONS``/``RouterHealthStatus``), so this file is
purely additive: just the one sweep's task name + cadence, following the
same "never a bare magic number in ``app.core.celery_app``" convention
every other sweep in that module's own ``beat_schedule`` already follows.
"""

from __future__ import annotations

# ============================================================================
# Enrollment token expiry cleanup sweep -- see
# ``service.RouterService.sweep_expired_provisioning_tokens``'s own
# docstring and ``tasks.run_provisioning_token_cleanup_sweep``'s own
# docstring.
# ============================================================================

TASK_RUN_PROVISIONING_TOKEN_CLEANUP_SWEEP = (
    "app.domains.router.tasks.run_provisioning_token_cleanup_sweep"
)

# Once per hour -- an expired-but-unused RouterProvisioningToken is already
# fully inert the moment it expires (``check_in`` rejects it via
# ``ProvisioningTokenExpiredError`` regardless of whether this sweep has
# gotten to it yet); soft-deleting it is pure housekeeping with no
# operationally-visible urgency, the identical "day/week/month rollover
# boundary never needs finer-than-hourly latency" reasoning
# ``app.domains.guest.constants.QUOTA_RESET_SWEEP_INTERVAL_SECONDS``'s own
# docstring already establishes for an analogous low-urgency proactive
# cleanup.
PROVISIONING_TOKEN_CLEANUP_SWEEP_INTERVAL_SECONDS = 3600.0

__all__ = [
    "TASK_RUN_PROVISIONING_TOKEN_CLEANUP_SWEEP",
    "PROVISIONING_TOKEN_CLEANUP_SWEEP_INTERVAL_SECONDS",
]
