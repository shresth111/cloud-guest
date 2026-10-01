"""Constants for the security activity collector."""

from __future__ import annotations

#: Hourly: the activity view reports hourly buckets, and a router's rule
#: counters are cumulative, so reading more often adds load and no
#: information. One read-only API session per router per hour.
TASK_RUN_SECURITY_COUNTER_SWEEP = (
    "app.domains.security_activity.tasks.run_security_counter_sweep"
)
TASK_COLLECT_SECURITY_COUNTERS_FOR_ROUTER = (
    "app.domains.security_activity.tasks.collect_security_counters_for_router"
)
SECURITY_COUNTER_SWEEP_INTERVAL_SECONDS = 3600.0
SECURITY_COUNTER_SWEEP_LOCK_REDIS_KEY = "security_activity:counter_sweep:lock"
SECURITY_COUNTER_SWEEP_LOCK_TTL_SECONDS = 300
#: Leaf tasks are spread with a ``countdown`` this many seconds apart,
#: wrapping inside the window, so a fleet is never dialled all at once.
SECURITY_COUNTER_STAGGER_SECONDS = 3
SECURITY_COUNTER_STAGGER_WINDOW_SECONDS = 1800

__all__ = [
    "SECURITY_COUNTER_STAGGER_SECONDS",
    "SECURITY_COUNTER_STAGGER_WINDOW_SECONDS",
    "SECURITY_COUNTER_SWEEP_INTERVAL_SECONDS",
    "SECURITY_COUNTER_SWEEP_LOCK_REDIS_KEY",
    "SECURITY_COUNTER_SWEEP_LOCK_TTL_SECONDS",
    "TASK_COLLECT_SECURITY_COUNTERS_FOR_ROUTER",
    "TASK_RUN_SECURITY_COUNTER_SWEEP",
]
