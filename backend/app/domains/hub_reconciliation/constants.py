"""Task name, cadence, and overlap-lock constants for the reconciliation
sweep.

Mirrors every other Beat-scheduled domain's own constants module
(``app.domains.router.constants``, ``app.domains.connected_devices
.constants``, ``app.domains.provisioning_engine.constants``): the task name
and its interval are named constants here, referenced from
``app.core.celery_app``'s ``beat_schedule``, never a bare literal inline in
the schedule.
"""

from __future__ import annotations

# The Celery task name (see ``tasks.run_hub_reconciliation_sweep``), kept as
# a constant so ``app.core.celery_app``'s ``beat_schedule`` and any future
# ``task_routes`` entry both reference one string rather than repeating a
# literal that can silently drift out of sync with the ``@celery_app.task``
# decorator.
TASK_RUN_HUB_RECONCILIATION_SWEEP = (
    "app.domains.hub_reconciliation.tasks.run_hub_reconciliation_sweep"
)

# EVERY FIVE MINUTES.
#
# Shorter than most sweeps in this codebase, and deliberately so: the window
# this closes is one in which guests at a venue cannot get online at all.
# When a router's WireGuard identity and its FreeRADIUS `client{}` stanza
# disagree, FreeRADIUS drops every Access-Request from that router without
# replying -- there is no error, no log line, and no degraded mode. The
# venue is simply down, and (measured on 2026-08-27) nobody finds out until
# someone at the venue complains.
#
# Five minutes is also not arbitrary: it matches the default
# `Settings.wireguard_handshake_stale_after_minutes`, which is the window
# `resolve_live_identity_for_router` and automatic adoption both use to
# decide whether a hub-reported handshake counts as "now". A sweep that ran
# less often than that staleness window would routinely be reasoning about
# handshakes it had already declared stale.
HUB_RECONCILIATION_SWEEP_INTERVAL_SECONDS = 300.0

# Redis SETNX-style overlap-prevention lock -- identical shape to
# ``app.domains.provisioning_engine.constants
# .ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY``'s own
# (``redis.set(key, "1", nx=True, ex=...)``, explicit release in a
# ``finally``, TTL purely as a crash-safety backstop).
#
# The scope here is WIDER than that constant's, and the difference matters.
# There, the lock guards only a coordinator's listing+dispatch phase,
# because the real work is fanned out to per-router leaf tasks that Celery
# is free to run concurrently. This sweep is not fanned out: it does its own
# work inline, and that work includes pushing to the hub's FreeRADIUS agent,
# which restarts the freeradius service. Two of these running at once could
# issue overlapping `systemctl restart freeradius` calls -- exactly the race
# `radius_agent.py`'s own `_WRITE_LOCK` docstring documents, where systemd
# cancels one, `_validate_and_restart` restores the backup, and a valid
# request fails for no reason a caller can see.
#
# So this lock is load-bearing, not hygiene: at 300s spacing a pass that
# runs long (a slow hub, several rebinds each with their own retries) would
# otherwise overlap itself and fight the previous pass over one config file.
HUB_RECONCILIATION_SWEEP_LOCK_REDIS_KEY = "hub_reconciliation:sweep:lock"

# Twice the interval. Unlike the fan-out coordinators' own lock TTLs -- pure
# crash backstops on a phase expected to take milliseconds -- this one has
# to outlast a genuine full pass: the hub read, plus up to
# ``MAX_NAS_REBINDS_PER_SWEEP`` pushes, each of which can take three
# attempts with 0.5s/2.0s backoff and a 15s timeout, plus a freeradius
# restart apiece. The sweep always releases explicitly in a ``finally``;
# this only decides how long a lock survives a worker killed mid-pass.
HUB_RECONCILIATION_SWEEP_LOCK_TTL_SECONDS = 600

# HOW MANY RADIUS CLIENTS ONE PASS WILL RE-PUSH.
#
# Not a performance knob -- a blast-radius bound. Every push makes
# ``radius_agent.add_client`` run `systemctl restart freeradius`, which
# drops in-flight authentication for the ENTIRE fleet, not just the router
# being rebound. So the cost of a rebind is paid by every venue, and a pass
# that rebound fifty routers back-to-back would bounce authentication fifty
# times in a row.
#
# That is not hypothetical on the first run after this ships:
# ``hub_client_synced_ip`` is NULL on every pre-existing NAS row (the column
# is new, and nothing before it recorded what the hub confirmed), so every
# single one reads as stale and qualifies for a re-push. With one venue
# today that is one restart; the cap is what keeps that from becoming N
# restarts the day the fleet is larger.
#
# Excess work is not dropped, it is deferred: the condition that identifies
# a stale binding (`hub_client_synced_ip` disagreeing with the peer's
# address) is still true on the next pass five minutes later, so a backlog
# drains steadily instead of all at once. The sweep reports
# ``rebinds_deferred`` so a backlog is visible rather than silent.
MAX_NAS_REBINDS_PER_SWEEP = 5

# Whether the scheduled pass ADOPTS, or only reports.
#
# True, and this is the judgement call worth stating explicitly rather than
# burying in a default argument.
#
# Automatic adoption is already narrowly gated (see
# ``WireGuardService.get_fleet_status``): the issuance ledger must attribute
# the key to a specific router, the hub must report a handshake inside the
# staleness window, AND the router's currently-recorded peer must never have
# handshaked on its own key. That third condition is what makes this safe
# without a human present -- the record being overwritten is an unproven
# assertion, never a competing observation. Anything ambiguous (two live
# identities) or unattributable (no ledger row) is reported and left alone,
# so the scheduled pass can only ever replace a guess with a measurement.
#
# The argument for reporting-only was that a timer adopting unattended is a
# different risk posture from an operator clicking. It is -- but the
# asymmetry runs the other way here. Not adopting is not a neutral
# hold: it leaves a venue where no guest can authenticate, silently, until
# a human notices. The residual risk is one misattribution scenario (the
# same `.rsc` imported onto two different routers, so the ledger's
# attribution is right about the file and wrong about the device), and an
# operator clicking `adopt` has no better information about that than this
# task does -- both are reading the same ledger and the same hub.
#
# The task takes ``adopt`` as a parameter defaulting to this, so an operator
# can still invoke a report-only pass by hand without a deploy.
HUB_RECONCILIATION_SWEEP_ADOPTS = True


__all__ = [
    "TASK_RUN_HUB_RECONCILIATION_SWEEP",
    "HUB_RECONCILIATION_SWEEP_INTERVAL_SECONDS",
    "HUB_RECONCILIATION_SWEEP_LOCK_REDIS_KEY",
    "HUB_RECONCILIATION_SWEEP_LOCK_TTL_SECONDS",
    "MAX_NAS_REBINDS_PER_SWEEP",
    "HUB_RECONCILIATION_SWEEP_ADOPTS",
]
