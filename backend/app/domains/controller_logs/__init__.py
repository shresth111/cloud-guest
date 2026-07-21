"""Controller Logs domain: a read-only aggregator over every *real*
log-like table this codebase already has -- never a new logging
pipeline, never a fabricated one.

## Six real categories, six real sources -- no new table

* **Provision Logs** -> ``app.domains.provisioning_engine.models
  .ProvisionLog`` (per job).
* **Configuration Logs** -> ``app.domains.router_provisioning.models
  .ConfigVersion``.
* **Router Logs** -> ``app.domains.router_provisioning.models
  .RouterEvent``.
* **Authentication Logs (admin/user)** -> ``app.domains.auth.models
  .LoginAttempt`` -- genuinely platform-wide (no ``organization_id``
  column exists on this table).
* **Authentication Logs (guest)** -> ``app.domains.guest.models
  .GuestLoginHistory`` -- tenant-scoped.
* **System Logs** -> ``app.domains.monitoring.models.HealthCheck`` --
  platform component health (database/redis/celery/...), not
  per-router; the roadmap's own "System Logs" category is honestly
  mapped to this real, existing table rather than a fabricated
  per-router system log that doesn't exist anywhere in this codebase.

This domain owns no table of its own, no migration, no write path --
every method here is read-only, composing each source's own real
service/repository. See ``docs/controller_logs/FLOW.md`` for the full
design write-up.
"""

from __future__ import annotations
