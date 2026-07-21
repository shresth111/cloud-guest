# Controller Logs Domain

Controller Logs is CloudGuest's read-only aggregator over every *real*
log-like table this codebase already has. It owns no table of its own,
runs no migration, and has no write path -- every endpoint composes an
existing domain's own already-real service/repository and reshapes the
result into one of six log categories:

* **Provision Logs** -- `app.domains.provisioning_engine.models.ProvisionLog`
  (per provisioning job step).
* **Configuration Logs** -- `app.domains.router_provisioning.models.ConfigVersion`
  (per rendered/applied router config version).
* **Router Logs** -- `app.domains.router_provisioning.models.RouterEvent`
  (per router lifecycle event).
* **Authentication Logs (admin/user)** -- `app.domains.auth.models.LoginAttempt`,
  genuinely platform-wide (no `organization_id` column exists on this table).
* **Authentication Logs (guest)** -- `app.domains.guest.models.GuestLoginHistory`,
  genuinely tenant-scoped.
* **System Logs** -- `app.domains.monitoring.models.HealthCheck`, platform
  component health (database/redis/celery/...), honestly mapped to this
  real, existing table rather than a fabricated per-router system log
  that doesn't exist anywhere in this codebase.

Each category has its own `GET` list endpoint (standard `ApiResponse`
envelope, paginated) and its own `GET .../export` endpoint (a raw
`text/csv` response, bounded to `constants.MAX_EXPORT_ROWS` rows -- see
`FLOW.md` for why that bound equals the shared pagination ceiling, not a
separate, larger number).

See `FLOW.md` for the full design write-up, including why Provision Logs
require an in-Python merge/paginate step the other five categories don't.

## Folder Structure

```text
backend/
  app/
    domains/
      controller_logs/
        __init__.py       # module docstring: the six real sources
        constants.py       # MAX_PROVISION_JOBS_FOR_LOG_MERGE, MAX_EXPORT_ROWS
        schemas.py          # 6 response/list-response schema pairs
        service.py           # ControllerLogsService + 7 composed Protocols
        dependencies.py       # get_controller_logs_service
        router.py              # 12 endpoints under /controller-logs
  tests/
    unit/
      test_controller_logs.py
  docs/
    controller_logs/
      README.md (this file)
      FLOW.md
```

No `models.py`, `exceptions.py`, `events.py`, `repository.py`, or
`alembic/versions/*.py` exist for this domain -- there is nothing to
migrate or persist. This is a deliberately different shape from every
other domain built this session (see `FLOW.md` §1).

## RBAC

Reuses the pre-existing `PermissionModule.AUDIT_LOGS` key -- already
seeded (ahead of any real domain claiming it, mirroring the same
`DHCP`/`FIREWALL` reuse precedent `app.domains.dhcp`/`app.domains
.port_forwarding` established) with `READ`/`EXPORT`/`VIEW` actions at
`ScopeType.ORGANIZATION`. Zero RBAC changes were needed: every route
gates on `RequirePermission("audit_logs.read")` or
`RequirePermission("audit_logs.export")`, and the pre-existing "Auditor"
system role already grants `FULL` access to this module.

## API Endpoints

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/controller-logs/provision/{router_id}` | `audit_logs.read` |
| GET | `/controller-logs/provision/{router_id}/export` | `audit_logs.export` |
| GET | `/controller-logs/configuration/{router_id}` | `audit_logs.read` |
| GET | `/controller-logs/configuration/{router_id}/export` | `audit_logs.export` |
| GET | `/controller-logs/router/{router_id}` | `audit_logs.read` |
| GET | `/controller-logs/router/{router_id}/export` | `audit_logs.export` |
| GET | `/controller-logs/authentication/admin` | `audit_logs.read` |
| GET | `/controller-logs/authentication/admin/export` | `audit_logs.export` |
| GET | `/controller-logs/authentication/guest` | `audit_logs.read` |
| GET | `/controller-logs/authentication/guest/export` | `audit_logs.export` |
| GET | `/controller-logs/system` | `audit_logs.read` |
| GET | `/controller-logs/system/export` | `audit_logs.export` |
