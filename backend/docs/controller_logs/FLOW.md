# Controller Logs -- Design Notes

## 1. Why this domain has no table, no migration, no repository

Every other domain built this session (ISP Management through Device
Synchronization) owns real state: a table, a migration, a repository.
Controller Logs is deliberately different -- the roadmap's "Controller
Logs" capability is a *view* over logs that already exist, scattered
across five other domains' own tables. Building a sixth, duplicate log
table and copying rows into it would create exactly the drift/staleness
risk this codebase's own composition-over-duplication discipline exists
to avoid. Instead, `ControllerLogsService` composes seven narrow,
duck-typed Protocols, each satisfied structurally by a real, already-wired
service or repository:

* `ProvisioningJobLookupProtocol` -> `ProvisioningEngineService.get_history`
* `ProvisionLogLookupProtocol` -> `ProvisioningEngineRepositoryProtocol.list_logs_for_job`
  (repository-level; no service wrapper exists for this one read)
* `ConfigVersionLookupProtocol` -> `RouterProvisioningService.list_versions`
* `RouterEventLookupProtocol` -> `RouterProvisioningService.list_events`
* `LoginAttemptLookupProtocol` -> `AuthService.list_login_attempts` (added
  to `app.domains.auth` specifically for this consumer -- see §3)
* `GuestLoginHistoryLookupProtocol` -> `GuestRepositoryProtocol
  .list_login_history` (composed directly, not through a `GuestService`
  wrapper -- mirrors `app.domains.connected_devices`'s own "narrow read,
  skip the heavy service dependency chain" precedent)
* `HealthCheckLookupProtocol` -> `MonitoringService.get_health_history`

## 2. Provision Logs: the one category that needs an in-Python merge

`ProvisionLog` rows are stored per `ProvisionJob`, not per router --
there is no single query that returns "every log line for router X"
directly. Listing provision logs for a router means:

1. Fetch this router's own most recent `MAX_PROVISION_JOBS_FOR_LOG_MERGE`
   (20) jobs via the real, org-validating `get_history`.
2. Fetch each job's own real logs via `list_logs_for_job`.
3. Merge, sort newest-first, and paginate in Python using the same real
   `PageParams`/`PaginationMeta.from_total` utilities every repository's
   own `.paginate()` call uses internally (`_paginate_in_memory` in
   `service.py`) -- not a hand-rolled parallel pagination mechanism.

The 20-job bound is a real, documented limit, not a silent, unbounded
fetch across every job a router has ever had. The other five categories
already have a single queryable table scoped by router/organization, so
they pass straight through to that domain's own paginated list method.

## 3. Two authentication-log scopes, never merged

`LoginAttempt` (`app.domains.auth`) has no `organization_id` column at
all -- a login attempt is recorded by email/IP, not scoped to one
organization; this table is genuinely platform-wide. `GuestLoginHistory`
(`app.domains.guest`) already carries `organization_id`/`location_id` --
genuinely tenant-scoped. Forcing these into one "Authentication Logs"
list would either fabricate a tenant scope the admin-login side doesn't
have, or silently drop the guest side's own real tenant filter. Controller
Logs exposes them as two distinct methods/endpoints instead:
`list_admin_authentication_logs` (no organization filter, ever) and
`list_guest_authentication_logs` (organization-scoped).

Neither `app.domains.auth` nor `app.domains.guest` had a listing method
for these tables before this domain needed one -- `list_login_attempts`
was added to `AuthRepository`/`AuthService`, and `list_login_history` was
added to `GuestRepository` (repository-level only; no `GuestService`
wrapper), each a small, real, paginated method mirroring that domain's
own existing conventions, not reimplemented inside `controller_logs`
itself.

## 4. System Logs: platform health, not a per-router log

The roadmap's "System Logs" category has no direct analog in this
codebase -- there is no per-router system log table anywhere. The closest
real, honest mapping is `app.domains.monitoring.models.HealthCheck`:
platform component health (database/redis/celery/api/auth/storage/
websocket/freeradius/wireguard), not per-router. `HealthCheckLookupProtocol
.get_health_history` requires a `component`; there is no "all components"
mode on the real source this composes, so `GET /controller-logs/system`
requires `component` as a query parameter rather than silently defaulting
to one component or fabricating a merged view across all of them.

## 5. CSV export bound: `MAX_EXPORT_ROWS == MAX_PAGE_SIZE`, not a bigger number

Every category here except Provision Logs reads through some domain's own
`GenericRepository.paginate` (directly, or via that domain's own service
method), which clamps `page_size` to `app.database.constants.MAX_PAGE_SIZE`
(100) via `PageParams.__post_init__` regardless of what a caller requests.
An initial draft set `MAX_EXPORT_ROWS = 1000`, which would have silently
truncated to 100 rows at that lower layer -- exactly the silent-truncation
failure mode this domain's own docstrings promise never happens. Fixed by
setting `MAX_EXPORT_ROWS = MAX_PAGE_SIZE` (imported, not hand-copied) so
the documented bound matches what the export endpoints can actually
return. A future domain wanting a genuinely larger, true "export
everything" capability would need a dedicated non-paginated `list_all_*`
repository method on the owning domain, mirroring `app.domains.voucher
.VoucherRepository.list_all_vouchers_for_batch` /
`app.domains.mac_authorization.MacAuthorizationRepository
.list_all_for_organization` -- out of scope for this read-only aggregator,
which only ever composes each source's own existing paginated method.

## 6. RBAC: zero new permission keys

`PermissionModule.AUDIT_LOGS` was already seeded (`READ`/`EXPORT`/`VIEW`
actions, `ScopeType.ORGANIZATION`) with no domain claiming it yet --
mirroring the same "pre-seeded ahead of any real domain" posture
`PermissionModule.DHCP`/`FIREWALL` had before `app.domains.dhcp`/
`app.domains.port_forwarding` filled them in. Log viewing/export is
exactly what this module was seeded for, so Controller Logs reuses it
entirely: `RequirePermission("audit_logs.read")` gates every list
endpoint, `RequirePermission("audit_logs.export")` gates every export
endpoint. No `seed.py` change was needed -- the pre-existing "Auditor"
system role already grants `FULL` access to `AUDIT_LOGS`.
