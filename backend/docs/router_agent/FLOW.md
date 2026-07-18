# Router Agent: Flows and Design Decisions

This document records every design decision this module made where the
brief left room for judgment, plus the end-to-end device lifecycle. Read
this before modifying `app/domains/router_agent/` or the two targeted seams
it touches in BE-008 (`app/domains/router/schemas.py`/`router.py`).

## 1. The full device lifecycle

```text
1. Admin generates a provisioning token          POST /routers/{id}/provisioning-token
   (Router: PENDING_PROVISIONING)                 (BE-008, RequirePermission-gated)

2. Device checks in with the token                POST /routers/provisioning/check-in
   (Router: PENDING_PROVISIONING -> PROVISIONING)  (BE-008, device-presented, no auth header)
   -- additively, this same call also issues the   -> returns { router_id, status,
      device's persistent agent credential            agent_credential, agent_credential_expires_at }

3. Device authenticates every subsequent call
   with that credential (X-Agent-Credential header)

   3a. Heartbeat                                  POST /agent/heartbeat
       (Router: PROVISIONING -> ONLINE, then       (this module, composes with
        ONLINE/OFFLINE -> ONLINE on every later      RouterService.heartbeat)
        call)

   3b. Config pull                                GET /agent/config
       (reads the current applied ConfigVersion)   (this module, reads Module 009
                                                     Part 1's own tables)

   3c. Status push                                POST /agent/status
       (routeros_version / agent software         (this module: RouterAgentCredential
        version / capabilities / license)           updated every call, Router.routeros_version
                                                      refreshed only if it changed)

   3d. Action queue poll + complete                GET /agent/actions
       (an admin queued a config-push/backup/       POST /agent/actions/{job_id}/complete
        restore/factory-reset job via Module 009    (this module, composes with
        Part 1 -- this module claims + reports it)   RouterProvisioningService)

4. (Optional) Factory reset completes ->
   Router: ONLINE/OFFLINE -> PENDING_PROVISIONING
   -> back to step 1, generating a *new*
   provisioning token; the device's next check-in
   (step 2) **rotates** its existing agent
   credential rather than creating a second row.
```

## 2. Where the persistent credential is issued

**Decision: additively, inside BE-008's check-in response -- not a separate
`POST /agent/activate` endpoint.**

By the time `RouterService.check_in` returns, the one-time provisioning
token it just validated has already been consumed
(`RouterProvisioningToken.used_at` is now set -- single-use, enforced by
`ProvisioningTokenAlreadyUsedError` on any second presentation). That
check-in call is therefore the device's **last** opportunity to prove its
identity with a credential this platform already trusts before the agent
credential needs to exist.

A separate, later `POST /agent/activate` endpoint was considered and
rejected: it would need its own credential to authenticate that call, and
the only candidate is the just-consumed provisioning token, which cannot be
presented a second time without either (a) weakening its single-use
guarantee (defeating the entire point of `used_at`), or (b) accepting an
*unauthenticated* activation call, which would let anyone claim an agent
credential for any router that happens to be mid-provisioning. Returning
the newly-issued credential directly in check-in's own response sidesteps
both problems entirely, at the cost of one small, purely additive change:

* `app.domains.router.schemas.ProvisioningCheckInResponse` gained two new,
  optional fields (`agent_credential: str | None = None`,
  `agent_credential_expires_at: datetime | None = None`) -- default `None`,
  so no existing consumer of this schema is affected.
* `app.domains.router.router.provisioning_check_in` gained one additional
  call, after `RouterService.check_in` succeeds:
  `RouterAgentService.issue_credential_for_router(updated_router)`.

No other line in either file changed. `tests/unit/test_router.py`'s own
check-in tests exercise `RouterService.check_in` directly (the service
layer, not the HTTP endpoint), so they were unaffected by this change --
confirmed by the full suite still passing unmodified.

**Reissue = rotate, not duplicate.** `RouterAgentCredential.router_id` is
unique -- if a router already has a credential (a factory-reset ->
re-provision -> check-in cycle), `issue_credential_for_router` updates that
same row in place (new hash, new `expires_at`, `rotation_count`
incremented, `revoked_at` cleared) rather than inserting a second one. This
is both simpler (no "which credential is current" ambiguity) and more
secure (the previous credential's hash is immediately invalidated, since it
no longer matches any stored row).

## 3. Device credential presentation: a header, not a request body

BE-008's device-facing precedent (`POST /routers/provisioning/check-in`)
presents its one-time provisioning token in the request body. This module
deliberately does **not** copy that shape for its own, persistent
credential:

* Two of this module's five endpoints (`GET /agent/config`,
  `GET /agent/actions`) are `GET`s, which cannot cleanly carry a request
  body across all HTTP clients/proxies a real embedded device agent might
  use.
* Presenting the credential in the body on three endpoints and some other
  way on the remaining two would make this module's own client
  implementation (a real RouterOS agent) reason about two different
  presentation mechanisms for the same one credential.

Every device-facing endpoint therefore reads the credential from one custom
header, `constants.AGENT_CREDENTIAL_HEADER` (`X-Agent-Credential`) --
deliberately **not** `Authorization: Bearer`, which is already semantically
owned by `app.domains.auth`/RBAC's platform-user JWT scheme (`CurrentUser`).
Using a distinctly-named header keeps the two credential spaces visibly
separate and makes it obvious at a glance that `dependencies.CurrentAgent`
is not `RequirePermission`/`CurrentUser` wearing a disguise.

## 4. Identity verification *is* credential validation

`dependencies.CurrentAgent` is this module's entire authentication
mechanism, and there is deliberately no second, separate "verify identity"
endpoint. On every device-facing call it:

1. Reads `X-Agent-Credential`; missing -> `AgentCredentialMissingError`.
2. Hash-compares it (SHA-256, the identical fast-hash-for-high-entropy-token
   posture `RouterProvisioningToken.token_hash`/
   `RouterService._hash_token` already established) against
   `RouterAgentCredential.credential_hash`; no match ->
   `AgentCredentialInvalidError`.
3. Rejects a revoked (`AgentCredentialRevokedError`) or expired
   (`AgentCredentialExpiredError`) credential.
4. Resolves the `Router` row the credential's own `router_id` FK points to,
   and rejects `decommissioned`/`suspended` routers
   (`AgentRouterNotEligibleError`) -- composes with BE-008's own
   `RouterStatus`, no new lifecycle of its own.
5. Records `last_used_at` on the credential.

There is deliberately **no** additional serial-number/MAC-address
tamper-check layered on top of this. Unlike BE-008's enrollment flow (where
a device supplies its own claimed identity facts *before* any `Router` row
exists to check them against), every agent call's `router_id` here comes
from the *credential itself* -- resolved server-side from a FK, never from
client-supplied input. There is nothing left for a caller to spoof that
step 4 above doesn't already derive independently.

## 5. Response envelope: minimal, not `ApiResponse`

Every endpoint in `router.py` returns its own small Pydantic schema
directly, mirroring `ProvisioningCheckInResponse`'s "the calling device is
not expected to parse a rich, user-facing API contract" reasoning -- a
physical RouterOS agent has no use for `{success, message, data,
request_id}`, only the fact(s) it asked for.

## 6. Config pull: always the current *applied* version

`GET /agent/config` composes with
`RouterProvisioningRepository.get_latest_applied_version` directly (no new
repository method was needed -- this read already existed, used internally
by that module's own `apply_version`/`create_backup`). It deliberately does
**not** use `get_latest_version_for_router` (the highest `version_number`
regardless of status) -- a `draft`/`pending_apply`/`failed` version is not
safe for a device to blindly treat as "my current config" outside of the
provisioning-queue/job flow that legitimately pushes it.
`NoConfigAssignedError` (409) is raised when nothing has ever been applied
yet (no `ConfigProfile` assigned, or one assigned but never successfully
applied).

## 7. Status push: what gets stored where

`POST /agent/status` accepts `routeros_version`, `agent_software_version`,
`capabilities`, `license_key`, `license_status`:

* `routeros_version` updates BE-008's existing `Router.routeros_version`
  via `RouterService.update_router` -- **but only when a value was reported
  and it actually changed**, to avoid writing an `audit_log_entries` row
  (which `update_router` always produces) on every routine status push. A
  routine push that reports the same, unchanged version is a no-op against
  BE-008's table, exactly mirroring BE-008's own "heartbeats are frequent
  telemetry, not an admin-driven event" reasoning for why heartbeats are
  never audited.
* `agent_software_version`/`capabilities`/`license_key`/`license_status`
  are genuinely new facts with no existing home -- stored on this module's
  own `RouterAgentCredential` row, updated unconditionally on every call
  (mirrors `RouterHealthSnapshot`'s own "recorded every call, never
  audited" posture from Module 009 Part 1).
* A `RouterEvent` (`event_type="agent_status_reported"`) is written on
  every call, composed via `RouterProvisioningRepository.create_event` --
  `RouterEvent` is explicitly documented (Module 009 Part 1's own
  `models.py`) as tolerating higher-volume, non-human-attributable device
  history, unlike `audit_log_entries`.

## 8. Action queue: poll claims, complete reports

`GET /agent/actions` composes with
`RouterProvisioningRepository.list_active_jobs_for_router` (queued +
running, already existing) and, for every job still `queued`, calls
`RouterProvisioningService.start_provisioning_job` -- the exact seam that
service's own docstring names for "a real worker picking a job off the
queue." Already-`running` jobs (e.g. the agent restarted mid-job) are
surfaced as-is, **not** re-transitioned (that would spuriously bump
`attempts` again) -- the agent always sees its complete current workload,
whether freshly claimed this poll or still in flight from a previous one.

`POST /agent/actions/{job_id}/complete` calls
`RouterProvisioningService.complete_provisioning_job` directly -- the exact
seam that service's own module docstring names this module as the intended
caller of, after actually performing the device-side action.
`validate_job_belongs_to_router` (imported directly from Module 009 Part
1's `validators.py`, not duplicated) guards against one router's agent
completing a job that belongs to a different router.

## 9. No RBAC permission keys of its own

Every endpoint in this module is device-facing and carries no
`RequirePermission`/`CurrentUser` dependency at all. This module defines no
new RBAC permission keys -- there is nothing here for a *platform user* to
be authorized against.
