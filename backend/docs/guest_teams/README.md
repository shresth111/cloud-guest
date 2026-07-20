# Guest Teams Domain

Guest Teams is grouped guest access: a named group of guests (a corporate
delegation, a wedding party, a conference cohort) who share one access
grant, are tracked/managed together as a unit via a shareable join code, and
can have their whole team's access revoked at once -- not just one guest at
a time.

This is an **extension of `app.domains.guest`**, not a new, independent
domain sitting beside it: it composes the real, already-built
`GuestService` (guest identity resolution, session lifecycle) for every
guest- and session-level operation, and reuses
`app.domains.voucher.constants.VOUCHER_CODE_ALPHABET`'s exact print-friendly
alphabet/generation approach for its own join code. See `FLOW.md` for the
full design write-up (team status lifecycle, join/removal/revocation
semantics, the RBAC permission-module decision, the shared-quota check's
real scope vs. enforcement) and `DATABASE.md` for the schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0027_create_guest_team_tables.py
  app/
    domains/
      guest_teams/
        __init__.py
        constants.py      # GuestTeamStatus, join-code alphabet/length (reused from voucher)
        models.py          # GuestTeam, GuestTeamMember (SQLAlchemy ORM)
        exceptions.py       # GuestTeamError subclasses (CloudGuestError)
        events.py          # GuestTeamCreated, GuestMemberJoined, GuestMemberRemoved, GuestTeamRevoked
        validators.py       # pure input/transition validation
        repository.py       # GuestTeamRepositoryProtocol/GuestTeamRepository
        service.py          # GuestTeamService: lifecycle, membership, summary, shared-quota check
        schemas.py           # Pydantic request/response DTOs
        dependencies.py      # get_guest_team_repository / get_guest_team_service
        router.py            # FastAPI routes (guest-facing join + admin CRUD/lifecycle)
      guest/                # composed, never modified
      voucher/               # composed (code alphabet only), never modified
      rbac/
        enums.py            # PermissionModule.GUEST_TEAMS, AuditAction gained guest_team_* values
        seed.py             # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE/SYSTEM_ROLES additions
  docs/
    guest_teams/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_guest_teams.py
```

## API Surface

All endpoints are registered under `/api/v1/guest-teams` (see
`app/api/v1/router.py`).

```text
POST   /api/v1/guest-teams/join                        # guest-facing, no RBAC
POST   /api/v1/guest-teams                              # guest_teams.create
GET    /api/v1/guest-teams                               # guest_teams.read
GET    /api/v1/guest-teams/{team_id}                      # guest_teams.read (+ summary)
DELETE /api/v1/guest-teams/{team_id}/members/{guest_id}    # guest_teams.execute
POST   /api/v1/guest-teams/{team_id}/revoke                # guest_teams.execute
```

`PermissionModule.GUEST_TEAMS` is a new, additive RBAC module (not a reuse
of `GUEST_USERS`/`GUEST_SESSIONS`) -- see `FLOW.md` §6 for the full
reasoning and the exact `SYSTEM_ROLES` overrides added. Every admin endpoint
resolves `CurrentOrganization` (`X-Organization-Id`) and passes it through
as `requesting_organization_id`, enforcing tenant scoping the same way every
other domain's router does.

`POST /guest-teams/join` carries no `RequirePermission`/`CurrentUser`
dependency at all -- the caller is a guest presenting a team's join code,
with no platform-user identity RBAC could ever grant a permission to,
mirroring `app.domains.otp`/`app.domains.voucher`/`app.domains.guest`'s own
identical guest-facing endpoints.

## Reused, Not Duplicated

* `app.domains.guest.service.GuestService._get_or_create_guest` -- guest
  identity resolution for `join_team` (composed directly, including its one
  leading-underscore "private" method, by explicit design mandate -- see
  `service.py`'s own module docstring for the full reasoning).
* `app.domains.guest.service.GuestService.get_guest_sessions` /
  `.terminate_session` / `.get_or_create_device` -- session listing,
  punitive session termination, and device tracking, for
  `remove_team_member`/`revoke_team`/`join_team` respectively. Never a
  hand-rolled bulk session-status update.
* `app.domains.voucher.constants.VOUCHER_CODE_ALPHABET` -- the team join
  code's exact alphabet, imported directly (not re-derived as a new string).
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries` (via a narrow `AuditLogWriter`
  protocol) -- the same foundational pieces every other domain reuses.
* `OrganizationService.get_organization` / `LocationService.get_location`,
  composed through the same narrow `OrganizationLookupProtocol`/
  `LocationLookupProtocol` shapes `app.domains.voucher.service` already
  defines for itself.

## Testing

`tests/unit/test_guest_teams.py` follows `test_voucher.py`/`test_guest.py`'s
conventions: hand-rolled in-memory fakes for `GuestTeamRepositoryProtocol`
and the organization/location lookups, composed with a **real**
`app.domains.guest.service.GuestService` (itself backed by an in-memory fake
`GuestRepositoryProtocol`) -- so assertions about `terminate_session`/
`get_guest_sessions`/`_get_or_create_guest` being genuinely called (not
reimplemented) are proven against the real method bodies. Coverage: team
creation + join-code generation (uniqueness, alphabet correctness), the join
flow (happy path, idempotent re-join while active, over-max-members
rejection, expired/revoked team rejection, re-join-after-removal creating a
new membership row), member removal (including its session-termination
decision, and the untouched-non-active-session control case), team
revocation (`GuestService.terminate_session` verified as actually invoked
per active member, plus a dedicated per-member failure-isolation test using
a repository that fails session lookup for one specific guest), the
shared-quota check (no-limit/under/over/ignores-non-active-sessions), team
summary, tenant isolation (team access, list scoping, revoke), and a direct,
structural check that the guest-facing join route carries no RBAC
dependency.
