# Policy Domain

Policy is the Unified Policy Engine: a single source of truth for
per-organization/location-configurable rules (session limits, authentication
rate limits, and, structurally, bandwidth/FUP/business-hours/access/VLAN/QoS/
routing policies), their assignment to a scope, and their versioning.

This module follows the design already written and merged into this
codebase in `docs/ARCHITECTURE_DESIGN.md` §6.1/§13 *before* this module was
built. A deliberate **leaf module**: it depends only on
`app.domains.organization`/`app.domains.location` (tenant/hierarchy lookups)
and `app.domains.rbac` (audit logging, and reusing `ScopeType` for assignment
scoping) -- never on `app.domains.guest`/`app.domains.guest_access`/
`app.domains.voucher`/etc. Those modules would depend on this one, never the
reverse, so `policy` can never be part of an import cycle as more consumers
are added. See `FLOW.md` for the full design write-up and `DATABASE.md` for
the schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0029_create_policy_tables.py
  app/
    domains/
      policy/
        __init__.py
        constants.py      # PolicyType, PolicyVersionStatus, PLATFORM_DEFAULT_RULES
        models.py          # Policy, PolicyVersion, PolicyAssignment (SQLAlchemy ORM)
        exceptions.py       # PolicyError subclasses (CloudGuestError)
        events.py           # PolicyCreated, PolicyVersionPublished, PolicyRolledBack, ...
        validators.py        # pure input/transition/scope validation
        schemas.py            # Pydantic DTOs + per-PolicyType rule schemas (POLICY_RULE_SCHEMAS)
        repository.py          # PolicyRepositoryProtocol/PolicyRepository
        service.py               # PolicyService + pure PolicyResolver
        dependencies.py           # get_policy_repository / get_policy_service
        router.py                 # FastAPI routes (all admin-facing, RBAC-gated)
      organization/         # composed (tenant lookup), never modified
      location/             # composed (hierarchy lookup), never modified
      rbac/
        enums.py            # PermissionModule.POLICY, AuditAction gained policy_* values
        seed.py             # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE/SYSTEM_ROLES additions
  docs/
    policy/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_policy.py
```

## API Surface

All endpoints are registered under `/api/v1/policies` (see
`app/api/v1/router.py`). Unlike most domains in this codebase, there is
**no guest-facing route at all** here -- Policy has no anonymous caller;
other domains would compose `PolicyService` directly, in-process (see
`FLOW.md`'s "what this module does not do yet" section).

```text
GET    /api/v1/policies/resolve                                # policy.read -- effective-policy resolution
POST   /api/v1/policies                                        # policy.create
GET    /api/v1/policies                                        # policy.read
GET    /api/v1/policies/{policy_id}                             # policy.read (+ versions + assignments)
POST   /api/v1/policies/{policy_id}/deactivate                   # policy.execute
POST   /api/v1/policies/{policy_id}/versions                      # policy.update
POST   /api/v1/policies/{policy_id}/versions/{version_id}/publish   # policy.execute
POST   /api/v1/policies/{policy_id}/rollback                        # policy.execute
POST   /api/v1/policies/{policy_id}/assignments                      # policy.create
GET    /api/v1/policies/{policy_id}/assignments                       # policy.read
DELETE /api/v1/policies/{policy_id}/assignments/{assignment_id}        # policy.execute
```

`GET /policies/resolve` is registered *before* `GET /policies/{policy_id}`
in `router.py` -- load-bearing route ordering, see that file's own module
docstring.

`PermissionModule.POLICY` is a new, additive RBAC module -- see `FLOW.md` §6
for the full reasoning and the exact `SYSTEM_ROLES` overrides added
(`Network Administrator`/`Location Manager`: `OPERATE`; `Helpdesk`: `READ`;
every `FULL`/`OPERATE`/`READ`-by-default role picks it up automatically).

## Reused, Not Duplicated

* `app.domains.rbac.enums.ScopeType` -- `PolicyAssignment.scope_type` reuses
  this exact enum's values (`global`/`organization`/`location`) rather than
  inventing a parallel one.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries` (via a narrow `AuditLogWriter`
  protocol) -- the same foundational pieces every other domain reuses.
* `OrganizationService.get_organization` / `LocationService.get_location`,
  composed through the same narrow `OrganizationLookupProtocol`/
  `LocationLookupProtocol` shapes `app.domains.guest_teams.service`/
  `app.domains.voucher.service` already define for themselves.

## Gap Analysis -- What This Module's Default Rules Mirror

`constants.PLATFORM_DEFAULT_RULES` mirrors real, already-hardcoded platform
constants found by grepping `app.domains.guest.constants`/
`app.domains.voucher.constants` for genuine per-organization-configurability
candidates:

| Policy rule | Mirrors | Original value |
|---|---|---|
| `SESSION.session_timeout_minutes` | `guest.constants.DEFAULT_SESSION_TIMEOUT_MINUTES` | 240 |
| `SESSION.max_concurrent_sessions_per_guest` | `guest.constants.DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST` | 3 |
| `SESSION.termination_reconnect_cooldown_minutes` | `guest.constants.TERMINATION_RECONNECT_COOLDOWN_MINUTES` | 60 |
| `SESSION.reconnect_grace_minutes` | `guest.constants.RECONNECT_GRACE_MINUTES` | 30 |
| `AUTHN.max_attempts_per_window` | `voucher.constants.DEFAULT_REDEMPTION_MAX_ATTEMPTS_PER_WINDOW` | 30 |
| `AUTHN.window_minutes` | `voucher.constants.DEFAULT_REDEMPTION_WINDOW_MINUTES` | 1 |

`guest.constants.DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`'s own docstring
already named this exact module as its intended successor before this module
existed. See `constants.py`'s own module docstring for why these values are
duplicated as literals rather than imported (leaf-module acyclicity), and
`FLOW.md` §9 for why `BANDWIDTH`/`FUP`/`BUSINESS_HOURS`/`ACCESS`/`VLAN`/
`QOS`/`ROUTING` have no seeded default yet.

## What This Module Does Not Do Yet

No consumer (`guest`, `guest_access`, `voucher`) has been rewired to
actually call `PolicyService.resolve_effective_policy` in place of its own
hardcoded constant. This module builds the real, working leaf itself --
correct, tested, versioned, resolvable end to end -- but wiring an existing
domain's enforcement path to read from it is a separate, later change,
outside this module's own directory boundary (see `FLOW.md`'s own write-up).
This is an honest scope boundary, not an unfinished feature: every piece
inside `app.domains.policy` itself is real and fully functional today.

## Testing

`tests/unit/test_policy.py` follows `test_guest_teams.py`'s conventions:
hand-rolled in-memory fakes for `PolicyRepositoryProtocol` and the
organization/location lookups. Coverage: policy creation (organization-scoped
and platform-wide, cross-organization rejection), rules validation against
the per-`PolicyType` schema registry (valid/missing/negative fields, the
generic passthrough for unseeded types), version numbering, publish/rollback
(the exhaustive status-transition graph, immutability of already-published
rules across later versions, rollback-target-mismatch/not-published
rejection), assignment creation (scope validation, the
publish-required precondition), effective-policy resolution (platform-default
fallback, organization-beats-nothing, location-beats-organization, priority
tie-break at the same scope, a deactivated assignment no longer being a
candidate), tenant isolation (cross-organization read rejection, a
platform-wide policy being readable by every organization, list scoping),
and a structural check that every route in this domain carries a
`RequirePermission` dependency (there is no guest-facing route here at all).
