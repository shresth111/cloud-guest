# Port Forwarding Management Domain

The Port Forwarding Management domain is CloudGuest's per-router
port-forwarding (NAT DSTNAT) rule inventory: Dashboard -> Port Forwarding
Management -> Router Service -> `port_forwarding_rules` (real device push
deferred -- see below).

It tracks every port-forwarding rule a router carries: name, protocol
(TCP/UDP/both), an optional source-address restriction, an optional
destination-address match (the router's own WAN address this rule
matches; unset means "any"), destination port, internal target
address/port, description, and an enable/disable toggle. Two rules that
would both claim the same external protocol/destination-address/
destination-port are rejected.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0040_create_port_forwarding_tables.py
  app/
    domains/
      port_forwarding/
        __init__.py
        constants.py        # PortForwardingProtocol, MIN_PORT/MAX_PORT
        models.py            # PortForwardingRule
        exceptions.py         # PortForwardingError subclasses (CloudGuestError)
        events.py              # PortForwardingRuleCreated/Updated/Deleted
        validators.py            # pure port/address validation + overlap checks
        repository.py             # PortForwardingRepositoryProtocol/Repository
        service.py                 # PortForwardingService: CRUD + validation + conflict detection
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI DI wiring (composes router's own DI)
        router.py                      # FastAPI routes (5 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (get_router), never modified
      rbac/
        enums.py             # AuditAction gained port_forwarding_rule_* values (PermissionModule.FIREWALL already existed)
        seed.py              # no change -- PermissionModule.FIREWALL's action tuple/scope/role grant already fit
  docs/
    port_forwarding/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_port_forwarding.py   # models/repository/service/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/port-forwarding` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("firewall.*")` -- this domain reuses the pre-existing
`PermissionModule.FIREWALL` key (port forwarding is a real RouterOS
`/ip firewall nat` DSTNAT concept, the same reuse posture
`app.domains.dhcp` established for the pre-existing
`PermissionModule.DHCP`).

```text
POST   /api/v1/port-forwarding/rules                 # firewall.create
GET    /api/v1/port-forwarding/rules                 # firewall.read
GET    /api/v1/port-forwarding/rules/{rule_id}       # firewall.read
PUT    /api/v1/port-forwarding/rules/{rule_id}       # firewall.update
DELETE /api/v1/port-forwarding/rules/{rule_id}       # firewall.delete
```

`GET /rules` is registered *before* `GET /rules/{rule_id}` -- load-bearing
route ordering (see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

## Validation and Conflict Detection

* `destination_port`/`internal_port` must fall within the real 1-65535
  range -- `validators.validate_port`.
* `source_address`/`destination_address`, when supplied, must be real,
  parseable IP addresses or CIDR blocks -- `validators.validate_address`.
* `internal_address` must be a real, parseable *single-host* IP -- CIDR
  notation is rejected (a DSTNAT rule's own target is always exactly one
  host) -- `validators.validate_ip_address`.
* A rule's `(protocol, destination_address, destination_port)` is
  checked against every other non-deleted rule on the *same router* for
  overlap (`PortForwardingConflictError`) -- `protocol="both"` and
  `destination_address=None` ("any") are treated as overlapping every
  other value, mirroring real RouterOS DSTNAT wildcard semantics. This is
  a service-layer check only, not a database constraint (see `models.py`'s
  own module docstring for why).

## Honest Scope: No Live Device Push in This Pass

Mirrors `app.domains.dhcp`/`app.domains.vlan`/`app.domains.isp_routing`'s
own "config resource + enable/disable, realized onto a device later"
precedent exactly -- no `device_adapters.py`, no Celery task. Real
RouterOS `/ip firewall nat` DSTNAT provisioning belongs to the not-yet-
built Network Configuration Management domain's own
provisioning-integration layer. See `FLOW.md` §2 for the full reasoning.

## Testing

`tests/unit/test_port_forwarding.py` exercises `PortForwardingService`
against small, hand-rolled in-memory fakes for its own repository and the
composed `RouterLookupProtocol` (mirrors `test_dhcp.py`'s own "fake the
narrow Protocol boundary" precedent). Coverage: rule CRUD (tenant
isolation), port-range validation, address validation (source/destination
CIDR-or-IP, internal single-host-only), conflict detection (overlap
rejected when protocol+destination_address+destination_port overlap on
the same router, allowed across different ports/protocols/addresses or
different routers, re-checked on update excluding the rule itself), and a
structural check that every route carries a `RequirePermission`
dependency.
