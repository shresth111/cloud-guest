# QoS & VOIP Priority Domain

The QoS & VOIP Priority domain is CloudGuest's per-router
traffic-classification rule inventory: Dashboard -> QoS & VOIP Priority
-> Router Service -> `qos_traffic_rules` (real device push composed via
`app.domains.network_config` -- see below).

It tracks every traffic-classification rule a router applies: a match
(either a protocol + port range -- e.g. SIP signaling on 5060/5061, RTP
media on a wider range -- or a DSCP value) mapped to a RouterOS priority
level (1-8), and an enable/disable toggle.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0045_create_qos_tables.py
  app/
    domains/
      qos/
        __init__.py
        constants.py        # MIN/MAX/DEFAULT_PRIORITY (re-exported from queue_management), DSCP bounds, QosProtocol
        models.py            # QosTrafficRule
        exceptions.py         # QosError subclasses (CloudGuestError)
        events.py              # QosTrafficRuleCreated/Updated/Deleted
        validators.py            # pure match/priority/DSCP/port-range validation
        repository.py             # QosRepositoryProtocol/Repository
        service.py                 # QosService: CRUD + validation
        schemas.py                  # Pydantic request/response DTOs
        dependencies.py               # FastAPI DI wiring (composes router's own DI)
        router.py                      # FastAPI routes (5 endpoints, all admin-facing, RBAC-gated)
      queue_management/       # composed for priority bounds only, never duplicated
      network_config/         # composes list_rules_for_router, renders /ip firewall mangle config
      router/                  # composed (get_router), never modified
      rbac/
        enums.py             # new PermissionModule.QOS (no pre-existing unclaimed module fit)
        seed.py              # AuditAction gained qos_traffic_rule_* values
  docs/
    qos/
      README.md (this file)
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_qos.py           # models/repository/service/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/qos-rules` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("qos.*")` against a brand-new `PermissionModule.QOS`
key -- see `FLOW.md` §3 for why no pre-existing, unclaimed module fit
this domain (unlike `PermissionModule.HOTSPOT`, which sat pre-seeded and
unclaimed before `app.domains.hotspot` was built).

```text
POST   /api/v1/qos-rules                 # qos.create
GET    /api/v1/qos-rules                 # qos.read
GET    /api/v1/qos-rules/{rule_id}       # qos.read
PUT    /api/v1/qos-rules/{rule_id}       # qos.update
DELETE /api/v1/qos-rules/{rule_id}       # qos.delete
```

No `EXECUTE`/`MANAGE`-gated action on this router -- real device
provisioning is composed via `app.domains.network_config`'s own
`EXECUTE`-gated push endpoint instead (mirrors `app.domains.hotspot`'s
identical scope).

`GET /qos-rules` is registered *before* `GET /qos-rules/{rule_id}` --
load-bearing route ordering (see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`.
* `app.domains.queue_management.constants.MIN_QUEUE_PRIORITY`/
  `MAX_QUEUE_PRIORITY`/`DEFAULT_QUEUE_PRIORITY` -- re-exported directly
  (not redeclared) as this domain's own `priority` column bounds, so the
  two domains can never silently drift apart. `queue_management` itself
  -- rate limits, the real RouterOS `/queue simple`/`/queue tree` device
  push -- is never touched or duplicated; this domain only classifies
  traffic, it does not manage bandwidth or priority queues itself.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

`app.domains.network_config` composes this domain's own
`list_rules_for_router` to render real RouterOS `/ip firewall mangle`
packet-marking config -- see that domain's own `FLOW.md` for the
render/push details.

## Validation

* Exactly one match kind per rule: a port range (both bounds present) or
  a DSCP value -- never both, never neither
  (`validators.validate_traffic_match`).
* `port_range_start`/`port_range_end` must both be real ports (1-65535)
  with start <= end.
* `dscp_value` must be a real DSCP value (0-63, RFC 2474's 6-bit field
  width).
* `priority` must be within `app.domains.queue_management`'s own real
  RouterOS 1-8 range.

## Honest Scope: No Live Device Push in This Pass, Composed via NCM

Mirrors `app.domains.dhcp`/`app.domains.vlan`/`app.domains
.port_forwarding`/`app.domains.hotspot`'s own "config resource + enable/
disable, realized onto a device later" precedent -- no
`device_adapters.py`, no Celery task of its own. Real device
provisioning is composed into `app.domains.network_config`'s pipeline in
the *same* pass this domain was built (mirroring Hotspot's own precedent)
-- see `FLOW.md` §2 for why only the packet-**marking** half of real QoS
is modeled, with pairing the resulting mark to an actual `/queue tree`
entry left as documented, real, separate device-side work.

## Testing

`tests/unit/test_qos.py` exercises `QosService` against small,
hand-rolled in-memory fakes for its own repository and the composed
`RouterLookupProtocol` (mirrors `test_hotspot.py`'s own "fake the narrow
Protocol boundary" precedent). Coverage: rule CRUD (tenant isolation),
traffic-match validation (exactly one of port-range/DSCP required,
re-validated on update), port-range/DSCP/priority bounds, the unpaginated
`list_rules_for_router` read path, and a structural check that every
route carries a `RequirePermission` dependency.
