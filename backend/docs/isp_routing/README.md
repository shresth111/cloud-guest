# ISP Routing Domain

The ISP Routing domain is CloudGuest's per-router traffic-steering rule
inventory: Dashboard -> ISP Routing -> {Router Service, ISP Service} ->
`isp_routing_rules` (real device push deferred -- see below).

It decides which `app.domains.isp` `IspLink` (WAN uplink) a piece of
traffic should route through: VLAN Routing, User Routing, IP Routing,
Source Routing, Interface Routing, Policy Routing -- one `rule_type`
discriminator with exactly one populated match field per type (`vlan_id`/
`source_mac_address`/`ip_address`/`source_cidr`/`interface_name`/
`policy_id`), plus a `priority` (lower tried first) and `is_enabled`
toggle.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0037_create_isp_routing_tables.py
  app/
    domains/
      isp_routing/
        __init__.py
        constants.py        # IspRoutingRuleType
        models.py            # IspRoutingRule
        exceptions.py         # IspRoutingError subclasses (CloudGuestError)
        events.py              # IspRoutingRuleCreated/Updated/Deleted
        validators.py            # pure per-rule_type match-field validation
        repository.py             # IspRoutingRepositoryProtocol/Repository
        service.py                  # IspRoutingService: CRUD + validation
        schemas.py                   # Pydantic request/response DTOs
        dependencies.py                # FastAPI DI wiring (composes router + isp's own DI)
        router.py                       # FastAPI routes (5 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (get_router), never modified
      isp/                    # composed (get_link, for isp_link/router validation), never modified
      rbac/
        enums.py             # PermissionModule.ISP_ROUTING (new) + AuditAction gained isp_routing_* values
        seed.py              # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE[PermissionModule.ISP_ROUTING]
  docs/
    isp_routing/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_isp_routing.py   # models/repository/service/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/isp-routing` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("isp_routing.*")` against a brand-new, additive
`PermissionModule.ISP_ROUTING` key.

```text
POST   /api/v1/isp-routing/rules                 # isp_routing.create
GET    /api/v1/isp-routing/rules                 # isp_routing.read
GET    /api/v1/isp-routing/rules/{rule_id}       # isp_routing.read
PUT    /api/v1/isp-routing/rules/{rule_id}       # isp_routing.update
DELETE /api/v1/isp-routing/rules/{rule_id}       # isp_routing.delete
```

No `EXECUTE` action -- unlike `app.domains.isp`'s own manual health-check/
failover/failback triggers, this domain has no device-facing action in
this pass.

`GET /rules` is registered *before* `GET /rules/{rule_id}` -- load-bearing
route ordering (see `router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`.
* `app.domains.isp.service.IspService.get_link` -- validates the
  `isp_link_id` supplied for a rule both exists (tenant-scoped) and
  belongs to the same `router_id` the rule itself is scoped to.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

## Honest Scope: No Live Device Push in This Pass

Unlike `app.domains.isp`/`app.domains.queue_management`, this domain has
no `device_adapters.py` and no Celery task -- it mirrors
`app.domains.policy`'s own "priority + enable/disable, realized onto a
device later" precedent instead. Real RouterOS policy routing needs
`/ip firewall mangle` (routing marks) + `/routing table`/`/ip route`
(per-mark default routes) plumbing together -- that belongs to the
not-yet-built Network Configuration Management domain's own
provisioning-integration layer (which is explicitly scoped to compose
DHCP/VLAN/Port Forwarding/QoS/ISP Routing/Hotspot Settings behind one
versioning/backup/restore/rollback mechanism), not this one. See
`FLOW.md` §2 for the full reasoning.

## Testing

`tests/unit/test_isp_routing.py` exercises `IspRoutingService` against
small, hand-rolled in-memory fakes for its own repository and the composed
`RouterLookupProtocol`/`IspLinkLookupProtocol` (mirrors
`test_isp.py`'s own "fake the narrow Protocol boundary" precedent).
Coverage: rule CRUD (tenant isolation), per-rule-type match-field
validation on both create and update (including a `rule_type` change that
invalidates the previously-set match field), isp_link/router mismatch
rejection, and a structural check that every route carries a
`RequirePermission` dependency.
