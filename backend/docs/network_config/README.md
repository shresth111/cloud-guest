# Network Configuration Management Domain

Network Configuration Management (NCM) is the "provisioning-integration
mechanism" that `app.domains.dhcp`/`app.domains.vlan`/`app.domains
.port_forwarding`'s own `FLOW.md` files all explicitly deferred real
device provisioning to. It renders a router's real, currently-enabled
DHCP pools/VLANs/port-forwarding rules/hotspot profiles/QoS traffic
rules into RouterOS script text and pushes that text through `app.domains
.router_provisioning`'s own already-real config-version/apply/rollback
pipeline.

## A thin renderer, not a fourth history table

This domain owns **no table, no migration, no history of its own**.
Every config version it creates lives in `app.domains.router_provisioning
.models.ConfigVersion` (via a new `create_version_from_content` method
added to that domain -- bypassing its `ConfigTemplate`/`ConfigProfile`
machinery, which is designed for a router's *one* assigned template, not
a dynamically-recomposed, multi-source config). Every version/diff/
rollback read this domain exposes delegates directly to that domain's
own already-tested methods. See `FLOW.md` for the full design write-up,
including why this scope was chosen over an NCM-owned push-run history
table (mirrors `app.domains.controller_logs`' identical "no table" shape,
but with a real write/push path this time, unlike that domain's pure
read aggregation).

## What "push" means here

A push renders **one combined RouterOS script** covering every enabled
`DhcpPool`/`Vlan`/`PortForwardingRule`/`HotspotProfile`/`QosTrafficRule`
row currently on the target router -- a full desired-state snapshot,
mirroring how `ConfigVersion` already represents a router's whole
config, never an incremental diff. That script is queued through the
same real,
already-established pull-model provisioning queue every other config
version already flows through: a real router-side agent
(`app.domains.router_agent`) polls for and completes these jobs. This
domain fabricates no second device-I/O mechanism.

## Folder Structure

```text
backend/
  app/
    domains/
      network_config/
        __init__.py       # module docstring: the full design rationale
        constants.py       # RouterOS section-header comment strings
        exceptions.py        # EmptyNetworkConfigError (the one new error)
        renderers.py           # pure functions: rows -> RouterOS script text
        service.py               # NetworkConfigService (preview/push/rollback)
        dependencies.py            # get_network_config_service
        router.py                   # 6 endpoints under /network-config
  tests/
    unit/
      test_network_config.py
  docs/
    network_config/
      README.md (this file)
      FLOW.md
```

No `models.py`, `events.py`, `repository.py`, or `alembic/versions/*.py`
exist for this domain.

## Composition, not duplication, with six other domains

* `app.domains.dhcp` / `app.domains.vlan` / `app.domains.port_forwarding` /
  `app.domains.hotspot` / `app.domains.qos` each has an unpaginated
  `list_*_for_router` method (real, small, well-tested additions -- see
  `FLOW.md` §1) that this domain composes to read every enabled row for
  a target router. `app.domains.hotspot`/`app.domains.qos` were both
  built with this method from day one (a lesson learned from the first
  three, which needed it added retroactively).
* `app.domains.router_provisioning` gained `create_version_from_content`
  (see `FLOW.md` §2) -- everything else (`apply_version`, `get_version`,
  `list_versions`, `diff_versions`, `rollback_to_version`) is composed
  as-is, unmodified.

## RBAC

Mints a new `PermissionModule.NETWORK_CONFIG` key (no pre-existing,
unclaimed module fit this domain's own umbrella scope -- confirmed by
grepping `rbac/enums.py` before adding it, per this session's own
established discipline). Action shape mirrors `PermissionModule
.DEVICE_SYNC`'s identical "no CRUD resource of its own" posture:
`READ`/`EXECUTE`/`MANAGE`, `ScopeType.ROUTER`. The pre-existing "Network
Administrator" role gains a `FULL` override, alongside its existing
`DEVICE_SYNC`/`CONNECTED_DEVICES`/etc. grants.

## API Endpoints

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/network-config/routers/{router_id}/preview` | `network_config.read` |
| POST | `/network-config/routers/{router_id}/push` | `network_config.execute` |
| GET | `/network-config/routers/{router_id}/versions` | `network_config.read` |
| GET | `/network-config/routers/{router_id}/versions/{version_id}` | `network_config.read` |
| GET | `/network-config/routers/{router_id}/versions/{version_id}/diff/{other_version_id}` | `network_config.read` |
| POST | `/network-config/routers/{router_id}/versions/{target_version_id}/rollback` | `network_config.execute` |
