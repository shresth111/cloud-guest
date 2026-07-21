# Connected Device Management Domain

The Connected Device Management domain is CloudGuest's per-router device
inventory: Dashboard -> Connected Device Management -> {Router Service,
Guest Access Service, Guest Repository} -> Connected Device Adapter ->
{MikroTik Connected Device Adapter (real DHCP-lease/ARP/wireless
registration-table sync), Cisco/Aruba/UniFi (future)}.

It tracks every device seen on a router's own network -- MAC address, IP
address, hostname, MAC-OUI vendor lookup, wired/wireless connection type
(with signal strength for wireless clients), which interface, active
status, connection time, and last-seen time -- plus a read-only
guest/session association, an admin comment, and device actions
(disconnect/refresh/sync/block/unblock/whitelist).

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0042_create_connected_devices_tables.py
  app/
    domains/
      connected_devices/
        __init__.py
        constants.py        # ConnectionType, OUI_VENDOR_PREFIXES (small, honest), sweep constants
        models.py            # ConnectedDevice
        exceptions.py         # ConnectedDeviceError subclasses (CloudGuestError)
        events.py              # ConnectedDeviceDiscovered/Updated/Disconnected/Deleted/AccessRuleApplied
        validators.py            # pure MAC normalization (lenient) + OUI vendor lookup
        device_adapters.py        # BaseConnectedDeviceAdapter Protocol + MikroTikConnectedDeviceAdapter (real DHCP-lease/ARP/wireless sync + disconnect)
        repository.py               # ConnectedDeviceRepositoryProtocol/Repository (+ platform-wide router enumeration)
        service.py                   # ConnectedDeviceService: sync, admin actions, guest/session cross-reference
        tasks.py                      # Celery: run_connected_device_sync_sweep (platform-wide, every 5 minutes)
        schemas.py                     # Pydantic request/response DTOs
        dependencies.py                  # FastAPI DI wiring (composes router/guest_access/guest's own DI)
        router.py                         # FastAPI routes (10 endpoints, all admin-facing, RBAC-gated)
      router/                # composed (device connection fields, decrypted API secret), never modified
      guest_access/           # composed (DeviceAccessRule create/list/deactivate for block/unblock/whitelist), never modified
      guest/                   # composed read-only (GuestDevice/GuestSession cross-reference), never modified or mutated
      rbac/
        enums.py             # PermissionModule.CONNECTED_DEVICES (new) + AuditAction gained connected_device_* values
        seed.py              # MODULE_ACTIONS/MODULE_DISPLAY_NAMES/MODULE_NARROWEST_SCOPE[PermissionModule.CONNECTED_DEVICES]
  docs/
    connected_devices/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_connected_devices.py   # sync/merge/actions/sweep/API structural tests
```

## API Surface

All endpoints are registered under `/api/v1/connected-devices` (see
`app/api/v1/router.py`). Every endpoint is RBAC-gated by
`RequirePermission("connected_devices.*")` against a brand-new, additive
`PermissionModule.CONNECTED_DEVICES` key.

```text
GET    /api/v1/connected-devices                      # connected_devices.read
POST   /api/v1/connected-devices/sync/{router_id}     # connected_devices.execute -- manual full-router sync
GET    /api/v1/connected-devices/{device_id}          # connected_devices.read
DELETE /api/v1/connected-devices/{device_id}          # connected_devices.delete
POST   /api/v1/connected-devices/{device_id}/comment  # connected_devices.update
POST   /api/v1/connected-devices/{device_id}/disconnect  # connected_devices.execute
POST   /api/v1/connected-devices/{device_id}/refresh     # connected_devices.execute
POST   /api/v1/connected-devices/{device_id}/block       # connected_devices.execute
POST   /api/v1/connected-devices/{device_id}/unblock     # connected_devices.execute
POST   /api/v1/connected-devices/{device_id}/whitelist   # connected_devices.execute
```

No `CREATE` action -- a row only ever comes into existence via a real
device sync, never a user-facing "add a device" request.

`GET /connected-devices` (list) is registered before
`GET /connected-devices/{device_id}` -- load-bearing route ordering (see
`router.py`'s own module docstring).

## Composition, Not Duplication

Reused, never re-implemented:

* `app.domains.router.service.RouterService.get_router`/
  `get_decrypted_api_secret`.
* `app.domains.guest_access.service.GuestAccessService.create_device_rule`/
  `list_device_rules`/`deactivate_device_rule` -- block/unblock/whitelist
  create or remove a real `DeviceAccessRule` row there; this domain never
  reimplements access-rule precedence.
* `app.domains.guest.repository.GuestRepositoryProtocol.get_device_by_mac`/
  `list_active_sessions_for_guest` -- a read-only cross-reference for
  "Session Association"/"Guest Association"; this domain never creates
  or mutates a guest, device, or session row.
* `GenericRepository`, `PageParams`/`PaginationMeta`, `ApiResponse`/
  `build_response`, `CloudGuestError`, RBAC's `RequirePermission`/
  `CurrentOrganization`/`audit_log_entries`.

The per-router vendor adapter is resolved dynamically from `Router.vendor`
(`device_adapter_resolver`, default
`device_adapters.get_connected_device_adapter`), mirroring
`app.domains.isp.service.IspService`'s own identical convention.

## Honest Scope: Real Device I/O, Untested End-to-End Here

`MikroTikConnectedDeviceAdapter` issues genuine RouterOS API queries --
`/ip/dhcp-server/lease`, `/ip/arp`, and
`/interface/wireless/registration-table` -- via the same real
`librouteros` dependency this codebase's other MikroTik adapters already
use. There is no live MikroTik device anywhere in this sandbox -- if
actually invoked, it raises a real `ConnectedDeviceConnectionError` the
moment it tries to open a real socket, never fabricated device data. See
`FLOW.md` §1-2 for the full merge/vendor-lookup/disconnect design and
their own honest scope notes.

## Testing

`tests/unit/test_connected_devices.py` exercises `ConnectedDeviceService`
against small, hand-rolled in-memory fakes for its own repository and
every composed cross-domain protocol (`RouterLookupProtocol`/
`GuestAccessProtocol`/`GuestLookupProtocol`) and a controllable fake
device adapter (mirrors `test_isp.py`'s own "fake the narrow Protocol
boundary" precedent). Coverage: real per-router sync (device discovery
merge, vendor lookup, existing-device updates, marking a dropped-off
device inactive), tenant isolation, admin actions (disconnect/comment/
delete/block/unblock/whitelist), the read-only guest/session association
cross-reference, the platform-wide sync sweep's per-router failure
isolation, and a structural check that every route carries a
`RequirePermission` dependency.
