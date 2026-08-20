# wyfy-device-gateway

Vendor-agnostic network device gateway for Wyfy Guest (formerly branded "ZIP WiFi" / "CloudGuest").

## What this is

Wyfy Guest's main platform (`cloud-guest-repo`) speaks to MikroTik RouterOS devices through
this package: **one** stable interface (`wyfy_device_gateway.contract.DeviceGatewayAdapter`) that
the backend calls regardless of vendor, with one adapter implementation per vendor behind it.

Read [`PRD.md`](./PRD.md) before touching any code.

## What this is not

- Not a rewrite of RADIUS/hotspot auth (standard RADIUS — out of scope; PRD §2.3).
- Not a running HTTP service in Phase 1 — a library `cloud-guest-repo` vendors into
  `backend/vendor/wyfy-device-gateway/` (private repos; Docker build has no git credentials).
- Not a secrets/encryption layer — `cloud-guest-repo` decrypts credentials per call (PRD §6).

## Status

**Phase 1 write path — shipped.** `contract.py`, `mikrotik_adapter.py` (`MikroTikAdapter`), and
vendor stubs are implemented with unit tests against a fake transport (no live device required).

**Wave 1 read-only discovery — shipped in the vendored copy.** `read_only_reader.py`
(`ReadOnlyDeviceReader`) is used by `POST /api/v1/routers/{id}/discover` in `cloud-guest-repo`.
It is read-only **by construction** (no write methods, print-path allowlist, row sanitization before
persistence). Source of truth today: `cloud-guest-repo/backend/vendor/wyfy-device-gateway/` —
backport to this standalone repo is tracked separately.

**Call-site migration (PRD §7) — in progress.** `router/device_adapters.py` (`list_available_device_interfaces`,
`reboot_device`) delegates here. Other domains (`network_diagnostics`, `queue_management`, most of
`provisioning_engine`, granular `isp/device_adapters` methods) remain on legacy adapters until the
contract is extended deliberately — see PRD §4.1 Phase 2 deferrals.

**Operator docs (Wave 1):** `cloud-guest-repo/backend/docs/router_fleet/` — provisioning runbook and
live-venue adoption procedure.

## Repo layout

```
wyfy_device_gateway/
  __init__.py
  contract.py           # DeviceGatewayAdapter Protocol + shared dataclasses
  mikrotik_adapter.py    # MikroTikAdapter — librouteros API + asyncssh provision path
  read_only_reader.py    # ReadOnlyDeviceReader — discovery-only (vendored copy; backport pending here)
  stub_adapters.py       # TP-Link Omada, Ruckus, UniFi, Aruba, Cisco Meraki stubs
  registry.py            # get_adapter(vendor) / list_supported_vendors()
  snmp_poller.py         # SNMP helpers (vendored copy only today)
tests/
  fake_transport.py      # in vendored copy; fake/mocked transports in standalone tests/
PRD.md
README.md
```

## ReadOnlyDeviceReader (Wave 1 discovery)

Used exclusively for router fleet **discovery** — not for config push.

| Layer | Enforcement |
|---|---|
| Surface | Only `read_section`, `read_all`, `section_names` — no SSH, no `push_config`, no raw command API |
| Allowlist | Every RouterOS path is a frozen `/.../print` entry validated before socket I/O |
| Sanitization | PPPoE passwords, WG private keys, RADIUS secrets stripped → `has_*` booleans |

Discovery service code in `cloud-guest-repo` is typed against this class so writes cannot be
expressed at the call site. See `app/domains/provisioning_engine/planner/service.py` and
`backend/docs/router_fleet/PROVISIONING_RUNBOOK.md`.

## Relationship to cloud-guest-repo

`cloud-guest-repo` vendors this directory and syncs README + code on gateway PRs. Migration is a
series of small PRs that swap one legacy `librouteros` call site at a time without changing outward
API behavior. This repo can be built and tested independently before any vendor bump lands in
production.

## New here?

1. `PRD.md` §2 — current-state audit
2. `PRD.md` §4 — API contract
3. `PRD.md` §7 — migration order
4. `cloud-guest-repo/backend/docs/router_fleet/README.md` — operator-facing Wave 1 docs
