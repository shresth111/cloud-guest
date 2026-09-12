# wyfy-device-gateway

Vendor-agnostic network device gateway for Wyfy Guest (formerly branded "ZIP WiFi" / "CloudGuest").

> **This directory is the canonical copy.** The standalone `shresth111/wyfy-device-gateway`
> repository is archived (read-only) as of 2026-09-11. Every gateway change is made here, in
> `cloud-guest`, and is gated by this repo's CI (`ruff --select F` over the package and this
> package's own pytest run — see `.github/workflows/ci.yml`). Do not re-create a second copy to
> sync by hand: two copies edited independently is exactly how the upstream repo ended up behind
> this one in code and ahead of it in tests.

## What this is

Wyfy Guest's main platform (`cloud-guest-repo`) speaks to MikroTik RouterOS devices through
this package: **one** stable interface (`wyfy_device_gateway.contract.DeviceGatewayAdapter`) that
the backend calls regardless of vendor, with one adapter implementation per vendor behind it.

Read `PRD.md` (in the archived standalone repo — see *History* below) before touching any code.

## What this is not

- Not a rewrite of RADIUS/hotspot auth (standard RADIUS — out of scope; PRD §2.3).
- Not a running HTTP service — a library that lives at `backend/vendor/wyfy-device-gateway/`
  in `cloud-guest` and is installed from there (the Docker build has no git credentials).
- Not a secrets/encryption layer — `cloud-guest-repo` decrypts credentials per call (PRD §6).

## Status

**Phase 1 write path — shipped.** `contract.py`, `mikrotik_adapter.py` (`MikroTikAdapter`), and
vendor stubs are implemented with unit tests against a fake transport (no live device required).

**Wave 1 read-only discovery — shipped in the vendored copy.** `read_only_reader.py`
(`ReadOnlyDeviceReader`) is used by `POST /api/v1/routers/{id}/discover` in `cloud-guest-repo`.
It is read-only **by construction** (no write methods, print-path allowlist, row sanitization before
persistence).

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
  controller_contract.py # controller-shaped contract (Omada) — separate from the router one
  mikrotik_adapter.py    # MikroTikAdapter — librouteros API + asyncssh provision path
  omada/                 # OmadaControllerAdapter — TP-Link Omada controller integration
  read_only_reader.py    # ReadOnlyDeviceReader — discovery-only
  stub_adapters.py       # Router-shaped stubs: TP-Link, Ruckus, UniFi, Aruba, Cisco Meraki
  registry.py            # get_adapter(vendor) / get_controller_adapter(vendor)
  snmp_poller.py         # SNMP helpers
tests/
  fake_transport.py        # read-only fake RouterOS transport (no mutating methods, on purpose)
  fake_write_transport.py  # write-capable fake RouterOS transport
  omada_support.py         # fake Omada controller responses
README.md
```

## Running the tests — from THIS directory, not from `backend/`

```bash
cd backend/vendor/wyfy-device-gateway
../../.venv/bin/python -m pytest tests/ -q      # 662 passed
```

This package has its own `[tool.pytest.ini_options]` with `pythonpath = ["."]`, which is what
makes `from tests.fake_write_transport import ...` resolve. Run the same files from `backend/`
instead and roughly half of them fail collection with:

```
ModuleNotFoundError: No module named 'tests.fake_write_transport'
```

That is a wrong working directory, **not broken code** — and it does not look like one, which is
why it is written down here. `backend/pyproject.toml` sets `testpaths = ["tests"]`, so the
backend's own suite never collects this package; CI runs it as a separate step from this
directory. Run both locally.

## ReadOnlyDeviceReader (Wave 1 discovery)

Used exclusively for router fleet **discovery** — not for config push.

| Layer | Enforcement |
|---|---|
| Surface | Only `read_section`, `read_all`, `section_names` — no SSH, no `push_config`, no raw command API |
| Allowlist | Every RouterOS path is a frozen `/.../print` entry validated before socket I/O |
| Sanitization | PPPoE passwords, WG private keys, RADIUS secrets stripped → `has_*` booleans |

> **Sanitization covers secrets, not guest personal data.** `SANITIZED_ROW_FIELDS` strips
> credential material. It does **not** strip PII, and several allowlisted sections carry it:
> `hotspot_hosts` and `ip/arp` return guest MAC addresses, `hotspot_active` returns the login
> identifier (a phone number on this platform), and `log` returns both. Rows that come back from
> this reader are safe from a *credential-leak* standpoint and are **not** automatically safe to
> display. Filtering PII belongs to whatever renders the rows.

Discovery service code in `cloud-guest-repo` is typed against this class so writes cannot be
expressed at the call site. See `app/domains/provisioning_engine/planner/service.py` and
`backend/docs/router_fleet/PROVISIONING_RUNBOOK.md`.

## History

Until 2026-09-11 this package also lived in a standalone repository that `cloud-guest` vendored
from. The two drifted: the vendored copy took every fix from cloud-guest #15 onward, while the
standalone repo kept ten test files the vendored copy never had. Those tests were ported here and
the standalone repo was archived. It is kept read-only rather than deleted, for its history and for
`PRD.md`, which the section references in this README and in module docstrings point to.

## New here?

1. `PRD.md` in the archived `shresth111/wyfy-device-gateway` repo — §2 current-state audit,
   §4 API contract, §7 migration order
2. `backend/docs/router_fleet/README.md` — operator-facing Wave 1 docs
