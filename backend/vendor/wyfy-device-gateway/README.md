# wyfy-device-gateway

Vendor-agnostic network device gateway for Wyfy Guest (formerly branded "ZIP WiFi" / "CloudGuest").

## What this is

Wyfy Guest's main platform (`cloud-guest-repo`) today only speaks to MikroTik RouterOS devices, and
it does so by calling MikroTik's own `librouteros` client library directly from six different
backend domains, each with its own copy-pasted "adapter" pattern. This repo is the fix: **one**
stable interface (`wyfy_device_gateway.contract.DeviceGatewayAdapter`) that the main backend calls
regardless of what hardware is actually deployed at a customer's location, with one adapter
implementation per vendor behind it.

Read [`PRD.md`](./PRD.md) before touching any code. It contains:

- A full audit of every place `cloud-guest-repo` currently talks to a router directly (file/line
  references), and why those six places all reinvented a slightly different version of the same
  idea.
- Research on what TP-Link Omada, Ruckus, Ubiquiti UniFi, Aruba, and Cisco (Meraki/Catalyst) each
  expose for programmatic management, RADIUS, and captive portal -- flagged where it needs live
  API-doc verification rather than trusted as-is.
- The actual API contract this repo exposes (concrete method signatures).
- Why Phase 1 ships as an importable Python package, not an HTTP microservice -- and the concrete
  conditions under which that should change.
- How per-device credentials work across vendors without touching `cloud-guest-repo`'s existing
  Fernet-encryption scheme.
- A step-by-step, zero-downtime migration plan for moving `cloud-guest-repo`'s six existing
  MikroTik call sites onto this package without changing any production behavior or touching the
  live RADIUS/hotspot authentication flow.
- What frontend work does (and mostly doesn't) exist for this.
- The phased vendor rollout plan.

## What this is not (yet)

- Not a rewrite of RADIUS/hotspot auth -- that flow is already vendor-neutral (standard RADIUS) and
  is explicitly out of scope; see PRD section 2.3.
- Not a running service in Phase 1 -- it's a library `cloud-guest-repo` imports. See PRD section 5
  for why, and what would need to be true before that changes.
- Not a place that touches secrets/encryption directly -- `cloud-guest-repo` decrypts a device's
  credentials and hands this package plaintext for the duration of one call, same as every existing
  adapter does today. See PRD section 6.

## Status

Phase 1: repo scaffolded, PRD complete, MikroTik adapter and contract not yet implemented in code
(the PRD includes the illustrative contract shape -- implementing it is the next task). No other
vendor has a real implementation; each has a stub that raises `NotImplementedError` and reports no
capabilities, so the Protocol shape is complete and checkable even though only MikroTik is real.

## Repo layout (target, once Phase 1 code lands)

```
wyfy_device_gateway/
  contract.py       # DeviceGatewayAdapter Protocol + shared dataclasses -- the ONE stable API
  adapters/
    mikrotik.py      # real, ported from cloud-guest-repo's six existing librouteros call sites
    tplink_omada.py  # stub
    ruckus.py        # stub
    unifi.py         # stub
    aruba.py         # stub
    cisco_meraki.py  # stub
  registry.py        # get_adapter(vendor) / list_supported_vendors()
tests/
  ...                # unit tests against a fake transport, no live device required
PRD.md
README.md
```

## Relationship to cloud-guest-repo

`cloud-guest-repo` is the main Wyfy Guest backend (FastAPI + SQLAlchemy + Celery + PostgreSQL) and
is not modified by this repo directly -- PRD section 7 describes the migration as a series of small
PRs *against cloud-guest-repo* that add this package as a dependency and swap one call site at a
time to delegate to it, keeping every existing function signature unchanged. This repo can be built,
tested, and released entirely on its own before `cloud-guest-repo` ever depends on it.

## New here? Start with

1. `PRD.md` section 2 (current-state audit) -- understand what actually exists today before
   assuming anything about the design.
2. `PRD.md` section 4 (API contract) -- the actual interface you're building against.
3. `PRD.md` section 7 (migration plan) -- how this gets adopted without breaking a live production
   system serving a real customer.
