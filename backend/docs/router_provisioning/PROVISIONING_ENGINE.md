# Provisioning Engine -- Design Write-Up

This document covers the Provisioning Engine extension: a real, bounded
Strategy/Adapter seam added on top of the already-substantial, already-real
`router_provisioning`/`router_agent` infrastructure, so a new device vendor
(OPNsense, Cisco, Aruba, UniFi, ...) can plug in without touching that
infrastructure's own workflow code. See `FLOW.md` for the original
config-template/version/job-queue design this builds on, `DATABASE.md` for
the full schema, and `docs/router_provisioning/adapters.py`'s own module
docstring for the code-level version of this write-up.

## 1. Why an extension, not a rebuild

A module brief asked for a full "Enterprise Provisioning Engine" -- device
onboarding, configuration, updates, validation, monitoring, rollback, all
vendor-agnostic via a Strategy/Adapter pattern, "must never contain
hardcoded MikroTik commands." A gap analysis of this actual codebase found:

* `app.domains.router_provisioning` already implements, for real: config
  template/variable/profile/version rendering (4-tier variable resolution,
  diff, rollback), a durable Postgres-backed job queue (Redis as a wake-up
  signal only), device-initiated enrollment + approval, and health/event
  history.
* `app.domains.router_agent` already implements, for real: the
  device-facing HTTP surface a real per-vendor agent process would call
  (credential issuance/rotation, heartbeat, config pull, action poll/
  complete).
* **Neither contains a single hardcoded RouterOS (or any vendor's) command.**
  Every device-affecting action (`config_push`/`backup`/`restore`/
  `factory_reset`) only ever creates a durable `ProvisioningJob` row --
  actually executing it against a live device is explicitly, honestly
  documented as `router_agent`'s future job, performed by a real external
  agent process this sandbox has no live device to run (the identical
  "platform builds the real workflow/wire-contract, an external process
  does the actual device call" split `app.domains.guest`'s FreeRADIUS
  `rlm_rest` integration already establishes for RADIUS).

So "must never hardcode MikroTik commands" was already true -- trivially,
because no command-execution code exists at all, for any vendor. Building a
second, parallel "Provisioning Engine" would have duplicated real, working,
honestly-documented infrastructure. This extension instead adds exactly the
piece that was genuinely missing: a formal seam for vendor identity and
vendor-aware behavior, real and useful without needing a live device to
prove it against.

## 2. What the adapter seam actually does

`app.domains.router_provisioning.adapters.ProvisioningAdapterProtocol` is
**not** "connect to a device and run commands" -- nothing in this codebase
could honestly implement that without a live device. It is the real,
bounded thing that *can* exist without one:

1. **Template/router vendor-compatibility validation.** Before this
   extension, any `ConfigTemplate` could be assigned to any `Router`
   regardless of vendor -- a real, previously-unenforced gap.
   `RouterProvisioningService.assign_profile` now calls
   `get_provisioning_adapter(router.vendor).validate_template_compatibility
   (template_vendor=template.vendor)` before ever creating/updating a
   `ConfigProfile`, raising `TemplateVendorMismatchError` on a mismatch.
2. **Vendor-aware job payload shaping.** `_enqueue_job` now calls
   `adapter.build_job_payload(...)` to enrich `ProvisioningJob.payload`
   (already a JSONB column, unchanged) with real, meaningful metadata a
   device-side agent would need (e.g. MikroTik's `content_type:
   "routeros_script"`/`apply_mechanism: "import"`). The job/queue mechanics
   themselves (Postgres row + Redis wake-up signal, status transitions,
   retry limits) are completely untouched.
3. **Capability introspection.** `adapter.describe_capabilities()` is a
   real, static dict (supported job types, config format, diff/rollback/
   health-snapshot support) exposed via
   `GET /router-provisioning/vendors` for dashboard/admin visibility.

## 3. Plugging in a new vendor

Implement `ProvisioningAdapterProtocol` (three methods:
`validate_template_compatibility`/`build_job_payload`/
`describe_capabilities`) and add one entry to `adapters._ADAPTERS`. Nothing
else in `router_provisioning` or `router_agent` needs to change -- both
already move config content and job payloads as opaque text/JSONB, never
inspecting vendor-specific syntax themselves. This is the concrete,
testable proof of the Strategy pattern the brief asked for: `mikrotik` is
one adapter among what could be several, registered the same way any other
would be.

## 4. `Router.vendor` / `ConfigTemplate.vendor`

Both new columns (migration `0031`) are `NOT NULL`, `server_default
'mikrotik'` -- and, unlike `RadiusNasClient.nas_code` (migration `0030`),
**are** effectively backfilled for every pre-existing row, because the
value is unambiguous: every `Router` and every `ConfigTemplate` in this
codebase targets MikroTik today. This is a materially different situation
from `nas_code`, which had to be freshly *generated* per row (no constant
default could honestly stand in for a real sequence number) -- see that
migration's own docstring for the contrast.

`Router.vendor` defaults to `"mikrotik"` on `POST /locations/{id}/routers`
(mirrors every device deployed today); `ConfigTemplate.vendor` defaults
identically on `POST /router-templates`. Neither field is exposed on its
respective `*UpdateRequest` schema -- a template's/router's vendor identity
is immutable after creation, the same "hierarchy/identity facts don't
silently change after the fact" convention `organization_id`/
`is_system_template` already establish on `ConfigTemplate` itself.

## 5. What this extension does not do

* **No live device connection, for any vendor, MikroTik included.** This
  was true before the extension and remains true after -- see §1.
* **No rename of existing MikroTik-specific fields.**
  `Router.routeros_version`/`ConfigTemplate.template_content`'s own
  "RouterOS config script" framing are left as-is (a real, honest fact
  about every device on the platform today) rather than being generalized
  into a vendor-neutral shape that would misrepresent the *actual* config
  language a template author writes in. A non-MikroTik router simply
  leaves `routeros_version` `NULL`, the same convention every other
  optional device fact on `Router` already uses.
* **No new `PermissionModule`.** `GET /router-provisioning/vendors` reuses
  the already-seeded `router_provisioning.read` permission -- vendor
  capability introspection is squarely within this domain's existing scope,
  not a genuinely distinct concern.
* **No change to `router_agent`'s own wire contract.** It already carries
  opaque config text and JSONB job payloads; this extension only changes
  *what* `router_provisioning` puts into that payload before an agent pulls
  it, never the transport/dispatch mechanism itself.
* **No `network_tools` module** (VLAN/QoS/DNS/firewall config templates) --
  `docs/ARCHITECTURE_DESIGN.md` §6.2 already plans that as a future,
  separate Phase 3 addition explicitly built to reuse this same
  `router_provisioning`/`router_agent` push pipeline; out of this
  extension's own bounded scope.
