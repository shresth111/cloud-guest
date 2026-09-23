# WyFyGuest — Security Module

**Product & Technical Requirements Document**
Status: Draft **v1.1** for product / frontend / backend / DevOps / network review
Scope: a new **Security** module *inside the existing WyFyGuest dashboard* — no new product, no new dashboard, no new login.

> **v1.1 — verification pass.** A read-only audit of the real device state changed three claims in v1.
> §7 (firewall ordering) was generic where the platform already has a proven production incident and a
> documented sentinel-band design; §10.2 (DNS bypass) understated what is already blocked;
> and §2.2 missed the existing `cloudguest-*` firewall rule namespace. All three are corrected below,
> and §37 records the device-verified constraints. Nothing in the MVP or roadmap changes shape — but
> Phase 2 gains a mandatory prerequisite.

---

## 0. How to read this document

This is **not** a greenfield design. It is written against the code that already exists in
`shresth111/cloud-guest.git` (backend) and `shresth111/cloudguest-foundation.git` (dashboard), and every
section names the real table, endpoint, adapter or component it extends.

Two rules governed every claim below, taken from the codebase's own conventions:

1. **A feature is not "supported" because a dashboard can display it.** Every feature is stated as
   `Dashboard UI → Policy → Enforcement mechanism → Technology actually required → Limitations`.
2. **Where the platform cannot honestly enforce something, this document says so** and puts it in
   *Requires Additional Technology* rather than quietly shipping a toggle that writes a database row.

A large part of the existing repo already follows rule 2 — for example
`app/domains/content_filtering/constants.py` documents that there is deliberately no URL-path or keyword
value type, and `app/domains/content_filtering/device_adapters.py` documents that a VPN-less DNS sinkhole
is bypassable. This document continues that discipline rather than fighting it.

---

## 1. Non-negotiables

| Requirement | How this document honours it |
|---|---|
| No separate product (`WyFyWall`) | All new code lands in the existing domains + the existing dashboard |
| No separate dashboard | Customer surface stays `CustomerFeaturePage`; operator surface stays `/network/*` |
| No separate login | Reuses `get_current_user`, `RequirePermission`, existing RBAC and audit |
| One place to manage Guest Wi-Fi + Network + Security | One sidebar, one org/venue scope, one policy engine |
| Customer thinks "I want to block this" | Policy authoring is in product language; RouterOS is generated server-side |

---

## 2. Ground truth: what already exists

This is the single most important section. Nearly every item in the brief has a partial or complete
implementation already, and the Security module's job is to **surface, unify and extend** it.

### 2.1 Platform shape

| Layer | Reality |
|---|---|
| Backend | Python 3.13 · FastAPI · SQLAlchemy · Alembic · Celery + Redis · PostgreSQL 17 · MinIO |
| Domain convention | `app/domains/<name>/` with `models.py` `service.py` `router.py` `repository.py` `schemas.py` `constants.py` `validators.py` `dependencies.py` `events.py` `exceptions.py` `device_adapters.py` `tasks.py` |
| Base model | `app.database.base.BaseModel` — UUID PK, timestamps, soft-delete, `version` |
| Enums | `StrEnum` stored in `String` columns — never native PG enums, so new values are additive, no `ALTER TYPE` |
| API envelope | `ApiResponse{success, message, data, request_id}` · `/api/v1` prefix · `page`/`page_size` pagination |
| Authz | `CurrentUser` + `RequirePermission("<module>.<action>", scope=ScopeType.X)` |
| Scope headers | `X-Organization-Id`, `X-Organization-Scope`, `X-Location-Id`, `X-Router-Id`; device side `X-Agent-Credential` |
| Background work | Celery + **Celery Beat** (`app/core/celery_app.py`), queues `celery` and `device_io` |
| Deploy | ECR images → `deploy/docker-compose.prod.yml` via `deploy/remote-deploy.sh` (SSM SendCommand from GitHub Actions), pre-migration `pg_dump` to S3, health wait, auto-rollback |
| Frontend | React 19 · TanStack Start + TanStack Router (file-based) · TanStack Query · Zustand · axios · shadcn/ui on Radix · Tailwind v4 · RHF + zod · recharts · sonner |

### 2.2 Domains that already do security-adjacent work

| Domain | What it already is | Why it matters here |
|---|---|---|
| `firewall` | `firewall_rules` CRUD: chain `input/forward/output`, action `accept/drop/reject`, protocol `tcp/udp/icmp/all`, src/dst address + port, `in_interface`, `priority`, `is_enabled`. **No device push, no conflict detection** (deliberate: overlapping filter rules are normal first-match-wins policy) | This is the Firewall module's skeleton. Missing: identity, push, ordering safety, hit counts |
| `content_filtering` | `content_filter_rules`: `DOMAIN` → `/ip dns static` sinkhole (exact name + subdomain `regexp=`) pointed at `127.0.0.1`; `IP_CIDR` → `/ip firewall address-list` named `wyfyguest-content-filter-blocked` + **one** shared `/ip firewall filter … action=drop`, position-managed above the first `accept`, re-checked on every push. Real push over **8728**, with `device_push_status/error/pushed_at` | This is the Blocking Center's engine. Already honest about its limits |
| `guest_access` | `guest_access_rules` (`WHITELIST/BLOCKLIST/TEMPORARY/VIP`) + `device_access_rules` (MAC-keyed). `BlocklistEnforcer` ends live sessions via `/ip hotspot active remove` over 8728, device-first, then marks the session terminated | The live "block a person right now" primitive |
| `connected_devices` | DHCP-lease/ARP discovery; `block`/`unblock`/`whitelist` delegate to `guest_access` (no direct device push) | Device Isolation's inventory |
| `vlan` | `vlans` + real push (`/interface vlan`, bridge port moves, `/ip address`, optional per-VLAN hotspot + NAT) with `device_push_status` | The segmentation substrate |
| `dhcp` | `dhcp_pools` + push, captive-portal option 114, rogue-DHCP alert guard | Zone addressing |
| `qos` | `/ip firewall mangle mark-packet` + `/queue tree` paired push | Not a security tool — classification only |
| `queue_management` | `queue_profiles/schedules/templates/assignments`, `/queue simple` push, RADIUS `Mikrotik-Rate-Limit`, advisory locking + supersede logic | Bandwidth, not firewall |
| `wireguard` | `wireguard_servers/peers/peer_issuances`; hub agent `POST /wg/peer` (no delete verb); tunnel is the management path and the RADIUS NAS identity | **This is already a VPN — but an infrastructure one, not a user VPN** |
| `network_diagnostics` | `diagnostic_runs`; real RouterOS `/tool ping` + `/tool traceroute`; 10 s cooldown, 120/hour/org | The connectivity-test primitive inside deploy safety |
| `monitoring` | `health_checks`, `service_health`, `heartbeat_logs`, `platform_events`, **`alert_rules`, `alerts`, `alert_rule_notification_channels`, `notification_channels`, `notification_logs`, `incidents`, `incident_alerts`, `sla_targets`, `sla_reports`**; `AlertService` + `NotificationService`; Beat sweeps (health 300 s, alert eval 30 s); channels EMAIL/SMS/WHATSAPP/SLACK/TEAMS/DISCORD/WEBHOOK | The alerting engine the Security module should reuse, not rebuild |
| `provisioning_engine` | `provision_jobs/steps/logs/templates` + `planner/` (`router_snapshots`, `configuration_plans`, `managed_resource_models`, `verification_models`); `PlanStatus` and `ProvisionJobStatus` state machines; `PlanRisk.MANAGEMENT_CONNECTIVITY` + `assess_management_risk`; `SAFETY_REVERT_SCHEDULER_COMMENT` | **This is the deploy-safety + rollback machinery the brief asks for — it already exists** |
| `router_provisioning` | `ConfigVersion` (`version_number` unique per router, `rollback_of_version_id`, `is_backup`), `ConfigProfile`, `diff_versions`, `ProvisioningJob` queue (Redis dispatch, Postgres truth) | **Policy versioning already exists here** |
| `device_sync` | `device_sync_runs` (append-only, per-component JSONB, per-component failure isolation) | Drift/reconcile reporting |
| `rbac` | `permission_groups`, `permissions`, `permission_scopes`, `roles`, `role_scopes`, `role_permissions`, `user_roles`, `permission_overrides`, `organization_roles`; `ScopeType` GLOBAL > ORGANIZATION > LOCATION > ROUTER > DEVICE; `LocationScope` + `enforce_entity_location` | The RBAC to extend |
| `audit` | `AuditLogEntry` written through a narrow `AuditLogWriter` protocol; `AuditAction` StrEnum; `CUSTOMER_HIDDEN_AUDIT_ACTIONS`; CSV export capped at 10 000 rows | The audit trail to extend |
| `policy` | `policies` + **`policy_versions`** (`version_number`, `status`, `rules` JSONB, `published_at`) + **`policy_assignments`** (`scope_type`, `scope_id`, `target_type`, `target_id`, `priority`) | **The Policy Engine and its versioning already exist** |
| `feature_entitlement` / `billing` | `PlanFeatureKey`, `BOOLEAN_FEATURE_KEYS`, `LIMIT_FEATURE_KEYS`, `TIER_FEATURE_KEYS`, `EntitlementChecker` | How "Security" is gated by plan |
| `network_config` | No table. Pure renderers that emit real RouterOS script: `render_firewall_rule`, `render_content_filter_rule`, `render_content_filter_enforcement`, `render_mac_authorization_entry`, `render_hotspot_walled_garden`, plus `wan/renderers.py` (PCC mangle, and **DNS rules that already exist**: `cloudguest-fw-block-wan-dns`, `cloudguest-fw-block-dot-udp`, `cloudguest-block-dot-tcp`, `cloudguest-block-doh`). Commands are wrapped by `_idempotent_lines` in per-line `:do {...} on-error={}` | The exact RouterOS text the Security writer must converge with. **It already blocks DoT and DoH** — see §37 |
| `network_integration` | Omada **controller** seam: `NetworkProvider` protocol, `OmadaControllerAdapter` | The controller-vendor template |
| `vendor/wyfy-device-gateway` | `DeviceVendor` enum, `DeviceGatewayAdapter` protocol (~60 methods), `registry.get_adapter`, `MikroTikAdapter` real, all other vendors **stubs raising `NotImplementedError`** | The multi-vendor abstraction already exists |

### 2.3 How the cloud actually reaches a router

This is the constraint that shapes every security feature. There are two paths and they are not
interchangeable:

**Path A — device-initiated HTTPS polling (control plane).**
Generated RouterOS `/system scheduler` scripts phone home. `cloudguest-heartbeat-sched` (5 m) →
`POST /api/v1/agent/heartbeat`; `cloudguest-authmac-sched` (1 m) → `GET /api/v1/agent/authorized-macs`;
plus `/agent/config`, `/agent/actions`, `/agent/actions/{id}/complete`. Auth is a SHA-256-compared
bearer `X-Agent-Credential` (`router_agent_credentials`). **There is no agent daemon installed on the router.**
"Updating the agent" means re-rendering and re-pushing RouterOS script.

**Path B — platform-initiated RouterOS API over the WireGuard tunnel.**
`librouteros` on **TCP 8728** to `Router.management_ip_address` (the WireGuard peer `/32`), using
`Router.api_username` + Fernet-encrypted `api_credentials_encrypted`. Every `configure_*` write and
every read in the platform uses this path.

**What this means in practice:**

- **SSH / port 22 is filtered on the live fleet.** A port sweep from the platform reached **only 8728**.
  Any design that assumes SSH/SFTP config push will fail on real routers.
- **`network_config`'s script push (SFTP + `/import`) cannot reach fleet routers, and its handler returns
  `202 success:true` regardless.** Do not route new security features through it. (The existing
  `content_filtering/device_adapters.py` documents this exact history — it exists because the right
  writer had been built and never plugged in.)
- **This is a strong security property and should be defended, not changed.** No RouterOS management port
  is exposed to the public internet. Traffic flows device → cloud, and the cloud reaches the device only
  inside a WireGuard tunnel. Keep it that way.

---

## 3. Capability tiers — the honest master matrix

Read this before the feature sections. It is the answer to "what can we actually ship".

### AVAILABLE NOW — real enforcement with the current stack

| Capability | Mechanism that exists today |
|---|---|
| Per-router firewall filter management (with push) | `/ip firewall filter`, `render_firewall_rule`, `MikroTikAdapter` |
| Domain blocking (exact + wildcard) | `/ip dns static` sinkhole, exact + `regexp=` subdomain pair |
| IP / CIDR blocking | `/ip firewall address-list` + one shared positioned `drop` |
| SNI-based domain blocking (incl. HTTPS) | RouterOS **`tls-host`** firewall matcher (6.41+) — **new to this platform, native to RouterOS** |
| Blocking a live guest, right now | `/ip hotspot active remove` via `guest_access` |
| Durable per-MAC block for known devices | `/ip hotspot ip-binding type=blocked` |
| Zone → zone policy (VLAN segmentation matrix) | `/ip firewall filter chain=forward` with `src-address`/`dst-address` per VLAN subnet |
| Intra-zone isolation / guest-to-guest blocking | RouterOS bridge **horizon**/`split-horizon` on the guest bridge port, or a forward drop |
| Brute-force / connection flood protection | `/ip firewall filter` `connection-limit`, `dst-limit`, `tcp-flags`, `syn-cookies` |
| Bogus/bogon IP drop | `/ip firewall address-list` of RFC1918/bogon ranges + raw prerouting drop |
| Port-scan heuristics | connection-limit + `dst-limit` + `tarpit` |
| DHCP rogue-server detection | already implemented (`router_rogue_dhcp_statuses`) |
| Traffic volume per device/session | RADIUS accounting → `guest_sessions.bytes_*`, `guest_quota_usages` |
| Per-VLAN / per-interface counters | `MikroTikAdapter.get_interface_traffic_counters` |
| Router / WAN / gateway health & alerting | `monitoring` (`AlertService`, `NotificationService`, Beat sweeps) |
| Security alerts on the channels the brief lists (except WhatsApp) | EMAIL, SMS, SLACK, TEAMS, DISCORD, WEBHOOK are real |
| Versioned policies + rollback | `policy_versions`, `ConfigVersion`, `provisioning_engine` plans + `SAFETY_REVERT` |
| Tenant isolation + RBAC + audit + CSV export | `rbac`, `audit` |

### REQUIRES ADDITIONAL TECHNOLOGY — cannot be honestly delivered today

| Capability | What it actually needs | Nearest honest interim |
|---|---|---|
| **Web category filtering** (Adult/Gambling/Streaming…) | A maintained category database + a resolver that applies it. RouterOS has neither | A **DNS filtering service** (Cloudflare Gateway / NextDNS / Umbrella) or a managed feed; or the customer curating their own domain lists per category (which is what `content_filtering` does today) |
| **Application control** (block Instagram, allow TikTok) | Application identification. Strongest available = DPI. Weaker = DNS + IP + SNI | DNS + SNI + IP heuristics for the *subset* of apps with stable domains. **Not** a guarantee — see §12 |
| **TLS SNI matching that survives ECH** | Nothing at the network layer once ECH is in play | We already block DoT/DoH pre-auth (`hotspot=!auth`); extend that to authenticated traffic, enforce our resolver, and accept decaying coverage |
| **Malware / phishing / botnet blocking by reputation** | A threat-intelligence feed + a sync pipeline + a fast lookup path | DNS blocklist feeds into the sinkhole mechanism — cheap and honest — or a DNS filtering service |
| **IDS / IPS, deep packet inspection** | Dedicated inspection hardware or a cloud inspection path | RouterOS is not an IDS. Do not build a UI that implies it is |
| **Per-application traffic accounting** ("YouTube = 2.4 GB") | DPI or flow export (NetFlow/IPFIX) + a collector | Per-device and per-zone bytes via firewall accounting/interface counters; per-*application* is not available |
| **Geo blocking, outbound reliability** | GeoIP database + maintenance + honest expectations | Inbound geo-block is workable via synced country CIDR address-lists; outbound is unreliable because CDN edges live everywhere |
| **Full URL-path / keyword filtering** | TLS interception (breaks trust, is not appropriate for guest Wi-Fi) | Domain-level only |
| **WhatsApp alerting (real)** | A real integration | Today `WhatsAppNotifier` is a **logging-only placeholder**. Do not promise WhatsApp |
| **Cloudflare WAF / Zero Trust protecting guest LAN traffic** | Cloudflare protects its own edge, not a LAN. Requires Cloudflare Gateway as the DNS resolver | See §17 — this is the single biggest correction in this document |

### FUTURE — enterprise, only after the above exists

Multi-vendor enforcement parity (Aruba/Omada/Meraki/UniFi are stubs today) · device-fingerprint based
policy · east-west microsegmentation with identity · SIEM export · ML anomaly baselining · per-tenant
threat-intel tenancy · remote-access VPN for staff · signed policy bundles with approval workflow.

---

## 4. Information architecture

### 4.1 The real dashboard today (customer surface)

`src/lib/customerNav.ts → CUSTOMER_NAV_GROUPS`, in order:

```
Overview          Dashboard · Users · Reports · Alerts
Engagement        Portal · Campaigns · Vouchers
Access & Policy   Access Rules · Always Allowed · Trusted Devices · Open Hours
Devices & Team    Devices · Guest Groups · Staff Access
Network           IP Addresses · Network Zones · Port Forwarding · Call Priority ·
                  Website Blocking · Internet Connection
Operations        Fix a Problem
Support & Logs    Support Tickets · Logs · Network Activity Log · How It Works
```

The brief's proposed sidebar (`Gateways`, `Access Points`, `Switches`, `VLANs`, `DHCP`, `DNS`, `WAN`,
`VPN`, `Compliance`, `Administration`) does **not** match this, and the mismatch matters:

- Several items are the same thing under a different name. `VLANs` → **Network Zones** (`/vlans`),
  `DHCP` → **IP Addresses** (`/dhcp`), `WAN` → **Internet Connection** (`/isp-details`),
  `Website Blocking` → already exists as `/website-blocking`.
- `Gateways`, `Access Points`, `Switches`, `DNS`, `VPN`, `RBAC`, `Audit Logs`, `Integrations` are
  **operator/console surfaces** (`/routers`, `/network/*`, `/settings`, `/integrations`, `/rbac`,
  `/audit`) — not customer surfaces. Adding them to the customer sidebar would expose internal
  concepts the product deliberately keeps operator-only.
- There is already a **`SecurityPanel`** in platform `/settings`, so naming must disambiguate.

### 4.2 Recommended IA — minimal, honest, additive

Do **not** restructure the existing sidebar. Add **one new group** to the customer surface and enrich
the existing Network group:

```
Overview          Dashboard · Users · Reports · Alerts
Engagement        Portal · Campaigns · Vouchers
Access & Policy   Access Rules · Always Allowed · Trusted Devices · Open Hours
Devices & Team    Devices · Guest Groups · Staff Access
Network           IP Addresses · Network Zones · Port Forwarding · Call Priority ·
                  Website Blocking · Internet Connection
Security   ←NEW   Security Overview · Blocking · Firewall · Zones & Isolation · Security Policies
Operations        Fix a Problem
Support & Logs    Support Tickets · Logs · Network Activity Log · How It Works
```

Rationale for squeezing nine proposed items into five:

| Proposed | Decision | Why |
|---|---|---|
| Overview | **Security Overview** | KPI home; the landing page for the group |
| Firewall | **Firewall** | Real, pushable, high value |
| Blocking | **Blocking** | Merges the brief's Blocking Center + IP blocking + Domain blocking. One mental model: "things I block", with a Type selector |
| Web Filtering | Merge into **Blocking** as a *Block by Category* tab | Honest: it is domain blocking with a category label — see §11 |
| Application Control | Merge into **Blocking** as an *Applications* tab, with an explicit "reliability" badge | See §12 |
| Geo Blocking | Merge into **Blocking** as a *Countries* tab, gated behind the geo feed | See §13 |
| Device Isolation | **Zones & Isolation** | One page for zone→zone matrix + per-device isolation |
| Security Policies | **Security Policies** | The unified policy list with versions, deploy, rollback |

This gives the customer the brief's mental model (*"I want to block this"*) without four tabs that are
the same mechanism wearing different labels.

### 4.3 Operator/console additions

The operator console (`src/routes/_authenticated/**`) is where the platform side lives. Add:

- `/security/policies` — cross-org policy authoring and deploy history
- `/security/feeds` — threat-intel and GeoIP feed status, last sync, entry counts
- `/security/catalog` — the honest capability matrix per vendor (drive it from `capabilities()`)
- extend `/integrations` with the **Cloudflare** card (§17) and a GeoIP/threat-intel provider card
- extend `/settings` `SecurityPanel` rather than creating a second security settings screen

---

## 5. Security module structure

```
app/domains/security/                     ← new, thin composition/orchestration domain
    models.py          security_events, security_score_snapshots
    service.py         SecurityOverviewService (read-only aggregation)
    router.py          /api/v1/security/*
    schemas.py         overview, event, score
    constants.py       SecurityEventType, SecurityEventSeverity, SecurityEventSource
    repository.py

app/domains/security_policies/            ← new, the authoring surface
    models.py          security_policy_rules, security_policy_deployments
    service.py         SecurityPolicyService (validate → compile → deploy → verify → rollback)
    device_adapters.py BaseSecurityAdapter  (MikroTik impl; others stub)
    compiler.py        policy → vendor-neutral intent → vendor config
    validators.py      conflict detection, lockout prevention
    constants.py       SecurityRuleKind, SecurityAction, SecurityScope

extended, not replaced:
    firewall/          + device_adapters.py, + identity/priority/position, + hit counts
    content_filtering/ + tls-host backing, + scope (zone/SSID/group), + category semantics
    guest_access/      + durable ip-binding block for known devices
    geo_blocking/      ← new, feed sync only (Celery Beat)
    policy/            + PolicyType.SECURITY + SecurityPolicyRules schema
    rbac/              + PermissionModule.SECURITY* + Security Administrator role seed
    monitoring/        + SECURITY_* alert trigger types + targets
```

**Why a new `security` domain rather than growing `firewall`:** `firewall` is deliberately a
*per-router packet-filter inventory* domain with no cross-domain knowledge. The Security module needs to
reason across zones, devices, groups, schedules and vendors, and to own the deploy pipeline. Keeping
`firewall` as the low-level writer and `security_policies` as the compiler preserves the layering the
codebase already enforces (domains compose through duck-typed protocols at the service layer, never by
importing each other's adapters).

---

## 6. Security Overview

### 6.1 Wireframe

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Security · <Venue name>                          [ Last 24h ▾ ]  [ Export ]│
├────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ Security     │ │ Threats      │ │ Threats      │ │ Firewall     │        │
│  │ Score        │ │ Detected     │ │ Blocked      │ │ Events       │        │
│  │   82 / 100   │ │     127      │ │     124      │ │   2,431      │        │
│  │ ▲ 4 this wk  │ │ ▲ 12         │ │ 97.6% rate   │ │ ▲ 8%         │        │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘        │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ Blocked      │ │ Blocked      │ │ Blocked      │ │ Isolated     │        │
│  │ Devices      │ │ Domains      │ │ Applications │ │ Devices      │        │
│  │     18       │ │     342      │ │     61       │ │      3       │        │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘        │
├────────────────────────────────────────────────────────────────────────────┤
│  Infrastructure health                                                     │
│  ● Gateway   Healthy  (3/3)     ● WAN  Healthy  ▶ Uptime 99.8%             │
│  ● VPN       3/3 online         ● Last policy deploy  18m ago  ✔ verified   │
├──────────────────────────────────────────┬─────────────────────────────────┤
│  Threats blocked over time               │  Top blocked destinations       │
│  [ stacked area: malware/geo/domain/app ]│  instagram.com      118         │
│                                          │  tiktok.com          94         │
│                                          │  45.147.x.x          61         │
│                                          │  *.doubleclick.net   48         │
├──────────────────────────────────────────┴─────────────────────────────────┤
│  Recent security events                                    [ View all ]    │
│  21:42  Critical  Malicious IP blocked            45.147.x.x   Guest VLAN   │
│  21:38  High      Port scan detected              10.20.4.11   WAN          │
│  21:31  Medium    Excessive connections           192.168.20.7 IoT VLAN     │
│  21:20  Low       Country policy triggered        RU → inbound Internet     │
└────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Where every number actually comes from

This matters more than the layout. A number with no real source is the defect this platform already
fought once (`content_filtering/device_adapters.py` documents the "dashboard showed a block that was
never enforced" incident).

| Card | Real source | Available? |
|---|---|---|
| Firewall Events | `/ip firewall filter print stats` counters on rules carrying our comment markers | ✅ with the new firewall push |
| Blocked Domains | count of DNS-sinkhole entries observed matching, per `/ip dns static` entry counters | ✅ for exact rules; wildcard counts need a rule-level counter (§10.3) |
| Blocked IPs | `content_filter_rules` (IP_CIDR) with `device_push_status = active` + address-list hit counter | ✅ |
| Blocked Devices | `device_access_rules` active + `guest_sessions.disconnect_enforced` | ✅ |
| Blocked Applications | **counts of DNS/SNI rules tagged as an application** — honest only if we label it as "blocked by domain match", not "app identified" | ⚠️ §12 |
| Threats Detected / Blocked | sum of firewalled events where action ∈ {drop, reject, tarpit} vs total | ✅ (events ≥ blocks is always true) |
| Suspicious traffic | connection-limit and scan-heuristic rule counters | ✅ |
| WAN health / Gateway health | `monitoring` health checks + `router_health_snapshots` + `isp` uplink health | ✅ |
| Active VPN tunnels | `wireguard_peers.status = ACTIVE` + `last_handshake_at` recency | ✅ |
| Security score | **derived, must be transparent** — see §6.3 | ⚠️ compute, don't invent |
| Geo-blocked events | geo address-list counters | ⚠️ requires the geo feed |

### 6.3 The Security Score

Do not ship an opaque number. Compute it from observable, listed inputs and show the breakdown on click:

```
score = 100
      − (fleet coverage gaps × w)      # routers not agent-managed / stale heartbeat > 15 m
      − (unpushed active policies × w) # device_push_status != active while is_enabled
      − (open critical/high alerts × w)
      − (insecure postures × w)        # no zone→zone policy, WAN input accept-all,
                                       # rogue-DHCP unguarded, mgmt not tunnel-only
      − (feed staleness × w)           # geo/threat feed older than N days
```

Every term is readable from existing tables. The score is a **diagnostic of our own configuration
health**, not a threat score — say so in the UI tooltip, with a "What affects this?" drawer.

### 6.4 Feature chain

**UI** KPI cards + trends + health strip + event feed.
**Policy** none (read-only).
**Enforcement** none — aggregation over `firewall_rules`, `content_filter_rules`, `device_access_rules`,
`wireguard_peers`, `monitoring.health_checks`, `router_health_snapshots`, `security_events`.
**Technology required** none new, except feed-backed cards which degrade gracefully when feeds are absent.
**Limitations** any card whose source is absent must render an explicit *"Not available — <reason>"*
state, never `0`. The codebase already does this for GeoIP
(`analytics/domain_analytics_service.py` ships a `_NO_GEOIP_MESSAGE`). Follow that precedent exactly.

---

## 7. Firewall

### 7.1 Table (customer language, not WebFig)

```
Priority │ Name                        │ From            │ To              │ Service │ Action │ Schedule │ Status  │ Hits
─────────┼─────────────────────────────┼─────────────────┼─────────────────┼─────────┼────────┼──────────┼─────────┼──────
1        │ Block Guest → Internal      │ Guest Network   │ Internal Network│ Any     │ BLOCK  │ Always   │ Applied │ 41,208
2        │ Allow Office → Internet     │ Office          │ Internet        │ HTTPS   │ ALLOW  │ Work hrs │ Applied │ 2.1M
3        │ Block IoT → Internal        │ IoT             │ Internal Network│ Any     │ BLOCK  │ Always   │ Applied │ 8,942
4        │ Allow Admin → Server        │ Admin           │ Server Zone     │ SSH     │ ALLOW  │ Always   │ Applied │ 312
5        │ Block Social Media (SNI)    │ Guest Network   │ Internet        │ HTTPS   │ BLOCK  │ 9–18    │ Pending │ —
```

Columns map 1:1 onto `firewall_rules` (`priority`, `source_address`, `destination_address`,
`protocol`+`destination_port`, `action`, `chain`, `is_enabled`) plus three new ones: `schedule_id`,
`device_push_status`, and a live hit count.

Customer-visible "From/To" are **named zone objects** (resolved to VLAN subnets / address-lists server
side); the raw form stays available behind an "Advanced" toggle for network engineers.

### 7.2 Create policy UI

```
Create Security Policy
┌──────────────────────────────────────────────────────────────────┐
│ Policy name   [ Block Guest Access to Internal Network         ] │
│                                                                  │
│ From          [ Guest Network          ▾ ]   (zone / VLAN / SSID)│
│ To            [ Internal Network       ▾ ]                       │
│ Application   [ Any                    ▾ ]   ⓘ limited — see §12 │
│ Service       [ Any                    ▾ ]   (or HTTPS/SSH/DNS…) │
│ Schedule      [ Always                 ▾ ]                       │
│                                                                  │
│ Action        ( ) Allow   (•) Block   ( ) Reject                 │
│               ⓘ Block = silent drop · Reject = tells the sender  │
│                                                                  │
│ [x] Log matched traffic (recommended)                            │
│ [x] Alert me when this fires more than [ 100 ] times / hour      │
│                                                                  │
│ ⚠ Impact preview: 1 zone, 3 gateways, ~240 devices                 │
│    Conflicts: none detected                                       │
│                                                                  │
│        [ Save draft ]   [ Save & Deploy ]   [ Test (dry run) ]    │
└──────────────────────────────────────────────────────────────────┘
```

### 7.3 How this becomes MikroTik config

The generated commands for entry #1 above, rendered by extending
`network_config/renderers.render_firewall_rule`:

```
/ip firewall filter add chain=forward \
    src-address=<guest VLAN subnet> \
    dst-address=<internal subnets> \
    action=drop \
    comment="wyfyguest-sec:<rule_uuid> Block Guest → Internal (priority=1)"
```

Three things the current renderer does **not** do and must gain:

1. **Identity.** Today the comment is `"<name> (priority=N)"`. A customer renaming a rule orphans the old
   device object. Every security rule must carry an immutable **`rule_id` marker** in the comment and the
   device writer must find-or-update by that marker — the pattern `configure_content_filter_rule` and
   `_ensure_content_filter_enforcement_rule` already use. The label is the mutable tail, the id is identity.
2. **Ordering — and this is the part that has already caused a production outage.** Priority is
   meaningless unless rules land in a controlled position. **Never `add` blind and never store an
   index.** RouterOS `add` appends to the tail of the chain, first-match-wins, so a security rule
   appended below `accept cloudguest-fw-fwd-established` stops enforcing exactly the live sessions it
   was created to stop. This is not hypothetical: on **2026-08-16 on router `gurugram`** the blanket
   WAN-input drop (`cloudguest-fw-drop-wan-input`) landed *above* the WireGuard management accept
   (`cloudguest-fw-allow-wg-mgmt`) because a plain `add` appended it there — the drop ate the tunnel's
   own inbound handshake and **the management tunnel could never come up**. And a stored
   `position = 7` is stale the instant the hotspot service adds or removes one of its own rules, which
   it does continuously as guests come and go.

   The required shape is the platform's own **sentinel band** (`cloudguest-fw-band-begin` /
   `cloudguest-fw-band-end`, `action=passthrough`) with every security rule written as
   `place-before=<.id of band-end>` in ascending `priority`. Position then becomes a pure function of
   (band location, priority) — stable across re-pushes and immune to anything outside the band.
   See §37 for the full contract, including what to do when the band is missing, and the paste trap
   that made this fail on a real router once already.
3. **Zone resolution.** "Guest Network" must resolve to the VLAN's real subnet (`vlans.cidr` /
   `gateway_ip_address`) at compile time, and re-resolve when the VLAN changes. A zone rule compiled from
   a stale subnet blocks nothing.

### 7.4 Non-negotiable safety rules for the generator

The generator must **refuse to render** (and explain why) any rule that would:

- match the WireGuard management interface, the tunnel subnet, or management port 8728;
- match traffic the platform needs (`established,related`, the agent's heartbeat destinations, DNS to the
  router, RADIUS, NTP);
- drop `input` traffic from the tunnel source;
- position a `drop` above the platform's own management-accept rules;
- be the *last* rule in a chain that would otherwise end in an implicit drop.

This is the "lock yourself out" class of bug, and it is the reason the brief's config-safety section
exists. `provisioning_engine/planner/management_safety.py::assess_management_risk` already models exactly
this risk (`PlanRisk.MANAGEMENT_CONNECTIVITY`); the security compiler must call it.

### 7.5 Hit counts

`/ip firewall filter print stats` returns `packets`/`bytes` per rule; `MikroTikAdapter` reads it through
librouteros. Poll on a Celery Beat sweep (per-router, `device_io` queue, staggered), write into a new
`security_rule_counters` time-series table, and render "Hits" plus a sparkline. Counters reset on reboot —
store deltas and detect counter resets rather than showing a wrong absolute.

### 7.6 Feature chain

**UI** table + policy builder + impact preview + dry run.
**Policy** `security_policy_rules` → compiled per router.
**Enforcement** `/ip firewall filter` (chain `forward` for zone→zone, `input` for WAN-specific, `output`
rarely) via `librouteros` on 8728, comment-marker identity, position-managed.
**Technology required** none beyond what exists — **this is the highest-value, most defensible feature in
the whole brief.**
**Limitations** first-match-wins semantics mean order *is* the policy — the UI must make reordering
first-class and show the effective order. Intra-subnet traffic that switches at L2 never reaches
`chain=forward` (see §15.3). Rule count costs CPU on low-power hardware; cap and warn.

---

## 8. Blocking Center

### 8.1 One page, a Type selector

```
Security → Blocking
┌───────────────────────────────────────────────────────────────────────────┐
│  Block something                                                            │
│  Type       [ Domain ▾ ]  Domain · IP address · Country · Application ·     │
│                            Category · Port · Device · User                  │
│  Value      [ facebook.com            ]                                     │
│  Apply to   [ Guest Wi-Fi ▾ ]   (Network / Zone / SSID / Group / Everyone)   │
│  Schedule   [ Always ▾ ]                                                    │
│  Action     [ Block ▾ ]         ⓘ Block · Allow (exception) · Block + alert  │
│                                                                             │
│  ⓘ How this works: blocked by DNS for guests using our DNS. Devices with     │
│    their own DNS settings can bypass it unless "Force our DNS" is on.        │
│                                          [ Force our DNS: ON ]              │
│                                                        [ Add exception ]     │
│                                          [ Save draft ] [ Deploy ]          │
└───────────────────────────────────────────────────────────────────────────┘

Active blocks                                        [ Search ]  [ Filters ]
Type      │ Value                    │ Applies to   │ Reason      │ By     │ Created    │ Hits │ Status
──────────┼──────────────────────────┼──────────────┼─────────────┼────────┼────────────┼──────┼────────
Domain    │ *.instagram.com          │ Guest Wi-Fi  │ Policy:Mktg │ A. Rao │ 2 Sep 14:02│ 118  │ Applied
Domain    │ *.tiktok.com             │ Guest Wi-Fi  │ Policy:Mktg │ A. Rao │ 2 Sep 14:02│  94  │ Applied
IP/CIDR   │ 185.220.101.0/24         │ Everyone     │ Threat feed │ System │ 5 Sep 03:11│  61  │ Applied
IP        │ 45.147.229.12            │ Everyone     │ Abuse report│ S. Khan│ 6 Sep 09:40│  27  │ Applied
Device    │ D4:6A:…:2F  (Front-desk) │ Everyone     │ Theft       │ S. Khan│ 6 Sep 10:15│  —   │ Applied
Country   │ RU (inbound)             │ Everyone     │ Policy      │ A. Rao │ 8 Sep 11:00│  —   │ Queued
```

The `Status` column is the existing `device_push_status` trio — `pending` / `active` / `failed` — with
`device_push_error` shown verbatim on hover. **No row may ever render "Applied" without it.** That is a
hard rule, taken from the incident this codebase already documents.

### 8.2 Apply-to scoping (an extension we must be explicit about)

Today `content_filter_rules` are **per-router**; there is no zone/SSID/group scope. The brief's
"Apply To: Guest Wi-Fi" therefore requires new work, and the mechanisms differ per type:

| Type | How scope is enforced | Honest verdict |
|---|---|---|
| Domain (DNS sinkhole) | Sinkhole is router-global. To scope it, add a `/ip hotspot walled-garden` **allow** for the zone's non-guest VLANs, or give non-guest zones a different DNS server | ⚠️ works, but it is a DNS-path construct, not a firewall rule |
| Domain (SNI) | Scope by `src-address-list` = the zone's subnet on the `tls-host` drop rule | ✅ clean |
| IP/CIDR | Scope by `src-address-list` on the drop rule | ✅ clean |
| Device | `/ip hotspot ip-binding` is per-MAC, effectively per-network | ✅ |
| Category / Application | Inherits the mechanism it compiles to (DNS or SNI) | ⚠️ inherits that mechanism's limits |

**Recommendation:** implement zone scoping via **SNI + IP rules with `src-address-list`**, and treat the
DNS sinkhole as the unscoped fallback. Be explicit in the UI about which scope is in force.

### 8.3 Feature chain

**UI** single-item block form + active blocks table + push status.
**Policy** a `security_policy_rules` row of `kind = BLOCK_<type>`, or a direct one-off block.
**Enforcement** DNS sinkhole / `tls-host` drop / address-list drop / `ip-binding` depending on type.
**Technology required** none new for Domain, IP, Device, Port. Countries need a feed (§13). Categories and
Applications need the caveats in §11–§12.
**Limitations** stated per type, in the UI, at the point of creation — including the DNS bypass above.

---

## 9. IP blocking

### 9.1 Input

Accept a single IP, CIDR, IP range, or a pasted list (one per line). Normalise to CIDR, reject private /
loopback / multicast / the management tunnel subnet, and require an explicit confirmation when the range is
larger than `/16`.

The existing `content_filtering.validators` already normalises values and
`firewall.validators.validate_address` validates addresses — reuse both, do not write new parsers.

### 9.2 Model extension

`content_filter_rules` already stores `value_type = ip_cidr` with `value`, and the address-list plus one
shared positioned drop rule. What it lacks and this feature needs:

| Need | Where it goes |
|---|---|
| Reason / note | `comment` exists |
| Created by | `BaseModel.created_by` + the audit entry |
| Created date | `BaseModel.created_at` |
| Locations | already `router_id`/`location_id`/`organization_id` |
| Hit count | new — address-list entries have no counters; count via the *drop rule's* counter, or add a per-rule mangle/accounting rule. Be honest: for a shared list, per-entry hits require per-entry rules |
| Allowlist (exceptions) | **new** — an `ALLOW` list evaluated *above* the block list, or `content_filter_rules` gains `action` |
| Expiry | **new** — `expires_at`, swept by Celery |

### 9.3 Rendering

```
/ip firewall address-list add list=wyfyguest-content-filter-blocked address=185.220.101.0/24 \
    comment="wyfyguest-cf:<rule_uuid> Threat feed"
/ip firewall filter add chain=forward src-address-list=wyfyguest-content-filter-blocked \
    action=drop comment="wyfyguest-cf-enforce"      # one per router, position-managed
```

### 9.4 Limitations

Inbound and outbound both work for literal IPs. Do **not** imply IP blocking stops a domain — modern
services are behind rotating CDN addresses, so blocking `facebook.com`'s IPs is a treadmill. The UI should
actively steer users from IP to Domain/SNI when they paste a hostname.

---

## 10. Domain blocking

### 10.1 Two enforcement mechanisms — both real, both limited

**Mechanism 1 — DNS sinkhole (already implemented, `content_filtering`).**

```
/ip dns static add name=facebook.com      address=127.0.0.1 comment="wyfyguest-cf:<id>"
/ip dns static add regexp="^.*\.facebook\.com$" address=127.0.0.1 comment="wyfyguest-cf:<id>"
```

Two entries because RouterOS treats `name=` and `regexp=` as mutually exclusive per entry.

**Mechanism 2 — TLS SNI matching via RouterOS `tls-host` (native, verified, not yet used by us).**

```
/ip firewall filter add chain=forward protocol=tcp dst-port=443 \
    tls-host=*.facebook.com action=drop \
    src-address-list=<guest zone> \
    comment="wyfyguest-cf:<id>"
```

This blocks HTTPS by the hostname in the TLS ClientHello and does **not** require DPI or interception.
It is a genuine RouterOS capability (available since 6.41) and is the single largest upgrade available to
our existing domain blocking.

### 10.2 Honest limitations (document these in the product, not just the spec)

| Limitation | Detail | Mitigation we can offer |
|---|---|---|
| **DNS bypass** | A device with hardcoded DNS or DoH/DoT never asks our resolver. **Precise state of play: the platform already blocks DoT (udp/tcp 853) and DoH (tcp 443 to `cloudguest-doh-ips`) — but only for *unauthenticated* hotspot clients** (`hotspot=!auth`). **Once a guest logs in, those rules no longer match and DoH/DoT is wide open.** So today a *logged-in* guest who turns on private DNS bypasses every domain block completely | **Highest-value cheap fix: extend the existing `hotspot=!auth` DoH/DoT drops to cover authenticated traffic too**, then add the `udp/tcp 53` redirect to the router for LAN clients. This reuses the rules and address-list that already exist. Remaining gap: DoH over 443 to an unknown host is indistinguishable from ordinary HTTPS without SNI, and the `cloudguest-doh-ips` list rots |
| **ECH (Encrypted Client Hello)** | RFC 9849 reached Standards Track in **March 2026**; Chrome and Firefox ship ECH enabled by default and Cloudflare distributes keys widely. When ECH negotiates, **SNI is encrypted and `tls-host` matches nothing.** Many clients still fall back to plain SNI, so coverage is partial and decaying | None at the network layer. The only durable path is enforcing our own resolver and relying on DNS, which ECH does not hide (the *client* still needs to resolve the name unless it uses DoH) |
| Non-TLS traffic | `tls-host` sees nothing for QUIC/HTTP3, plain HTTP, or a VPN | Block QUIC/UDP 443 to force TCP fallback where acceptable |
| Wildcards | Only prefix-wildcard style hostnames; no path, query or regex semantics beyond what RouterOS accepts | Keep UX to exact + `*.` |
| Rule volume | Every SNI rule is a per-packet match; hundreds are costly on small hardware | Cap, warn, and prefer one rule per *group* |

**Product rule:** the Blocking UI must show, next to every domain entry, a one-line *"Blocks: DNS + HTTPS
hostname. May not block: apps with private DNS (DoH) or ECH. [Learn more]"*. The customer is told the
truth at the moment they create the policy.

### 10.3 Wildcards and groups

- `*.facebook.com` → SNI `tls-host=*.facebook.com` + DNS `regexp="^.*\.facebook\.com$"`.
- Domain groups = one `security_policy_rules` entry referencing many domains → **one** `tls-host` rule
  cannot take a list, so a group compiles to N rules joined by an address-list-style jump or a single
  regexp SNI rule where RouterOS permits. If neither is efficient, compile to N rules and surface the
  count in the impact preview ("this will create 14 firewall rules on 3 gateways").

### 10.4 Feature chain

**UI** Block form, Type = Domain; wildcard helper; DNS-force toggle; limitation note verbatim.
**Policy** `security_policy_rules(kind=BLOCK_DOMAIN)` with scope.
**Enforcement** `/ip dns static` sinkhole **and** `/ip firewall filter tls-host` drop (both, so one covers
the other's gap).
**Technology required** none new.
**Limitations** as tabulated in §10.2 — DNS bypass, ECH, QUIC, non-TLS, rule volume.

---

## 11. Web category filtering

**Verdict: not deliverable with the current stack. Do not ship checkboxes that write rows.**

Why: category filtering needs (a) a maintained, licensing-backed database mapping domains/IPs to
categories, (b) periodic updates, and (c) a resolver or inspection point that applies the category at
request time. RouterOS provides none of the three. Our own code already says this —
`ContentFilterCategory` is documented as *"deliberately not a seeded, complete blocklist-per-category…
shipping a fabricated one that only looks complete would be exactly the kind of shortcut this codebase's
conventions reject."* That judgement is correct and should be preserved.

### 11.1 Three honest paths, in order of preference

| Option | What it is | Cost / effort | Coverage |
|---|---|---|---|
| **A. Managed DNS filtering service** (Cloudflare Gateway / NextDNS / Cisco Umbrella) | Point the venue's guest DNS at the provider; categories and policies are configured there, results sync back into WyFyGuest | Provider subscription per venue; a real integration | ✅ 50+ categories, blocklists, per-policy rules, logging. **This is the only path that honestly delivers the brief's category list** |
| **B. Licensed domain-category feed, applied by us** | Buy a category feed (e.g. a Domain Reputation/URL-category API), sync domains per category into our existing DNS-sinkhole + `tls-host` machinery | Feed licence + a Celery sync + a lot of address-list/rule volume on device | ⚠️ Partial. Category feeds are enormous (hundreds of thousands of domains); pushing them to a RouterOS device is not viable. Would need a DNS-resolver-side filter, which we do not operate |
| **C. Customer-curated categories** | What exists today: the customer picks domains and tags them with a category label for reporting | Free, already built | ⚠️ Not category filtering. It is grouped domain blocking — which is fine, if it is labelled that way |

**Recommendation:** ship **C** now (labelled honestly as "Your own lists"), design the UI so **A** slots in
as a provider toggle later, and **do not build B**.

### 11.2 UI (target state, with A integrated)

```
Security → Blocking → Categories
  Apply to  [ Guest Wi-Fi ▾ ]      Provider: ● WyFyGuest DNS Filtering (configured)  [ Change ]

  ☐ Adult & Explicit        ☑ Malware & Phishing       ☐ Gambling
  ☑ Social Media            ☐ Streaming                ☐ Gaming
  ☐ Cryptocurrency          ☐ Shopping                 ☐ News
  ☐ Education               ☐ Productivity             ☐ Ads & Trackers

  ⓘ These categories are enforced by your DNS provider, not by the gateway.
    Devices that bypass our DNS (private DNS / DoH) are not covered.
  [ How to enforce our DNS ]                                    [ Save & Deploy ]
```

Without a provider configured, this screen renders the **Not available** state with a "Connect a DNS
filtering provider" CTA — never an empty checkbox grid that appears to work.

### 11.3 Feature chain

**UI** category grid, provider-aware.
**Policy** `security_policy_rules(kind=CATEGORY)` — stored, but only enforceable when a provider exists.
**Enforcement** provider DNS policy (Option A). Never RouterOS.
**Technology required** maintained category DB + resolver (a provider, or a licensed feed plus an operator
we do not have).
**Limitations** DNS-path only; bypassable by DoH/private DNS; provider cost; provider outage = no filtering.

---

## 12. Application Control

**Verdict: deliverable for a *subset* of applications, provided the UI states reliability per application.
Never label it "Application Control" as if it were DPI.**

### 12.1 What each signal can actually identify

| Signal | Native? | Identifies | Fails on |
|---|---|---|---|
| **DNS** | ✅ `/ip dns static` sinkhole | Apps whose client resolves a stable domain through our resolver | DoH/private DNS, hardcoded IPs, shared domains |
| **IP / CIDR** | ✅ address-list | Apps with stable, owned ranges | CDN-hosted apps, IP rotation, shared edges |
| **SNI (`tls-host`)** | ✅ RouterOS, no DPI | Apps whose traffic is TLS with a distinctive hostname | **ECH**, QUIC/HTTP3, apps using a generic front, cert-pinning to a non-matching SNI |
| **Port / protocol** | ✅ | Crude classes (e.g. non-443 UDP = often QUIC/WebRTC) | Almost everything modern |
| **RouterOS `layer7-protocol`** | ⚠️ exists | Plaintext HTTP payload regex | All HTTPS; CPU-heavy; unreliable — **do not build on this** |
| **Hotspot `walled-garden`** | ✅ | **Allow**-listing only, not denying | Not a blocking mechanism |
| **External intelligence / provider** | ❌ not integrated | Category/app mapping | Requires a provider (§11) |
| **Deep Packet Inspection** | ❌ none | True app identity, robust against ECH | Requires dedicated hardware or a cloud inspection path |

### 12.2 Reliability tiers shown in the UI

Every application row carries a badge, driven by a maintained table — not by optimism:

```
Category › Application                    Reliability        Mechanism
─────────────────────────────────────────────────────────────────────────
Social Media
  Facebook                                Good               DNS + SNI
  Instagram                               Good               DNS + SNI
  TikTok                                  Fair               DNS + SNI (app also uses DoH)
  X / Twitter                             Good               DNS + SNI
Streaming
  YouTube                                 Fair               DNS + SNI (many CDN hosts)
  Netflix                                 Fair               DNS + SNI (pinned, fragmented)
  Prime Video                             Fair               DNS + SNI
Gaming
  Steam                                   Good               DNS + SNI + IP
  Roblox                                  Fair               DNS + SNI + IP
  Other                                   Unreliable         —
Messaging ≠ blockable
  WhatsApp                                Unreliable         Uses ECH/private infra; shows as "Unknown"
  Signal                                  Unreliable         Same
```

`Good` = domain/SNI set is stable and we can name it. `Fair` = works most of the time; CDN or ECH may leak.
`Unreliable` = we will not offer a toggle, and the row explains why. **Shipping a WhatsApp toggle would be
the exact lie this document exists to prevent.**

### 12.3 UI

```
Security → Blocking → Applications
  Apply to  [ Guest Wi-Fi ▾ ]     Schedule [ 9:00 – 18:00 ▾ ]

  [ Search applications… ]                        Reliability: [ All ▾ ]

  ▾ Social Media
    ☑ Facebook        Good    DNS + SNI      [Allow ▾]
    ☑ Instagram       Good    DNS + SNI      [Allow ▾]
    ☑ TikTok          Fair    DNS + SNI      [Allow ▾]
    ☐ X / Twitter     Good    DNS + SNI      [Allow ▾]
  ▸ Streaming        (3 apps, 1 blocked)
  ▸ Gaming
  ▸ Messaging        (2 apps — cannot be reliably blocked)   ⓘ

  [ Apply Policy ]
```

The brief's exact example — *Block Social Media · Guest Wi-Fi · 9:00–18:00* — is deliverable: it compiles
to a scheduled `tls-host`+DNS group on the Guest zone. What is **not** deliverable is claiming we
identified the app; we matched names, and the badge says so.

### 12.4 Feature chain

**UI** categorised app tree with per-app reliability + mechanism badges, allow/block/schedule.
**Policy** `security_policy_rules(kind=APPLICATION)` → compiles to the domain/SNI rules for that app's
known hostname set (a maintained `application_hostnames` catalogue).
**Enforcement** DNS sinkhole + `tls-host` drop on scheduled windows (schedules via `queue_schedules`'
existing shape, reused).
**Technology required** none for the Good/Fair tier; **DPI or a provider** for the Unreliable tier.
**Limitations** ECH, DoH, CDN churn, shared frontends. Maintained per-app hostname catalogue is now an
ongoing data-maintenance obligation — budget for it or the reliability badges will rot.

---

## 13. Geo Blocking

### 13.1 What works

Inbound geo-blocking is genuinely achievable: sync per-country CIDR lists into
`/ip firewall address-list`, then reference them from `input`/`forward` rules.

```
/ip firewall address-list add list=wyfyguest-geo-RU address=5.8.0.0/19 comment="geo:RU"
/ip firewall filter add chain=input in-interface=<WAN> src-address-list=wyfyguest-geo-RU \
    action=drop comment="wyfyguest-geo-enforce:RU"
```

### 13.2 Feed maintenance and sync

- **Source:** a GeoIP country-CIDR source (MaxMind GeoLite2 export, or a published aggregated country zone
  file). Note: the platform has **no GeoIP integration today** — `analytics/domain_analytics_service.py`
  carries an explicit `_NO_GEOIP_MESSAGE`. This feature introduces the first one.
- **Pipeline:** nightly Celery Beat task (`device_io` queue), per-router and staggered:
  1. download/refresh the source (cached in object storage, immutable, checksummed);
  2. compute per-country CIDR sets;
  3. diff against what the router currently holds (read back by `list=` prefix);
  4. apply the diff (add/remove), never a wholesale rewrite — a full rewrite on a busy router is a
     self-inflicted outage;
  5. record `feed_version`, `synced_at`, `entry_count` per router; alert on failure.
- **Versioning:** store `feed_version` on the rendered rule so "why did this change?" is answerable.

### 13.3 Limitations — say these out loud

| Limitation | Detail |
|---|---|
| List size | A large country is tens of thousands of CIDRs. RouterOS address-list lookups are linear-ish and memory-hungry on small hardware. Cap the number of countries, show entry counts, warn above a threshold |
| **Outbound is unreliable** | CDN edges resolve into many countries. Blocking "RU outbound" will break legitimate destinations and miss the intended ones. Offer inbound confidently; label outbound "best effort" |
| Staleness | Feeds are days-to-weeks behind allocation changes |
| Geo ≠ intent | A VPN/proxy in a permitted country defeats inbound geo-block entirely |
| IPv6 | Must be maintained as a separate list and referenced by `/ipv6 firewall filter`; forgetting this silently leaves the IPv6 path open |
| Management lockout | Never geo-block the tunnel or management path — the lockout guard in §7.4 applies |

### 13.4 Feature chain

**UI** `Security → Blocking → Countries`, with inbound/outbound toggle, per-country entry counts, and a
"last updated" timestamp.
**Policy** `security_policy_rules(kind=GEO)`.
**Enforcement** country address-lists + `input`/`forward` drop.
**Technology required** a GeoIP/CIDR source + a sync pipeline (new).
**Limitations** as tabulated; inbound ✅, outbound ⚠️, IPv6 must be handled separately.

---

## 14. Device Isolation

### 14.1 The device view

```
Device:  MacBook-102
IP:      192.168.10.23     MAC: D4:6A:6A:…:2F
User:    John Mathew       Zone: Office     Vendor: Apple
Last seen: 2 min ago       Session: active (1h 12m, 480 MB)

[ Block Internet ]   [ Isolate Device ]   [ Allow ]   [ Add to Policy ]   [ Disconnect now ]
```

### 14.2 The three real actions, and what each does

| Action | Real implementation | Durability | Honest notes |
|---|---|---|---|
| **Disconnect now** | `guest_access` → `/ip hotspot active remove` over 8728 (existing `BlocklistEnforcer`) | Session only — the device can re-authenticate | The only thing that takes effect *immediately* today |
| **Block Internet** | `/ip firewall filter chain=forward src-address=<ip>` `action=drop` (or an address-list entry + the shared drop), **plus** a `guest_access` blocklist rule so re-login is refused | Durable, but IP-keyed → breaks on DHCP lease change | Must be tied to the MAC→IP binding to survive a lease change, or scoped by MAC |
| **Isolate Device** | Drop all `forward` from/to that address **except** an allow-list (DNS to router, the captive portal, admin-approved destinations). For a known MAC use `/ip hotspot ip-binding type=blocked`; for hotspot guests prefer the firewall-list approach | Durable | Isolation is a firewall construct. There is no "quarantine VLAN" today; adding one is a `vlan` + DHCP + hotspot change — a larger piece of work |
| **Allow** | Remove the address-list/ip-binding entry, clear the `guest_access` rule | — | Must be idempotent and audited |

### 14.3 MAC randomisation — the standing caveat

Guest devices randomise MACs per SSID. `mac_authorization` and `guest_access.device_adapters` already
document this: a durable `/ip hotspot ip-binding type=blocked` is reserved for *known* device rules and is
explicitly rejected for randomising guest clients. Therefore:

- **Known / enrolled devices** (staff laptop, front-desk tablet, printer): MAC-keyed block is durable ✅
- **Anonymous guests**: block by current IP **and** force re-auth refusal via `guest_access`, accepting
  that a fresh random MAC gets a fresh identity. The UI must say this.

### 14.4 Feature chain

**UI** device drawer with the four actions + confirmation dialogs on the destructive ones.
**Policy** `security_policy_rules(kind=DEVICE_BLOCK | DEVICE_ISOLATE)` or a `guest_access` rule.
**Enforcement** `ip-binding type=blocked` (known MACs) / address-list + `forward` drop (IPs) /
`/ip hotspot active remove` (immediate).
**Technology required** none new.
**Limitations** MAC randomisation for guests; DHCP lease changes for IP-keyed blocks; isolation is
allow-list-based and must include the platform's own required destinations or the device becomes
unmanageable.

---

## 15. VLAN Security

### 15.1 The matrix (the highest-value UI in this document)

```
Security → Zones & Isolation                                   [ Edit matrix ]

              │ Internet   Office     Guest      IoT        CCTV       Servers    Admin
──────────────┼────────────────────────────────────────────────────────────────────────
 Office    →  │  ALLOW     —          ALLOW      BLOCK      BLOCK      ALLOW      BLOCK
 Guest     →  │  ALLOW     BLOCK      BLOCK      BLOCK      BLOCK      BLOCK      BLOCK
 IoT       →  │  ALLOW     BLOCK      BLOCK      BLOCK      BLOCK      BLOCK      BLOCK
 CCTV      →  │  BLOCK     BLOCK      BLOCK      BLOCK      BLOCK      BLOCK      BLOCK
 Servers   →  │  ALLOW     SELECT     BLOCK      BLOCK      BLOCK      —          BLOCK
 Admin     →  │  ALLOW     ALLOW      ALLOW      ALLOW      ALLOW      ALLOW      —

Legend:  ALLOW · BLOCK · SELECT (choose hosts/ports) · — (same zone / not applicable)
⚠ 2 cells are implicit-deny and will be enforced even though not set explicitly.
```

Clicking a cell opens a small editor: allow/block, plus optional service and schedule. A **Preview rules**
button shows the exact RouterOS rules the matrix compiles to, and a **Dry run** validates against the
live snapshot.

### 15.2 Compilation

The matrix is a *declarative* zone-policy. It compiles to `chain=forward` rules, and the compiler must
emit an explicit default-deny posture rather than relying on RouterOS's implicit behaviour:

```
# per zone pair, in matrix order
/ip firewall filter add chain=forward src-address-list=zone-guest dst-address-list=zone-office \
    action=drop comment="wyfyguest-sec:<matrix_cell_id> guest→office"
/ip firewall filter add chain=forward src-address-list=zone-guest dst-address-list=zone-servers \
    action=drop comment="wyfyguest-sec:<matrix_cell_id> guest→servers"
# zone membership lists, refreshed whenever a VLAN subnet changes
/ip firewall address-list add list=zone-guest address=<guest VLAN cidr> comment="wyfyguest-zone:guest"
```

Reuse the existing renderers/adapters and the position-management pattern; add a
`SecurityPolicyCompiler` that turns matrix cells into these rules, and store the cell ids so the rules
remain identifiable after a rename.

### 15.3 The trap you must not walk into

**If two zones share a bridge without inter-VLAN routing, their traffic never reaches `chain=forward`.**
Firewall rules only see traffic that is *routed* by the router. So:

- the compiler must verify each zone has its own VLAN interface + subnet (i.e. it is routed), and
- if a zone's VLAN has no gateway/IP on this router (the `vlans` table has `gateway_ip_address`/`cidr`),
  the matrix cell must render as **"cannot enforce — zone not routed on this gateway"** rather than a
  green tick.

This is exactly the "looks configured, blocks nothing" failure class the codebase already guards against
for content filtering. It applies with more force here.

### 15.4 Also supported, cheaply

- **Intra-zone isolation** (guest↔guest): a forward drop for `src-address-list=zone-guest
  dst-address-list=zone-guest`, or bridge port horizon. Offer it as a per-zone toggle "Prevent devices in
  this zone from talking to each other".
- **Internet-only zone**: a single cell that drops everything except the WAN egress.
- **Per-SSID zones**: an SSID can be bound to a VLAN (existing `vlans.enable_hotspot`), so SSID scoping is
  mostly a naming concern over the same machinery.

### 15.5 Feature chain

**UI** visual matrix + cell editor + preview + dry run.
**Policy** `security_policy_rules(kind=ZONE_MATRIX)` — one row owning all cells, or one per cell for
auditability. Prefer one row per cell (cleaner versions, diffs and rollbacks).
**Enforcement** `/ip firewall filter chain=forward` with zone address-lists.
**Technology required** none new. Depends on `vlan` being pushed and routed.
**Limitations** routed traffic only (§15.3); rule-count growth is O(zones²) — with 6 zones that is up to 30
rules/gateway, fine; with 20 zones it is 380, which is not. Cap zones in the matrix UI and warn.

---

## 16. Threat Protection

Each toggle must declare **who actually enforces it**. Fill this in truthfully:

```
Security → Threat Protection
                                    Enforced by          Status
  Bogus / bogon IP drop             Gateway (RouterOS)   [ON]
  Connection flood / SYN flood      Gateway (RouterOS)   [ON]
  Port scan detection               Gateway (heuristic)  [ON]
  Brute force on router services    Gateway (RouterOS)   [ON]
  DHCP rogue-server detection       WyFyGuest (existing) [ON]
  Malicious IP blocklist            WyFyGuest + feed     [OFF — connect a feed]
  Malware / phishing domains        DNS provider         [Not available]
  Botnet C&C domains                DNS provider         [Not available]
  DoS protection                    Gateway (partial)    [ON]
  Threat intelligence               Feed required        [Not available]
```

| Protection | Native MikroTik | WyFyGuest cloud | Cloudflare | Third-party feed | Honest label |
|---|---|---|---|---|---|
| Bogon / RFC1918 drop | ✅ `address-list` + raw drop | Renders it | ✗ | ✗ | **Gateway** |
| Connection/dst limits | ✅ `connection-limit`, `dst-limit` | Renders it | ✗ | ✗ | **Gateway** |
| SYN flood | ✅ `tcp-syncookies` (`/ip settings`) | Toggles it | ✗ | ✗ | **Gateway** |
| Port-scan heuristic | ⚠️ `dst-limit` + `psd` where the ROS version has it; otherwise heuristic only | Renders it | ✗ | ✗ | **Gateway (heuristic)** — say "heuristic", never "detects port scans" |
| Brute force on 22/8728/8291 | ✅ connection-limit per source | Renders it | ✗ | ✗ | **Gateway** |
| Rogue DHCP | ✅ existing `/ip dhcp-server alert` | ✅ implemented | ✗ | ✗ | **WyFyGuest** |
| Malicious IP blocklist | ✅ address-list (we supply the content) | Sync pipeline | ✗ | ✅ needed | **Feed-dependent** |
| Malware/phishing/botnet **domains** | ✅ sinkhole/`tls-host` (we supply the list) | Sync pipeline | ⚠️ only if Cloudflare Gateway is the resolver | ✅ needed | **Feed-dependent** |
| IDS/IPS signature detection | ❌ | ❌ | ✗ | ⚠️ dedicated appliance | **Not available** |

**Product rules:** every toggle renders its enforcement owner inline; any toggle whose owner is
`Not available` is rendered **disabled with a reason**, never as an off switch. A feed-dependent feature
shows feed freshness, or it is disabled.

---

## 17. Cloudflare Integration — an honest correction

**This is the most important correction in the document.**

### 17.1 The premise needs fixing

The brief implies Cloudflare can be an inline security layer for a customer's guest network. It cannot.
Cloudflare protects **things that sit behind Cloudflare's edge** — its own proxied DNS, WAF, DDoS
mitigation, Zero Trust. A guest on a venue's Wi-Fi is not behind Cloudflare's edge; their traffic goes
straight out the venue's WAN.

**Current state of our stack: there is no Cloudflare integration of any kind.** A full-repo search found
only incidental uses of public Cloudflare *endpoints*:
`isp/constants.py` uses `speed.cloudflare.com` as a speed-test target, and `system_time.py` lists
`time.cloudflare.com` as an NTP server. No API client, no token, no WAF, no Zero Trust, no Tunnel. Every
"tunnel" in the codebase is our own WireGuard tunnel. Any spec that assumes a Cloudflare integration
exists is starting from zero.

### 17.2 Where Cloudflare genuinely helps — and where it does not

| Cloudflare product | Helps WyFyGuest how | Does **not** do |
|---|---|---|
| **DNS** (authoritative + proxied) | Protect `wyfyguest.com` and each venue's portal/custom domain | Protect a guest's browsing |
| **WAF + DDoS** | Protect the WyFyGuest **platform** (our API, portal, dashboard) | Sit in a guest's packet path |
| **Zero Trust / Access** | Gate **operator/admin** access to the console and internal tools; replace any IP-allowlist | Filter guest traffic |
| **Tunnel (cloudflared)** | Expose a venue's internal service (e.g. a PMS) to the platform without opening inbound ports | Act as a firewall for the LAN |
| **Gateway (Zero Trust DNS filtering)** | ⭐ **The one genuinely useful path for guest security:** the venue's DNS forwards to Cloudflare Gateway (DoH), so domain + **category** filtering and logging happen in Cloudflare, and we manage the policy + show the results in WyFyGuest | Work if guests bypass our DNS. Category coverage depends on the plan |

### 17.3 What to build

```
Settings → Integrations → Cloudflare
  Status            ● Connected   (account: WyFyGuest · zone: wyfyguest.com)
  Protection        WAF ● Active   DDoS ● Active   Bot Management ○ Off
  Zero Trust        ● Enabled — protecting console access (3 policies)
  DNS               ● Proxied — 4 records
  Gateway (DNS)     ● Configured as guest resolver — 2 locations   [ Manage categories ]
  Last API sync     2 min ago                                     [ Test connection ]
```

**Control from WyFyGuest:** connection status, DNS records for our own domains, WAF on/off + managed ruleset
level, Zero Trust policy presence, and — importantly — **Gateway DNS category policy**, because that is the
guest-facing capability.

**Leave as advanced settings (link out, do not reimplement):** custom WAF rules, rate-limiting rule
expressions, bot-fight modes, TLS/SSL configuration, page rules, Tunnel ingress config, Access policy
expressions. Reimplementing Cloudflare's configuration surface inside our dashboard would be an enormous
maintenance liability for near-zero customer value; a deep link into the Cloudflare dashboard with the
right account is the correct integration.

### 17.4 Credentials

Per the deployment conventions: **no Cloudflare token in the repo.** Store the token Fernet-encrypted in a
new `integration_credentials` row or `network_integrations.credentials_encrypted` (the existing pattern),
key from env, token supplied by the operator. Never log it; redact on read.

### 17.5 Feature chain

**UI** integration card + link-outs; Gateway category management on the Blocking page when configured.
**Policy** `security_policy_rules(kind=CATEGORY)` delegated to Cloudflare Gateway.
**Enforcement** Cloudflare Gateway as the venue's DNS resolver; Cloudflare edge for our own domains.
**Technology required** a new Cloudflare API client (does not exist), a Cloudflare account/plan, and a
per-venue DNS change.
**Limitations** DNS-path only and bypassable; Cloudflare cannot filter a guest's traffic on our behalf;
its usefulness to the guest-security story is *only* as a DNS filtering provider.

---

## 18. MikroTik Integration

### 18.1 Keep the existing architecture; do not regress it

| Requirement from the brief | Current reality | Verdict |
|---|---|---|
| Secure outbound management | Router-initiated HTTPS polling with `X-Agent-Credential`, plus platform-initiated librouteros **inside** the WireGuard tunnel | ✅ Keep. This is the safest part of the system |
| No public exposure of RouterOS mgmt ports | A fleet port sweep reached **only 8728**, and only over the tunnel; SSH/22 is filtered | ✅ Keep. Add a fleet-wide assertion so this never regresses |
| mTLS | ❌ Not used. Agent auth is a SHA-256-compared bearer credential; RouterOS API auth is username/password | ⚠️ **Recommended upgrade:** issue the agent a client certificate and verify it at the edge, so a leaked credential string is not sufficient. Cheap relative to the risk |
| Device-initiated connection | ✅ Two `/system scheduler` scripts (heartbeat 5 m, authmac 1 m) | ✅ Keep |
| RouterOS REST API | ❌ Not used. The platform uses librouteros (binary API) on 8728 | ⚠️ Correctly so: **do not expose 443/REST**, it widens the attack surface for no gain |
| SSH | Used for file movement only, and unreachable in the field | ❌ Do not build new features on SSH/SFTP |

### 18.2 What WyFyGuest manages on the device (and how)

| Object | Adapter method | Push state | Immediate or queued |
|---|---|---|---|
| Firewall filter rules | **new** `configure_firewall_rule` / `delete_firewall_rule` | `device_push_status` | queued (new), direct today for peers |
| Firewall address-lists | extend `configure_content_filter_rule` pattern | ✅ | direct |
| DNS static / sinkhole | `configure_content_filter_rule` (exists) | ✅ | direct |
| TLS host rules | extend the firewall writer | new | direct |
| VLANs | `configure_vlan` (exists) | ✅ | direct |
| DHCP pools | `configure_dhcp_pool` (exists) | ✅ | direct |
| NAT / port forwards | `configure_port_forward` / `configure_nat_masquerade` (exist) | ✅ | direct |
| Queues / bandwidth | `create_simple_queue` etc. (exist) | ✅ | direct + Celery sweeps |
| Hotspot bindings | `end_hotspot_sessions` (exists) | ✅ | direct |
| WireGuard peers | hub agent `POST /wg/peer` (exists; **no delete verb**) | partial | direct |
| Routing | `set_default_route_distances`, `ensure_wan_egress` (exist) | ✅ | direct |

**How customers get told the truth:** every row that reaches a device carries the
`device_push_status` / `device_push_error` / `device_pushed_at` trio, and
`app/common/device_push.demote_device_push_on_edit` demotes an `active` row when a device-carried field is
edited. Any new security table must adopt the identical trio and declare its own `DEVICE_CARRIED_FIELDS`.
This is a platform invariant, not a nice-to-have — it is the mechanism that prevents the
*"dashboard says blocked, device says no"* class of bug.

---

## 19. Multi-Vendor Abstraction

### 19.1 It already exists — extend it, do not invent a second one

```
DeviceVendor:            MIKROTIK · TPLINK_OMADA · RUCKUS · UNIFI · ARUBA · CISCO_MERAKI
Device-gateway contract: wyfy_device_gateway.contract.DeviceGatewayAdapter  (~60 methods)
                         registry.get_adapter(vendor) → real = MikroTikAdapter only
                         all others = stubs raising NotImplementedError, capabilities() all False
Controller contract:     ControllerVendor.TPLINK_OMADA → ControllerAdapter → OmadaControllerAdapter
App-level seams:         ProvisioningAdapterProtocol · BaseProvisionAdapter · NetworkProvider
App-level predicates:    router/vendor_capabilities.py · fleet_scope.agent_managed_only()
```

### 19.2 The Security layer's own contract

Add a narrow, vendor-neutral protocol rather than teaching every adapter about our policy model:

```python
class SecurityEnforcementAdapter(Protocol):
    vendor: str
    def capabilities(self) -> SecurityCapabilities: ...      # what CAN be enforced here
    async def apply_rule(self, creds, *, rule: CompiledRule) -> None: ...
    async def remove_rule(self, creds, *, rule_id: str) -> None: ...
    async def deploy_rule_set(self, creds, *, ruleset: CompiledRuleSet) -> None: ...
    async def read_rule_counters(self, creds) -> list[RuleCounter]: ...
    async def read_zone_subnets(self, creds) -> list[ZoneSubnet]: ...   # for §15.3
    async def health_check(self, creds) -> SecurityHealth: ...
```

`SecurityCapabilities` is the crux — it is how the UI stays honest per vendor:

```python
@dataclass(frozen=True)
class SecurityCapabilities:
    zone_to_zone_firewall: bool
    sni_filtering: bool          # RouterOS yes; most others no
    dns_sinkhole: bool
    address_lists: bool
    per_device_isolation: bool
    ipv6_firewall: bool
    schedules: bool
    counters: bool
```

**The UI renders from `capabilities()`, not from a hardcoded list.** A customer on an Omada-only venue sees
"Zone firewall — not supported on this gateway type", instead of a toggle that silently does nothing. This
is the same "evidence beats label" posture `router/vendor_capabilities.py` already takes.

### 19.3 Translation example

Customer policy: **Guest → LAN = BLOCK**

| Vendor | Compiled to |
|---|---|
| MikroTik | `/ip firewall filter add chain=forward src-address-list=zone-guest dst-address-list=zone-lan action=drop comment="wyfyguest-sec:<id>"` |
| Omada (controller API) | Controller request creating an ACL/gateway rule with source/destination network and deny action |
| Aruba / Meraki / UniFi | Vendor rule object with source network, destination network, deny — shape differs, semantics identical |
| None supported | Cell renders "cannot enforce on this gateway" |

Implementing non-MikroTik enforcement is **FUTURE**, and this document does not pretend otherwise: those
adapters are stubs today. What must be built now is the *contract* and the *capability-driven UI*, so that
the first non-MikroTik implementation does not require re-architecting anything.

---

## 20. Policy Engine

### 20.1 The pipeline the brief asks for, mapped to real components

```
WyFyGuest Dashboard
      ↓
SecurityPolicyService            ← new domain
      ↓
Policy Validation                ← validators.py (reuse firewall.validators, content_filtering.validators)
      ↓
Conflict Detection               ← new: zone/port/priority conflicts + lockout guard
      ↓
Configuration Generator          ← compiler.py  (policy → CompiledRuleSet per router)
      ↓
provisioning_engine plan         ← REUSE: configuration_plans, PlanStatus, assess_management_risk
      ↓
MikroTik / Cloudflare            ← MikroTikAdapter (8728) · Cloudflare API
      ↓
Enforcement + verification       ← ManagedRouterResource, VerificationRun, RouterSnapshot
      ↓
Monitoring                       ← security_events, monitoring.AlertService
```

Nothing in the middle column is new invention: `provisioning_engine` already implements plan → approve →
render → prepare → apply → verify with a persisted state machine, a snapshot of actual state, managed-
resource drift tracking, and a management-connectivity risk assessment.

### 20.2 Policy dimensions

All seven dimensions from the brief are already supported by `policy_assignments`
(`scope_type`, `scope_id`, `target_type`, `target_id`, `priority`):

| Dimension | Where it resolves |
|---|---|
| Organization | `PolicyAssignment.scope_type = organization` |
| Location | `scope_type = location` |
| Gateway | `target_type = router` (or `scope_type = router`) |
| VLAN / Zone | new `target_type = vlan` |
| SSID | new `target_type = ssid` (an SSID maps to a VLAN/hotspot profile) |
| User group | `target_type = guest_team` (existing `guest_teams`) |
| Device group | `target_type = device_group` (new; backed by MAC/device sets) |
| Schedule | reuse `queue_schedules` shape (`days_of_week`, `start_time`, `end_time`, `timezone`) |

### 20.3 Adding a policy type (additive, per house style)

```python
class PolicyType(StrEnum):
    ...
    SECURITY = "security"      # additive member; stored as String, so no migration
```

Plus a typed schema so `rules` is validated rather than "any JSON object":

```python
class SecurityPolicyRules(BaseModel):
    kind: SecurityRuleKind          # ZONE_MATRIX | BLOCK_DOMAIN | BLOCK_IP | BLOCK_DEVICE |
                                    # BLOCK_APP | BLOCK_CATEGORY | BLOCK_GEO | PROTECTION
    action: SecurityAction          # allow | block | reject
    zones: ZoneRef | None
    domains: list[str] = []
    addresses: list[str] = []
    applications: list[str] = []
    categories: list[str] = []
    countries: list[str] = []
    service: ServiceRef | None
    schedule_id: UUID | None
    log: bool = True
    alert_threshold_per_hour: int | None = None
```

This gives us, for free: `policy_versions` (compare/rollback), `published_at`, per-scope assignment with
priority-based precedence, and the audit + RBAC plumbing that already wraps the `policy` domain.

### 20.4 Conflict detection rules

| Conflict | Detection | Resolution |
|---|---|---|
| Same source+destination+service, both ALLOW and BLOCK | Compare compiled tuples | Block wins; warn the author |
| Duplicate semantic rules across scope precedence | Compare compiled tuples with resolved scope | Shadowed rule flagged as *redundant*, not an error |
| A BLOCK that shadows an ALLOW the platform needs | Lockout guard (§7.4) | **Refuse to compile** |
| Ordering ambiguity at equal priority | Same priority + overlapping match | Require explicit ordering; show effective order |
| Zone referenced but not routed | `read_zone_subnets` finds no subnet | Block the cell with "zone not routed here" |
| Total rule count over a device threshold | Compile-time count | Warn with the count; require acknowledgement |
| Schedule overlap producing contradictory states | Interval intersection per zone | Warn; last-writer with an explicit preview |

Conflict detection runs **before** a plan is created, so the customer sees it in the builder rather than as a
failed deploy.

---

## 21. Configuration Safety & Deployment

### 21.1 The pipeline — and what already implements each stage

```
Policy
 ↓  Validation            validators (existing per-domain validators)                   ✅ exists (extend)
 ↓  Conflict Detection    new compiler conflict pass                                    ⚠️ new
 ↓  Backup                ConfigVersion is_backup + provisioning_engine snapshot         ✅ exists
 ↓  Dry run               PlanStatus draft + plan_engine actions/conflicts               ✅ exists
 ↓  Deploy                ProvisionJob stages configuring → verifying                    ✅ exists
 ↓  Connectivity Test     network_diagnostics ping/traceroute + adapter health_check     ✅ exists
 ↓  Health Check          RouterHealthSnapshot + monitoring health checks                ✅ exists
 ↓  Commit                PlanStatus applied + ConfigVersion published                   ✅ exists
 ↓  Automatic Rollback    rollback_of_job_id / rollback_target_version_id               ✅ exists
      ↳ and device-side  SAFETY_REVERT_SCHEDULER_COMMENT scheduled revert                ✅ exists
```

**The device-side safety revert is the crown jewel.** A RouterOS `/system scheduler` entry
(`WYFYGUEST-safety-revert`) reverts the configuration after a timeout unless the platform confirms
connectivity succeeded. That is exactly the "if deployment causes the gateway to become unreachable →
automatic rollback" requirement from the brief, and it works even when the platform has lost contact with
the router — which is the only case that actually matters.

### 21.2 Security-specific additions

1. **Always arm the safety revert for security deploys.** Firewall changes are the highest-risk deploy
   class in the product; the safety net should be mandatory, not optional.
2. **Two-phase apply for zone matrices.** Apply allow rules before drop rules, so there is never an instant
   where a required path is closed.
3. **Never remove a rule and add its replacement in the same step in a way that leaves a gap.** Apply new →
   verify → remove old (the pattern `queue_management.move_queue` already uses to avoid a guest being at
   "0 kbps").
4. **Deployment status must be a first-class object** with a reachable UI: `SecurityPolicyDeployment
   {id, policy_version_id, routers[], status, steps[], started_at, finished_at, rollback_of_id,
   failure_reason}`. Show per-router progress with the same seven-step vocabulary as
   `PROVISION_STEP_SEQUENCE`.
5. **Dry run where supported, and be explicit where it is not.** RouterOS cannot dry-run a firewall change.
   Our "dry run" is a *plan + snapshot comparison*, not a device-side simulation. Label it accordingly.
6. **Concurrency.** One deploy per router at a time (advisory lock, as `queue_management` already does per
   target). Two concurrent firewall deploys racing is how a network goes down.

---

## 22. Policy Versioning

Already largely present. What to add is the *security-specific* view.

```
Security → Security Policies → "Block Guest → Internal"

  Policy: Block Guest Access to Internal Network        Type: Security · Zone rule
  ─────────────────────────────────────────────────────────────────────────────
  v18 ● Live        2 Sep 14:02  by A. Rao    Gateway: Mumbai-HQ            [Compare]
  v17              28 Aug 09:10  by S. Khan   Gateway: Mumbai-HQ · Pune    [Compare]
  v16              21 Aug 17:44  by A. Rao    Gateway: Mumbai-HQ            [Compare]
  v15 ○ Rolled back 14 Aug 11:02  by System   Gateway: Mumbai-HQ            [Rollback]

  Diff v17 → v18
    action        block → block
    service       any   → HTTPS          ← changed
    schedule      always → work-hours    ← changed
    scope         + Pune added           ← changed
```

- **View / Compare / Deploy / Rollback** map onto `policy_versions` (`rules` JSONB diff),
  `provisioning_engine` apply, and `rollback_of_version_id`.
- **Who / what / when / which locations** are all already captured (`created_by_user_id`, `published_at`,
  the audit entry, and the deployment's router list).
- **Immutable history** — a new version on every save; never mutate a version. This mirrors
  `ConfigVersion`'s `version_number` uniqueness per router and `ProvisionJob.retry_of_job_id`'s
  "a retry is a new job, never a mutation" rule.

---

## 23. Multi-Tenancy & RBAC

### 23.1 Hierarchy (existing — do not change)

```
GLOBAL ─► ORGANIZATION ─► LOCATION ─► ROUTER ─► DEVICE          (ScopeType, ordered)
CloudGuest → MSP (an Organization flagged as an MSP container) → Organization → Location → Router → Guest
```

Every new security table denormalises `organization_id` + `location_id` at write time, exactly as
`provision_jobs`, `device_sync_runs` and `content_filter_rules` do. Tenant isolation is enforced at two
layers — never one:

1. **Service layer:** `requesting_organization_id` equality checks + `LocationScope` (constructor-injected,
   fixed for the request) + `enforce_entity_location(...)` on every by-id read.
2. **HTTP layer:** `RequirePermission(..., scope=ScopeType.X)`.

### 23.2 Roles for Security

Existing seeded roles already cover most of the brief. `Network Administrator` (LOCATION scope) is the
natural Security Admin; `Read Only` and `Auditor` (ORGANIZATION scope) cover read/audit. The gap:

| Brief's role | Nearest existing | Action |
|---|---|---|
| Super Admin | `super-admin` (GLOBAL) | ✅ none |
| Organization Admin | `organization-admin` | ✅ none |
| Location Admin | `location-manager` / `network-administrator` | ✅ none |
| Network Admin | `network-administrator` (LOCATION) | ✅ none |
| **Security Admin** | — | **Add a seed**: `security-administrator`, LOCATION scope, granted the new `security.*` module in full + read on `firewall`/`vlan`/`connected_devices` |
| Read Only | `read-only` (ORGANIZATION) | ✅ none; ensure new permission keys are included in the read grant |

Two deliberate restrictions to seed **explicitly** (following the `users.impersonate` precedent, which is
granted only to Super Admin because it is materially more sensitive):

- `security.policy_rollback` and `security.policy_deploy` should **not** ride along on a generic "full
  network management" grant. A destructive firewall deploy is a distinct capability. Grant it to
  Super Admin, Platform Admin, Organization Owner and Security Admin only.
- `security.geo_feed_manage` / `security.threat_feed_manage` are platform-level (GLOBAL scope); an org admin
  selects from feeds, does not define them.

### 23.3 Permission keys

```
security.read              security.policy_create      security.policy_update
security.policy_delete     security.policy_publish     security.policy_deploy
security.policy_rollback   security.block_create       security.block_delete
security.device_isolate    security.device_block       security.events_read
security.events_export     security.feed_manage        security.integration_manage
```

Per the repo convention these are generated into the frontend's
`src/lib/backendPermissionKeys.generated.ts` and drift-checked by `test:permission-key-drift`, and mirrored
into `src/lib/customerNavPermissions.ts → NAV_PERMISSION_KEYS`. **This is a build step, not optional** — the
frontend and backend must not be allowed to disagree about permission names.

---

## 24. Traffic Analytics

### 24.1 What we can honestly show

```
Traffic → Devices
Time [ Last 1h ▾ ]  Location [ All ▾ ]  Zone [ Guest ▾ ]  [ Search device… ]

Device        Zone    IP            Vendor   Down      Up     Sessions  Action
Laptop-01     Guest   192.168.20.41 Apple    2.4 GB    180 MB 3         Allowed
Phone-02      Guest   192.168.20.77 Samsung  400 MB     42 MB 1         Blocked
PC-05         Office  192.168.10.15 Dell     120 MB     12 MB 2         Allowed
IoT-03        IoT     192.168.30.9  Espressif 20 MB      2 MB 1         Blocked
```

**The brief's per-application column ("YouTube · 2.4 GB") is not deliverable.** There is no DPI and no flow
export in the stack. Do not render an Application column with invented data.

### 24.2 Provenance, honestly split by zone type

| Source | Covers | Gives |
|---|---|---|
| RADIUS accounting → `guest_sessions.bytes_uploaded/downloaded`, `guest_quota_usages` | **Hotspot-authenticated guest traffic only** | Per guest, per device (MAC), per session, per voucher — accurate |
| `MikroTikAdapter.get_interface_traffic_counters` | Per interface / per VLAN | Per-zone and per-WAN totals |
| `/ip firewall filter` rule counters | Anything a rule matches | Per-device bytes **if** we add per-device accounting rules (costly) or a per-zone aggregate (cheap) |
| SNMP (`snmp_poller.py`) | Interface counters | Redundant with the above, useful as a cross-check |

**Honest consequence:** per-device byte accounting inside a hotspot zone is accurate today. Per-device
accounting in **non-hotspot** zones (Office, IoT, CCTV) requires either per-device firewall accounting rules
(rule-count explosion) or flow export (new collector). Ship zone-level totals there, and label them as such.

### 24.3 What to build

- `Traffic → Live Traffic`: WebSocket-driven (the platform already has `/monitoring/ws/dashboard`).
- `Traffic → Zones`: per-VLAN bandwidth, up/down, top talkers.
- `Traffic → Devices`: per-device table with zone, bytes, sessions, action taken.
- `Traffic → Destinations`: **top blocked destinations** — this we can do, from counters on our own
  DNS/SNI/IP rules.
- Filters: time range, location, zone, device, action. Search over MAC/IP/hostname.
- An explicit "Application-level breakdown requires deep packet inspection — not available" informational
  panel, so the missing column is explained rather than simply absent.

---

## 25. Security Events

### 25.1 The event sources we actually have

| Event | Source | Real? |
|---|---|---|
| Firewall rule triggered (drop/reject) | Rule counters + RouterOS `/ip firewall` logging | ✅ with syslog ingestion, or ⚠️ counters-only (aggregated) |
| Malicious IP blocked | address-list drop counter | ✅ |
| Domain/SNI block matched | rule counter | ✅ |
| Country policy triggered | geo rule counter | ✅ |
| Port scan detected | heuristic rule counter | ⚠️ heuristic — label it |
| Excessive connections | `connection-limit` rule counter | ✅ |
| Device isolated / blocked | `guest_access`, `device_access_rules` | ✅ (we write this ourselves) |
| Rogue DHCP detected | `router_rogue_dhcp_statuses` | ✅ existing |
| Gateway/WAN down | `monitoring` + `isp` | ✅ existing |
| Config/policy deploy failed | `ProvisionJob.status` | ✅ existing |
| Admin action on security config | `audit` | ✅ existing |

**The gap: there is no syslog pipeline today.** RouterOS can ship `/system logging action=remote`, but
nothing on the platform receives it. Two options:

- **Option 1 (fast, honest): counter-based events.** Poll counters on a Beat sweep; emit an aggregated
  event when a rule's counter increments. No per-packet detail, but no new infrastructure.
- **Option 2 (full): syslog ingestion.** A collector → parser → `security_events`. Gives real per-event
  detail with source IP, port and rule, which is what an investigation view needs. This is a genuine new
  component (ingest service, parser, retention, back-pressure) and should be its own workstream.

Recommend Option 1 for MVP, Option 2 in phase 3.

### 25.2 UI

```
Security → Events        [ Critical ] [ High ] [ Medium ] [ Low ]   Time [ 24h ▾ ]

 21:42  ● Critical  Malicious IP blocked          45.147.229.12 → Guest VLAN     [Investigate]
 21:38  ● High      Port scan detected            10.20.4.11 on WAN              [Investigate]
 21:31  ● Medium    Excessive connections         192.168.20.7 → 12 conns/10s    [Investigate]
 21:20  ● Low       Country policy triggered      RU inbound, 4 packets          [Investigate]
 21:15  ● Medium    Device isolated               D4:6A:…:2F (Front-desk)        [Investigate]
```

`Investigate` opens a drawer with: the matched rule, the source/destination, the zone, the device (linked to
the device drawer), related events in the window, and the exact policy that produced the match — with a link
to that policy version. **Traceability from an event back to the policy version that caused it is the
feature that makes this module operationally useful.**

Severity: the existing `AlertSeverity` is `info | warning | critical`. Add `low | medium | high | critical`
for security events as a separate additive `StrEnum` rather than widening the alert enum — different
consumers, different semantics.

---

## 26. Alerting

Reuse `monitoring.AlertService` + `NotificationService`. Do not build a second alerting engine.

### 26.1 New trigger types

Add to `AlertTriggerType` / targets: `SECURITY_THRESHOLD` and `SECURITY_EVENT_OCCURRED`, with targets
`SECURITY_POLICY`, `SECURITY_FEED`, `SECURITY_EVENT`.

| Alert | Trigger | Default severity |
|---|---|---|
| Gateway offline | existing `HEALTH_STATUS_CHANGE` | critical |
| WAN down | existing `ISP_LINK` | critical |
| High CPU / memory | existing `THRESHOLD` on `RouterHealthSnapshot` | warning |
| Excessive traffic | new threshold on zone/device bytes | warning |
| Firewall attack detected | counter rate over threshold on a security rule | critical |
| Port scan detected | heuristic rule rate | high |
| Multiple failed VPN attempts | WireGuard handshake failures | warning |
| Threat detected | feed/rule match | high |
| Configuration failure | `ProvisionJob.status = failed` | critical |
| Policy deployment failure | `SecurityPolicyDeployment.status = failed` | critical |
| Feed stale | feed `synced_at` older than N days | warning |
| Security score dropped | score delta over threshold | info |

### 26.2 Channels — the truthful list

| Channel | Status |
|---|---|
| Dashboard | ✅ existing (in-app alerts) |
| Email | ✅ real (SMTP/SES providers) |
| SMS | ✅ real (Twilio / Exotel / Ping4SMS) |
| Slack / Teams / Discord | ✅ real webhooks |
| Webhook | ✅ real (URL Fernet-encrypted) |
| **WhatsApp** | ⚠️ **`WhatsAppNotifier` is a logging-only placeholder.** Do not offer it as a channel until it is real. Note: a *Twilio WhatsApp* provider exists in `otp` for OTP delivery — if WhatsApp alerting is wanted, evaluate reusing that path, and be explicit that the monitoring-side notifier is currently a stub |

Dedupe: reuse the existing key `(rule_id, organization_id, location_id, router_id)` — an already-firing
condition must not spam. Security rules with `alert_threshold_per_hour` fold into the same mechanism.

---

## 27. Reports

`analytics` already has `report_templates` + `scheduled_reports` + Celery scheduling. Add three security
templates.

**Security Report** (weekly/monthly): total events, blocked vs detected, firewall rule hits, top blocked IPs,
top blocked domains, top blocked applications, most-targeted devices, deploy history, policy changes.

**Network Report** (exists — extend with security context): bandwidth, users, devices, WAN uptime, gateway
health, zone traffic split.

**Compliance Report**: every firewall change (from `audit` — `FIREWALL_RULE_*`, `CONTENT_FILTER_RULE_*`
and the new `SECURITY_*` actions), admin actions, security events, policy history with diffs, RBAC changes.
Export via the existing CSV path (capped at `AUDIT_EXPORT_MAX_ROWS = 10_000`; stream rather than truncate
silently).

Reports must state their data sources and any gaps (e.g. "application-level detail unavailable") rather
than emitting an empty section.

---

## 28. API Architecture

Follow the existing conventions exactly: `/api/v1`, `ApiResponse` envelope, `page`/`page_size`,
`RequirePermission`, registered in `app/api/v1/router.py`.

### 28.1 Security overview

```
GET    /api/v1/security/overview                 security.read
GET    /api/v1/security/score                    security.read
GET    /api/v1/security/events                   security.events_read
GET    /api/v1/security/events/{event_id}        security.events_read
GET    /api/v1/security/events/export            security.events_export
```

### 28.2 Blocking

```
GET    /api/v1/security/blocks                   security.read
POST   /api/v1/security/blocks                   security.block_create
GET    /api/v1/security/blocks/{id}              security.read
PUT    /api/v1/security/blocks/{id}              security.block_create
DELETE /api/v1/security/blocks/{id}              security.block_delete
POST   /api/v1/security/blocks/{id}/deploy        security.policy_deploy
POST   /api/v1/security/blocks/import            security.block_create
GET    /api/v1/security/blocks/export            security.events_export
POST   /api/v1/security/blocks/preview           security.read   # compile only, no device write
POST   /api/v1/security/dns-enforcement          security.policy_deploy  # force-our-DNS toggle
```

### 28.3 Firewall / policies

```
GET    /api/v1/security/policies                     security.read
POST   /api/v1/security/policies                     security.policy_create
GET    /api/v1/security/policies/{id}                security.read
PUT    /api/v1/security/policies/{id}                security.policy_update
DELETE /api/v1/security/policies/{id}                security.policy_delete
GET    /api/v1/security/policies/{id}/versions       security.read
GET    /api/v1/security/policies/{id}/versions/{v}   security.read
POST   /api/v1/security/policies/{id}/publish        security.policy_publish
POST   /api/v1/security/policies/{id}/validate       security.read   # conflicts + lockout guard
POST   /api/v1/security/policies/{id}/preview        security.read   # exact RouterOS config
POST   /api/v1/security/deployments                  security.policy_deploy
GET    /api/v1/security/deployments                  security.read
GET    /api/v1/security/deployments/{id}             security.read
POST   /api/v1/security/deployments/{id}/rollback    security.policy_rollback
```

### 28.4 Zones, devices, protection, feeds

```
GET    /api/v1/security/zones                        security.read
GET    /api/v1/security/zones/matrix                 security.read
PUT    /api/v1/security/zones/matrix                 security.policy_update
GET    /api/v1/security/zones/{id}/subnets           security.read   # §15.3 routability check

GET    /api/v1/security/devices                      security.read
POST   /api/v1/security/devices/{id}/isolate         security.device_isolate
POST   /api/v1/security/devices/{id}/block-internet  security.device_block
POST   /api/v1/security/devices/{id}/allow           security.device_block
POST   /api/v1/security/devices/{id}/disconnect      security.device_block

GET    /api/v1/security/protections                  security.read
PUT    /api/v1/security/protections                  security.policy_update
GET    /api/v1/security/capabilities/{router_id}     security.read   # per-vendor capabilities()

GET    /api/v1/security/feeds                        security.read
PUT    /api/v1/security/feeds/{kind}                 security.feed_manage
POST   /api/v1/security/feeds/{kind}/sync            security.feed_manage
```

Traffic analytics stays in `analytics`/`monitoring` — extend those rather than duplicating endpoints.

---

## 29. Database Schema

All new tables extend `BaseModel` (UUID PK, `created_at`, `updated_at`, `created_by`, soft-delete,
`version`) and denormalise `organization_id` + `location_id`. All enums are `String` columns.

```
security_events                     -- §25
  id, organization_id, location_id, router_id, device_id (null), guest_session_id (null)
  event_type        String(40)      -- SecurityEventType
  severity          String(20)      -- low|medium|high|critical
  source            String(30)      -- ROUTEROS_COUNTER|SYSLOG|PLATFORM|FEED|HEURISTIC
  matched_rule_id   UUID (null)     -- → security_policy_rules.id  (traceability)
  source_address    String(64), destination_address String(64), destination_port Integer (null)
  zone_id           UUID (null), application_key String(60) (null)
  detail            JSONB
  occurred_at       DateTime, ingested_at DateTime
  indexes: (organization_id, occurred_at desc), (router_id, occurred_at desc),
           (severity, occurred_at desc), (event_type, occurred_at desc)

security_policy_rules                -- §20  (the compiled, deployed unit)
  id, policy_id → policies.id, policy_version_id → policy_versions.id
  router_id, organization_id, location_id
  kind              String(40)      -- ZONE_MATRIX|BLOCK_DOMAIN|BLOCK_IP|BLOCK_DEVICE|BLOCK_APP|
                                    -- BLOCK_CATEGORY|BLOCK_GEO|PROTECTION|ISOLATE
  action            String(20)      -- allow|block|reject
  category          String(40) (null)
  zone_src_id       UUID (null), zone_dst_id UUID (null)
  schedule_id       UUID (null)     -- reuses queue_schedules shape
  value             String(255) (null)
  application_key   String(60) (null)
  priority          Integer
  log_enabled       Boolean, alert_threshold_per_hour Integer (null)
  is_enabled        Boolean
  expires_at        DateTime (null)
  device_push_status String(20), device_push_error Text (null), device_pushed_at DateTime (null)
  indexes: (router_id), (organization_id), (location_id), (policy_version_id), (kind), (is_enabled)

security_policy_deployments          -- §21.4
  id, organization_id, location_id, policy_id, policy_version_id
  status            String(20)      -- draft|queued|running|verifying|succeeded|failed|rolled_back
  router_ids        UUID[]
  steps             JSONB           -- per-router, per-step status + error
  plan_id           UUID (null)     -- → configuration_plans.id
  provision_job_ids UUID[]
  safety_revert_armed Boolean
  rollback_of_id    UUID (null)
  failure_reason    Text (null)
  started_at, finished_at, requested_by

security_rule_counters               -- §7.5   time-series
  id, router_id, organization_id, location_id
  rule_id           UUID (null)     -- → security_policy_rules.id
  comment_marker    String(120)
  packets           BigInteger, bytes BigInteger
  delta_packets     BigInteger, delta_bytes BigInteger
  counter_reset     Boolean         -- detected reset (reboot) so UI does not show a bogus drop
  sampled_at        DateTime
  indexes: (router_id, sampled_at desc), (rule_id, sampled_at desc)

security_feeds                       -- §13
  id, kind String(30)               -- geoip|malware_domains|phishing_domains|botnet_ips|malicious_ips
  provider String(60), source_url Text (encrypted where needed)
  version String(60), entry_count Integer
  last_synced_at DateTime (null), last_error Text (null), is_enabled Boolean

security_feed_applications           -- per-router feed state
  id, feed_id, router_id, organization_id, location_id
  applied_version String(60), applied_entry_count Integer
  last_applied_at DateTime, status String(20), error Text (null)

security_protections                 -- §16  per-router toggle state
  id, router_id, organization_id, location_id
  protection_key String(40), is_enabled Boolean
  device_push_status String(20), device_push_error Text (null), device_pushed_at DateTime (null)
  unique (router_id, protection_key) where is_deleted = false

security_score_snapshots             -- §6.3
  id, organization_id, location_id (null)
  score Integer, breakdown JSONB, computed_at
  indexes: (organization_id, computed_at desc)

integration_credentials              -- §17.4  (or extend network_integrations)
  id, organization_id (null = platform)
  provider String(40)               -- cloudflare|geoip|threat_intel
  credentials_encrypted BYTEA       -- Fernet
  config JSONB, is_active Boolean, last_verified_at DateTime
```

Deliberate choices: no native PG enums (additive-only change); partial unique indexes matching the
`content_filter_rules` precedent; every device-touching table carries the `device_push_*` trio.

---

## 30. Backend Services

| Service | New/extend | Responsibility |
|---|---|---|
`SecurityOverviewService` | new | Read-only aggregation: cards, score, health strip. Depends on nothing that writes |
`SecurityPolicyService` | new | CRUD, validate, publish, version, assign scope |
`SecurityPolicyCompiler` | new | Policy → `CompiledRuleSet` per router; identity markers; position; lockout guard |
`SecurityDeploymentService` | new | Orchestrate plan → apply → verify → rollback via `provisioning_engine`; advisory lock per router |
`SecurityEventService` | new | Ingest (counters/syslog), classify, correlate, retention |
`SecurityFeedService` | new | GeoIP + threat-feed download, version, diff against device, apply |
`SecurityEnforcementAdapter` (MikroTik impl) | new | Device I/O: apply/remove/deploy rule sets, read counters, read zone subnets |
`FirewallService` | extend | Add `configure_firewall_rule` push, priority→position, counters; keep its "no conflict detection" stance (order is the policy) |
`ContentFilterService` | extend | Add `tls-host` backing, scope (zone/SSID/group), `action`, `expires_at` |
`GuestAccessService` | extend | Durable ip-binding block for known MACs; `expires_at` sweep |
`AlertService` | extend | New security trigger types + targets (reuse dedupe) |
`NotificationService` | extend | Nothing — reuse; only revisit WhatsApp if it becomes real |
`FeatureEntitlementService` | extend | New `PlanFeatureKey.SECURITY` + per-tier limits (e.g. max zones, max rules) |
Celery tasks | new | `security_counter_sweep`, `security_feed_sync`, `security_score_snapshot`, `security_event_retention`, `security_expiry_sweep`, `security_deploy_verify` |

Cross-domain composition rules to respect: services talk through narrow duck-typed `Protocol`s;
`device_io` queue for anything touching a router; sync task bodies bridging via
`app/core/async_task_bridge.py`.

---

## 31. Frontend Components

### 31.1 Files to touch (the "five coordinated edits" the codebase requires)

1. `src/lib/customerNav.ts → CUSTOMER_NAV_GROUPS` — add the **Security** group. **Icons must be unique**:
   `ShieldCheck`, `Shield`, `Fingerprint`, `Ban`, `Radar`, `Network` are already taken. Use e.g.
   `ShieldAlert`, `ShieldOff`, `Bug`, `Lock`, `GlobeLock` — and run
   `scripts/test-customer-nav-shell.mjs`, which asserts no glyph is reused (a collapsed rail hides labels).
2. `src/config/customerFeatureCatalog.ts → FEATURE_GROUPS` — mirror ids/labels/icons so Staff Access can be
   granted per feature.
3. `src/lib/customerNavPermissions.ts → NAV_PERMISSION_KEYS` — map each new nav id → backend keys; keys must
   exist in `src/lib/backendPermissionKeys.generated.ts` (`test:customer-nav-permissions` enforces this).
4. `src/routes/security*.tsx` — thin file-based routes:
   ```tsx
   export const Route = createFileRoute("/security")({
     ssr: false,
     beforeLoad: ({ context, location }) => {
       requireCustomerSession(context.auth, location);
       requireActiveLocationId();
     },
     component: () => <CustomerFeaturePage feature="security" />,
   });
   ```
   (plus `/security-blocking`, `/security-firewall`, `/security-zones`, `/security-policies` — or a
   sub-route layout if the group warrants tabs.)
5. `src/components/customer/CustomerFeaturePage.tsx` — add `lazyView(...)` imports and the feature branches.

### 31.2 Components to build

Clone the canonical anatomy from `src/components/network/FirewallManagement.tsx` and
`ContentFilterManagement.tsx`: `SectionHeader` → `StatCard` row → `Card` + filter bar → shadcn `Table` →
`Dialog` (RHF + zodResolver) → `AlertDialog` → `sonner` toast.

| Component | Notes |
|---|---|
`SecurityOverviewView` | KPI grid of `StatCard`, `WidgetCard`/`ChartCard` + recharts via `chart-theme.ts`; health strip; recent events |
`SecurityScoreCard` | Animated score + "What affects this?" drawer listing every term |
`BlockingHub` | Type selector + form + active-blocks table with `device_push_status` badges and verbatim `device_push_error` |
`IpBlockListEditor` | Paste-a-list textarea, CIDR normalisation preview, allowlist sub-table, expiry |
`DomainBlockEditor` | Wildcard helper, **DNS-bypass + ECH note inline**, force-our-DNS toggle |
`ApplicationControlTree` | Grouped tree with per-app **reliability + mechanism badges**; Unreliable rows disabled with a reason |
`CategoryGrid` | Provider-aware; renders the Not-available state without a provider |
`GeoBlockPanel` | Country multi-select with per-country entry counts, inbound/outbound, feed freshness |
`FirewallRuleTable` | Priority drag-reorder **with effective-order preview**, hits sparkline, schedule, status |
`FirewallRuleBuilder` | The §7.2 dialog; impact preview; conflict list; Save / Save & Deploy / Dry run |
`ZoneMatrix` | The §15.1 grid; cell editor; *"cannot enforce — zone not routed"* states; rule-count warning |
`ZoneMatrixPreview` | Exact generated rules, read-only |
`DeviceSecurityDrawer` | The §14.1 drawer; the four actions; MAC-randomisation caveat for guests |
`ThreatProtectionPanel` | Toggles with **enforcement-owner** labels; Not-available rows disabled |
`SecurityEventsTable` + `SecurityEventDrawer` | Severity filter chips; event → matched rule → policy version traceability |
`SecurityPolicyVersions` | Version list, diff view, compare, deploy, rollback |
`DeploymentStatusPanel` | Per-router step progress using the existing `Stepper`/`StepStatusBadge` |
`SecurityCapabilityNotice` | A small shared component that renders "not supported on this gateway type" from `capabilities()` |
`CloudflareIntegrationCard` | Settings → Integrations; status + link-outs (§17) |

### 31.3 Data layer

Per existing convention: `src/services/security.service.ts` (+ `blocking`, `securityPolicy`, `zone`,
`securityEvent` split if it grows), `src/hooks/useSecurity.ts` with a `securityKeys` query-key factory and
mutation invalidation, `src/types/security.ts` with camelCase app types mapping snake_case DTOs.
`X-Organization-Id` is attached automatically by `attachOrganizationScope()` — do not hand-roll it.

### 31.4 UX rules

- **Plain language, no RouterOS vocabulary.** No "chain", "mangle", "address-list", "dst-nat" in the
  customer surface. The operator console may use them.
- Every destructive action gets an `AlertDialog` with the blast radius named ("will affect 3 gateways and
  ~240 devices").
- Every device-touching row shows its push status; **never render "Applied" without a push**.
- Every limitation is surfaced **where the decision is made**, not in a help article.
- Empty states explain what to do; unavailable states explain why. Never a zero that means "unknown".

---

## 32. Security Architecture of the Platform Itself

| Area | Current state | Recommendation |
|---|---|---|
Management path | WireGuard tunnel + RouterOS API 8728; SSH filtered; nothing exposed publicly | ✅ Preserve. Add a fleet assertion test so this cannot silently regress |
Device auth | `X-Agent-Credential` bearer, SHA-256-compared | ⚠️ Add mutual TLS for the agent's HTTPS calls; a leaked credential string should not be sufficient |
Secrets | Fernet-encrypted columns (`Router.api_credentials_encrypted`, `network_integrations`, `notification_channels`) | ✅ Continue. **No integration token in the repo** — Cloudflare/feed tokens encrypted, key from env |
Credential exposure | `RouterService.reveal_credentials` exists | Ensure every reveal is audited and RBAC-gated; never render a secret in a list response |
Tenant isolation | Service-layer org check + `LocationScope` + `enforce_entity_location`, plus HTTP `RequirePermission` | ✅ Mandatory for every new endpoint. A security module with a cross-tenant leak is the worst possible outcome |
Audit | `AuditLogEntry` via `AuditLogWriter` | ✅ Every security mutation audited — including **failed** deploys and rollbacks |
Blast radius | `plan → validate → snapshot → apply → verify → safety-revert` | ✅ Reuse. Arm the safety revert for **every** security deploy |
Self-lockout | `management_safety.assess_management_risk` | Mandatory pre-compile check for the security compiler |
Two-person rule | Not present | ⚠️ Consider for destructive platform-level security changes (feed replacement, global block of a management subnet): require an approval step, mirroring `PlanStatus.awaiting_approval` which already exists |
SSRF | Webhook notifier POSTs a stored URL | Validate/allowlist where feasible; a customer-supplied webhook URL is an SSRF vector |
Rate limiting | Diagnostics cooldowns exist (10 s/router, 120/h/org) | Apply the same pattern to deploy and preview endpoints (a deploy is far more expensive than a ping) |
Data retention | Diagnostics purge at 90 days | Define retention per new table: events (90 d default, configurable), counters (30 d), score snapshots (1 y), feeds (keep N versions) |
Compliance/PII | Guest MAC/IP are personal data; `audit` already masks PII via `data_masking_enabled` | Security events contain guest IPs/MACs — respect the same masking rules in the events UI and exports |

---

## 33. Consolidated feature truth table

Every row is `UI → Policy → Enforcement → Technology required → Limitations`.

| Feature | Dashboard UI | Policy | Enforcement mechanism | Technology required | Limitations |
|---|---|---|---|---|---|
Domain block | Blocking → Domain | `BLOCK_DOMAIN` | `/ip dns static` sinkhole (exact + `regexp=`) **and** `/ip firewall filter tls-host` | none — **AVAILABLE NOW** | DNS bypass: DoT/DoH already dropped, but **only pre-auth (`hotspot=!auth`)** — a logged-in guest on private DNS bypasses every block (§37.1); **ECH**; QUIC; non-TLS; per-rule volume |
IP/CIDR block | Blocking → IP | `BLOCK_IP` | address-list + shared positioned `drop` | none — **AVAILABLE** | not a domain substitute; CDN churn; per-entry hits need per-entry rules |
Wildcard domain | Blocking → Domain (`*.x`) | `BLOCK_DOMAIN` | `regexp=` sinkhole + `tls-host=*.x` | none — **AVAILABLE** | same as domain; one rule per pattern |
Category filtering | Blocking → Categories | `BLOCK_CATEGORY` | provider DNS policy (Cloudflare Gateway / NextDNS) | maintained category DB + resolver — **REQUIRES NEW TECH** | DNS-path only; bypassable; provider cost; cannot be done on RouterOS |
Application control | Blocking → Applications | `BLOCK_APP` | DNS + SNI + IP for a curated hostname set | curated app→hostname catalogue; **DPI for the Unreliable tier** | ECH, DoH, CDN churn, shared fronts. Never "app identified" |
Geo blocking | Blocking → Countries | `BLOCK_GEO` | country address-lists + input/forward drop | GeoIP feed + sync — **REQUIRES NEW TECH** (feed) | large lists; **outbound unreliable**; staleness; VPN defeats it; IPv6 separate |
Device isolation | Zones & Isolation → device | `ISOLATE` / `DEVICE_BLOCK` | ip-binding blocked (known MAC) / address-list + forward drop / `/ip hotspot active remove` | none — **AVAILABLE** | MAC randomisation for guests; DHCP lease change for IP-keyed blocks |
Zone → zone | Zones & Isolation → matrix | `ZONE_MATRIX` | `/ip firewall filter chain=forward` with zone address-lists | none — **AVAILABLE** | routed traffic only (§15.3); O(zones²) rules |
Firewall (L3/L4) | Firewall | `FIREWALL_RULE` | `/ip firewall filter` + position management | none — **AVAILABLE** | order is the policy; CPU on small hardware; lockout risk requires the guard |
Firewall events | Overview / Events | — | rule counters (+ syslog later) | counters now; **syslog collector for per-packet detail** | counter resets on reboot; aggregated without syslog |
Bogon / flood / brute force | Threat Protection | `PROTECTION` | address-list, `connection-limit`, `dst-limit`, syncookies | none — **AVAILABLE** | heuristics, not IDS; false positives possible |
Port-scan detection | Threat Protection | `PROTECTION` | `dst-limit`/`psd` heuristic | none — **AVAILABLE (heuristic)** | heuristic — label it, never claim certainty |
Malware/phishing/botnet | Threat Protection | feed-backed | sinkhole/`tls-host` from a feed, or provider DNS | threat feed + sync — **REQUIRES NEW TECH** | feed cost, staleness, false positives |
Malicious IP blocklist | Threat Protection | feed-backed | address-list from feed | threat feed + sync — **REQUIRES NEW TECH** | as above |
IDS / IPS | — | — | none | dedicated appliance — **NOT AVAILABLE** | do not display |
Per-app traffic bytes | — | — | — | DPI or NetFlow + collector — **NOT AVAILABLE** | show per-device/per-zone instead |
WhatsApp alerts | Alerting | — | `WhatsAppNotifier` is a **stub** | real integration — **NOT AVAILABLE** | evaluate reusing the `otp` Twilio WhatsApp provider |
VPN (infrastructure) | Operator only | — | WireGuard hub, already live | none — **AVAILABLE** | hub has no peer-delete verb → orphaned peers quarantine |
VPN (staff remote access) | — | — | would reuse WireGuard peers | client tooling + policy — **FUTURE** | not a user VPN today |
Cloudflare WAF/DDoS for guest LAN | — | — | Cloudflare cannot sit in a guest's path | n/a — **NOT POSSIBLE** | only Cloudflare's own edge; see §17 |
Cloudflare Gateway DNS filtering | Blocking → Categories | `BLOCK_CATEGORY` | venue DNS → Cloudflare Gateway | Cloudflare API client + account — **REQUIRES NEW TECH (no integration exists today)** | DNS-path only |
Multi-vendor enforcement | Capability-driven UI | same policies | vendor adapters | vendor adapters for Omada/Aruba/etc. — **FUTURE (stubs today)** | MikroTik is the only real adapter |

---

## 34. Recommended MVP

**Goal: ship real enforcement, be honest about the rest, and do not touch Guest Wi-Fi reliability.**

### In scope

1. **Security group in the sidebar** (5 items) with the three parallel frontend lists kept in sync.
2. **Security Overview** — but only cards whose data sources exist (§6.2); every other card renders an
   explicit Not-available state. Security score with a visible breakdown.
3. **Blocking Center** — Domain (DNS + **new `tls-host` SNI**), IP/CIDR, Device. Real push, real status,
   real error text, real limitations inline. Extend the **existing** DoH/DoT drops from `hotspot=!auth`
   to authenticated traffic rather than building a second DNS-enforcement path (§37.1).
4. **Firewall** — push, identity markers, **the sentinel band as the insertion point**, `place-before`
   positioning against existing anchors, **the lockout guard**, dry-run preview, hit counts, schedules.
5. **Zones & Isolation** — the matrix, with the not-routed guard; per-device isolate/block/disconnect.
6. **Deploy safety** — reuse `provisioning_engine`; safety revert **mandatory**; deployment status UI;
   per-router advisory lock.
7. **Policy versioning** — reuse `policy_versions`; compare/rollback UI.
8. **Security Events** — counter-derived (Option 1), with event → matched rule → policy version
   traceability.
9. **Alerting** — new security triggers on existing channels, existing dedupe. No WhatsApp.
10. **RBAC + audit** — new `security.*` keys, `security-administrator` role seed, every mutation audited,
    frontend permission keys regenerated and drift-checked.
11. **Feature gating** — `PlanFeatureKey.SECURITY` with limits (max zones, max rules, max domains).

### Explicitly out of MVP

Category filtering · Application control · Geo blocking · Threat-intel feeds · Cloudflare integration ·
syslog ingestion · per-application analytics · staff remote-access VPN · non-MikroTik enforcement.

Each of these ships later **with its own honest UI state**, or not at all.

### MVP acceptance criteria

- No existing guest flow changes behaviour when no security policy exists.
- Every device-touching row shows `pending|active|failed`; editing a device-carried field demotes to
  `pending` via `demote_device_push_on_edit`.
- The compiler refuses any rule matching the management path, with a message explaining why.
- A deliberately-broken deploy (block the tunnel) **auto-reverts** and the platform reports it.
- No customer-surface string contains RouterOS vocabulary.
- `test:permission-key-drift` and `test:customer-nav-permissions` pass; nav icons are unique.
- **A push that cannot find both band sentinels refuses with `ACCESS_RULES_BAND_MISSING`** and never
  creates the band at a guessed position (§37.2).
- **A server-side rule-order gate exists and is mutation-verified** — re-introducing a blind `add`
  makes it fail, restoring makes it pass (§37.4). Verified on a real router, not just in a fake: force
  a re-push and confirm from `print` that the security rule sits above
  `cloudguest-fw-fwd-established` and inside the band.
- **Extending the DoH/DoT drops to authenticated traffic is confirmed on a device** with a logged-in
  client using private DNS, since that is the claim the whole domain-blocking story rests on (§37.1).

---

## 35. 90-Day Roadmap

Sequenced, not estimated. Each phase ships something usable; nothing later is a prerequisite for the
honest UI of something earlier.

### Phase 1 (Weeks 1–3) — Foundation, no device writes
- Permission module + `security.*` keys + `security-administrator` role seed; regenerate frontend keys.
- `security` domain skeleton, `security_events`, `security_score_snapshots`, `security_rule_counters`.
- Nav group + 5 routes + `CustomerFeaturePage` branches; empty/Not-available states everywhere.
- **Security Overview** reading only existing tables. Score with a transparent breakdown.
- Verify: no device write anywhere; nothing in Guest Wi-Fi touched.

### Phase 2 (Weeks 4–7) — Real blocking + firewall push
- **Prerequisite, before any rule is written: implement the sentinel band** (§37.2). Designed and
  documented in `docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md` §5.2.1 but not yet implemented.
  Without it there is no safe insertion point and the rules below cannot be positioned correctly.
- `SecurityEnforcementAdapter` (MikroTik) + capability discovery (`read_zone_subnets`, counters).
- **Firewall push**: identity markers, `place-before` positioning, **lockout guard** (reuse the
  existing `cloudguest-fw-allow-wg-mgmt` / `cloudguest-fw-drop-wan-input` anchors), counters.
- Extend the **existing** DoH/DoT drops from `hotspot=!auth` to cover authenticated traffic (§10.2) —
  this is a small change with outsized effect on domain-blocking reliability.
- Extend `content_filtering`: `tls-host` backing, `action`, `expires_at`, scope.
- Blocking Center: Domain / IP / Device with real push + status + verbatim errors + limitation notes.
- Deployment service with **mandatory safety revert** + per-router advisory lock + status UI.
- **Add a server-side rule-order regression gate** mirroring `scripts/test-fw-rule-order.mjs`
  (`npm run test:fw-order`), and mutation-verify it by re-introducing the append and confirming red.
- Verify: deploy a deliberate lockout rule in a lab → auto-revert works; and confirm on a real router
  that the accept sits above the drop after a re-push.

### Phase 3 (Weeks 8–10) — Zones, policies, events, alerts
- `security_policy_rules` + `PolicyType.SECURITY` + compiler + conflict detection.
- **Zone matrix** with the not-routed guard, intra-zone isolation, preview, rule-count warnings.
- Device Isolation actions (isolate / block / allow / disconnect) with the MAC caveat.
- `security_policy_deployments` → `provisioning_engine`; version compare/rollback UI.
- Security Events (counter-derived) + event→rule→policy-version traceability.
- Security alerts on existing channels, reusing dedupe.
- Reports: Security + Compliance templates.
- Verify: policy rollback restores the previous device state; events trace to the right version.

### Phase 4 (Weeks 11–13) — Feeds and the honest long tail
- `security_feeds` + GeoIP sync pipeline (diff-apply, IPv6 handled, per-router state).
- Geo blocking UI with entry counts, feed freshness, and **"outbound is best effort"**.
- Threat-feed path: malicious-IP blocklists through the existing address-list machinery.
- Threat Protection panel with **enforcement-owner** labels and disabled-Not-available rows.
- Cloudflare integration (§17): connection card, DNS/WAF/Zero Trust status, **and Gateway DNS as the
  category-filtering path**; category UI activates only when Gateway is configured.
- Application Control with per-app **reliability badges** for the Good/Fair tier only.
- Decide and scope: syslog collector (per-packet events), staff remote-access VPN, second vendor adapter.

**Do not start Phase 4 work before Phase 2's safety revert is proven.** Everything in Phase 4 increases
the blast radius; the safety net must exist first.

---

## 36. Open decisions for product

1. **Category filtering path** — commit to a DNS filtering provider (Cloudflare Gateway recommended, since
   the brief already leans Cloudflare) or formally drop category filtering? This is the single biggest
   scope decision.
2. **Application Control** — is a Good/Fair-tier name-matching feature acceptable to ship with visible
   reliability badges, or does the brand promise require DPI (which means hardware we do not have)?
3. **Geo blocking outbound** — ship it with a "best effort" label, or inbound-only?
4. **App catalogue ownership** — an Application Control feature creates a permanent obligation to maintain
   app→hostname mappings. Who owns that, and is it funded?
5. **mTLS for the agent** — fund it now, or accept bearer-credential risk?
6. **Syslog ingestion** — is per-event investigation a v1 expectation, or is counter-aggregation acceptable
   for the first year?
7. **Customer-facing VPN** — the WireGuard hub is infrastructure-only. Is a staff remote-access VPN in
   scope, and for which tier?
8. **Naming** — a new `SecurityPanel` already exists in platform settings; confirm the customer-facing
   "Security" name and the operator-facing "Security Operations" split so they do not collide.
9. **Which repo owns this doc** — both repos are public; confirm where the PRD should live (not in a public
   repo if any part of it states production topology or credentials).

## 37. Addendum — device-verified constraints (v1.1)

Read this before designing, writing or reviewing any code that touches `/ip firewall filter`.
Everything here was read out of the codebase or off a real router; none of it is inferred.

### 37.1 What is already enforced on the device today

Read off the lab router (hEX lite, **RouterOS 7.23.3**), `forward` chain, in order:

```
 0 D jump   -> hs-unauth        hotspot=from-client,!auth
 1 D jump   -> hs-unauth-to     hotspot=to-client,!auth
 2   drop   cloudguest-block-dot-udp          hotspot=!auth  udp/853
 3   drop   cloudguest-block-dot-tcp          hotspot=!auth  tcp/853
 4   drop   cloudguest-block-doh              hotspot=!auth  tcp/443  dst-address-list=cloudguest-doh-ips
 5   accept cloudguest-fw-fwd-established     connection-state=established,related
 6   drop   cloudguest-fw-fwd-drop-invalid    connection-state=invalid
```

Two consequences the v1.0 spec got wrong or missed:

1. **DoT and DoH are already blocked — but only `hotspot=!auth`, i.e. only before a guest logs in.**
   A logged-in guest who enables private DNS bypasses every DNS-sinkhole domain block we have. This
   makes "extend the existing DoH/DoT drops to authenticated traffic" the single highest-value cheap
   fix in the domain-blocking story (§10.2).
2. **A blocking rule must sit ABOVE `cloudguest-fw-fwd-established`** to affect already-open flows.
   When the content-filter drop was appended to the tail instead, an already-established flow to a
   blocked destination kept flowing after the operator pressed Block. Device tests assert the ordering
   explicitly (`order.index(_ENFORCEMENT_COMMENT) < order.index("cloudguest-fw-fwd-established")`).

The full set of comment markers this platform already owns on devices:

| Chain | Markers |
|---|---|
| `input` | `cloudguest-fw-allow-wg-mgmt` · `cloudguest-fw-drop-wan-input` · `cloudguest-fw-block-wan-dns` · `cloudguest-fw-block-wan-dns-tcp` · `cloudguest-mangle-input-wan` |
| `forward` | `cloudguest-block-dot-udp` · `cloudguest-block-dot-tcp` · `cloudguest-block-doh` · `cloudguest-fw-fwd-established` · `cloudguest-fw-fwd-drop-invalid` |
| `mangle` | `cloudguest-mangle-pcc-wan{N}[-idx{i}]` · `cloudguest-mangle-route-wan{N}` |
| lists / legacy | `wyfyguest-content-filter-blocked` · `cloudguest-doh-ips` · `WYFYGUEST-{safety-revert,accept-guest,guest-bridge,guest-ip,masq,hotspot,dhcp,bridge-port-guest-*}` |

**Security rules must be namespaced inside this existing set, not beside it.** A new rule that is not
recognisable by comment marker is a rule the platform can neither converge, count nor remove.

### 37.2 The sentinel band — designed, documented, not yet implemented

> **Status 2026-09-23: implemented for `chain=forward`, not yet verified on hardware.**
> `wyfy_device_gateway/mikrotik_firewall.py` locates the band on every push and refuses with
> `ACCESS_RULES_BAND_MISSING` without it; `install_band` places it once, directly above
> `cloudguest-fw-fwd-established`, from a Master-only endpoint
> (`POST /firewall-rules/routers/{router_id}/band`). The placement is not yet recorded on the
> router's `ConfigVersion`, and `input`/`output` chains have no band and are refused.

`docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md` §5.2.1 specifies it; the implementation is not in
the codebase yet. Two `action=passthrough` rules per managed chain, created once at provisioning:

```
/ip firewall filter add chain=forward action=passthrough comment="cloudguest-fw-band-begin"
/ip firewall filter add chain=forward action=passthrough comment="cloudguest-fw-band-end"
```

`passthrough` is the documented exception to first-match-wins, so a sentinel cannot change behaviour —
and its packet counter is free evidence that traffic actually reaches the band. **A band whose
begin-sentinel counter is zero after real guest traffic is a band in the wrong place**, visible in
`print stats` with no client device needed.

Contract for the Security writer:

- **Position is never an integer.** Every rule is written `place-before=<.id of band-end>`, ascending by
  `priority`. Position = f(band location, priority) — stable across re-pushes and unaffected by the
  hotspot service adding/removing its own rules continuously.
- **A push that cannot find both sentinels must refuse** (`ACCESS_RULES_BAND_MISSING`) and say so. It
  must never create the band at a guessed position mid-push: creating a filter band at a guessed
  position on a router someone else configured is the exact shape of "took the guest network down".
- **The band's location is a provisioning-time decision**, made once against a real `print` of that
  specific router and recorded on the router's `ConfigVersion`. A later push reads the sentinels by
  comment and never recomputes where they belong.
- Hotspot's dynamic rules sit at the top of the built-in chains and are not movable. Whether a static
  rule can sit above them was `[UNVERIFIED — test T2]` in that doc; the later
  `render_content_filter_enforcement` docstring records it as **confirmed** (a static rule *can* sit
  above hotspot's own dynamic `forward` rules) — and records why that is safe for *that* rule
  specifically: it matches `dst-address-list=` and nothing else, so it can never affect the portal, the
  tunnel or 8728. **A zone-matrix drop has no such property** and needs its own bound.

### 37.3 Hard-won device behaviours the writer must respect

| Behaviour | Consequence for us |
|---|---|
| RouterOS `add` appends to the tail; first-match wins | Never blind-`add`. Always `place-before=<anchor>` |
| **`/ip firewall filter` has no unique key**, so `on-error={}` catches nothing | A bare `add` appends a **duplicate on every push**. Find-by-comment, then act |
| The RouterOS **terminal runs each entered line as its own program** | A `:local` bound on one line is unreadable on the next → `place-before=$var` became a **syntax error**, the accept was appended below the drop, and the tunnel died. Generated scripts must emit `;`-joined **single-line** statements — the same discipline `render_content_filter_enforcement` and `render_hotspot_walled_garden` already follow |
| `place-before` takes a `.id`, not an ordinal | Resolve the anchor id first, in the same statement |
| Fail-closed ordering | Capture stale rows **before** adding the new one; **add before remove**, so the window holds two identical drops rather than none. "A duplicated drop is harmless; a gap is a site briefly unblocked" |
| `platform carries 27 rules` / hotspot `hs-*` chains present | Rule-count and position assumptions must come from a read, never a constant |

### 37.4 The regression gate that already exists — and its planned server-side port

`cloudguest-foundation/scripts/test-fw-rule-order.mjs` (`npm run test:fw-order`) is the existing guard
for the 2026-08-16 incident. It bundles the real `buildRouterSetupScriptChunks` from
`src/components/routers/RouterDetailTabs.tsx` and asserts four properties: the shared anchor tag exists
on both sides; the accept is inserted with `place-before=$wanDropRule`; there is **exactly one**
plain-`add` fallback and it comes *after* the place-before add; and a `move ... destination=$wanDropRule`
self-heal exists for already-broken devices.

Its own header states it exists so that nothing — "**nor the coming server-side port of the generator,
router-fleet plan P16**" — can silently regress the fix, and warns that **`tsc` cannot see any of this:
it is emitted RouterOS text, not types.** Two implications for the Security module:

1. The frontend generator and the (planned) server-side generator both emit firewall rules. The Security
   writer is a **third** emitter and must share the same anchors rather than inventing its own.
2. A server-side rule-order gate is mandatory in Phase 2, and must be mutation-verified — re-introduce
   the append, confirm red, restore, confirm green. A gate that cannot fail is not a gate.

### 37.5 RouterOS version floor — the `tls-host` question, answered

`app/domains/provisioning_engine/planner/compatibility.py` gates on **major version 7 or higher**;
anything below or unparseable is `BLOCKED`. `tls-host` has been available since **6.41**.

**Therefore `tls-host` carries no version risk on any router this platform will accept** — no new
capability gate is needed for it, and `planner/compatibility.py` (`CompatibilityCheckStatus`,
`CompatibilityOverall`) is the established home if one is ever required for a newer feature. The
field fleet also carries a documented, per-version behaviour table in `docs/mikrotik/PORTAL_AND_DNS.md`
(7.15/7.16/7.17/7.18 differences), which is the precedent for how version-sensitive behaviour is
recorded here — as a table with the observed version, not a comment.

---

### Sources verified for §10.2 and §11

- [Common Firewall Matchers and Actions — RouterOS (MikroTik)](https://help.mikrotik.com/docs/spaces/ROS/pages/250708064/Common+Firewall+Matchers+and+Actions)
- [Filter — RouterOS (MikroTik)](https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter)
- [MikroTik Blocking Websites with TLS Host Firewall Matcher](https://systemzone.net/mikrotik-blocking-websites-with-tls-host-firewall-matcher/)
- [ECH Protocol — Cloudflare SSL/TLS docs](https://developers.cloudflare.com/ssl/edge-certificates/ech/)
- [Encrypted Client Hello (ECH): What RFC 9849 Breaks in Network Security](https://blog.gtfo.dev/blog/encrypted-client-hello-sni-blind-spot/)
- [Encrypted Client Hello: what ECH breaks and what still sees traffic (2026)](https://dope.security/post/encrypted-client-hello-web-filtering-2026)
