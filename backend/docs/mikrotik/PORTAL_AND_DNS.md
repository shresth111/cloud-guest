# Portal and DNS: the device path

**Status:** design document. No code. Nothing here has been run against a
device — the orchestrator holds device access, and every claim below is
either sourced from a file in this repo, from MikroTik's own published
documentation, or explicitly flagged as unsettled with the test that would
settle it.

**Scope.** Two customer-dashboard features that have no `device_adapters.py`:

* **Portal** — `app/domains/captive_portal/` (and its relationship to
  `app/domains/hotspot/`, settled in §1.1).
* **DNS** — `app/domains/dns/`.

Trusted Devices and Access Rules are being designed in parallel by someone
else and are deliberately not covered.

**Sources, and which one wins when they disagree.** MikroTik's
documentation now exists in three tiers that contradict each other, and this
matters enough to state as a rule before anything else:

| Tier | URL | Use it for |
|---|---|---|
| Frozen Confluence prose | `help.mikrotik.com/docs/spaces/ROS/…` | nothing new — explicitly frozen, "no further edits will be made here" |
| New prose | [`manual.mikrotik.com/docs/…`](https://manual.mikrotik.com/docs/introduction/) | **semantics** — but largely a copy of the frozen prose, including its errors |
| Auto-generated CLI reference | [`manual.mikrotik.com/docs/cli-reference/…`](https://manual.mikrotik.com/docs/cli-reference/ip/hotspot/profile) | **which properties exist** — generated from the binary |
| Per-version changelogs | `https://download.mikrotik.com/routeros/<version>/CHANGELOG` | **when a property appeared or disappeared** |

**Rule for any adapter built from this document: take property names from the
CLI reference, semantics from the prose, and every version boundary from the
changelog.** The prose is demonstrably stale — it still documents
`https-redirect`, a property deleted in 7.5 (§2.3), and it still describes
`trial-uptime` as a single composite when the CLI has the pair
`trial-uptime-limit` / `trial-uptime-reset`.

Nine further prose defects were found while researching this document and are
listed in §9, because a design that transcribes them ships them.

Forums are cited in exactly two places below, and are labelled as forums.

**Sibling document that does not exist yet.** This document was asked to
build on `docs/vlan/BRIDGE_VLAN_FILTERING.md` — a colleague's write-up of a
config change that took the guest network down on this exact router, and in
particular its "what verification would actually have caught it" section.
That file is not in the tree at the time of writing (`docs/vlan/` holds only
`DATABASE.md`, `FLOW.md`, `README.md`, all dated 22 Jul). Rather than invent
its contents, §6 derives the same discipline from the three places this repo
already records it in first-person, live-confirmed form:
`network_config/renderers.py`'s "confirmed live this session" standard, the
setup script's own verdict-chunk convention in
`cloudguest-foundation/src/components/routers/RouterDetailTabs.tsx`, and
`provisioning_engine/planner/final_verification.py`'s named-check shape. If
the colleague's document lands, §6 should be reconciled against it, not
replaced by it.

---

## 0. Ground truth this document is written against

The live lab router, as read by the orchestrator (not re-derived here):

```
hEX lite / RB750r2, RouterOS 7.23.3, mipsbe, switch chip Atheros-8227
bridge 'bridge'  vlan-filtering=no   10.5.50.1/24 directly on it
ether1 = WAN (dhcp-client 192.168.1.100/24), wg-cloudguard = management tunnel
/ip hotspot        hotspot1  interface=bridge  profile=hsprof1  address-pool=hotspot-pool
/ip pool           hotspot-pool  10.5.50.10-10.5.50.254
/ip dhcp-server    hotspot-dhcp  interface=bridge  address-pool=hotspot-pool  use-radius=no
/ip hotspot profile hsprof1: hotspot-address=10.5.50.1, dns-name=wifi.wyfyguest.com,
    use-radius=yes, radius-accounting=yes, radius-interim-update=received,
    login-by=http-pap, html-directory='flash/hotspot'
/ip hotspot profile default: hotspot-address=0.0.0.0, use-radius=no, html-directory='hotspot'
/ip dns  servers=8.8.8.8  allow-remote-requests=yes  dynamic-servers=192.168.1.1
/ip firewall filter includes cloudguest-fw-block-wan-dns (+tcp),
    cloudguest-block-dot-udp, cloudguest-block-dot-tcp, cloudguest-block-doh
/radius  service=hotspot  address=10.20.0.1  comment='cloudguest-radius'
/radius incoming  accept=FALSE  port=3799
```

Two things in that dump are load-bearing and are easy to read past:

1. `hsprof1` has `html-directory='flash/hotspot'`, but the script that
   creates `hsprof1` writes `html-directory=hotspot` — a bare `hotspot`, no
   prefix (`RouterDetailTabs.tsx:6321`). MikroTik's own customization
   instructions say the **full** path is required on a board with flash:
   *"Full path must be typed in html-directory field, including
   '/flash/(hotspot_dir)'"*
   ([Hotspot](https://manual.mikrotik.com/docs/authentication-authorization-accounting/hotspot-captive-portal/)).
   So either RouterOS normalized the bare name onto this board's NAND mount
   and reports the resolved path back, or somebody set it by hand. Which one
   decides whether the setup script is silently wrong on every flash board
   it touches. Not settled (§2.2.4, test **T-P1**).
2. `hsprof1` is `use-radius=yes` while the DHCP server bound to the same
   bridge is `use-radius=no`. That is correct and not a drift: RADIUS
   authenticates the *hotspot login*, not the DHCP lease.

---

## 1. What these two features actually are today

### 1.1 Portal is not the hotspot, and only one of the two is in the catalog

`src/config/customerFeatureCatalog.ts` contains exactly one relevant entry
(line 58, group `Engagement`):

```ts
{ id: "portal", label: "Portal", icon: Palette },
```

There is **no `dns` entry and no `hotspot` entry in the catalog at all.**
The catalog carries no route, no endpoint, and no domain mapping — those
live in `src/lib/customerNav.ts` (`portal → /guest-portal`, `roles:
["owner"]`) and `src/config/customerFeatures.tsx` (`portal → <PortalPage>`).

* **Portal** = `src/components/features/PortalPage.tsx`, backed by
  `app/domains/captive_portal/` via `/captive-portal-configs`. Scope is
  organization + optional location. Content is branding, copy, login-method
  toggles, a post-login HTML fragment.
* **Hotspot** = `src/components/network/HotspotManagement.tsx`, backed by
  `app/domains/hotspot/` via `/hotspot-profiles`. Scope is **per router**.
  Content is session/idle timeout, up/down kbps, walled-garden hosts. It is
  an orphan feature id: renderable at `/c/hotspot`, seeded into an agent
  role in `src/stores/agentPermissionStore.ts:53`, but with no catalog
  entry, no nav entry, and no permission toggle.

So the answer to "which domain actually backs the Portal screen" is
`captive_portal`, unambiguously — and that domain's own module docstring is
explicit that it is a **cloud-rendered** page:

> This module is pure configuration data plus a guest-facing "resolve the
> effective config" read path (`service.CaptivePortalService
> .resolve_portal_config`) — it does **not** implement guest authentication
> itself
> — `app/domains/captive_portal/models.py`

Every one of its ~40 columns (`theme`, `logo_url`, `primary_color`,
`background_focal_x`, `content_survey`, `otp_whatsapp_enabled`,
`business_hours_schedule`, …) is consumed by the SPA served from
`https://auth.wyfyguest.com`. **None of them is a RouterOS field, and none
of them can be made into one.** That is the single most important fact in
this document and §2 is built on it.

### 1.2 Neither screen has a device path, and the DNS screen says so

The Portal screen has no Apply/Push/Sync button, no router selector, and no
push-status badge; its only outward actions are Preview and a cosmetic
"Download QR". Every mutation is `PUT /captive-portal-configs/{id}` or a
`/branding` multipart upload — database writes.

The DNS screen states the gap in its own header copy
(`DnsManagement.tsx:116`):

> `description="Per-router static DNS entries (A / AAAA / CNAME). Device
> push happens through a separate configuration pipeline."`

That pipeline is not linked, not referenced, and — see §3.4 — does not
reach a fleet router by the transport it uses. Its delete confirmation
("This permanently removes it from *&lt;router name&gt;*") is actively
misleading: it deletes a row.

The existing precedent to copy is DHCP, and only DHCP:
`DhcpPool` carries `device_push_status` / `device_push_error` /
`device_pushed_at`, `DhcpManagement.tsx:204` renders a `DevicePushBadge`
("Not yet applied" / "Couldn't apply"), and a per-row Apply button calls
`POST /dhcp-pools/{id}/push`. **Both designs below should adopt that exact
three-column + badge + explicit-Apply shape rather than push implicitly on
save.**

### 1.3 What already reaches the device, and over which transport

| Transport | Port | Used by | Reaches fleet routers? |
|---|---|---|---|
| librouteros structured API | 8728 | every `configure_*` in `mikrotik_adapter.py`, every `*/device_adapters.py` | **Yes** — this is the working path |
| asyncssh + SFTP + `/import` | 22 | `push_config`, `upload_file`, `backup`, `restore`, `execute_raw_command` | **Contested** — see below |
| Human paste into WinBox/SSH terminal | — | `buildRouterSetupScriptChunks` in `RouterDetailTabs.tsx` | Yes, with a human |

`app/domains/vlan/device_adapters.py` is unambiguous about the SSH path:

> `network_config`'s push path renders a script and ships it with SFTP +
> `/import` over **asyncssh on port 22**, which is filtered on the fleet.
> That path cannot reach a real router, and its handler returns 202
> `success: true` regardless.

But `ops/letsencrypt-hotspot/renew-hotspot-certs.sh` **does** `scp` two
files and then `ssh` a `/certificate import` command to a production
router — at `10.20.0.50`, a WireGuard tunnel address, unattended, on a
systemd timer. Both statements are true and they are not in conflict: SSH is
filtered from the public internet and open across the management tunnel.
`app/domains/router/models.py` resolves credentials host as
`router.management_ip_address or router.public_ip_address`
(`vlan/service.py:962`), so a router whose `management_ip_address` is its
tunnel IP is reachable over SSH today.

**Consequence for §2.2:** file upload to a router is not impossible. It is
unexercised from the backend, its reachability is per-router rather than
fleet-wide, and no design should assume it without probing first.

---

## 2. Portal

### 2.1 Recommendation in one line

**Do not map the Portal screen onto `/ip hotspot profile` fields.** The
Portal screen configures a cloud-hosted page; the router's only job is to
*get the guest to that page*. Build a `captive_portal/device_adapters.py`
that pushes exactly four things — the walled-garden pair, the redirect
hostname, the login method, and the DHCP option-114 hint — none of which
come from the Portal screen's own columns, and all of which are today
delivered only by a human pasting a script.

### 2.2 Which RouterOS object each setting becomes

#### 2.2.1 The honest mapping table

Every editable control on `PortalPage.tsx`, and where it lands:

| Portal screen control | Column | RouterOS object |
|---|---|---|
| Headline | `splash_headline` | **none** — cloud SPA |
| Welcome Message | `splash_welcome_message` | **none** |
| Brand Color | `primary_color` | **none** |
| Portal Logo / Background Image | `/branding` blobs | **none** |
| Theme, Font | (dead controls, not saved) | **none** |
| Languages | `supported_languages` | **none** |
| Redirect URL | `redirect_url` | **none** |
| Post-login page (HTML) | `post_login_html` | **none** — rendered in a sandboxed iframe by the SPA |
| Auth Methods (5 switches) | `otp_*_enabled`, `voucher_enabled`, `social_login_enabled` | **none directly**; see §2.2.2 |
| Terms & Conditions | (dead control, discarded on save) | **none** |

That column of "none" is the correct answer, not a gap to be filled. The
one place a naive design would reach for is `/ip hotspot profile
html-directory` + an uploaded page set, and §2.2.4 shows why that is a trap
this codebase has already fallen into once and climbed back out of.

#### 2.2.2 What the router *does* need, and where it comes from

Four device-side objects are required for a guest to reach the cloud portal
at all. **None of them is derived from a Portal-screen field**; three are
platform constants and one is derived from the router's own LAN address.

| # | RouterOS object | Value | Source of truth today |
|---|---|---|---|
| P1 | `/ip hotspot walled-garden` `dst-host=<portal host>` `action=allow` `comment="cloudguest-portal"` | `auth.wyfyguest.com` | `RouterDetailTabs.tsx:buildWalledGardenLines` |
| P2 | `/ip hotspot walled-garden ip` `dst-address=<resolved A>` `action=accept` `comment="cloudguest-portal-https"` | `:resolve` on the device | same |
| P3 | `/ip hotspot profile hsprof1 dns-name=` | `wifi.wyfyguest.com` (`HOTSPOT_DNS_NAME`) | `RouterDetailTabs.tsx:1704`, `renderers.py:706` |
| P4 | `/ip hotspot profile hsprof1 login-by=` | `http-pap`, or `https,http-pap` **iff** the profile is already bound to the fleet certificate | `HOTSPOT_LOGIN_BY`, `RouterDetailTabs.tsx:6381-6384` |

Plus one optional discovery hint, RFC 8910/8908:
`/ip dhcp-server option code=114` pointing at
`GET /captive-portal/rfc8908?portal_url=http://wifi.wyfyguest.com/`
(`RouterDetailTabs.tsx:6296`, served by
`captive_portal/router.py:captive_portal_api`).

**P1 and P2 are one feature and must be pushed together.** This is the most
expensive lesson in the whole repo and it is recorded twice, live:

> **CONFIRMED TWICE, on real hardware:**
> — 2026-08-18, fleet-wide (router "WYFY-GUEST"): firewall hit-counters
> showed 1,965 HTTPS hits against 30 HTTP hits on the hotspot's own redirect
> rules — ~98% of real guest traffic. […]
> — 2026-08-27, "huda city center": `/ip hotspot walled-garden` held
> `auth.wyfyguest.com` at HITS: 0 — it had never matched anything, because
> the hostname it keys on is inside TLS — while
> `/ip hotspot walled-garden ip` was empty and Safari reported "couldn't
> establish a secure connection".
> — `RouterDetailTabs.tsx:1549-1563`

**The documentation and the live evidence disagree here, and the live
evidence governs.** MikroTik's own Hotspot page says of
`/ip hotspot walled-garden`: *"The menu only manages Walled Garden for HTTP
and HTTPs protocols"*, and of `/ip hotspot walled-garden ip`: *"To bypass
HotSpot authentication for other protocols and different src/dst addresses
(or address-lists). Used for different services (Winbox, SSH, Telnet, SIP,
etc.)"*
([Hotspot](https://manual.mikrotik.com/docs/authentication-authorization-accounting/hotspot-captive-portal/)).
Read literally, the host-based menu should have covered the HTTPS portal.
The documentation even supplies a mechanism: `method` is a closed enum that
includes **`CONNECT`**
([CLI reference](https://manual.mikrotik.com/docs/cli-reference/ip/hotspot/walled-garden/)),
and the hotspot's own dynamic NAT rule 12 sends unauthenticated `dst-port=443`
to the HTTPS proxy on port 64875. It did not work, twice, on real hardware,
with hit-counters as the evidence.

**The docs do not say how the walled garden extracts a hostname from an
HTTPS flow** — TLS SNI or a proxy `CONNECT` line — and that gap is exactly
where the failure lives. What settles the design without settling the
mechanism is §2.3's finding: since **RouterOS 7.5, unauthenticated HTTPS
through the hotspot is rejected outright**, not proxied. A rejected flow
never reaches the layer where `dst-host` would be evaluated, so the
host-based row cannot match and sits at HITS: 0 forever — precisely what was
observed. `/ip hotspot walled-garden ip` acts at the firewall/NAT layer,
*before* that rejection. The portal is HTTPS-only.
**A design that pushes only the host-based entry is not a partial fix, it is
no fix**, and it will report success. Push both, always, and let the
address-based row be the one the verdict keys on. Note also that on the IP
menu, *"when `dst-host` is specified a dynamic entry is added to Walled
Garden"* and `dst-address` is *"ignored if dst-host is already specified"* —
so pass an address there, not a name, or the two menus collapse back into
one.

`dst-host` matching is both stricter and more permissive than this repo
believes. Stricter: it *"matches a complete string (i.e., they will not match
'example.com' if they are set to 'example')"* — **a bare host does not cover
its own subdomains**, which is why `_portal_walled_garden_hosts` is right to
emit `*.wifi.wyfyguest.com` alongside the bare name. More permissive:
MikroTik documents `*` and `?` wildcards **and** full regular expressions,
which must be prefixed with a colon and may be anchored with `^`/`$` — e.g.
`add dst-host=:^www.example.com path=":/test\$"`.
`hotspot/validators.py`'s comment ("`*`-prefixed wildcard domains") is
narrower than reality; its deliberately permissive validation happens to be
correct anyway. **`path=` should not be relied on for HTTPS** — it cannot be
visible inside TLS, and the docs never claim it works there.

**The backend renderer has exactly this bug today.**
`network_config/renderers.py::_portal_walled_garden_hosts` returns

```python
hosts = [HOTSPOT_DNS_NAME, f"*.{HOTSPOT_DNS_NAME}"]   # wifi.wyfyguest.com
if api_host and api_host not in hosts:
    hosts.append(api_host)                             # api.wyfyguest.com
```

— which walls in the *redirect* hostname and the *API* host, emits only
host-based rows, and never mentions `auth.wyfyguest.com`, the host the guest
is actually sent to, nor any `walled-garden ip` row. `HOTSPOT_DNS_NAME`'s
own frontend docstring is explicit that these two names are deliberately
different and that conflating them broke guests live
(`RouterDetailTabs.tsx:1674-1703`). Fixing `_portal_walled_garden_hosts` is
a prerequisite for this design, not part of it, and it is a defect worth
raising on its own.

#### 2.2.3 `login-by`: read before you write, never write `ssl-certificate`

`login-by` must stay a single-writer property. The repo records what
happened when it was not:

> Two separate chunks used to set `login-by` on the same profile. […] Both
> `set`s succeeded, in paste order, and the last one won — so every router
> this generator provisioned ended up serving its hotspot login page over
> TLS with a certificate no client on earth trusts […] Confirmed live,
> guest-facing: a real Android phone on a freshly provisioned hEX showed a
> certificate/security warning the moment the captive portal opened.
> — `RouterDetailTabs.tsx:1706-1727`

The three symptoms of that one cause (no sign-in popup on Windows/macOS at
all, a visible certificate error on Android, and "OTP verifies but no
internet" because `$(link-login-only)` inherits the scheme) are documented
at `RouterDetailTabs.tsx:1729-1755` and match the incident already recorded
in this engineer's own notes.

The rule the adapter must follow, unchanged from the script:

* Gate on **"is this profile already bound to the fleet certificate"**
  (`/ip hotspot profile find where name="hsprof1" and
  ssl-certificate~"<HOTSPOT_FLEET_CERT_NAME>"`), never on "does a
  certificate object exist".
* Write `login-by=https,http-pap` only when that count is > 0, else
  `login-by=http-pap`.
* **Never write `ssl-certificate`.** That property belongs to
  `ops/letsencrypt-hotspot/renew-hotspot-certs.sh` and to nothing else. An
  adapter that writes it can rebind a router that has the real Let's Encrypt
  leaf onto something self-signed.

#### 2.2.4 How portal HTML actually gets onto the router — the answer

**Short answer: it does not, from the platform. A human pastes a script that
overwrites the *contents* of files RouterOS already ships. Nothing uploads a
directory, nothing creates one, and the one backend constant that names a
custom directory is stale and would break a portal if it were ever pushed.**

The long answer has four parts.

**(a) There is no upload path in the backend for this.**
`MikroTikAdapter.upload_file` writes a single file to the SFTP root by bare
filename (`sftp.open(filename, "wb")`); it takes no directory, creates no
directory, and every caller passes a fixed constant
(`_PROVISIONING_ENGINE_CONFIG_FILENAME`, `_PROVISIONING_ENGINE_BACKUP_FILENAME`).
`push_config` is `upload_file` + `/import`. Neither has ever carried an HTML
page. `capabilities()` advertises no file/portal operation.

**(b) The frontend's mechanism is `/file set contents=`, by basename, with
loud failure on a miss.** `PORTAL_OVERRIDE_FILES`
(`RouterDetailTabs.tsx:1452-1477`) lists five stock pages —
`login.html`, `rlogin.html`, `alogin.html`, `status.html`, `logout.html` —
and `buildPortalOverrideFileSetLines` overwrites each one's contents with a
~700-byte page whose `<head>` does a synchronous `location.replace()` to
`https://auth.wyfyguest.com/portal?organizationId=…&locationId=…&routerId=…&mac=$(mac)&dst=$(link-orig)&link-login-only=$(link-login-only)`.
`radvert.html` and `redirect.html` are deliberately left stock, with reasons
given.

Two details in that function are not stylistic and any adapter must
reproduce both:

* **Match on `/login.html`, not `login.html`.** RouterOS's `~` is a regex
  substring match and `login.html` is a substring of both `rlogin.html` and
  `alogin.html`; matching the bare basename silently overwrites all three
  with login.html's body.
* **`/file set [find …]` against an empty match succeeds, silently, with no
  error to catch.** This is stated as the defect that motivated the current
  code:

  > These used to be written as `flash/hotspot/login.html`. That `flash/`
  > prefix is a per-MODEL detail […] Getting it wrong did not raise anything
  > — RouterOS's `set [find ...]` against an EMPTY match succeeds, silently,
  > with no error to catch — so on those models every one of these five
  > `set`s did nothing, the paste looked clean, and the guest got MikroTik's
  > stock blue login page instead of the venue's portal.
  > — `RouterDetailTabs.tsx:1440-1450`

  The fix was to `:len [/file find where name~"/login.html"]` **first**, act
  on it, and print the count either way. An API-based adapter gets the same
  problem in a different shape: `api.path("file")` filtered client-side to
  zero rows is indistinguishable from a successful write unless the adapter
  counts.

**(c) `html-directory=cloudguest-hotspot` in the backend is stale and is a
latent portal outage.** `network_config/renderers.py:713` defines

```python
HOTSPOT_HTML_DIRECTORY = "cloudguest-hotspot"
```

and it is written into every per-VLAN hotspot profile by both
`_render_vlan_hotspot` (`renderers.py:851`) and
`MikroTikAdapter._ensure_hotspot_profile` (via `vlan/service.py:871,883,931`).
**Nothing in this repository creates that directory or puts a file in it.**
The frontend abandoned it on purpose:

> Uses RouterOS's own *stock* hotspot template ("hotspot", not a
> custom-uploaded one) — present with all its supporting CSS/error/logout
> pages on every fresh device out of the box. A previous, one-off custom
> folder ("cloudguest-hotspot") required manually uploading a whole asset
> folder that no repeatable script ever covers; only login.html itself needs
> to be ours […] and the stock folder already has everything else login.html
> depends on.
> — `RouterDetailTabs.tsx:6314-6320`

So today the fleet's `hsprof1` points at the stock folder while the
platform's own VLAN-hotspot code points at a folder that does not exist.
**`HOTSPOT_HTML_DIRECTORY` should be changed to `"hotspot"` before any
per-VLAN portal is pushed to a customer router** (§2.4, refusal
`PORTAL_HTML_DIR_MISSING`).

**(c2) What MikroTik documents about this, and the one recovery path.**
`html-directory` defaults to `"hotspot"` and is documented as *"Directory
name in which HotSpot HTML pages are stored"*; the customization procedure is
*"get HotSpot files from your router, change and upload them back to same
location. Full path must be typed in html-directory field, including
'/flash/(hotspot_dir)'"*. There is a separate `html-directory-override` —
*"Alternative path for hotspot html files"* — intended for external storage;
this design does not use it, but a customer router that has it set will serve
from there, and any `/file` write that ignores it writes to a directory
nobody reads. **Read `html-directory-override` before writing
`html-directory`, and refuse if it is set** (`PORTAL_HTML_DIR_OVERRIDDEN`).

RouterOS also ships a **"Reset HTML"** function that restores the stock page
set. That is the documented recovery path when a `/file` content write has
corrupted a page, and it is the reason overwriting contents is recoverable
where deleting files is not. It is also load-bearing for captive-portal
detection: *"If you have set up Hotspot before RouterOS v7.3 when RFC 7710
was implemented, you will have to use 'Reset HTML' function, or manually
add/edit the api.json file."* The `api.json` file is served at
`https://<dns-name-of-hotspot>/api` **when DNS configuration and valid SSL
certificates exist** — so on a router without the fleet certificate (i.e. all
but one, §4), the RFC 7710 endpoint is not available and the DHCP option-114
hint pointing at the platform's own `/captive-portal/rfc8908` is doing real
work rather than duplicating RouterOS's.

**(d) What a real upload path would cost, if it is ever wanted.**
`renderers.py:1383-1394` already scopes it honestly and declines to ship it:

> That needs a file on the device, so it needs either a `/tool fetch` of a
> page the API serves or a `/file` write — neither of which is rendered
> here, and neither of which has been confirmed against a real device, which
> this module's own "confirmed live" standard requires before it ships.

**Both options are more available than that paragraph assumes, and one
option is permanently closed.** From the documentation:

* **Directory creation over the API is documented and works** —
  `/file add name=/flash/<dir> type=directory`
  ([Files](https://manual.mikrotik.com/docs/system-information-and-utilities/files)),
  added in **7.15** (`*) file - allow adding and renaming files and
  directories;`). Before 7.15 there was no API path to create one at all, so
  a fleet spanning that boundary needs FTP/SFTP as a fallback.
* **Content writes over the API are capped at 60 KB** (`/file` `contents`).
  The redirect page is ~700 bytes, so this is not a constraint for the
  current design — but it is a hard ceiling on ever shipping a real asset
  set this way. `/file/read` offers `offset` + `chunk-size` for *reads*;
  there is no documented chunked write.
* **`/file/copy`, `/head`, `/tail` arrived in 7.23** — exactly the lab
  router's version. Do not depend on them if 7.22 must also work.
* **There is no unzip, and there never was.** Verified across all 83
  RouterOS 7 and all 135 RouterOS 6 changelogs: zero occurrences. An
  "upload a zip, expand on device" design is off the table permanently.
* **Whether `/tool fetch` or SFTP create missing intermediate directories is
  not documented.** Only `/file add … type=directory` is. Do not rely on
  either to make a path for you.
* SFTP `put` into a subdirectory is documented working in MikroTik's own
  container guides; whether the RouterOS SFTP server implements `mkdir`, and
  whether SCP is supported at all, are both undocumented — SCP appears
  exactly once in the entire manual, in an unrelated OSI-layer table. That
  `renew-hotspot-certs.sh` uses `scp` successfully in production is stronger
  evidence than the docs provide, and is worth recording as such.

So the transport exists, directory creation exists, and the 60 KB cap is
survivable. What still does not exist is an asset set worth uploading or any
per-router reachability signal. **Recommendation is unchanged: do not build
it.** Keep `html-directory` on the stock folder and keep the venue's identity
in the redirect URL — a ~700-byte content write against a file RouterOS
already ships, recoverable with "Reset HTML", rather than a directory tree
this platform would then own forever.

#### 2.2.5 The `dns-name` / `/ip dns static` conflict — settled

Two in-repo write-ups directly contradict each other here. **MikroTik's
documentation settles it, and it settles it against the code.**

**Position A** — `network_config/renderers.py` module docstring, and the code
it justifies: `dns-name` changes only the redirect URL, so
`_render_vlan_hotspot` emits a paired
`/ip dns static add name=<dns_name> address=<gateway>` and
`_ensure_dns_static` maintains it. That docstring already flags its own
uncertainty ("Not independently confirmed against a real device this
session").

**Position B** — `RouterDetailTabs.tsx:1690-1694`, presented as
live-confirmed: RouterOS auto-manages the DNS answer once `dns-name` is set,
and no manual `/ip dns static` entry is needed.

**The documentation says B.** The `dns-name` property description is:

> "DNS name of the HotSpot server. This is the DNS name used as the name of
> the HotSpot server (i.e., it appears as the location of the login page).
> **This name will automatically be added as a static DNS entry in the DNS
> cache.**"
> — [HotSpot](https://manual.mikrotik.com/docs/authentication-authorization-accounting/hotspot-captive-portal/)

Corroborated structurally: the `/ip hotspot` **server** carries a read-only
`ip-of-dns-name` property
([CLI reference](https://manual.mikrotik.com/docs/cli-reference/ip/hotspot/)),
i.e. RouterOS resolves the name itself and hands the result back. And the
§0 lab dump shows `dns-name=wifi.wyfyguest.com` with a working portal and no
`/ip dns static` row listed.

**Design decision, revised.** The manual row is redundant, not required — so
the argument for emitting it is no longer "otherwise guests get NXDOMAIN",
it is only "it is harmless and it is already there." That is a weaker
argument, and it comes with a real cost: a static row this platform owns and
a dynamic row RouterOS owns, for the same name, both live, is a drift source
the reconciler will trip over every push. **Keep emitting it for now** —
removing a row on the strength of one doc sentence, against code that has
shipped, is the wrong direction to be wrong in — but treat removal as the
expected end state once **T-P2** confirms the dynamic entry exists on a real
device, and correct `renderers.py`'s module docstring either way, because it
currently asserts the opposite of what MikroTik documents.

One further documented caveat worth carrying into the constant's own
docstring: the archived RouterOS 6 wiki notes that the chosen name can affect
captive-portal detection — *"iOS devices may not detect Hotspot that has a
name which includes '.local'"*. `wifi.wyfyguest.com` is safe; a future
`.local` or pseudo-TLD choice would not be.

### 2.3 Is editing a live hotspot profile safe?

**This cannot be settled from documentation and this document does not
pretend otherwise.** MikroTik's Hotspot page documents the full profile
property table (`dns-name`, `hotspot-address` default `0.0.0.0`,
`html-directory` default `"hotspot"`, `login-by` default `http-chap,cookie`,
`https-redirect` default `yes`, `ssl-certificate`, `use-radius` default `no`,
`radius-interim-update` default `received`, `trial-uptime` `30m/1d`,
`http-cookie-lifetime` `3d`, `smtp-server`, `split-user-domain`, `rate-limit`,
`nas-port-type`, `radius-mac-format`, …). It says **nothing** about what
happens to `/ip hotspot active` or `/ip hotspot host` when any of them is
changed on a profile a running server is using, nor about disable/enable of
the server. Forum reports that a profile `set` re-initializes the server and
drops active users exist, but a forum post is not a basis for deciding
whether customer edits are applied live, and this design does not treat it
as one.

Two documented details do bear on the design regardless:

* **`login-by` defaults to `http-chap,cookie`.** A freshly-added profile that
  nobody sets `login-by` on will not accept the platform's form POST, which
  needs `http-pap`. `_ensure_hotspot_profile` does not write `login-by` at
  all today, so every `vlan{id}-hsprof` it creates is on the default and
  cannot authenticate a guest. That is a defect, not a design choice
  (§2.4).
* **`https-redirect` no longer exists, and what replaced it is a hard
  constraint on this whole feature.** Both prose sites still document it.
  It was deleted in RouterOS 7.5, in the same changelog entry as the
  behaviour that replaced it
  ([7.5 CHANGELOG](https://download.mikrotik.com/routeros/7.5/CHANGELOG)):

  ```
  *) hotspot - removed "https-redirect" option;
  *) hotspot - automatically reject all HTTPS requests passing through
     HotSpot server for unauthorized users;
  ```

  **On 7.23.x an unauthenticated guest's HTTPS request is rejected,
  unconditionally, and there is no knob.** Captive-portal detection
  therefore rests entirely on the plain-HTTP probe path and on the RFC 7710
  DHCP option — and that option is only emitted when the router has both a
  `dns-name` **and** a valid certificate, which all but one fleet router
  lacks (§4). This is why the platform's own option-114 hint exists and is
  doing real work rather than duplicating RouterOS. It is also the cleanest
  explanation available for the two live walled-garden observations in
  §2.2.2, and it is invisible to anyone reading only the prose docs.
  **Never emit `https-redirect`** — a tool that does gets a hard error on
  7.5+.

What *is* known, from this repo, and is enough to design around:

* The setup script sets `login-by`, `dns-name` and `hotspot-address` on a
  live `hsprof1` on production routers today, by hand, and no incident note
  anywhere in this repo attributes a session flush to it. That is absence of
  evidence, not evidence of absence — nobody was watching `/ip hotspot
  active` across those pastes.
* `login-by` is categorically different from the other two: it changes the
  scheme RouterOS redirects to and the scheme `$(link-login-only)` inherits.
  Even if no session is dropped, every guest mid-login when it changes lands
  on the wrong scheme. Treat `login-by` as a maintenance-window change
  regardless of what T-P3 finds.
* `/ip hotspot walled-garden` and `/ip hotspot walled-garden ip` are
  separate menus from the profile. Adding a row there does not touch the
  profile and is the safest write in this whole design. The existing script
  already reasons that rows are only ever added, never pruned, because
  "withdrawing a host a live guest may be mid-request against is a worse
  failure than one extra allow rule" (`renderers.py:1370-1374`).

**Design decision, pending T-P3:**

| Object | Applied immediately | Rationale |
|---|---|---|
| `walled-garden`, `walled-garden ip` (P1, P2) | **yes** | separate menu, additive, never pruned |
| DHCP option 114 | **yes** | option table, not the hotspot |
| `dns-name` (P3) | **yes**, but see T-P3 | changes a redirect target, not a session |
| `login-by` (P4) | **no** — maintenance path | scheme change breaks in-flight logins irrespective of session survival |
| `html-directory` | **no** — maintenance path, and see §2.2.4(c) | a wrong value serves the stock blue page to every guest with no error |

If T-P3 shows a profile `set` *does* flush `/ip hotspot active`, move all
four profile properties (P3, P4, `html-directory`, `hotspot-address`) behind
the maintenance path and leave only the two walled-garden menus and the DHCP
option on the immediate path.

### 2.4 Relationship to the per-VLAN portal

`configure_vlan_hotspot` builds six objects per VLAN, all named from the
tag (`_HotspotNames`): `vlan{id}-hs-pool`, `vlan{id}-hs-dhcp`, the
`/ip dhcp-server network`, `vlan{id}-hsprof`, an `/ip dns static` row
commented `vlan{id}-hotspot-dns-name`, and `vlan{id}-hotspot`. Its docstring
is explicit: "Nothing here touches the router's own default `hotspot1` or
any other VLAN's portal."

The customer's mental model is different, and the dashboard reinforces it:
the Portal screen is scoped to **organization + optional location**, has no
router selector, no VLAN selector, and is labelled simply "Portal" in the
Engagement group. A customer editing it means *"the sign-in experience at my
venue"* — all of it.

**Recommendation.** Reconcile these by scope, not by object:

* **Portal-screen settings (§2.2.1) apply to every portal at the location,
  because they apply to none of them individually.** They are cloud config
  resolved per `locationId`; `hotspot1` and every `vlan{id}-hotspot` on that
  location's routers all redirect to the same
  `/portal?organizationId=…&locationId=…&routerId=…` URL, and the SPA
  resolves the same row. No fan-out is required and none should be built.
* **The four device-side objects (P1–P4) apply per router, to every hotspot
  profile on it.** `hsprof1` and each `vlan{id}-hsprof` need their own
  `dns-name` and `login-by`; the two walled-garden menus and the DHCP option
  are router-global and are written once. `_render_vlan_hotspot` already
  gives each VLAN a distinct `{tag}.wifi.wyfyguest.com` to avoid the
  `/ip dns static` name collision, and `_portal_walled_garden_hosts` already
  emits `*.wifi.wyfyguest.com` for exactly that reason — that part of the
  design is sound and should be kept.
* **The Portal screen must not gain a router or VLAN selector.** Adding one
  would make the customer responsible for a fan-out the architecture already
  handles, and would imply per-VLAN branding the `captive_portal` schema
  cannot express (it has no router tier at all — see its module docstring:
  "this module has no router-level tier — a captive portal's branding is a
  business/site concern, not a per-device one").

**Before any of this ships**, `HOTSPOT_HTML_DIRECTORY` must be corrected
(§2.2.4(c)) and `_portal_walled_garden_hosts` must learn about
`auth.wyfyguest.com` and the address-based menu (§2.2.2), and
`_ensure_hotspot_profile` must start writing `login-by=http-pap` (§2.3). A
per-VLAN portal pushed today points at a directory that does not exist, walls
in a host the guest is never sent to, and sits on RouterOS's
`http-chap,cookie` default that the platform's login form cannot satisfy —
three independent reasons a guest on it cannot get online, none of which
surfaces as an error.

### 2.5 Refusal codes — Portal

Named, returned rather than guessed, and modelled on
`final_verification.py`'s `name=`/`status=` check shape.

| Code | Condition | Why refuse rather than guess |
|---|---|---|
| `PORTAL_NO_HOTSPOT_SERVER` | `/ip hotspot` has no row, or none whose profile this push targets | Writing walled-garden rows and a `dns-name` on a router with no hotspot produces a clean success and zero guest-visible effect |
| `PORTAL_PROFILE_MISSING` | the named `/ip hotspot profile` row does not exist | A RouterOS `set [find …]` against an empty match succeeds silently — the single most repeated failure in this repo |
| `PORTAL_HTML_DIR_MISSING` | `html-directory` names a directory with no `login.html` under it (`/file find where name~"/login.html"` is empty for that prefix) | Serves MikroTik's stock blue page to every guest, with no error anywhere |
| `PORTAL_HTML_DIR_OVERRIDDEN` | the profile has a non-empty `html-directory-override` | RouterOS serves from the override path; a `/file` write against `html-directory` lands in a directory nobody reads |
| `PORTAL_HOST_UNRESOLVABLE` | the router cannot `:resolve` the portal host | Without an address there is no `walled-garden ip` row, and the portal is unreachable over HTTPS for every guest. This is already a hard `:error` stop in the script |
| `PORTAL_WALLED_GARDEN_IP_UNSUPPORTED` | `/ip hotspot walled-garden ip` menu is absent (see §5) | Pushing only the host-based row is not a partial fix |
| `PORTAL_CERT_BINDING_UNKNOWN` | `login-by=https` requested but `ssl-certificate` on the profile does not match the fleet cert name | Untrusted TLS on the hotspot is worse than plain HTTP — three confirmed guest-facing symptoms |
| `PORTAL_LOGIN_BY_UNSUPPORTED_VALUE` | requested `login-by` token not accepted by this RouterOS version | Silent partial application of a comma list |
| `PORTAL_MULTIPLE_PROFILE_MATCH` | more than one profile matches the target name | Ambiguous identity; two portals could be rebound at once |
| `PORTAL_FILE_MATCH_EMPTY` | a `/file` content write matched zero rows | The `flash/` prefix defect, restated as a refusal |
| `PORTAL_FILE_MATCH_MULTIPLE` | a `/file` content write matched more rows than the one page intended | The `/login.html` vs `login.html` substring defect |

### 2.6 Verification that would actually catch it

Every check below re-reads the device after the write and asserts a property
that is false when the write silently did nothing. A guarded command that
does not fire is indistinguishable from one that succeeded; the count is the
only honest report.

| Check name | Assertion |
|---|---|
| `portal_profile_present` | exactly one `/ip hotspot profile` matches the target name |
| `portal_dns_name_set` | that row's `dns-name` equals the intended value, re-read |
| `portal_login_by_exact` | that row's `login-by` string-equals the intended value (not "contains") |
| `portal_walled_garden_host` | ≥1 enabled `/ip hotspot walled-garden` row with `comment="cloudguest-portal"` |
| `portal_walled_garden_ip` | ≥1 enabled `/ip hotspot walled-garden ip` row with `comment="cloudguest-portal-https"` — **ERROR, not WARNING**, if absent |
| `portal_html_login_page` | `/file` has ≥1 row named `…/login.html` under the profile's `html-directory`, and its contents contain the platform's own portal marker |
| `portal_sessions_preserved` | `/ip hotspot active` count after ≥ count before (only meaningful on the maintenance path; see T-P3) |

The `portal_html_login_page` check is the one that would have caught the
`flash/` prefix defect, and it is the one an API adapter is most likely to
skip because the write "succeeded".

---

## 3. DNS

### 3.1 Recommendation in one line

**Keep `app/domains/dns/` as what its model already is — `/ip dns static`
only — give it a `device_adapters.py` with a `comment`-marker identity, and
rename the screen so it stops implying it controls resolvers.** Do not add
"DNS servers" to it; upstream resolvers belong to the WAN renderer that
already owns them, and a customer-set resolver interacts with four existing
firewall rules and with content filtering in ways §3.3 shows are not safe to
expose as a free-text field.

### 3.2 Four different things, and which one this is

The dashboard is conflating them, and the conflation is across two screens.

| # | RouterOS object | What it means | Exposed today |
|---|---|---|---|
| 1 | `/ip dns servers=` | the resolvers **the router itself** queries | **not exposed** — hardcoded `8.8.8.8,1.1.1.1` in `wan/context.py:32` and `wan/build_context.py:50`, written by `render_wan_dns_section` |
| 2 | `/ip dns static` | name → address answers **the router serves** to its LAN | **this is the DNS screen** |
| 3 | `/ip dhcp-server network dns-server=` | which resolver a guest's device is *told* to use | the **DHCP** screen, as `dnsPrimary`/`dnsSecondary` (`DhcpManagement.tsx:825-831`) |
| 4 | `/ip hotspot profile dns-name` | the hostname in the hotspot's redirect URL | not exposed; a platform constant |

`app/domains/dns/models.py` is unambiguous that the domain is #2 —
`name`, `record_type` ∈ {a, aaaa, cname}, `address`, `ttl_seconds`,
`comment`, `is_enabled`, scoped to one `router_id` for the row's whole
lifetime. `renderers.py` renders it as `address=` for A/AAAA and `cname=`
for CNAME. That is a correct, narrow model and should not be widened.

**The labelling defects to fix alongside the device path:**

* The module label is bare **"DNS"** at `/network/dns`, which reads as
  resolvers. The page title `"DNS Record Management"` is honest; the nav
  label is not.
* `dnsPrimary`/`dnsSecondary` on the DHCP screen and A-records on the DNS
  screen are unrelated things with no cross-reference between the screens.
* The `name` field's placeholder is `portal.hotel.local`, which invites the
  customer to believe this is where a portal hostname is configured. It is
  not (§2.2.5), and per `RouterDetailTabs.tsx:1690` RouterOS may already own
  that name itself.
* The delete confirmation claims to remove the record from the router. It
  removes a row.

### 3.3 The interaction with the four existing filter rules

**This is the section where the naive change does damage, and the premise
needs correcting first: the four rules are not one mechanism, they are two,
and only one of them is about forcing guests onto the router's resolver.**

| Rule comment | Actual rule | What it does |
|---|---|---|
| `cloudguest-fw-block-wan-dns` | `chain=input in-interface-list=WAN protocol=udp dst-port=53 action=drop` | drops DNS arriving **from the WAN to the router**. This is open-resolver hardening, and it is literally what MikroTik tells you to do: *"When DNS server allow-remote-requests are used make sure that you limit access to your server over TCP and UDP protocol port 53 only for known hosts"* ([DNS](https://manual.mikrotik.com/docs/network-management/dns)). **It has nothing to do with guests.** |
| `cloudguest-fw-block-wan-dns-tcp` | same, `protocol=tcp` | same |
| `cloudguest-block-dot-udp` | `chain=forward hotspot=!auth protocol=udp dst-port=853 action=drop` | blocks DNS-over-TLS **for unauthenticated guests only** |
| `cloudguest-block-dot-tcp` | `chain=forward hotspot=!auth protocol=tcp dst-port=853 action=drop` | same |
| `cloudguest-block-doh` | `chain=forward hotspot=!auth protocol=tcp dst-port=443 dst-address-list=cloudguest-doh-ips action=drop` | blocks DNS-over-HTTPS to 10 known resolver IPs, unauthenticated guests only |

Sources: `network_config/wan/renderers.py:970-983` (the first two);
`RouterDetailTabs.tsx:6855-6900` (the DoT/DoH trio, plus the
`cloudguest-doh-ips` address-list). The `hotspot=!auth` matcher and the
stated intent — "a clean drop (not a redirect) is what reliably triggers
each browser's own automatic fallback to normal DNS, which the hotspot
already correctly intercepts" — are load-bearing: **once a guest logs in,
none of the DoT/DoH rules apply to them.**

Now the four ways a "custom DNS server" setting could be implemented, and
what each actually does:

**(i) Change `/ip dns servers` (#1).** Changes only where *the router*
forwards queries it cannot answer locally. Interacts with none of the five
rules: the router's own queries leave in `chain=output`, and
`cloudguest-fw-block-wan-dns` is `chain=input`. `/ip dns static` still wins
for names it holds, so content filtering and the hotspot redirect are
unaffected. **This is the only one of the four that is safe, and it is the
one the dashboard does not expose.** If a "custom DNS" feature is ever
wanted, this is what it should mean.

**(ii) Change `/ip dhcp-server network dns-server` (#3) to a public
resolver — or leave it unset, which is the same failure with no setting
involved.** MikroTik documents this field as *"DNS servers that will be
passed to DHCP clients. Two comma-separated DNS servers can be specified"*
and — critically — that **if none are configured, the router passes the
dynamic DNS servers from `/ip dns`, or the static ones if no dynamic ones
exist**
([DHCP](https://manual.mikrotik.com/docs/network-management/dhcp)).

So an unset `dns-server` on this lab router hands guests `192.168.1.1` (the
upstream), not `10.5.50.1`. **Guests would never ask the router anything.**
`_render_vlan_hotspot` and `_ensure_dhcp_network` both set
`dns-server=<gateway>` explicitly and are safe. `render_dhcp_pool`
(`renderers.py:800-802`) sets it **only when `pool.dns_primary` or
`dns_secondary` is populated** — and those are the optional, blank-by-default
"DNS primary/secondary" fields on the customer DHCP screen. A customer who
creates a DHCP pool and leaves them blank gets a pool whose guests bypass the
router's resolver entirely, and every one of the consequences below follows
without anyone having changed a "DNS" setting at all. **That is a live defect
in the DHCP renderer, found by reading this documentation, and it is the
highest-value thing in this section.** The fix is to default to the pool's
own `gateway_ip_address` rather than omitting the parameter.

The two-address cap is also real: `dns_primary`/`dns_secondary` is exactly
the shape RouterOS accepts, so no widening is needed there.

**The hotspot changes this picture, and the documentation settles how.**
Whether an unset-or-wrong `dns-server` actually causes a bypass depends
entirely on whether the interface has a hotspot on it, because the hotspot
hijacks DNS for everyone regardless of what DHCP told them. MikroTik
documents the dynamic NAT rules it installs
([Hotspot customisation](https://manual.mikrotik.com/docs/authentication-authorization-accounting/hotspot-captive-portal/hotspot-customisation)):

```
0 D chain=dstnat  action=jump jump-target=hotspot hotspot=from-client
1 I chain=hotspot action=jump jump-target=pre-hotspot
2 D chain=hotspot action=redirect to-ports=64872 dst-port=53 protocol=udp
3 D chain=hotspot action=redirect to-ports=64872 dst-port=53 protocol=tcp
```

> "Redirect all DNS requests to the HotSpot service. The 64872 port provides
> DNS service for **all** HotSpot users."

Three things follow, and the third is the one everyone gets wrong:

* Rule 0 pulls **every** packet from a hotspot client into the `hotspot`
  chain. Rules 2 and 3 are `action=redirect` — local destination NAT — so
  they fire **regardless of which resolver the client was configured to
  use**. The client's chosen server IP is simply overwritten.
* **Rules 2 and 3 carry no `hotspot=!auth` matcher**, unlike the sibling
  rules 6 and 7. The DNS redirect therefore applies to *authenticated*
  clients too, for the whole session — not just before login. The
  documentation's own wording ("all HotSpot users") is deliberate.
* `chain=hotspot action=jump jump-target=pre-hotspot` runs **before** them,
  and `pre-hotspot` is documented as *"under full administrator control and
  does not contain any rules set by the system"*. **That is the supported
  hook for overriding the DNS redirect**, and it is the only correct place
  to put one.

**So the customer-set-resolver case splits in two:**

| Interface | Effect of a custom `dns-server` | Verdict |
|---|---|---|
| has a hotspot (`bridge`/`hotspot1`, any `vlan{id}-hotspot`) | **none** — rules 2/3 redirect the query back to the router anyway | the setting is *inert*, and a UI that implies otherwise is lying |
| plain DHCP pool, no hotspot | guests really do resolve against the customer's server | the destructive case below |

This is materially better news than a naive reading gives, and materially
worse for the dashboard: on the networks that matter most, a "custom DNS
server" control cannot do what it says. **Refuse it there
(`DNS_RESOLVER_INERT_UNDER_HOTSPOT`) rather than accepting a setting the
device will ignore.**

On a non-hotspot pool the bypass is real, nothing blocks it — no rule in
`chain=forward` drops plain udp/53 — and three things break at once, all
silently:

* **Content filtering stops working.** `configure_content_filter_rule`
  implements blocking as `/ip dns static` sinkhole rows pointing at
  `127.0.0.1` (`mikrotik_adapter.py`, `_CONTENT_FILTER_SINKHOLE_ADDRESS`).
  A guest not using the router's resolver never sees them. The dashboard's
  "Website Blocking" feature would report every rule as applied and block
  nothing.
* **Local names stop resolving**, including any `/ip dns static` row this
  domain writes for that customer.
* **Every per-VLAN portal's `/ip dns static` row becomes dead** on that
  segment. `_render_vlan_hotspot` emits `{tag}.wifi.wyfyguest.com` → gateway;
  only the router can answer it.

**Reconciliation for the non-hotspot case: pair the custom resolver with a
redirect rule, or refuse.** A `dst-nat`/`redirect` on udp+tcp 53 back to the
gateway keeps the router authoritative and keeps the sinkholes live, at the
cost that the customer's chosen resolver is in practice ignored — which is
honest and should be said in the UI, not hidden. Adding *block* rules for
udp/53 instead of a redirect breaks name resolution for every guest outright,
which is the "naive change breaks everything" half of the question.

**One thing the documentation does not settle** and that decides how much of
the above is real: whether the hotspot's port-64872 DNS service consults the
router's own `/ip dns static` table at all. The circumstantial case is strong
— `dns-name` is documented as being added *"as a static DNS entry in the DNS
cache"*, which is only useful if the hotspot answers from that cache, and the
setup wizard says DNS *"configuration is taken from /ip dns menu of the
HotSpot gateway"* — but no page states it. **If it does not, content
filtering has never worked for hotspot guests on any router in the fleet.**
That is a large enough consequence to test before anything else here ships
(**T-D1**).

One overlap worth naming before it is discovered the hard way: the
`cloudguest-doh-ips` address-list contains `8.8.8.8`, `8.8.4.4`, `1.1.1.1`
and `1.0.0.1` — which are exactly the values `wan/build_context.py:50`
writes into `/ip dns servers`. This is not a conflict, because the DoH rule
is `chain=forward` and the router's own upstream queries leave in
`chain=output` on udp/53, not tcp/443. It becomes one the moment anybody
"simplifies" the DoH rule's chain, or adds a `dst-address-list` match to a
rule that also catches the router's own traffic. Any change to either list
must be checked against the other.

**(iii) Add a `/ip dns static` row (#2, the current model).** Interacts with
none of the five rules. This is the safe, already-modelled case. Its one
real interaction is *internal*: it shares a table with content filtering's
sinkhole rows and with the hotspot `dns-name` rows, so identity discipline
matters (§3.5).

**(iv) Change `dns-name` (#4).** Covered in §2. Not a DNS-screen concern.

**Recommendation: the DNS screen implements (iii) and nothing else.** If
"custom DNS server" is a real customer request, implement (i) as a separate,
explicitly-labelled setting on the ISP/WAN screen where `dns_servers`
already lives, and never (ii) without the paired redirect rule.

### 3.4 `dynamic-servers` and the WAN re-lease

`/ip dns` shows `servers=8.8.8.8 dynamic-servers=192.168.1.1`. The dynamic
entry is not something the platform set — it arrives from the `ether1` DHCP
client's lease (`use-peer-dns` defaults on), and RouterOS refreshes it on
every re-lease. `provisioning_engine/planner/collector.py:270-279` already
reads both fields into the snapshot as `servers` / `dynamic_servers`, so the
distinction is visible to the planner today.

What this means for a static customer setting:

* A value written to `servers=` is **static configuration and survives a
  re-lease.** It is not overwritten by DHCP.
* `dynamic-servers` is **maintained by RouterOS and must never be written
  by an adapter.** A design that tries to `set dynamic-servers=` is either
  rejected or fighting the DHCP client on every lease renewal.
* On a WAN re-lease, `dynamic-servers` changes to whatever the new upstream
  advertises — including, on a customer site behind a consumer router, an
  ISP resolver that hijacks NXDOMAIN. **MikroTik's two documentation pages
  contradict each other on which list wins, and that contradiction is the
  finding.** The DNS page says outright: *"When both static and dynamic
  servers are set, static server entries are preferred"*, and describes
  `dynamic-servers` as read-only — *"List of dynamically added DNS servers
  from different services, for example, DHCP"*
  ([DNS](https://manual.mikrotik.com/docs/network-management/dns)).
  The DHCP page says of `use-peer-dns` (*"Whether to accept the DNS settings
  advertised by DHCP Server"*, default **yes**) that enabling it will
  *"override the settings put in the `/ip dns` submenu"*
  ([DHCP](https://manual.mikrotik.com/docs/network-management/dhcp)).
  One of the two is stale — most plausibly the DHCP page, describing the
  older behaviour where the client wrote directly into `servers=` rather
  than into a separate read-only list — but **which one is stale decides
  whether a customer's configured resolver is used at all**, so it is
  settled by test **T-D2**, not by picking the more convenient sentence.
* The deterministic fix, if precedence turns out to favour the dynamic list,
  is `/ip dhcp-client set [find interface=<wan>] use-peer-dns=no`, which
  empties `dynamic-servers` and leaves only the configured list. **That is a
  WAN-touching write and is out of this document's scope** — it belongs
  with `network_config/wan/`, and it changes what happens if the static list
  is ever unreachable. Flag it, do not do it here.
* **Reconciliation must therefore never compare against the union.** A
  reconciler that reads `servers` + `dynamic-servers` and finds a value it
  did not write will re-push forever on every lease renewal. Compare
  `servers` only. (`dynamic-servers` is confirmed **read-only** by the
  [CLI reference](https://manual.mikrotik.com/docs/cli-reference/ip/dns/),
  which lists it under "Read-only Argument" — note the prose calls it
  `dynamic-server`, singular, which is wrong; the property is plural.)
* **"Preferred" does not mean "always used", and the resolver is sticky.**
  The DNS page qualifies its own precedence sentence: *"it does not indicate
  that a static server will always be used (for example, previously query
  was received from a dynamic server, but static was added later, then a
  dynamic entry will be preferred)"*. And: *"When DNS cache has to send a
  request to the server, it tries servers one by one until one of them
  responds. **After that this server is used for all types of DNS
  requests**"*, with a re-scan only when the chosen server stops answering.
  So a router that latched onto the dynamic server before the static list
  was written keeps using it until that server fails or the cache is
  flushed. **Any push that changes `servers` must be followed by
  `/ip dns cache flush`**, or the change appears to have no effect for an
  unbounded time — which is exactly the shape of bug that gets diagnosed as
  "the push didn't work".

### 3.5 Idempotent create / update / delete, with a stable identity

The established handle in this codebase is a `comment` marker, and
`configure_nat_masquerade` states the whole design:

> **The comment is the rule's identity, and that is the whole design.**
> Every other field is something an operator edits: re-subnet a VLAN and
> `src-address` changes, re-cable a site and `out-interface` changes. Keyed
> on any of those, the next push would find no match, add a second rule, and
> leave the first one masquerading a subnet nothing uses — silent,
> cumulative, and invisible in this platform's own UI.

`/ip dns static` already carries a `cloudguest-*` comment convention on this
platform: `_HotspotNames.dns_comment` writes `vlan{id}-hotspot-dns-name`,
and content filtering writes the rule's own label plus `" (subdomains)"`.

**Identity: `comment = f"cloudguest-dns-{record.id}"`** — the row's own UUID,
which is the only field a customer cannot edit. Keying on `name` (as
`_ensure_dns_static` does, deliberately, because RouterOS treats `name` as
the row identity for its own collision purposes) is wrong for this domain
for a reason the model states outright:

> two DNS records may legitimately share the same `name` on one router
> (real-world round-robin DNS — multiple `A` records for one name) — so no
> uniqueness/conflict check is enforced here at all
> — `app/domains/dns/models.py`

Key on `name` and a customer who renames a record leaves the old row on the
device forever, answering a name nothing points at.

**Create / update — one read-before-write, mirroring
`_ensure_nat_masquerade_rule` line for line:**

```
menu = api.path("ip", "dns", "static")
desired = {"name": …, "address"|"cname": …, "ttl": f"{ttl_seconds}s", "type": "A"|"AAAA"|"CNAME"}
rows = [r for r in menu if r.get("comment") == f"cloudguest-dns-{id}"]
  len(rows) == 0 -> menu.add(**desired, comment=marker, disabled="no")
  len(rows) == 1 -> update only the keys whose current value differs;
                    normalize `disabled` through _is_truthy, never string-compare "no"
  len(rows)  > 1 -> refuse: DNS_DUPLICATE_MARKER
```

`_is_truthy` normalization is not cosmetic; `_ensure_dns_static`'s own
docstring records why:

> comparing the raw value against `"no"` would instead issue a pointless
> update on every single push

**Delete:** `remove` **only** rows whose `comment` equals the marker. Never
`remove [find name=…]` — that would take out a content-filter sinkhole or a
hotspot `dns-name` row that happens to share the name. `_remove_where(api,
("ip","dns","static"), "name", …)` in `delete_vlan_hotspot` is safe only
because that name is `{tag}.wifi.wyfyguest.com` and unique by construction;
a customer-supplied name has no such guarantee.

**Disable rather than delete on `is_enabled=false`:** set `disabled=yes` and
keep the row, so re-enabling is a `set` rather than a re-`add` that races
with a concurrent push.

**Two documented facts that should change what this domain models.**

MikroTik's `/ip dns static` property table is wider than
`app/domains/dns/constants.py` assumes: `type` accepts
**`A | AAAA | CNAME | FWD | MX | NS | NXDOMAIN | SRV | TXT`**, plus the
per-type value columns (`mx-preference`/`mx-exchange`, `srv-*`, `ns`,
`text`), `forward-to`, `address-list`, `match-subdomain`, and `ttl`
(default `24h` — which is where this domain's own
`DEFAULT_TTL_SECONDS = 86_400` correctly came from)
([CLI reference](https://manual.mikrotik.com/docs/cli-reference/ip/dns/static)).

Version boundaries, from the changelogs rather than the prose:
`match-subdomain` and `address-list` both arrived in **7.5**, CLI-only, with
WinBox exposure in 7.6
([7.5 CHANGELOG](https://download.mikrotik.com/routeros/7.5/CHANGELOG)) —
third-party sources claiming 7.6 or 7.7 are wrong. **`type=` is not new**:
the RouterOS 6 wiki lists the identical nine values, so it is safe on a v6
router.

Two documented behaviours that affect correctness here:

* **Ordering:** *"The list is ordered and checked from top to bottom.
  Regular expressions are checked first, then the plain records."* A
  content-filter `regexp=` row therefore outranks a customer's plain `name=`
  row for the same host — which is the right precedence, and worth saying in
  the UI rather than letting a customer wonder why their record "does not
  work".
* **Type promotion:** *"If DNS static entries list matches the requested
  domain name, then the router will assume that this router is responsible
  for **any type** of DNS request for the particular name."* So an `A` row
  for a name makes the router authoritative for that name's `AAAA`, `MX`,
  etc. — it forwards upstream for the missing types, but the name is now
  partly the router's. A customer A-record for a public hostname changes more
  than they expect.
* A `PTR` record is auto-created in cache for every static `A`/`AAAA`.
* Regexps are matched against a lowercased name — *"You should write regex
  only with lowercase letters"* — and *"adding the entry itself might require
  escape characters when added from CLI… print… to verify that regex was not
  changed during addition."* An API adapter should read the row back and
  compare, not assume the string it sent is the string stored.

* `DnsRecordType`'s three values are a defensible first pass and its
  docstring already says so honestly. `FWD` and `NXDOMAIN` are the two worth
  adding later — a venue pointing one internal zone at its own server, and a
  venue blackholing a name.
* **`match-subdomain` is a materially better mechanism than the regexp pair
  content filtering currently emits.** `configure_content_filter_rule` adds
  *two* rows per blocked domain (an exact `name=` and a
  `regexp=`-for-subdomains) because it believes the two are mutually
  exclusive per entry. The exclusivity claim is not stated in the current
  documentation either way, but `match-subdomain=yes` on a single `name=`
  row expresses the same intent in one row with no regex. That is a
  content-filtering change, not a DNS-domain one, but it halves the row count
  in the table this domain shares — worth raising with whoever owns it.

**One further constraint the reader will hit:**
`wyfy_device_gateway/read_only_reader.py`'s `READ_ONLY_SECTION_PATHS` has
sections for `dns` (`/ip dns`) but **none for `/ip dns static`**, and none
for `/file`. Reconciliation and drift detection for both features need those
two sections added to the allowlist, or they will be blind to exactly the
tables they own.

### 3.6 Refusal codes — DNS

| Code | Condition | Why refuse rather than guess |
|---|---|---|
| `DNS_DUPLICATE_MARKER` | more than one `/ip dns static` row carries this record's marker | Ambiguous identity; updating one leaves the other answering |
| `DNS_MARKER_COLLISION_FOREIGN` | the marker matches a row whose `name` is a content-filter sinkhole (`address=127.0.0.1`) or a hotspot `dns-name` row | Overwriting either silently disables website blocking or the portal redirect |
| `DNS_NAME_SHADOWS_PORTAL` | the requested `name` equals or is a subdomain of `HOTSPOT_DNS_NAME` | A customer record for `wifi.wyfyguest.com` overrides the portal redirect for every guest on that router |
| `DNS_NAME_SHADOWS_FILTER` | the requested `name` already has a sinkhole row from content filtering | The customer is unblocking a site the blocklist blocks, through a screen that does not say so |
| `DNS_CNAME_WITH_ADDRESS` | `record_type=cname` but the device row has `address=` set, or vice versa | RouterOS uses distinct, mutually-exclusive parameters |
| `DNS_REGEXP_ROW_TARGETED` | the matched row has `regexp=` rather than `name=` | Content filtering owns those rows; `name=` and `regexp=` are mutually exclusive per entry |
| `DNS_STATIC_UNREADABLE` | `/ip dns static` cannot be listed | Writing blind produces duplicates |
| `DNS_RESOLVER_NOT_LOCAL` | (only if a resolver setting is ever added) the router's `/ip dhcp-server network dns-server` is not the router's own gateway address, on a segment with no hotspot | Content filtering and every local name silently stop working — refuse, do not "apply and hope" |
| `DNS_RESOLVER_INERT_UNDER_HOTSPOT` | a custom resolver is requested for a segment that has a hotspot on it | The hotspot's dynamic `dst-port=53 action=redirect` overrides it for every client, authenticated or not. Accepting the setting would store a preference the device provably ignores |
| `DNS_ALLOW_REMOTE_REQUESTS_OFF` | `dns-server=<router>` is to be handed out but `/ip dns allow-remote-requests=no` | MikroTik states this combination requires it; without it the router does not answer on port 53 and every guest loses DNS |
| `DNS_DYNAMIC_SERVERS_WRITE` | any attempt to write `dynamic-servers` | Documented read-only; the write is either rejected or fights the DHCP client every lease |
| `DNS_UNSUPPORTED_RECORD_TYPE` | the stored `record_type` is not one this RouterOS version's `/ip dns static` accepts | v7 accepts `A\|AAAA\|CNAME\|FWD\|MX\|NS\|NXDOMAIN\|SRV\|TXT`; v6 accepts fewer. Refuse rather than write a row RouterOS reinterprets |

### 3.7 Verification — DNS

| Check name | Assertion |
|---|---|
| `dns_row_present` | exactly one `/ip dns static` row carries the marker |
| `dns_row_fields_match` | re-read `name`, `address`/`cname`, `ttl`, `type`, `disabled` all equal desired |
| `dns_no_orphans` | no row carries a `cloudguest-dns-*` marker whose UUID has no live DB row |
| `dns_filter_rows_intact` | the count of content-filter sinkhole rows is unchanged across the push |
| `dns_portal_row_intact` | the hotspot `dns-name` row (if any) still exists and still points at the gateway |
| `dns_resolves_on_device` | `/ping <name> count=1` from the router returns the intended address — the only check that proves the router actually *answers* the name rather than merely storing it |

`dns_resolves_on_device` is the analogue of `portal_html_login_page`: it is
the check that distinguishes "the row is in the table" from "a guest asking
for this name gets this answer", and it is the one that catches a row that
was written but shadowed.

---

## 4. What varies across customer routers

| Variable | Consequence | Handling |
|---|---|---|
| **RouterOS version, generally** | See the table below — this is not one variable, it is nine. | Read `/system/resource` `version` (already collected by `discover`) and gate. Refuse rather than downgrade silently. |
| **Boards with no `/flash`** | The hotspot page path is `hotspot/login.html` on some boards and `flash/hotspot/login.html` on others. This has already caused a silent fleet-wide portal failure. **MikroTik publishes no model list and no architecture rule** — the only documented test is a runtime one: does `/file print` show `name=flash type=disk`. Product pages give `Storage: … NAND` and never mention the directory. | **Never write an absolute path and never infer from the model.** Probe with `/file print`, then discover the page with `/file find where name~"/login.html"`, act on the count, refuse `PORTAL_FILE_MATCH_EMPTY` on zero. |
| **`/flash` is persistent, the root is not** | *"files which you want to be kept after the system reboot/power cycle must be stored within it, as anything outside of it is kept within a RAM disk and will be lost upon reboot"*. `upload_file`'s SFTP write goes to the **root** — so anything it uploads is gone on reboot. | Any future file write must target `flash/…` on boards that have it. The current `push_config` behaviour is survivable only because `/import` runs immediately. |
| **`device-mode` can disable hotspot outright** | v7-only gate: *"HotSpot functionality could be blocked by the device-mode. Prior to configuring HotSpot make sure that it is enabled in system/device-mode."* Changing it **requires physical intervention** (power cycle or button press). | Read `/system/device-mode` before any portal push and refuse with a message that names the physical step. A remote provisioning flow cannot recover from this on its own. |
| **Routers never provisioned with `cloudguest-*` rules** | No `cloudguest-doh-ips` list, no DoT/DoH drops, no `cloudguest-fw-block-wan-dns`, possibly no `WAN` interface list. A DNS design that assumes guests are pinned to the router's resolver is wrong on these. | Detect by counting `/ip firewall filter` rows with `is_wyfy_managed(comment)` (`planner/collector.py:55`, prefixes `WYFYGUEST-` / `cloudguest-`). Report "unmanaged router" as a distinct state, not as a failed push. |
| **Routers with the fleet Let's Encrypt cert vs without** | `login-by` must differ. Only `WYFY-GUEST` at `10.20.0.50` is in `renew-hotspot-certs.sh`'s `ROUTERS` inventory. | Read `ssl-certificate` off the profile; never infer from a certificate object's existence. |
| **`hsprof1` vs `default` vs `vlan{id}-hsprof`** | The lab router's `default` profile is `hotspot-address=0.0.0.0 use-radius=no html-directory=hotspot` — an unused stock row. A push that matches "the first profile" would hit it. | Always target by exact name. `PORTAL_MULTIPLE_PROFILE_MATCH` on ambiguity. |
| **Management reachability: 8728 always, 22 sometimes** | §1.3. `/file` writes over the API are possible; SFTP is proven over the tunnel but not fleet-wide. | Probe, do not assume. A `/file` design that needs SFTP must degrade to a refusal, not a hang. |
| **`use-peer-dns` on the WAN DHCP client** | Determines whether `dynamic-servers` is populated at all, and therefore whether §3.4's precedence question even arises on a given router. | Collect it alongside `dns_config`; it is not in the snapshot today. |
| **`smips` boards lost hotspot from the base package in 7.20** | `*) smips - reduced package size, removed hotspot feature and provide it as a separate package;`. **The lab hEX lite is mipsbe and is unaffected**, but a mixed fleet is not. | Gate on `/system/resource` architecture, not model name. |
| **Hotspot is IPv4-only** | *"A hotspot can work reliably only when IPv4 is used. Hotspot relies on Firewall NAT rules which currently are not supported for IPv6."* | `DnsRecordType.AAAA` is legitimate for `/ip dns static`, but no portal path depends on it. Do not build IPv6 into the portal design. |

### Version boundaries that would break an adapter

Every entry sourced from `https://download.mikrotik.com/routeros/<version>/CHANGELOG`.

| Version | Change | Why it matters here |
|---|---|---|
| **7.5** | `https-redirect` **removed**; unauthenticated HTTPS through the hotspot rejected unconditionally | Emitting the property is a hard error. The behaviour change is the core constraint of §2.2.2/§2.3 |
| **7.5** | `/ip dns static` gains `match-subdomain` and `address-list` (CLI-only; WinBox 7.6) | Reading these off a ≤7.4 router returns nothing |
| **7.7** | `/ip hotspot profile` gains `install-hotspot-queue` | Controls whether `rate-limit` creates dynamic queues at all — interacts with `queue_management` |
| **7.15** | `/file add … type=directory` becomes possible | Below this, no API directory creation at all |
| **7.16** | `/file` `creation-time` **renamed** to `last-modified` | Any file-metadata parsing breaks across this line |
| **7.17–7.17.1** | RouterOS itself prepended a spurious `flash/` to `html-directory` on flash boards; fixed in 7.17.2/7.18 | A read-back-and-compare reconciler sees permanent drift on these versions. Detect and skip rather than fight it |
| **7.18** | `*) firewall - fixed incorrectly inverted hotspot value configuration;` | The DoT/DoH rules use `hotspot=!auth`; below this the inversion could be wrong |
| **7.21** | `*) firewall - fixed hotspot value loss on rule enable/disable;` | **Directly dangerous:** on <7.21, toggling a rule's `disabled` flag silently drops its `hotspot=` matcher — turning `hotspot=!auth protocol=udp dst-port=853 action=drop` into a rule that drops DoT for *everyone*, authenticated guests included. Any adapter that disables/re-enables rules as part of applying a change must not do so on <7.21 |
| **7.21 / 7.22** | `/ip hotspot user` `totp-secret` renamed to `otp-secret`, gains `sensitive` flag | Changes export output; not used today but will bite anyone reading hotspot users |
| **7.23** | `/file/copy`, `/head`, `/tail` added | The lab router has them; 7.22 routers do not |

---

## 5. Things this document could not settle from documentation

Stated plainly rather than inferred. Each has the exact test that settles it
in §7. Three questions that were open in the first draft of this document
turned out to be **answered** by the CLI reference and the changelogs, and
are recorded under §5.1 so nobody re-opens them.

1. **The effect of a live `set` on a running hotspot — entirely unsettled,
   and the largest open risk here.** Checked exhaustively: the hotspot prose
   pages contain zero occurrences of "restart", "re-init", "reinit" or
   "flush"; every hotspot CLI reference page is a bare type dump with no
   behavioural prose; a Confluence full-text search for
   `text ~ "hotspot restarted"` returns 0 results; and no entry in any of the
   83 RouterOS 7 changelogs states that a config change restarts the service
   or clears sessions. The docs *do* tie the dynamic rule set to "activating
   a HotSpot service" and put hosts and active users in the same dynamic
   category — but never say what re-triggers activation. **This is absence of
   documentation, not documentation of absence.** → **T-P3**

   Two changelog entries circle it without answering: `7.6` —
   *"fixed service initialization when HTML directory configured on an
   external disk"* (a distinct init step exists, coupled to
   `html-directory`); `7.21` — *"prevent service from starting unnecessarily
   in the background on export/print commands"* (the service can be started
   as a side effect of a *read*, and MikroTik treats that as a bug).

   *Forum, not official docs, corroboration only:* one thread reports the log
   line `host removed: ip binding changed`, i.e. at least one hotspot config
   change demonstrably removes hosts; another recommends removing individual
   `/ip hotspot host` rows rather than restarting the service because
   restarting *"could affect signups"*. Neither is a basis for a design.

2. **Whether `html-directory` naming a non-existent directory errors at
   set-time, is accepted silently, or falls back.** No statement anywhere —
   prose, CLI reference, or changelog. Note the contrast with
   `html-directory-override`, which *does* have documented fallback
   semantics: it is availability-tracked (*"hotspot will switch to this html
   path as soon as it becomes available and switch back to html-directory
   path if override path becomes non-available"*), and *"if the value path is
   missing or empty then the hotspot server will revert to default HTML
   files"*. The plain property has no such guarantee. The only nearby
   documented behaviour is per-page: *"If it is not possible to meet a
   request using the pages stored on the router's FTP server, Error 404 is
   displayed"*. → **T-P1**

3. **Whether the hotspot's port-64872 DNS service consults `/ip dns
   static`.** The interception itself is now fully settled (§5.1), but this
   is not, and it is the consequential half: **if it does not, content
   filtering has never worked for hotspot guests on any router in this
   fleet.** → **T-D1**

4. **`servers` vs `dynamic-servers` in practice.** The DNS page says static
   is preferred *but explicitly qualifies that it is not always used*, and
   describes a sticky-server selection that survives config changes. The DHCP
   page says `use-peer-dns` *"will override the settings put in the /ip dns
   submenu"*. The two official pages disagree, and the qualification means
   even the winning one does not promise determinism. → **T-D2**

5. **`hotspot-address=0.0.0.0`.** The complete documented text of this
   property is five words — *"IP address of HotSpot service"*. What the zero
   value means is explained nowhere, in any version, and the lab router's
   unused `default` profile sits on it. Setting it explicitly sidesteps the
   question, which is what both the script and `_ensure_hotspot_profile`
   already do.

6. **`/ip hotspot reset-html` — arguments, target directory, and overwrite
   behaviour.** The CLI reference page's entire body is `Type: Command`, with
   no argument table. The only prose sentence about it anywhere is the RFC
   7710 note. The RouterOS 6 wiki never documented it either. It is the
   documented remedy for a missing `api.json`, so it must write defaults
   somewhere — but where is unstated. **Treat as destructive; never run it
   against a customised directory without a backup.**

7. **Whether `/tool fetch` or SFTP create missing intermediate directories,
   whether RouterOS's SFTP server implements `mkdir`, and whether SCP is
   supported at all.** Only `/file add … type=directory` is documented.

8. **Whether `name=` and `regexp=` may coexist on one `/ip dns static`
   entry.** v6 had one auto-classified field with an `R` flag; v7 shows two
   separate columns and no `R` flag, and states no exclusivity rule. The
   adapter's own comment asserts exclusivity; that assertion is unsourced.
   Write one, never both.

9. **How the walled garden extracts a hostname from an HTTPS flow** (SNI vs
   `CONNECT`), and therefore whether `path=` means anything for HTTPS. Does
   not need settling — push both menus (§2.2.2) — but recorded so nobody
   "simplifies" it away.

### 5.1 Questions the documentation did settle, against the code

Recorded so they are not re-opened, and because in each case the code
currently says otherwise:

* **Hotspot DNS interception is documented, and it is total.** Dynamic NAT
  rules 2 and 3 redirect all TCP and UDP port-53 traffic from every hotspot
  client to port 64872, with **no `hotspot=!auth` matcher** — authenticated
  clients included. A client's configured resolver is overwritten. The
  supported override hook is the `pre-hotspot` chain. (§3.3)
* **`dns-name` auto-creates its own DNS answer** — *"This name will
  automatically be added as a static DNS entry in the DNS cache"* — so
  `_ensure_dns_static`'s paired row is redundant, and `renderers.py`'s module
  docstring asserts the opposite of the documentation. (§2.2.5)
* **`https-redirect` was deleted in 7.5** and unauthenticated HTTPS is now
  rejected unconditionally. Both prose sites still document the removed
  property. (§2.3)

## 6. The verification discipline these designs inherit

Derived from the three places this repo records it, pending the colleague's
`BRIDGE_VLAN_FILTERING.md`:

1. **A guarded command that does not fire is indistinguishable from one that
   succeeded.** Every `:if ([:len [find …]] = 0) do={ add }` and every
   `set [find …]` against an empty match returns success. Count first, act,
   and report the count either way. This is stated as the cause of six
   separate silent failures in `RouterDetailTabs.tsx` alone.
2. **Verify by re-reading the device, never by trusting the variables you
   just wrote.** The setup script's verdict lines deliberately re-query both
   walled-garden tables rather than carry `$portalIp`/`$pgOk` across the
   line boundary.
3. **The verdict must be able to fail.** A check that counts *entries*
   would have printed PASS at "huda city center" while no guest on that
   network could load the portal. Assert the property that matters
   (address-based row present), not the property that is easy to count.
4. **"Confirmed live this session" is the bar for shipping a command shape,
   and anything below it is labelled.** `renderers.py` labels its own
   unconfirmed sections; so does this document.
5. **Named checks with `PASS`/`WARNING`/`ERROR`, not booleans.**
   `final_verification.py`'s shape, so results are comparable across
   features.

---

## 7. Hardware tests, in priority order

Run on the lab hEX lite. Each is written so the answer is unambiguous.

**T-P3 — does a profile edit drop sessions?** *(highest value; gates §2.3)*
```
/ip hotspot active print count-only          # note N
/ip hotspot host print count-only            # note M
/ip hotspot profile set [find name=hsprof1] dns-name="wifi.wyfyguest.com"   # same value
/ip hotspot active print count-only          # still N?
/ip hotspot profile set [find name=hsprof1] dns-name="test.wyfyguest.com"   # changed value
/ip hotspot active print count-only          # still N?
/ip hotspot profile set [find name=hsprof1] dns-name="wifi.wyfyguest.com"   # restore
```
With at least one real device associated and authenticated. Repeat for
`login-by` and `html-directory` separately — they may not behave alike, and
the `7.6` changelog specifically couples `html-directory` to service
initialization. Also diff `/ip firewall nat print dynamic` and
`/ip firewall filter print dynamic` before and after: if the dynamic rule set
is torn down and rebuilt, the service re-activated, and hosts are documented
as belonging to the same dynamic category. Watch `/log print` for re-init
lines and for `host removed: …`.

**T-P1 — `html-directory` normalization and a missing directory.**
```
/ip hotspot profile get [find name=hsprof1] html-directory     # expect flash/hotspot
/ip hotspot profile set [find name=hsprof1] html-directory=hotspot
/ip hotspot profile get [find name=hsprof1] html-directory     # normalized back to flash/hotspot?
/ip hotspot profile set [find name=hsprof1] html-directory=cloudguest-hotspot
```
Does the last line error, or succeed? If it succeeds, connect a guest and
record what is served. Also read `html-directory-override` — if it is
non-empty, `html-directory` is not what is being served at all.
**Restore to the original value immediately.**

**T-P2 — confirm the auto-created `dns-name` entry, so the redundant static
row can be retired.** The documentation says RouterOS adds it; this confirms
it on the device and shows whether it is flagged dynamic.
```
/ip dns static print detail where name~"wifi.wyfyguest.com"   # D flag on any row?
/ip dns cache print where name~"wifi.wyfyguest.com"
/ip hotspot print detail                                       # read ip-of-dns-name
```
Then, from a connected unauthenticated client, `nslookup wifi.wyfyguest.com`
→ `10.5.50.1`? Then disable (do not delete) any platform-written static row,
flush the cache, repeat the lookup, and restore. Also check
`/ip hotspot walled-garden print` for a dynamic row RouterOS added itself.

**T-D1 — does the hotspot's DNS service consult `/ip dns static`?**
*(interception itself is documented, §5.1 — this tests the consequential
half.)* First confirm the rules are present:
```
/ip firewall nat print dynamic where chain=hotspot
```
Expect the two `action=redirect to-ports=64872 dst-port=53` rows, and
confirm neither carries `hotspot=!auth`. Then, from a connected client with
its resolver hardcoded to `1.1.1.1`:
```
nslookup wifi.wyfyguest.com 1.1.1.1
nslookup <a domain that has a content-filter sinkhole row> 1.1.1.1
```
The first should return `10.5.50.1` despite the client asking Cloudflare —
that is the redirect working. **The second is the one that matters:** if it
returns `127.0.0.1`, the hotspot's resolver reads `/ip dns static` and
content filtering works. If it returns the real address, **content filtering
has never worked for hotspot guests**, which is a fleet-wide finding, not a
lab curiosity. Repeat both after authenticating — per the docs the answers
should be identical, since the DNS redirect has no `!auth` matcher.

**T-D2 — `servers` vs `dynamic-servers` precedence.**
```
/ip dns set servers=9.9.9.9
/ip dns print                                # dynamic-servers still 192.168.1.1
/ip dns cache flush
```
Then resolve a name with a known distinct answer per resolver (or packet-
capture on `ether1`) and see which upstream was used — the DNS page predicts
`9.9.9.9`, the DHCP page predicts `192.168.1.1`. Then
`/ip dhcp-client release [find interface=ether1]` to force a re-lease and
confirm `servers=9.9.9.9` survived. **Restore `servers=8.8.8.8`.**

**T-D3 — walled-garden ip availability.**
```
/ip hotspot walled-garden ip print
/ip hotspot walled-garden ip add action=accept dst-address=1.2.3.4 comment=probe
/ip hotspot walled-garden ip remove [find comment=probe]
```

---

## 8. Summary of changes this design depends on

Not part of the two adapters, but blocking them:

1. `HOTSPOT_HTML_DIRECTORY` in `network_config/renderers.py:713` →
   `"hotspot"`. Today's value names a directory nothing creates.
2. `_portal_walled_garden_hosts` must include the real portal host
   (`auth.wyfyguest.com`, not just `wifi.wyfyguest.com` and the API host),
   and `render_hotspot_walled_garden` must emit `/ip hotspot walled-garden
   ip` rows alongside the host-based ones.
3. `read_only_reader.READ_ONLY_SECTION_PATHS` needs `("ip","dns","static")`
   and a `/file` listing section, or neither feature can reconcile.
4. `collect_dns_config` should also collect the WAN DHCP client's
   `use-peer-dns`.
5. Both screens need the DHCP screen's `device_push_status` /
   `device_push_error` / `device_pushed_at` + `DevicePushBadge` + explicit
   Apply, rather than pushing on save.
6. The DNS screen's nav label, its `portal.hotel.local` placeholder, and its
   delete confirmation copy all currently describe something the feature
   does not do.
7. **`render_dhcp_pool` must default `dns-server=` to the pool's own
   gateway.** Today it omits the parameter when both `dns_primary` and
   `dns_secondary` are blank, and RouterOS's documented fallback then hands
   guests the *upstream* resolvers — silently disabling content filtering
   and every local name on that pool. This is the highest-severity item on
   this list and it is not hypothetical: those two fields are optional and
   blank by default on the customer DHCP screen. (§3.3(ii))
8. **`_ensure_hotspot_profile` must write `login-by`.** RouterOS defaults a
   new profile to `http-chap,cookie`; the platform's form POST needs
   `http-pap`. Every `vlan{id}-hsprof` created by `configure_vlan_hotspot`
   today is on the default and cannot authenticate a guest. (§2.3)
9. **`renderers.py`'s `dns-name` module-docstring section asserts the
   opposite of MikroTik's documentation** and should be corrected whichever
   way T-P2 lands. (§2.2.5)
10. **Any adapter that changes `/ip dns servers` must follow with
    `/ip dns cache flush`**, or the sticky-server selection keeps the old
    upstream indefinitely. (§3.4)
11. **No adapter may disable/re-enable a firewall rule carrying a
    `hotspot=` matcher on RouterOS < 7.21** — the matcher is silently lost,
    which converts the DoT/DoH rules from unauthenticated-only into
    everyone. (§4)

---

## 9. Documentation defects found while writing this

Recorded because a design that transcribes them ships them. All are in
MikroTik's own prose (both the frozen and the current site); the CLI
reference and the changelogs are correct in each case.

| Defect | Reality |
|---|---|
| `https-redirect` documented as a live `/ip hotspot profile` property | **Removed in 7.5.** Emitting it is a hard error |
| `trial-uptime` documented as one composite `time/time` | CLI has the pair `trial-uptime-limit` + `trial-uptime-reset` |
| `mac-auth-mode` (`mac-as-username` \| `mac-as-username-and-password`) | Exists in the CLI, documented **nowhere** — not v7 prose, not the v6 wiki |
| `radius-location-id` | Exists in the CLI, in **no** prose table |
| `radius-location-name` described as *"RADIUS-Location-Id to be sent…"* | The description belongs to the other property |
| `nas-port-type` typed `(string)` | Closed 3-value enum: `ethernet:15`, `cable:17`, `wireless-802.11:19` |
| `/ip dns static` `disabled` documented as `Default: yes` | It is `no` |
| `/ip dns` `dynamic-servers` called `dynamic-server` (singular) | Property is plural, and read-only |
| Hotspot customisation page spells it `html-override-directory` | Real name is `html-directory-override`. **Do not copy that string into code** |
| `/ip dhcp-server network dns-server` documented as max two | CLI types it as an unbounded list. Design to two — that is the documented guarantee |
| `use-peer-dns` prose (*"will override /ip dns"*) vs DNS page (*"static preferred"*) | The two official pages contradict each other (§3.4) |
| Walled-garden prose says the host menu covers *"HTTP and HTTPs"* | Contradicted by two live hit-counter observations; 7.5's unconditional HTTPS rejection is the likely reconciliation (§2.2.2) |
