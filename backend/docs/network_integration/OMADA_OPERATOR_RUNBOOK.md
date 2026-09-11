# Omada Operator Runbook

How to put a venue that already runs **TP-Link Omada** WiFi onto Wyfy Guest, and how
to work out what went wrong when a guest signs in and still has no internet.

**Written for:** the platform staff member onboarding the controller, and the support
engineer answering "the WiFi didn't work". Not a developer document. The code and
PR history are cited so every step can be checked, but you do not need to read them.

**Status, stated plainly:** everything below comes from the merged code and the PRs
that built it (cloud-guest #203 #204 #206 #209 #210 #211 #212 #214 #218 #221,
cloudguest-foundation #251 #253 #254 #256 #257 #258 #259 #264). Several steps were
measured on real controllers. **No real guest device has yet been let onto the
internet end to end through this integration.** Read §1 before promising a venue a
go-live date.

---

## 1. What has and has not been proven on real hardware

| Claim | Status | Where it was shown |
|---|---|---|
| Our servers can sign in to a controller as a hotspot operator and read its version | **Verified** on a self-hosted Omada Software Controller 5.15.24.19 and a TP-Link cloud controller 6.3.0.100 | #210, #212 |
| The portal URL we generate is accepted, and the controller *appends* its own parameters to it with `&` | **Measured** on hardware | #211 |
| Guests hang forever without a Pre-Authentication Access entry for our portal host | **Measured** on hardware | #256 |
| The guest's first hop is the controller's own portal page on port 8088 | **Measured** on hardware | #211, #256 |
| Our authorize call reaches the controller with a valid session | **Verified** on 5.15 and 6.3, using a made-up MAC, which the controller refuses with `-41501` | #218 |
| **A real guest phone gets internet after signing in** | **Not verified. Never done.** "`-41501` proves the route and the session, not that a guest gets internet." | #210 |
| The authorization's `time` is a duration in milliseconds, not an expiry date | **Inferred** from TP-Link's sample code, not stated anywhere by TP-Link | `vendor/wyfy-device-gateway/wyfy_device_gateway/omada/portal.py` |
| The redirect's `site=` value is Omada's site id rather than its display name | **Unverified** | `app/domains/network_integration/providers/omada.py` |
| `clientIp` is accepted on firmware v6.2.10+ | Sent whenever the controller supplies it; **not verified with a real client** | #206, #254 |
| Ending one guest's access early | **Observed** on 5.15.24.19 only, against authorizations created by hand. **Not tried on 6.x.** Not tried with a site *name* in place of a site id | #214, `omada/deauth.py` |
| Pinning a self-signed controller certificate | **Verified** on 5.15.24.19 | #212 |
| **Configure controller automatically** (§12): portal, Pre-Authentication Access, operator account written over the Open API | **Not verified on hardware.** Every path and field comes from the OpenAPI document the 5.15.24.19 controller serves about itself, and the operations exist there; no write has been sent to a real controller yet | §12.7 |

The first real venue is also the first end-to-end test. Plan to be on site or on a
call with a phone on the guest WiFi (§8).

---

## 2. Known defects that change the procedure

These are not configuration mistakes. They are gaps in the product today, and the
steps below work around them. Each should be fixed; until then, follow the workaround.

1. **"Open API" sign-in cannot let any guest online.** Guest authorization uses the
   controller's hotspot operator login in *both* modes
   (`omada/adapter.py`, `authorize_guest`), but the backend refuses to store an
   operator name and password on an Open API integration
   (`validators.validate_auth_mode_credentials`). An Open API integration therefore
   answers every guest with `OMADA_API_UNSUPPORTED`. The dashboard nevertheless marks
   Open API **Recommended** and says "guest sign-in is enforced".
   **Workaround: always choose the hotspot operator account** (labelled
   *Hotspot operator* in the admin wizard and *Hotspot operator account* on the
   customer page). You lose the Access points and Connected clients screens; guest
   sign-in is what matters.
   *Update:* the backend now stores an operator login next to an Open API app,
   and automatic configuration (§12) creates that operator itself. Once §12 has
   been verified on hardware, an Open API app plus §12 replaces this workaround.
2. **An integration created from the customer page can never produce a portal link.**
   Guests need a fleet record ("router" row) for their session. Only the platform
   onboarding path creates one (`POST /network-integrations/platform/onboard`). The
   customer page's **Add integration** leaves the `fleet_device_missing` gap, and the
   page says "Guests cannot sign in at this venue yet".
   **Workaround: onboard from the admin Routers page (§4)**, not from the customer page.
3. **No dashboard form sets certificate trust or the Omada ID.** `tls_mode`,
   `tls_pinned_sha256` and `controller_id` exist on the API only (#210, #212). A
   self-hosted controller, which almost always has a self-signed certificate, and a
   TP-Link cloud controller both need them.
   **Workaround: platform staff set them through the API (§5).**
4. **The activity tab does not show the failure record.** The diagnostics bundle
   (§9) is stored on the event, but the dashboard's Activity table shows only the
   code and message. **Workaround: read it through the API or the database (§9.1).**
5. **The admin onboarding wizard sends you to a screen with no site picker.** Its
   final step says "Go to Integrations", which opens the Network Integrations list in
   the Master console. That list has no site or SSID fields.
   **Workaround: finish the mapping on the venue's own Network Integrations page (§6).**
6. The dashboard has no wording for `OMADA_TLS_UNTRUSTED` or `OMADA_TLS_PIN_MISMATCH`,
   so it shows the backend's own sentence instead. That sentence is accurate; it just
   points at a pinning control the dashboard does not have (see item 3).

---

## 3. Before you start

| Requirement | Why |
|---|---|
| Controller firmware **5.0.15 or newer** | The oldest version the integration accepts (`MIN_SUPPORTED_VERSION` in `omada/adapter.py`). Open API features need 5.13, but see §2 item 1. |
| The controller is reachable **from the internet over HTTPS**, on port **443, 8043, 8088 or 8843** | Our servers make the calls, not the operator's browser. Other ports are refused (`DEFAULT_CONTROLLER_PORTS`). Addresses that resolve to private ranges are refused in every shared environment. Software controllers usually listen on 8043; hardware controllers (OC200/OC300) on 443. |
| A **hotspot operator account** on the controller | This is the credential that authorizes guests. It is a separate account created in the controller's **Hotspot Manager**, not a controller admin login. TP-Link's doc 13080 says to use the operator's credentials "rather than the account and password for the controller account". |
| For a **self-hosted** controller: its certificate fingerprint (captured in §5) | Self-hosted controllers present a self-signed certificate (`CN=localhost`, issued by itself), which the default `strict` check refuses. |
| For a **TP-Link cloud** controller: its **Omada ID** | One cloud address fronts every controller in a region, so the controller cannot be identified without it (#210). TP-Link shows it on the credentials screen and in the controller's web address. |
| The venue already exists in Wyfy Guest | The controller is mapped to a venue (location). |
| Platform staff access with the global `network_integrations.create` permission | Required by the onboarding endpoint. |

---

## 4. Onboard the controller (platform staff)

Admin dashboard → **Routers** → **Add router**.

1. **Device type:** choose **TP-Link Omada controller**.
2. **Controller** (identity & venue):
   * **Controller name**: anything recognisable, for example "Lobby Controller".
   * **Controller model**.
   * **Serial number (hardware only)** and **MAC address (hardware only)**: for an
     OC200/OC300, copy both from the label. For a software controller, leave **both**
     blank and an identifier is generated. Enter both or neither.
   * **Location**: the venue.
3. **Connection** (address & credentials):
   * **Controller address**: for example `https://controller.example.com:8043`. Scheme
     and host only, no path.
   * **Authentication**: choose **Hotspot operator** (see §2 item 1).
   * **Operator name** / **Operator password**: the hotspot operator account.
4. **Connect controller**.

You should see "*name* is registered", along with "One step left before guests can
get online." The integration now holds credentials but authorizes nobody until §6 is
done.

If the controller is self-hosted or cloud-managed, do §5 **before** §6.

---

## 5. Certificate trust and Omada ID (API only for now)

Skip this section for a controller with a certificate from a public certificate
authority that is reached directly.

### 5.1 Choose a certificate mode

| Mode | What it does | Use it for |
|---|---|---|
| `strict` (default) | Ordinary public-CA verification | A controller with a real certificate |
| `pinned` | The certificate must match a SHA-256 fingerprint we recorded | **A self-hosted controller. This is the intended answer.** |
| `insecure` | No check at all, recorded as a decision | Only a controller behind something that reissues its certificate constantly |

Symptoms that tell you which one you need:

* `OMADA_TLS_UNTRUSTED`: "The Omada controller answered, but its HTTPS certificate is
  not trusted by this platform … The URL and port are fine." Pin it.
* `OMADA_TLS_PIN_MISMATCH`: the certificate changed since it was pinned. **Do not
  re-pin blindly.** Find out why it changed first (controller reinstalled? certificate
  renewed?). Of all the errors, this is the one that can mean somebody is in the
  middle.

### 5.2 Capture the fingerprint

Run a connection test. The response carries the certificate the controller is really
presenting, **on failure as well as success**: `tls_fingerprint_sha256`,
`tls_chain_trusted`, `tls_certificate_subject`, `tls_certificate_issuer` and
`tls_certificate_expires_at`.

* Existing integration (platform scope):
  `POST /api/v1/network-integrations/platform/integrations/{integration_id}/test-connection`
* Before saving anything, as a draft probe (organization scope, with an
  `X-Organization-ID` header):
  `POST /api/v1/network-integrations/test-connection` with `base_url`,
  `auth_mode: "legacy"`, `username`, `password` and optionally `controller_id`.

Confirm the fingerprint with whoever runs the controller before trusting it.

### 5.3 Save it

`PATCH /api/v1/network-integrations/{integration_id}` (organization scope, with
`X-Organization-ID`):

```json
{ "tls_mode": "pinned", "tls_pinned_sha256": "<64 hex characters; colons and spaces are accepted>" }
```

For a cloud controller, send `"controller_id": "<Omada ID>"` in the same request.
`POST /api/v1/network-integrations/platform/onboard` accepts all three fields too, so
next time they can be set at onboarding.

`pinned` without a fingerprint is refused; it never quietly falls back to `insecure`.

---

## 6. Map the site, venue and guest network

The venue's dashboard → **Network Integrations**. A half-configured integration shows
a red banner. Press **Finish setup**.

With a hotspot operator account the controller cannot be asked for its sites or
networks, so both are typed by hand:

1. **Omada site**, in the **Site** field: it must match the site **exactly as Omada
   spells it**. The reliable source is the `site=` value in the phone's address bar
   when the sign-in page appears. Most single-site controllers use `Default`. That
   address only exists once §7 is done, so if you are unsure, enter `Default` now and
   check it during the test in §8. A mismatch is refused before the controller is
   called and is recorded as `OMADA_SITE_NOT_FOUND`.
2. **Wyfy Guest venue:** choose it under **Select a venue…**.
3. **Guest network**, in the **Guest SSID** field: it must match the `ssidName=` value
   on the same sign-in address.
4. **Save.** The confirmation reads "Controller connected. Guest logins will be
   enforced on it from now on."

**Guest session length** defaults to 1 hour. The maximum is 7 days (the platform owner
set it on 2026-09-11, `MAX_SESSION_DURATION_SECONDS`).

---

## 7. Configure the controller

Once §6 is done, the integration's detail card shows an **Omada portal configuration**
panel. If it instead says "Guests cannot sign in at this venue yet", it names what is
still missing: credentials, venue, site or fleet device (see §2 item 2).

Guests cannot sign in until **both** steps below are done.

### 7.1 External Portal Server

On the controller: **Site View → Network Config → Authentication → Portal →** your
portal **→ Authentication Type: External Portal Server → Host Type: URL**.

These are two **separate** fields. Copy each from our panel:

* **Scheme**: `https`
* **URL**: the host and query, **without** `https://`. It looks like
  `auth.wyfyguest.com/portal?organizationId=…&locationId=…&routerId=…&netProvider=omada`.
  The controller rejects a value that includes the scheme, and it needs the `/portal`
  segment.

The panel's **Full link** is for opening in a browser to check it. **Do not paste it
into the controller.**

### 7.2 Pre-Authentication Access

This is the step that is easiest to miss and hardest to diagnose.

On the controller: **Settings → Authentication → Portal → Access Control →
Pre-Authentication Access**. Turn it on and add **one entry of type URL** with the
host from our panel (**Pre-authentication URL**, which is `auth.wyfyguest.com`).

Why it matters: this was measured from a real unauthorized phone. DNS resolves, the
connection opens, and then **every HTTPS request times out**, our portal included.
Omada does not automatically allow the external portal it is itself redirecting to.
The phone just shows a blank page for about 20 seconds, and nothing on the controller
reports a problem.

A URL entry allows the **address** the name resolves to, not the name. Today one entry
also covers the API the sign-in page calls, because both names point at the same
address. If those names are ever moved apart, this entry stops being enough: the page
will load and then hang.

### 7.3 Controller reachability for guests

The access point's first redirect sends the phone to the **controller's own portal
page on port 8088** (8843 if HTTPS Redirect is on), not to us. Guest devices must be
able to reach the controller on that port, or the sign-in page never appears. Our own
cloud security group once had this port closed (#211). If the controller is in the
cloud, check its firewall and security group.

---

## 8. Test with a real phone

Do this at every new venue. As §1 says, it is also the first time the full path
runs for real.

1. Join the guest SSID on a phone that is **not** already authorized.
2. The Wyfy Guest sign-in page should appear within a few seconds.
   * Blank page, then a timeout: §7.2 (Pre-Authentication Access).
   * The page never starts loading at all: §7.3 (port 8088).
3. Before signing in, read the address bar and compare `site=` and `ssidName=` with
   §6. Correct them if they differ.
4. Sign in (OTP or voucher). The phone should reach the internet.
5. On **Network Integrations → Activity**, the latest `portal authorize` row should
   say **OK**.
6. If the guest signed in but has no internet, the row says **Failed**. Go to §9.
7. Once it works, try **ending access** (§10) on the test phone and confirm it loses
   internet. This step matters most on 6.x firmware, where ending access has never
   been tried.

---

## 9. When a guest signed in but has no internet

What you will usually see is `OMADA_AUTHORIZATION_FAILED`: "The controller refused to
let that guest online. Their sign-in worked; the network step did not."

### 9.1 Why the error message cannot tell you more

The controller answers almost every rejected authorization with one catch-all code:

| Raw code | Meaning | Note |
|---|---|---|
| `-41500` | "Invalid authentication type." Only a bad `authType` produces it. | **Does not exist on 5.15.** There, the same fault returns `-1 "General error."` Do not rely on it. |
| `-41501` | "Failed to authenticate." A catch-all. | A wrong MAC, a stale timestamp, the wrong site, an access point that never saw the client, a missing field and an unacceptable `clientIp` all produce this same code. |

No message we write can be more specific than that. Instead, every **failed**
authorization stores a record you can diff afterwards, without asking the guest to
come back. Successful ones do not store it
(`PORTAL_AUTHORIZE_DIAGNOSTICS_ON_SUCCESS = False`).

### 9.2 Get the record

* **API:** `GET /api/v1/network-integrations/{integration_id}/events` (organization
  scope). Look at failed `portal_authorize` events. The record is at
  `context.authorize_diagnostics`.
* **Database:**

  ```sql
  SELECT created_at, error_code, context -> 'authorize_diagnostics'
  FROM network_integration_events
  WHERE integration_id = '<id>'
    AND context ? 'authorize_diagnostics'
  ORDER BY created_at DESC
  LIMIT 20;
  ```

### 9.3 Read it

It has four parts. The whole job is to compare **what the controller sent the guest
with** against **what we sent the controller**.

| Part | What it holds |
|---|---|
| `redirect` | The parameters the controller put on the guest's redirect: `client_mac`, `site`, `ap_mac`, `ssid_name`, `radio_id`, `gateway_mac`, `vid`, `t`, and a summary of `redirect_url` (origin, path and parameter *names* only). |
| `request.body` | The **exact** body sent to the controller, in TP-Link's own field names. It is produced by the same function that made the request, so it is what was sent, not a copy. If the controller supplied `clientIp`, it appears here. |
| `request.fields` | The sorted list of fields sent. This is where a **missing** field shows up. |
| `precall` | Checks we could make from our own data before calling (below). |
| `controller.provider_code` | The raw vendor code, for example `-41501`. |

What each `precall` field tells you:

* **`redirect_shape`**
  * `ap` or `gateway`: normal.
  * `neither`: no device fields arrived, which is a guaranteed failure. Look at the
    controller's portal configuration.
  * `ambiguous`: both shapes arrived. We send the gateway fields and drop the AP ones,
    which you would otherwise never see.
  * `ap-partial` or `gateway-partial`: one field is missing. This is a strong suspect.
* **`site_matched_by`**
  * `id`: normal.
  * `name`: the site check passed on the display name, so the body carries a name
    where the controller may want a key. Suspect this first on a `-41501`, and consider
    changing the stored site to the value in `redirect.site`.
  * `none`: see the site mismatch below.
* **`client_mac_wire_format`** and **`client_mac_rewritten_for_wire`**: Omada
  redirects with dashes (`AA-BB-CC-DD-EE-FF`), while we store colons. `true` means the
  controller was sent a different spelling from the one it gave us. This has been
  harmless on every firmware tested so far, but it is worth noting on an unexplained
  `-41501`.
* **`t_age_seconds`** and **`t_stale`**: how old the redirect's timestamp was.
  * `t_stale: true` (older than 15 minutes) usually means the guest reopened the
    sign-in page from browser history. Ask them to rejoin the WiFi and start fresh.
  * `null` means we could not tell, which is not the same as fresh.
* **`requested_duration_seconds`**: the session length we asked for.

Nothing in `precall` blocks a guest. These checks describe; they never refuse.

### 9.4 Other failures you may see

| Code | Meaning | What to do |
|---|---|---|
| `OMADA_SITE_NOT_FOUND` (at authorize time) | The redirect's `site` did not match the stored site, so the controller was never called | Correct the site (§6) to the value on the redirect. |
| `OMADA_API_UNSUPPORTED` | The integration has no hotspot operator credentials. That covers every Open API integration (§2 item 1). | Switch to a hotspot operator account. |
| `OMADA_AUTH_FAILED` | The controller rejected the stored operator login | **Replace credentials** on the integration. Check that the account is an operator, not an admin. |
| `OMADA_CONNECTION_FAILED` / `OMADA_TIMEOUT` | We could not reach the controller | Power, address, port, and internet reachability. |
| `OMADA_TLS_UNTRUSTED` / `OMADA_TLS_PIN_MISMATCH` | Certificate trust | §5. |

---

## 10. Ending one guest's access

Venue dashboard → **Guests** → the live sessions table → the row's menu → **End access
on controller**. The item appears only when the venue has an Omada controller **and**
we know the device's MAC. You can add a reason (**Reason (optional)**). Staff see it;
the guest never does.

The result keeps three facts separate:

* **`disconnected`**: the only one that means the device stopped getting internet. If
  it is not confirmed, "Treat the guest as still online, and try again."
* **`had_active_authorization: false`**: normal. The grant had already expired on its
  own.
* **`guest_session_ended`**: whether our own session record was closed at the same
  time.

What to know:

* **It is not a ban.** The guest can open the portal and sign in again. Permanent
  blocking is not built.
* It needs a **hotspot operator account**. Without one: "This controller connection
  can't end a guest's access."
* The endpoints behind it are **observed**, not documented by TP-Link, and were
  checked on 5.15.24.19 only. If TP-Link moves them, the attempt fails loudly (`-1600
  "Unsupported request path."`) rather than claiming success.
* It sends the controller the **site id stored in §6**. It was tested with a real site
  id. With a site *name* typed in its place (for example `Default`), it has **not**
  been tried. Test it at the first such venue (§8, step 7).

API: `POST /api/v1/network-integrations/{integration_id}/clients/disconnect` with
`{"client_mac": "…", "reason": "…"}`, permission `network_integrations.update`.

---

## 11. Credentials and security, for the record

* Controller credentials are encrypted with the platform's own
  `CLOUDGUEST_NETWORK_INTEGRATION_ENCRYPTION_KEY`. No endpoint ever returns them and
  they are never logged. **Replace credentials** is the only way to change them,
  because nothing can read them back.
* Controller addresses are checked against SSRF rules when saved and again before
  every call.
* The failure record in §9 stores the guest's MAC, which is already stored elsewhere
  for the same attempt. There is no retention sweep on `network_integration_events`
  yet; that is an open decision.

---

## 12. Automatic configuration ("Configure controller automatically")

**Status: built and unit-tested against mocked HTTP; not yet run against a real
controller.** Follow §12.7 on our own EC2 controller before offering it to a
venue, and keep §7 as the fallback until then.

### 12.1 What it does

One request replaces §7.1, §7.2 and the operator account from §3, through the
controller's **Open API** (not the operator login):

| Step (`step`) | What it makes true | Idempotent how |
|---|---|---|
| `portal` | An **External Portal Server** portal (host type URL, scheme `https`) whose URL is exactly the one on the integration card, bound to the integration's guest SSID. Named `Wyfy Guest - <venue> (<first 8 hex of the integration id>)`. | Created if absent, patched if it drifted (name, enabled, auth type, host type, scheme, URL, SSID binding), otherwise `unchanged`. HTTPS redirect, landing page and timeout are the venue's to tune and are not treated as drift. |
| `pre_auth_access` | Pre-Authentication Access switched on with a URL entry for the portal host (`auth.wyfyguest.com`). | **Merge-only.** The controller's own settings are read and sent back with our entry appended; every existing entry is kept verbatim, nothing is ever removed. If it was switched off, the report says that switching it on also activates the entries already in the list. |
| `hotspot_operator` | An operator account for guest authorization. | If the integration holds no operator login: creates `wyfy-<first 12 hex of the integration id>` with a random password (Python `secrets`), stores it encrypted with the other controller credentials, and proves it signs in. If one is stored: proves it signs in and **never changes it**. |
| `ssid_takeover` | Only with `take_over_ssid_portal: true`: removes the guest SSID from a portal this integration did not create. | That portal is otherwise sent back exactly as the controller returned it. It is never deleted. |

**How "our" portal is recognised.** By its exact name, *or* by its URL: host
`auth.wyfyguest.com` and a `routerId=` query value equal to this integration's
fleet device id. The name carries the integration's id prefix and the `routerId`
is unique per integration, so two locations of one customer on one site can never
claim each other's portal, and a portal a venue renamed is still recognised. No
other portal is ever written, except in take-over as above.

**Refusals (HTTP 409, nothing changed on the controller or in our database):**

| `data.code` | Meaning |
|---|---|
| `NETWORK_INTEGRATION_AUTOCONFIG_PRECONDITIONS` | Something the run needs is missing. `data.missing` lists all of them: `integration_disabled`, `provider_unsupported`, `openapi_required`, `credentials_missing`, `location_not_mapped`, `site_not_selected`, `fleet_device_missing`, `guest_ssid_missing`. |
| `NETWORK_INTEGRATION_PORTAL_CONFLICT` | The guest SSID is bound to a portal we did not create. `data.portal_name` / `data.portal_id` name it. Remove the SSID from it on the controller, or run again with `take_over_ssid_portal: true`. |
| `NETWORK_INTEGRATION_CONTROLLER_SITE_SHARED` | Another customer account has an integration on the same controller and site. Neither may automate it; the other account is not named. |
| `NETWORK_INTEGRATION_GUEST_SSID_IN_USE` | Another location in the same organization already uses this SSID on this site. Each location needs its own guest SSID. |
| `NETWORK_INTEGRATION_GUEST_SSID_NOT_FOUND` / `..._AMBIGUOUS` | The stored SSID does not exist on the site, or its name matches SSIDs in two WLAN groups. |

Controller failures before anything is written keep their usual codes
(`OMADA_AUTH_FAILED`, `OMADA_TLS_*`, ...). New: `OMADA_PERMISSION_DENIED`, the
controller's `-1005 Operation forbidden` / `-1505 no permissions to access this
site` -- the Open API app's role does not cover the call (§12.2). Once writing
has started, a failure is reported on its step instead (`outcome: "failed"`,
`provider_code`), the other steps still run, and the response is 200 with
`ok: false`. A lost connection marks the remaining steps `skipped`. Creates are
never retried after a timeout, so re-run instead: it re-reads and converges.

Every real run writes one `controller_configured` event (the step report, no
secrets) and one audit entry. A dry run writes nothing at all.

### 12.2 What the venue must provide

1. **Controller 5.13 or newer** (Open API). 5.15 was checked, see §12.6.
2. **An Open API app.** On the controller: **Settings -> Platform Integration ->
   Open API -> Add New App**.
   * **Mode: Client** (client credentials). Authorization-code mode is for apps
     that log a person in; this platform never does.
   * **Role: Administrator** -- or, least privilege, a custom role with
     **Site Settings (network) = Modify** and **Hotspot = Modify**; everything
     else may be Block/View. Site Settings covers the portal and access-control
     settings; Hotspot covers operator accounts. *Inferred:* TP-Link documents the
     role privileges (`privilege.network`, "Site network settings permission in
     site view -> settings"; `privilege.hotspot`, "Hotspot permission") but not
     which privilege each endpoint checks. A role that is too weak fails with
     `OMADA_PERMISSION_DENIED`, which names this fix.
   * **Site Privileges:** at least the venue's site.
   * Copy the **Client ID**, **Client Secret** and the **Omada ID** shown with
     the app. The controller's own guide notes that changing an app's role or
     site privileges invalidates tokens already issued; nothing needs doing
     about that, the next call gets a new one.
3. Save them on the integration (`auth_mode: "openapi"`, `client_id`,
   `client_secret`), pick the site and the guest SSID, map the venue. **No
   operator account is needed** -- the run creates one. If the venue already has
   one it wants used, save it too and the run will only prove it.

### 12.3 What stays manual

* **Reachability.** Guests' devices must reach the controller's portal port
  (**8088**, or **8843** with HTTPS redirect on) -- §7.3; our servers must reach
  its HTTPS management port (8043 software / 443 hardware, from the allowlist in
  §3).
* **Certificate trust** for a self-signed controller -- §5. Do it first; every
  call in this run goes over that connection.
* **The SSID itself** must exist and be broadcast by adopted access points. The
  run binds a portal to an SSID; it does not create one.
* **The real-phone test** -- §8. Nothing here replaces it.

### 12.4 API

Customer, organization scope (`X-Organization-Id`), permission
`network_integrations.update`:

```
POST /api/v1/network-integrations/{integration_id}/configure-controller
{"dry_run": true, "take_over_ssid_portal": false}
```

Platform staff, GLOBAL scope, same permission key:

```
POST /api/v1/network-integrations/platform/integrations/{integration_id}/configure-controller
```

`dry_run` is required (no default); unknown fields are rejected with 422. The
customer route reads the integration with the caller's organization in the
query, so another tenant's id is a 404. Everything written -- URL, site, SSID,
operator name -- comes from the integration row, never from the request.

Response `data`:

```json
{
  "integration_id": "…",
  "dry_run": false,
  "ok": true,
  "changed": true,
  "steps": [
    {"step": "portal", "outcome": "created", "message": "Created portal …",
     "provider_code": null, "details": {"portal_name": "…", "ssid_id": "…", "portal_id": "…"}},
    {"step": "pre_auth_access", "outcome": "created", "message": "Added a URL entry …",
     "provider_code": null, "details": {"host": "auth.wyfyguest.com", "entries_preserved": 2, "was_enabled": true}},
    {"step": "hotspot_operator", "outcome": "created", "message": "Created hotspot operator account 'wyfy-…' …",
     "provider_code": null, "details": {"operator_name": "wyfy-…"}}
  ],
  "portal_id": "…",
  "guest_ssid_id": "…",
  "portal_url_scheme": "https",
  "portal_url_host_and_query": "auth.wyfyguest.com/portal?organizationId=…&locationId=…&routerId=…&netProvider=omada",
  "pre_auth_host": "auth.wyfyguest.com"
}
```

`outcome` is one of `created`, `updated`, `unchanged`, `skipped`, `failed`; on a
dry run it is what *would* happen and the messages start with "Would".

### 12.5 Sources

Every path and field is taken from TP-Link's OpenAPI 3.0.1 document in two
copies: the cloud gateway's (<https://use1-omada-northbound.tplinkcloud.com/v3/api-docs>)
and the one **our 5.15.24.19 controller serves about itself** at
`GET https://<controller>:8043/v3/api-docs` (unauthenticated; Swagger UI at
`/doc.html`). Operations: `getPortalList`, `getPortalDetail`, `addPortal`,
`modifyPortal`, `getAccessControl`, `modifyAccessControl`,
`getHotspotOperatorList`, `createHotspotOperator`, `modifyHotspotOperator`,
plus the existing site and SSID reads. Implementation:
`vendor/wyfy-device-gateway/wyfy_device_gateway/omada/portal_setup.py`.

### 12.6 Does 5.15 have these operations? Yes -- checked on the controller itself

Read on 2026-09-12 from our EC2 controller's own `GET /v3/api-docs` (5.15.24.19,
1224 paths; TP-Link's public docs site only covers software controllers from
6.2.0):

* **Present, same request/response fields as the cloud spec:** every operation
  in §12.5. The only differences are fields this run does not use (5.15 lacks
  `socialLogin`/`google` on portals and `description` on access-control entries;
  its `welcomeInformation` pattern is shorter).
* **Absent on 5.15:** `POST .../hotspot/portal/candidates` (`getPortalCandidates`)
  and `GET /openapi/v2/.../wireless-network/ssids`. So SSIDs are resolved through
  the WLAN-group walk, which both versions serve. 5.15's WLAN and SSID rows carry
  `wlanId`/`ssidId` and no `id`; the SSID reader already handles that.
* **Also from that controller's embedded Open API guide:** the client-credentials
  token call is documented there exactly as we send it, and the general error
  codes `-1005` / `-1505` used for `OMADA_PERMISSION_DENIED`.

Confidence: **high that the routes exist and take these shapes on 5.15.24.19**
(the controller's own document, not an inference from another version);
**none that the controller accepts every value** until §12.7 is done. Two
specific unknowns: whether `modifyPortal` resets settings it is not sent
(`portalCustomize`, `pageType`, `importedPortalPage` are not returned by the
detail call, so take-over cannot echo them -- matters only when taking over a
portal with a customised local page), and whether a Viewer-role operator could
authorize guests (we create role 0, Administrator, the only role ever proven).

### 12.7 Hardware verification recipe (our EC2 controller)

Controller `https://13.126.39.79:8043`, 5.15.24.19, Omada ID
`15ab5e4b7c2ca6cd134a3fded6e2ec59`, site `6aa3913c3ee1605f71ac35a1`, SSID
`WyfyGuest`. Admin login and certificate pin are in
`~/wyfy-omada/EC2-CONTROLLER.md`. Port 8043 is open only to the office IP and the
prod app server; run the API calls from one of those.

1. **Snapshot what is there now**, so it can be put back. In the controller UI:
   Site -> Settings -> Authentication -> Portal (note the existing portal on
   `WyfyGuest`, its URL and SSIDs), Access Control -> Pre-Authentication Access
   (note every entry), Hotspot Manager -> Operators (note `wyfyportal`).
2. **Create the app:** Settings -> Platform Integration -> Open API -> Add New
   App, name `wyfy-autoconfig-test`, Mode **Client**, Role **Administrator**, Site
   Privileges `wyfyguest`. Copy Client ID and Client Secret.
3. **Prove the token** (read-only):

   ```bash
   curl -sk "https://13.126.39.79:8043/openapi/authorize/token?grant_type=client_credentials" \
     -H 'content-type: application/json' \
     -d '{"omadacId":"15ab5e4b7c2ca6cd134a3fded6e2ec59","client_id":"<ID>","client_secret":"<SECRET>"}'
   TOKEN=AT-...   # result.accessToken
   B=https://13.126.39.79:8043/openapi/v1/15ab5e4b7c2ca6cd134a3fded6e2ec59/sites/6aa3913c3ee1605f71ac35a1
   curl -sk "$B/portals" -H "Authorization: AccessToken=$TOKEN"
   curl -sk "$B/setting/access-control" -H "Authorization: AccessToken=$TOKEN"
   curl -sk "$B/hotspot/operators?page=1&pageSize=100" -H "Authorization: AccessToken=$TOKEN"
   ```

   Save the three responses with the step 1 notes -- they are the first real
   5.15 payloads for these calls; compare their fields with §12.5.
4. **Point a test integration at it** (a test organization, never a live
   venue's): `POST /api/v1/network-integrations/{id}/credentials` with
   `{"auth_mode":"openapi","client_id":"<ID>","client_secret":"<SECRET>","tls_mode":"pinned","tls_pinned_sha256":"<pin>"}`,
   then `PATCH` it with `external_site_id: "6aa3913c3ee1605f71ac35a1"`,
   `guest_ssid_name: "WyfyGuest"` and a venue. Leave the operator out on purpose
   so step 6 exercises account creation.
5. **Dry run:** `POST .../configure-controller {"dry_run": true}`. Expect
   `pre_auth_access` `unchanged` if the `auth.wyfyguest.com` entry added by hand
   on 2026-09-11 is still there and switched on (step 1 tells you),
   `hotspot_operator` `created`, and for the portal
   either `portal` `updated` (if the manual portal's URL carries this
   integration's `routerId`) or a 409 `NETWORK_INTEGRATION_PORTAL_CONFLICT`
   naming the manual portal. **Confirm nothing changed in the UI.**
6. **Real run:** `{"dry_run": false}`, adding `"take_over_ssid_portal": true` if
   step 5 was a conflict. Check in the UI: the portal (External Portal Server,
   Scheme `https`, URL = the card's URL, SSID `WyfyGuest`); Pre-Authentication
   Access still holds every step-1 entry; operator `wyfy-…` exists under Hotspot
   Manager; with take-over, the manual portal still exists with everything but
   the SSID unchanged. Check the integration's Activity feed for one
   `controller_configured` row.
7. **Re-run:** `{"dry_run": false}` again. **Expect every step `unchanged`**, and
   no new entries in the controller's audit log (Logs -> Audit Logs).
8. **Real phone** through §8 -- this is what proves the auto-created operator can
   authorize a guest.
9. **Put it back** if needed: delete the created portal and `wyfy-…` operator in
   the UI, restore the manual portal's SSID, delete the Open API app.

Record what differed from this section in `~/wyfy-omada/HARDWARE-FINDINGS.md`,
and flip the §1 row only after steps 6-8 pass.
