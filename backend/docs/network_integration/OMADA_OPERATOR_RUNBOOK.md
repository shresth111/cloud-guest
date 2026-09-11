# Omada Operator Runbook

How to put a venue that already runs **TP-Link Omada** WiFi onto Wyfy Guest, and how
to work out what went wrong when a guest signs in and still has no internet.

**Written for:** the platform staff member onboarding the controller, and the support
engineer answering "the WiFi didn't work". Not a developer document. The code and
PR history are cited so every step can be checked, but you do not need to read them.

**Status, stated plainly:** everything below comes from the merged code and the PRs
that built it (cloud-guest #203 #204 #206 #209 #210 #211 #212 #214 #218 #221 #224
#226, cloudguest-foundation #251 #253 #254 #256 #257 #258 #259 #264 #265, and the
change that added a controller as a provisioning wizard's first device). Several steps were
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

The first real venue is also the first end-to-end test. Plan to be on site or on a
call with a phone on the guest WiFi (§8).

---

## 2. Known gaps that change the procedure

The first version of this runbook listed six defects. Four are fixed; two remain.

**Fixed -- no workaround needed any more:**

* **An Open API integration could let nobody online.** Guest authorization uses the
  controller's hotspot operator login in *both* modes, and the backend used to refuse
  to store one on an Open API integration. It now stores the operator login alongside
  the Open API app (cloud-guest #226), every Open API form asks for it
  (cloudguest-foundation #265), and an Open API integration saved without one shows a
  **Hotspot operator account** gap with an **Add operator account** button instead of
  failing at the first guest.
* **An integration created from the customer page never got a fleet record**, so it
  sat on `fleet_device_missing` with no portal link. Mapping a venue now registers the
  controller as that venue's device (#226). An integration created *before* that fix
  shows a **Register controller** button once it has a venue; it is a one-click,
  idempotent repair (`POST /api/v1/network-integrations/{id}/fleet-device`). Nothing
  rewrites existing rows on its own -- a person presses the button.
* **Certificate trust and the Omada ID had no form.** They now do: a **Certificate &
  Omada ID** section in the connect wizard (it opens by itself when a test fails with a
  certificate error, and offers the fingerprint the controller presented as **Use this
  fingerprint**), a **Certificate & Omada ID** dialog on an existing integration, and
  the same three fields in the admin onboarding form and the provisioning wizard (§4).
* **No wording for the certificate errors.** `OMADA_TLS_UNTRUSTED` and
  `OMADA_TLS_PIN_MISMATCH` now have operator-facing sentences (#265).

**Still open:**

1. **The Activity tab does not show the failure record.** The diagnostics bundle (§9)
   is stored on the event, but the Activity table shows only the code and message.
   **Workaround: read it through the API or the database (§9.2).**
2. **The admin onboarding form's last step sends you to a screen with no site
   picker.** Its "Go to Integrations" link opens the Master console's Network
   Integrations list, which has no site or SSID fields.
   **Workaround: finish the mapping on the venue's own Network Integrations page
   (§6).**

## 3. Before you start

| Requirement | Why |
|---|---|
| Controller firmware **5.0.15 or newer** | The oldest version the integration accepts (`MIN_SUPPORTED_VERSION` in `omada/adapter.py`). The Open API app (device, client and site lists) needs 5.13 or newer; guest sign-in works on either mode as long as the operator account below is stored too. |
| The controller is reachable **from the internet over HTTPS**, on port **443, 8043, 8088 or 8843** | Our servers make the calls, not the operator's browser. Other ports are refused (`DEFAULT_CONTROLLER_PORTS`). Addresses that resolve to private ranges are refused in every shared environment. Software controllers usually listen on 8043; hardware controllers (OC200/OC300) on 443. |
| A **hotspot operator account** on the controller, **whichever mode you choose** | This is the credential that authorizes guests -- in Open API mode too. It is a separate account created in the controller's **Hotspot Manager** (Operators), not a controller admin login. TP-Link's doc 13080 says to use the operator's credentials "rather than the account and password for the controller account". |
| For a **self-hosted** controller: its certificate fingerprint (captured in §5) | Self-hosted controllers present a self-signed certificate (`CN=localhost`, issued by itself), which the default `strict` check refuses. |
| For a **TP-Link cloud** controller: its **Omada ID** | One cloud address fronts every controller in a region, so the controller cannot be identified without it (#210). TP-Link shows it on the credentials screen and in the controller's web address. |
| The venue already exists in Wyfy Guest | The controller is mapped to a venue (location). |
| Platform staff access with the global `network_integrations.create` permission | Required by both onboarding paths in §4 -- the provisioning wizard asks for it on top of `locations.manage` when the first device is a controller. |

---

## 4. Onboard the controller (platform staff)

There are three ways in. All three write the controller integration **and** the fleet
record a guest session needs (`guest_sessions.router_id` is NOT NULL) together, and all
three render the same controller form, validated by the same rules.

| Situation | Use |
|---|---|
| A **new customer**, or a new location for an existing customer, whose venue has an Omada controller and **no MikroTik** | §4.1 -- the provisioning wizard |
| The customer and venue **already exist** | §4.2 -- Routers → Add router |
| The venue's own staff are connecting it themselves | The venue dashboard's **Network Integrations → Add integration**. Pick the venue in the wizard; mapping it registers the controller (§2). |

**Never type an invented serial number or MAC** to get past a form that asks for one.
The MAC is the join key for client lookups, MAC authorization and DHCP leases, and an
invented one can collide with a real device. A software controller needs neither: leave
both blank and a locally-administered identity is generated, which no manufacturer can
burn into hardware and so cannot collide.

### 4.1 New customer: the provisioning wizard

Master console → **Customers** → **Add Customer** (or, for another location of an
existing customer: select the customer → **New Location**).

1. **Organization**, **Location** and **Owner**: as for any customer.
2. **First device** → **Device type: TP-Link Omada controller**.
   * **Controller name** and **Controller model**.
   * **Serial number (hardware only)** and **MAC address (hardware only)**: from the
     label of an OC200/OC300; leave **both** blank for a software controller. Enter
     both or neither.
   * **Controller address**, **Authentication**, the **Hotspot operator name** and
     **password** (in both modes), and for Open API the **Client ID** and **Client
     secret**.
   * **Omada ID** for a TP-Link cloud controller; **Certificate check** → **Pinned
     certificate** with its fingerprint for a self-hosted one (§5).
3. **Plan**, **Features**, **Review** → **Provision location**.

Everything is one transaction: if any part fails, nothing is saved -- no organization,
no owner, no location, no controller. Mistakes the controller step can catch from the
form alone (an address the security rules refuse, credentials that do not fit the
mode, the platform's encryption key not being configured) are caught **before**
anything is created. No RouterOS configuration template is applied and no WireGuard
tunnel is allocated; a controller uses neither.

The result screen says **One step left before guests can get online**: map the site and
guest network (§6), then configure the controller (§7). The new owner can do §6 after
signing in; platform staff reach the venue's page from **Customers → View dashboard**.

### 4.2 Existing venue: Routers → Add router

Admin dashboard → **Routers** → **Add router**.

1. **Device type:** choose **TP-Link Omada controller**.
2. **Controller** (identity & venue):
   * **Controller name**: anything recognisable, for example "Lobby Controller".
   * **Controller model**.
   * **Serial number (hardware only)** and **MAC address (hardware only)**: as in §4.1.
   * **Location**: the venue.
3. **Connection** (address & credentials): the same fields as §4.1 step 2.
4. **Connect controller**.

You should see "*name* is registered", along with "One step left before guests can
get online." The integration now holds credentials but authorizes nobody until §6 is
done. (Its "Go to Integrations" link is the dead end in §2, still open item 2.)

## 5. Certificate trust and Omada ID

Skip this section for a controller with a certificate from a public certificate
authority that is reached directly.

Every form that registers a controller now has these fields (§2): the provisioning
wizard and Routers → Add router (**Omada ID** and **Certificate check**), the connect
wizard's **Certificate & Omada ID** section, and the **Certificate & Omada ID** dialog
on an existing integration, which has its own **Test connection** to capture the
fingerprint. The API calls below remain for scripting and for support.

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
still missing: credentials, the operator account, venue, site or fleet device. A missing
operator account has an **Add operator account** button and a missing fleet device a
**Register controller** button (§2).

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
| `OMADA_API_UNSUPPORTED` | The integration has no hotspot operator credentials -- for example an Open API integration saved before #226, or without the operator account. | **Add operator account** (or **Replace credentials**) and enter the hotspot operator login. |
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
