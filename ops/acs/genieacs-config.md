# GenieACS configuration (Phase 1)

GenieACS 1.2.16, unmodified. Everything below was exercised locally on
2026-10-22 against the image built from `Dockerfile`, through `nginx-acs.conf`
with a stub `acs-auth`. Staging still has to confirm it with a real MikroTik.

## `cwmp.auth`: leave it UNSET

The CWMP edge (nginx `auth_request` → `GET /api/v1/internal/tr069/acs-auth`)
is the only authentication. GenieACS must accept every session that reaches it.

In 1.2.16 an unset `cwmp.auth` already means "accept". From the shipped bundle
(`bin/genieacs-cwmp`, the session auth function):

```js
let r = Cn(e.cacheSnapshot, "cwmp.auth"); if (r == null) return !0;
```

So the correct value is **no `config` document with `_id: "cwmp.auth"`**.
Do not set it to `true` either: that works, but unset is the default and the
smallest surface. `bootstrap-genieacs.sh` checks that it is unset and refuses
to continue if someone set it.

The NBI in 1.2 has no `/config` route. Config lives in Mongo's `config`
collection (normally edited through the UI, which we do not run). To inspect:

```sh
docker exec wyfy-acs-mongo-acs-1 mongosh --quiet genieacs --eval 'db.config.find().toArray()'
```

Also verified locally:
- a session is correlated by GenieACS's `session=` cookie, so nginx opening a
  new upstream connection per request is fine;
- an empty POST with no session gets `400 Invalid session` from GenieACS
  (that is the "GenieACS answers, not the edge" signal in FS-4);
- the edge's subrequest arrives as `GET`, carries `Authorization` and the gate
  header, and carries no body.

## `cwmp.connectionRequestAuth`

GenieACS defaults. Connection requests rarely reach CPEs behind NAT; tasks run
at the next periodic inform (STATUS Risks). STUN/XMPP is Phase 2.

## Preset + provision `wyfy-periodic`

`genieacs/wyfy-periodic.provision.js`, as loaded:

```js
const hourAgo = Date.now() - 3600 * 1000;
const tr181 = declare("Device.ManagementServer.PeriodicInformEnable", { path: 1 });
const root = tr181.size ? "Device" : "InternetGatewayDevice";
declare(root + ".ManagementServer.PeriodicInformEnable", { value: 1 }, { value: true });
declare(root + ".ManagementServer.Username", { value: hourAgo });
declare(root + ".ManagementServer.PeriodicInformInterval", { value: hourAgo });
```

`genieacs/wyfy-periodic.preset.json`, as loaded:

```json
{ "weight": 0, "channel": "", "events": {}, "precondition": "",
  "configurations": [ { "type": "provision", "name": "wyfy-periodic", "args": null } ] }
```

It **writes** `PeriodicInformEnable=true` only. It also **reads**
`ManagementServer.Username` and `PeriodicInformInterval`, at most hourly. That
read is load-bearing: an Inform does not carry `Username`, and GenieACS stores
only the parameters something asked for. Without it, the backend's sync query
on `*.ManagementServer.Username._value` (API_CONTRACT §6.2) would match no
device at all. It never sets the interval and never declares a password path. There are no ISP-specific presets in Phase 1.
Locally, a fresh Inform followed by an empty POST was answered with
`GetParameterNames` (the provision probing the data model), as expected.

Load or reload both (idempotent):

```sh
cd ~/deploy/acs && ./bootstrap-genieacs.sh
```

## NBI smoke commands (from inside the api container; NBI is not published)

```sh
# empty inventory on a fresh install -> []
docker exec deploy-api-1 curl -s http://genieacs-nbi:7557/devices/

# what the backend's sync asks for (TR-181 + TR-098 username, projection trimmed)
docker exec deploy-api-1 curl -s -G http://genieacs-nbi:7557/devices/ \
  --data-urlencode 'query={"$or":[{"Device.ManagementServer.Username._value":"isp-xxxxxxxx"},{"InternetGatewayDevice.ManagementServer.Username._value":"isp-xxxxxxxx"}]}' \
  --data-urlencode 'projection=_id,_lastInform,_deviceId'

# presets / provisions loaded
docker exec deploy-api-1 curl -s 'http://genieacs-nbi:7557/presets/?projection=_id,weight'
docker exec deploy-api-1 curl -s 'http://genieacs-nbi:7557/provisions/?projection=_id'

# pending tasks and faults (what BE-10's sync reads)
docker exec deploy-api-1 curl -s http://genieacs-nbi:7557/tasks/
docker exec deploy-api-1 curl -s http://genieacs-nbi:7557/faults/
```

## Fallback if edge auth cannot work (STATUS Risks)

What could break edge auth on staging is CPE behaviour, not GenieACS. A
`tr069-client` that only does Digest, or that does not re-send `Authorization`
after a `401 Basic`, would fail at the edge. Check in this order:

1. **Look at the edge log first.** `/var/log/nginx/wyfy-acs.access.log` shows
   whether the CPE retries after the 401. The api log shows what `acs-auth`
   received.
2. **Mode B: GenieACS-side auth.** Remove `proxy_set_header Authorization "";`
   and the `auth_request` lines from `nginx-acs.conf`, then set
   `cwmp.auth` to

   ```
   AUTH(Device.ManagementServer.Username, EXT("wyfy-acs-auth", "password", Device.ManagementServer.Username))
   ```

   GenieACS then checks Basic or Digest itself. **Two costs, which is why it is
   not the default.** (a) It needs a new gate-secret internal endpoint that
   returns a credential's decrypted password to the ext script. That is a
   contract change (PM). (b) An expression cannot read the username out of the
   `Authorization` header (checked in the 1.2.16 source). It can only use the
   device's stored `ManagementServer.Username`, which a brand-new CPE's first
   Inform may not carry. Prove that on staging before relying on mode B.
3. Whatever the mode, suspension and disable still have to give a 401. Re-run
   `smoke-acs.sh` and the acs-auth tests after any switch.
