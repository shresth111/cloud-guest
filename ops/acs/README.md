# ops/acs: GenieACS for the ISP partner TR-069 control plane

**Staging only.** Nothing here runs on the prod box until the founder signs
off (STATUS Q5). The approval-gated, step-by-step runbook is
`~/wyfy-ops/isp-network/DEPLOY.md`. This README explains the parts.

| File | What it is |
|---|---|
| `Dockerfile` | `node:20-bookworm-slim` + `genieacs@1.2.16` from npm, unmodified (AGPL-3.0, separate process, nothing patched) |
| `docker-compose.acs.yml` | compose project `wyfy-acs`: `mongo-acs`, `genieacs-cwmp`, `genieacs-nbi` (+ `genieacs-fs` behind a profile, not started) |
| `nginx-acs.conf` | `acs-staging.wyfyguest.com` :443 → cwmp, with CPE auth through `auth_request` to our backend |
| `nginx-acs-gate.conf.example` | template for the root-only file holding the edge gate secret |
| `nginx-network-staging.conf` | `network-staging.wyfyguest.com`, a copy of the staging SPA block (FS-5) |
| `genieacs/wyfy-periodic.*` | the only Phase-1 preset + provision |
| `bootstrap-genieacs.sh` | loads the preset/provision through the NBI and checks `cwmp.auth` is unset |
| `smoke-acs.sh` | FS-4 acceptance checks, run from the laptop |
| `genieacs-config.md` | the `cwmp.auth` decision, the preset JSON, NBI smoke curls, and the fallback |

## How it fits together

```
MikroTik /tr069-client ──HTTPS Basic──▶ nginx :443 acs-staging.wyfyguest.com
                                          │ auth_request (GET, no body)
                                          ├──▶ api 127.0.0.1:8000 /api/v1/internal/tr069/acs-auth
                                          │      + X-Wyfy-Acs-Gate (secret)   204 ok / 401 no
                                          ▼
                                   genieacs-cwmp 127.0.0.1:7547  (cwmp.auth unset = accept)
                                          │
                                       mongo-acs  (private network acs-internal, no port)
                                          │
api (deploy_default) ──HTTP──▶ genieacs-nbi :7557 (deploy_default only, no port)
```

- **CPE auth is at the edge.** The backend checks the Basic credential against
  `tr069_acs_credentials` and answers 204 or 401. A suspended ISP or a disabled
  customer gets 401 from nginx, and GenieACS never sees the request.
  Anything else (api down, gate secret wrong → 404) becomes a 500 to the CPE,
  so the edge fails closed. The CPE's `Authorization` header is stripped
  before GenieACS, so it cannot appear in a GenieACS log.
- **Tenant isolation is not in GenieACS.** GenieACS is single-tenant. The NBI has
  no auth, so its only boundary is the docker network. Isolation lives in the
  backend's `tr069_devices` table (API_CONTRACT §6.2).
- **Separate compose project, shared network.** `wyfy-acs` joins the box
  stack's `deploy_default` as an external network, so `api` resolves
  `genieacs-nbi`. The box's own `~/deploy/docker-compose.yml` is not edited, and
  `remote-deploy.sh` (which runs `up -d --no-deps <svc>` in `~/deploy`) can
  never recreate or stop these containers. `mongo-acs` sits only on the
  project-private `acs-internal` network, so no other container on the box can
  reach it (verified locally: NXDOMAIN from a container on `deploy_default`).

## Ports

| Port | Bound to | Reachable from |
|---|---|---|
| 443 | nginx (existing) | internet (existing SG rule) |
| 7547 cwmp | `127.0.0.1` | nginx on the box only |
| 7557 nbi | not published | containers on `deploy_default` |
| 27017 mongo | not published | `genieacs-*` on `acs-internal` |
| 7567 fs | not started | – |
| 3000 ui | no UI container | – |

No security-group change is needed: nothing new listens on a public interface.

## Bring it up (staging box, as ubuntu)

```sh
mkdir -p ~/deploy/acs && cd ~/deploy/acs     # copy this directory here
docker compose -p wyfy-acs -f docker-compose.acs.yml build
docker compose -p wyfy-acs -f docker-compose.acs.yml up -d mongo-acs genieacs-cwmp genieacs-nbi
docker compose -p wyfy-acs -f docker-compose.acs.yml ps     # all three (healthy)
./bootstrap-genieacs.sh
docker exec deploy-api-1 curl -s http://genieacs-nbi:7557/devices/   # -> []
```

Always pass `-p wyfy-acs -f docker-compose.acs.yml`, and never run compose for
this from inside `~/deploy` without them. The memory "build from ~/deploy, not
the repo subdir" is about the app stack; this project is deliberately separate.

Building on the staging box is fine (one `npm install`, ~1 min). For prod,
build in CI and pull from ECR like `wyfy/api`. Building next to live uvicorn
on the prod box is what the app pipeline moved away from.

## Backend env (api container)

Add these to the env file the **box** compose loads for `api`:
`~/deploy/backend.env` on staging (`${BACKEND_ENV_FILE:-./backend.env}`; read
2026-10-22).

```
ISP_PARTNER_ENABLED=true          # staging only; prod stays false
TR069_ENABLED=true                # staging only
TR069_NBI_URL=http://genieacs-nbi:7557
TR069_ACS_PUBLIC_URL=https://acs-staging.wyfyguest.com/
TR069_EDGE_SHARED_SECRET=<openssl rand -hex 32; same value as /etc/nginx/wyfy/acs-gate.conf>
ISP_PARTNER_LOGIN_URL=https://network-staging.wyfyguest.com
```

Then recreate api only (`cd ~/deploy && docker compose up -d --no-deps api`).
The box compose has ignored extra env files before (memory: "Box compose
ignores mail.env"), so **verify inside the container**:

```sh
docker exec deploy-api-1 env | grep -E '^(TR069_|ISP_PARTNER_)' | sed 's/SECRET=.*/SECRET=<set>/'
```

## TLS + renewal

Certificates come from certbot with the nginx authenticator, the same way the
existing `staging.wyfyguest.com` lineage does. Use `--key-type rsa`: the
MikroTik script trusts **ISRG Root X1** only (API_CONTRACT §5 step 2), and an
RSA leaf chains to X1. The staging box already runs `certbot.timer` (active
2026-10-22), so new lineages renew without extra work. Check with
`systemctl list-timers certbot.timer` and `certbot renew --dry-run`. The
"LE renewal never moved to AWS" memory is about the hotspot fleet cert
pipeline on prod, not the box's own nginx certs. On the prod box, check that
`certbot.timer` exists before relying on it, and add it if it does not.

## Headroom

The staging box is a t3.medium: 3.8 GiB RAM, about 1 GiB available, **no swap**
(2026-10-22). Locally measured idle use: mongo ~275 MiB, cwmp ~76 MiB,
nbi ~49 MiB, ~400 MiB in total. Limits: 512 + 256 + 128 = 896 MiB. That fits
the free memory but leaves little margin, and no swap means the kernel
OOM-kills rather than slows down. DEPLOY.md asks for a 2 GiB swapfile on
staging before the first `up`.

## Ad-hoc GenieACS UI (ops only, never public)

There is no UI container in Phase 1. If ops needs one for a debugging session:

```sh
# 3000 is the frontend's on the box; use 3300. Ports cannot be published from an
# internal-only network, so create on deploy_default and then attach acs-internal.
docker create --rm --name wyfy-acs-ui --network deploy_default -p 127.0.0.1:3300:3000 \
  -e GENIEACS_MONGODB_CONNECTION_URL=mongodb://mongo-acs/genieacs \
  -e GENIEACS_UI_JWT_SECRET="$(openssl rand -hex 32)" wyfy/genieacs:1.2.16 genieacs-ui
docker network connect wyfy-acs_acs-internal wyfy-acs-ui && docker start wyfy-acs-ui
# laptop: aws ssm start-session --target <id> --document-name AWS-StartPortForwardingSession \
#   --parameters portNumber=3300,localPortNumber=3300
docker stop wyfy-acs-ui      # when done (--rm removes it)
```

Never publish it on a public interface, and never leave it running.

## Tear down

```sh
docker compose -p wyfy-acs -f docker-compose.acs.yml down        # keeps the acs-mongo volume
docker compose -p wyfy-acs -f docker-compose.acs.yml down -v     # also deletes all ACS data
```
