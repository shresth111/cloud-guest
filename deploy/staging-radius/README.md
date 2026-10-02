# Staging RADIUS hub (staging only)

A self-contained FreeRADIUS 3.2.1 + `radius_agent.py` for **wyfy-staging-server**
(`i-0a6a08bb87c6f0f84`, 13.207.123.212), so a NAS-only device (Aruba Instant On
AP21) can be tested end to end against staging instead of the prod hub.
Nothing here is used by prod: prod CD (`cd.yml`) never references this directory,
and the prod hub keeps its systemd install.

| Piece | Where it comes from |
|---|---|
| `mods-available/rest` | `backend/ops/freeradius/rest.conf`, `connect_uri` rewritten to `$ENV{WYFY_RADIUS_API_URI}` (default `http://127.0.0.1:8000/api/v1` = the staging api) |
| `sites-available/default` | the image's stock site + `backend/ops/freeradius/sites-default.snippets.conf`, spliced in at the hub's points (`gen_site.py`) |
| client stanzas | written at runtime by the unmodified `backend/ops/hub-agents/radius_agent.py`, on the `radius_state` volume |
| `systemctl restart freeradius` | `systemctl-shim.sh`: kills the supervised radiusd, `entrypoint.sh` starts a fresh one |

Network: `network_mode: host`, because FreeRADIUS matches a client by its
**source address** and must see the venue's real public IP. The agent binds to
the `deploy_default` bridge gateway (`172.18.0.1:9092`) only, so the api
container can reach it and nothing outside the box can. The image's stock
`localhost/testing123` client is not carried over.

## Install / upgrade
```bash
~/wyfy-ops/ssm-run-on.sh i-0a6a08bb87c6f0f84 deploy/staging-radius/install.sh
```
Clones/fetches this repo into `~/deploy/staging-radius/src` (`REF`, default
`origin/staging`), generates the agent secret once into
`~/deploy/staging-radius/radius.env` (600), builds and starts compose project
`wyfy-staging-radius`, writes `CLOUDGUEST_HUB_RADIUS_AGENT_URL/_SECRET/_PUBLIC_ADDRESS`
into `~/deploy/backend.env` (backup alongside) and recreates api/celery. It prints
only sha256[:12] fingerprints. The CD deploy does not touch this project.

## Verify
```bash
~/wyfy-ops/ssm-run-on.sh i-0a6a08bb87c6f0f84 deploy/staging-radius/selftest.sh
```

## Tear down
```bash
cd ~/deploy/staging-radius/src && docker compose -p wyfy-staging-radius -f deploy/staging-radius/docker-compose.yml down -v
# then remove the three CLOUDGUEST_HUB_RADIUS_* lines from ~/deploy/backend.env and
# `docker compose --env-file .deploy.env up -d --no-deps api celery-worker celery-beat` in ~/deploy
```

## Not done here: the security group
The staging instance shares `wyfy-app-sg` (`sg-04cb10156254e1690`) with the **prod**
app server, so UDP 1812/1813 must NOT be opened on that group. Use a separate
staging-only group with the venue /32 and attach it to the staging instance as
an extra group (commands in `~/wyfy-ops/aruba-ap21/STAGING_RADIUS.md`).
