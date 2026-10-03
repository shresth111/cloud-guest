#!/bin/bash
# STAGING ONLY. Install/upgrade the staging RADIUS hub on wyfy-staging-server
# (i-0a6a08bb87c6f0f84) and point the staging backend at it. Idempotent.
# Run as root on the box, e.g. from a laptop:
#   ~/wyfy-ops/ssm-run-on.sh i-0a6a08bb87c6f0f84 deploy/staging-radius/install.sh
# Optional env: REF (git ref of cloud-guest to build, default origin/staging),
#               SKIP_BACKEND=1 (do not touch backend.env / recreate api).
# Never prints a secret: only sha256[:12] fingerprints.
set -euo pipefail
REF="${REF:-origin/staging}"
REPO_URL="${REPO_URL:-https://github.com/shresth111/cloud-guest.git}"
DEPLOY=/home/ubuntu/deploy
BASE=$DEPLOY/staging-radius
PUBLIC_ADDRESS="${PUBLIC_ADDRESS:-13.207.123.212}"
log() { echo "[staging-radius $(date -u +%H:%M:%S)] $*"; }
fp()  { printf '%s' "$1" | sha256sum | cut -c1-12; }

[ -f "$DEPLOY/docker-compose.yml" ] || { echo "no $DEPLOY/docker-compose.yml -- wrong box?" >&2; exit 1; }
grep -q '^CLOUDGUEST_ENVIRONMENT=staging$' "$DEPLOY/backend.env" || { echo "backend.env is not staging -- refusing" >&2; exit 1; }
GW=$(docker network inspect deploy_default --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
[ -n "$GW" ] || { echo "deploy_default network has no gateway" >&2; exit 1; }

# 1. source
install -d -o ubuntu -g ubuntu "$BASE"
if [ ! -d "$BASE/src/.git" ]; then git clone -q "$REPO_URL" "$BASE/src"; fi
git -C "$BASE/src" fetch -q origin '+refs/heads/*:refs/remotes/origin/*'
git -C "$BASE/src" checkout -q --detach "$REF"
log "source: $REF = $(git -C "$BASE/src" rev-parse --short HEAD)"

# 2. agent secret (generated here once, never leaves the box)
if [ ! -s "$BASE/radius.env" ]; then
  ( umask 077
    S=$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(40)))')
    printf 'RADIUS_AGENT_SECRET=%s\nAGENT_BIND_ADDR=%s\n' "$S" "$GW" > "$BASE/radius.env" )
  log "generated radius.env"
fi
sed -i "s/^AGENT_BIND_ADDR=.*/AGENT_BIND_ADDR=$GW/" "$BASE/radius.env"
chown ubuntu:ubuntu "$BASE/radius.env"; chmod 600 "$BASE/radius.env"
AGENT_SECRET=$(grep '^RADIUS_AGENT_SECRET=' "$BASE/radius.env" | cut -d= -f2-)

# 3. build + start
cd "$BASE/src"
DC="docker compose -p wyfy-staging-radius -f deploy/staging-radius/docker-compose.yml"
RADIUS_ENV_FILE="$BASE/radius.env" $DC build -q
RADIUS_ENV_FILE="$BASE/radius.env" $DC up -d
for _ in $(seq 1 30); do docker logs wyfy-staging-radius-radius-1 2>&1 | grep -q 'Ready to process requests' && break; sleep 1; done
docker logs wyfy-staging-radius-radius-1 2>&1 | grep -q 'Ready to process requests' || { docker logs --tail 50 wyfy-staging-radius-radius-1; exit 1; }
log "freeradius ready; agent on $GW:9092"

# 4. staging backend env
if [ "${SKIP_BACKEND:-0}" != 1 ]; then
  cp -p "$DEPLOY/backend.env" "$DEPLOY/backend.env.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  tmp=$(mktemp "$DEPLOY/backend.env.XXXXXX")
  grep -vE '^CLOUDGUEST_HUB_RADIUS_(AGENT_URL|AGENT_SECRET|PUBLIC_ADDRESS)=' "$DEPLOY/backend.env" > "$tmp" || true
  printf 'CLOUDGUEST_HUB_RADIUS_AGENT_URL=http://%s:9092/radius/client\nCLOUDGUEST_HUB_RADIUS_AGENT_SECRET=%s\nCLOUDGUEST_HUB_RADIUS_PUBLIC_ADDRESS=%s\n' \
    "$GW" "$AGENT_SECRET" "$PUBLIC_ADDRESS" >> "$tmp"
  chown ubuntu:ubuntu "$tmp"; chmod 600 "$tmp"; mv "$tmp" "$DEPLOY/backend.env"
  cd "$DEPLOY"
  sudo -u ubuntu -H docker compose --env-file .deploy.env up -d --no-deps api celery-worker celery-beat
  for _ in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' deploy-api-1)" = healthy ] && break; sleep 3
  done
  log "api: $(docker inspect -f '{{.State.Health.Status}}' deploy-api-1)"
fi

# 5. fingerprints (must all match)
IN_API=$(docker exec deploy-api-1 printenv CLOUDGUEST_HUB_RADIUS_AGENT_SECRET 2>/dev/null || true)
IN_AGENT=$(docker exec wyfy-staging-radius-radius-1 printenv RADIUS_AGENT_SECRET)
log "agent secret fp: radius.env=$(fp "$AGENT_SECRET") agent=$(fp "$IN_AGENT") api=$(fp "$IN_API") len=${#AGENT_SECRET}"
log "api sees: $(docker exec deploy-api-1 printenv CLOUDGUEST_HUB_RADIUS_AGENT_URL) public=$(docker exec deploy-api-1 printenv CLOUDGUEST_HUB_RADIUS_PUBLIC_ADDRESS)"
