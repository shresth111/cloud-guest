#!/bin/bash
# STAGING ONLY. Install/upgrade the staging RADIUS hub on wyfy-staging-server
# (i-0a6a08bb87c6f0f84) and point the staging backend at it. Idempotent.
# Run as root on the box, e.g. from a laptop:
#   ~/wyfy-ops/ssm-run-on.sh i-0a6a08bb87c6f0f84 deploy/staging-radius/install.sh
# Optional env: REF (git ref of cloud-guest to build, default origin/staging),
#               SKIP_BACKEND=1 (do not touch backend.env / recreate api),
#               RADSEC_HOST (default staging.wyfyguest.com: the certbot lineage
#               whose certificate the RadSec listener presents).
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

# 3a. RadSec material (radsec/README in this dir). Server cert = the certbot
#     lineage for $RADSEC_HOST (public CA: Instant On has no CA upload).
#     Client trust = the staging test CA generated here (its key never leaves
#     $RD/ca) + any device CA dropped into $RD/trust.d by radsec-map.sh.
RADSEC_HOST="${RADSEC_HOST:-staging.wyfyguest.com}"
LE=/etc/letsencrypt/live/$RADSEC_HOST
RD=$BASE/radsec
[ -s "$LE/fullchain.pem" ] || { echo "no certbot lineage $LE" >&2; exit 1; }
install -d -m 0755 "$RD"; install -d -m 0750 "$RD/certs" "$RD/trust.d"; install -d -m 0700 "$RD/ca"
install -d -m 0770 -g 101 "$RD/state"   # 101 = freerad inside the image
install -m 0644 "$LE/fullchain.pem" "$RD/certs/server.pem"
install -m 0640 -g 101 "$LE/privkey.pem" "$RD/certs/server.key"
chgrp 101 "$RD/certs"
if [ ! -s "$RD/ca/test-ca.key" ]; then
  ( umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
      -keyout "$RD/ca/test-ca.key" -out "$RD/ca/test-ca.pem" \
      -subj "/O=Wyfy Guest STAGING/CN=Wyfy RadSec Staging Test CA" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null )
  log "generated the staging RadSec test CA"
fi
cat "$RD/ca/test-ca.pem" $(ls "$RD"/trust.d/*.pem 2>/dev/null) > "$RD/certs/trust.pem.new"
chmod 0644 "$RD/certs/trust.pem.new"; mv "$RD/certs/trust.pem.new" "$RD/certs/trust.pem"
[ -s "$BASE/radsec.env" ] || printf 'RADSEC_TLS_MAX=1.2\n' > "$BASE/radsec.env"
chmod 600 "$BASE/radsec.env"
# certbot renews in place; copy + restart on every renewal of this lineage.
HOOK=/etc/letsencrypt/renewal-hooks/deploy/wyfy-staging-radsec.sh
cat > "$HOOK" <<HOOKEOF
#!/bin/sh
# installed by cloud-guest deploy/staging-radius/install.sh (STAGING ONLY)
case " \$RENEWED_DOMAINS " in *" $RADSEC_HOST "*) ;; *) exit 0;; esac
install -m 0644 "$LE/fullchain.pem" "$RD/certs/server.pem"
install -m 0640 -g 101 "$LE/privkey.pem" "$RD/certs/server.key"
docker restart wyfy-staging-radius-radsec-1 >/dev/null
HOOKEOF
chmod 0755 "$HOOK"
log "radsec: server cert $(openssl x509 -in "$RD/certs/server.pem" -noout -subject -enddate | tr '\n' ' ')"
log "radsec: trust.pem = $(grep -c 'BEGIN CERTIFICATE' "$RD/certs/trust.pem") CA(s); test CA sha256 $(openssl x509 -in "$RD/ca/test-ca.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | cut -c1-16)"

# 3b. build + start (radius = UDP 1812/1813 on 3.2.1, radsec = TCP 2083 on 3.2.8)
cd "$BASE/src"
DC="docker compose -p wyfy-staging-radius -f deploy/staging-radius/docker-compose.yml"
export RADIUS_ENV_FILE="$BASE/radius.env" RADSEC_ENV_FILE="$BASE/radsec.env" RADSEC_DIR="$RD"
$DC build -q
$DC up -d
for c in radius radsec; do
  for _ in $(seq 1 40); do docker logs wyfy-staging-radius-$c-1 2>&1 | grep -q 'Ready to process requests' && break; sleep 1; done
  docker logs wyfy-staging-radius-$c-1 2>&1 | grep -q 'Ready to process requests' || { docker logs --tail 50 wyfy-staging-radius-$c-1; exit 1; }
done
log "freeradius ready (udp 1812/1813 + shared aruba udp 1912/1913 + radsec tcp 2083); agent on $GW:9092"
log "listeners: $(ss -Hltnu '( sport = :1812 or sport = :1813 or sport = :1912 or sport = :1913 or sport = :2083 )' | awk '{print $1"/"$5}' | sort -u | tr '\n' ' ')"
SHARED_FILE=$(docker exec wyfy-staging-radius-radius-1 cat /var/lib/wyfy-radius/wyfy-aruba-shared-clients.conf)
if printf '%s' "$SHARED_FILE" | grep -q '^# PLACEHOLDER'; then
  log "shared aruba listener: placeholder secret (rejects everything) -- set it from Master > Aruba shared secret"
else
  log "shared aruba listener secret fp: $(fp "$(printf '%s' "$SHARED_FILE" | awk '/^[[:space:]]*secret = /{print $3; exit}')")"
fi

# 4. staging backend env
if [ "${SKIP_BACKEND:-0}" != 1 ]; then
  cp -p "$DEPLOY/backend.env" "$DEPLOY/backend.env.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  tmp=$(mktemp "$DEPLOY/backend.env.XXXXXX")
  grep -vE '^CLOUDGUEST_HUB_RADIUS_(AGENT_URL|AGENT_SECRET|PUBLIC_ADDRESS|ARUBA_SHARED_AGENT_URL)=' "$DEPLOY/backend.env" > "$tmp" || true
  printf 'CLOUDGUEST_HUB_RADIUS_AGENT_URL=http://%s:9092/radius/client\nCLOUDGUEST_HUB_RADIUS_AGENT_SECRET=%s\nCLOUDGUEST_HUB_RADIUS_PUBLIC_ADDRESS=%s\nCLOUDGUEST_HUB_RADIUS_ARUBA_SHARED_AGENT_URL=http://%s:9092/radius/shared-client\n' \
    "$GW" "$AGENT_SECRET" "$PUBLIC_ADDRESS" "$GW" >> "$tmp"
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
log "api sees: $(docker exec deploy-api-1 printenv CLOUDGUEST_HUB_RADIUS_AGENT_URL) public=$(docker exec deploy-api-1 printenv CLOUDGUEST_HUB_RADIUS_PUBLIC_ADDRESS) shared=$(docker exec deploy-api-1 printenv CLOUDGUEST_HUB_RADIUS_ARUBA_SHARED_AGENT_URL)"
