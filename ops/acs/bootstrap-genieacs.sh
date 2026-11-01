#!/usr/bin/env bash
# Load the Phase-1 GenieACS config through the NBI (idempotent; PUT replaces).
#
#   ./bootstrap-genieacs.sh                # on the box, from ~/deploy/acs
#   API_CONTAINER=deploy-api-1 ./bootstrap-genieacs.sh
#
# The NBI is not published on the host, so every call goes through the api
# container (it has curl and sits on deploy_default with genieacs-nbi).
# Run it after the first `up`, and again whenever genieacs/*.js|*.json change.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_CONTAINER="${API_CONTAINER:-deploy-api-1}"
NBI="${NBI_URL:-http://genieacs-nbi:7557}"

nbi() { # nbi METHOD PATH [FILE]
  local method="$1" path="$2" file="${3:-}"
  if [[ -n "$file" ]]; then
    docker exec -i "$API_CONTAINER" curl -fsS -X "$method" --data-binary @- "$NBI$path" <"$file"
  else
    docker exec "$API_CONTAINER" curl -fsS -X "$method" "$NBI$path" </dev/null
  fi
}

echo "== NBI reachable from $API_CONTAINER"
nbi GET "/devices/?projection=_id&limit=1" >/dev/null
echo "ok"

echo "== provision wyfy-periodic"
nbi PUT /provisions/wyfy-periodic "$HERE/genieacs/wyfy-periodic.provision.js"
echo "ok"

echo "== preset wyfy-periodic"
nbi PUT /presets/wyfy-periodic "$HERE/genieacs/wyfy-periodic.preset.json"
echo "ok"

echo "== cwmp.auth must be UNSET (the edge authenticates; see genieacs-config.md)"
# The NBI has no /config route in 1.2; read the collection directly.
auth=$(docker exec wyfy-acs-mongo-acs-1 mongosh --quiet genieacs \
  --eval 'const d=db.config.findOne({_id:"cwmp.auth"}); print(d ? JSON.stringify(d) : "UNSET")' </dev/null)
echo "cwmp.auth: $auth"
if [[ "$auth" != "UNSET" ]]; then
  echo "!! cwmp.auth is set. Edge-auth mode expects it unset. Fix deliberately; this script does not change it." >&2
  exit 1
fi

echo "== presets now"
nbi GET "/presets/?projection=_id,weight" ; echo
