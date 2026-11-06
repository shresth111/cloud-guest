#!/usr/bin/env bash
# Renews the wyfy-hotspot-fleet Let's Encrypt cert (DNS-01 via GoDaddy) and,
# only when a renewal actually happened, re-imports + rebinds it on every
# router the DATABASE says is pushable. Meant to run unattended via
# wyfy-hotspot-cert-renew.timer (systemd). See README.md in this directory.
#
# THIS FILE IS THE CANONICAL COPY. Read this before editing it anywhere else.
#
# For two weeks there were two copies of this script and they drifted:
# this one, in the product repo, and a second in the separate wyfy-infra
# operations repo (scripts/renew-hotspot-certs.sh). The rewrite that took
# the fleet from the database instead of a hand-written array (wyfy-infra
# e395fcd, 2026-08-23) landed only in wyfy-infra. What stayed here was the
# pre-rewrite version: a literal `ROUTERS=( "WYFY-GUEST|10.20.0.50|..." )`
# array with ONE entry and one fleet-wide `ROUTER_SSH_PASSWORD`.
#
# That is not a cosmetic difference. On 2026-09-05 a MikroTik engineer read
# this directory to answer "does the hotspot certificate cover the fleet?"
# and correctly concluded, from what was written here, that it covers
# exactly one router -- because that is what this file said. The repo an
# engineer actually opens is the repo that has to be right.
#
# So: the product repo is canonical from here on, and wyfy-infra carries a
# copy for the operator who is already SSH'd into the box. Any change to the
# push mechanism lands HERE first. The inventory helper it depends on lives
# beside it (fleet-inventory.py) for the same reason -- a script whose data
# source lives in a different repo is a drift waiting to happen.
#
# 2026-11-06: TRANSPORT SWITCHED TO THE ROUTEROS API. The ssh/scp push that
# lived here could not reach any router (only 8728/8729 answer; 22 is
# filtered). The push is now push-hotspot-certs.py, run from the api image
# with host networking so its one-shot PEM listener can bind an address the
# routers can route to. See "PUSH" below and README.md.
#
# Usage:
#   renew-hotspot-certs.sh               timer path: certbot renew, push if renewed
#   renew-hotspot-certs.sh --push-only   certbot renew_hook path: push, no certbot
#   renew-hotspot-certs.sh --dry-run     no certbot, no router contact: prints the
#                                        cert's SANs/expiry and the push inventory
#   FORCE_RENEW=1 renew-hotspot-certs.sh  certonly --force-renewal, then push
#   ONLY_ROUTER=<name> ...               push to that one router only (supervised test)
#
# Config: /etc/wyfy/hotspot-push.env (root-owned, 0600), sourced if present:
#   HOTSPOT_PUSH_BIND_HOST   REQUIRED for a real push. The app box's own address
#                            that routers can route to (its WireGuard/tunnel-side
#                            address). Never guessed; wildcards are refused.
#   HOTSPOT_PUSH_BIND_PORT   fixed listener port (default 18731). Must be allowed
#                            inbound from the router tunnel range only.
set -euo pipefail

MODE=renew
case "${1:-}" in
  "")           ;;
  --push-only)  MODE=push-only ;;
  --dry-run)    MODE=dry-run ;;
  -h|--help)    sed -n '2,60p' "$0"; exit 0 ;;
  *)            echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
esac
[[ "${DRY_RUN:-0}" == "1" ]] && MODE=dry-run

# Everything this script calls lives BESIDE it. The unit file used to name
# /opt/wyfy/renew-hotspot-certs.sh while the box keeps its ops scripts in
# /opt/wyfy/scripts/ -- a path mismatch nobody notices until a cert expires.
# Resolving our own directory removes the second literal entirely.
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

CERT_NAME="wyfy-hotspot-fleet"
LIVE_DIR="/etc/letsencrypt/live/${CERT_NAME}"
# Overridable so a dry run can be pointed at an exported copy of a cert when
# the lineage does not exist on this host yet.
FULLCHAIN="${FULLCHAIN:-${LIVE_DIR}/fullchain.pem}"
PRIVKEY="${PRIVKEY:-${LIVE_DIR}/privkey.pem}"
PUSH_ENV="${PUSH_ENV:-/etc/wyfy/hotspot-push.env}"
LOG_TAG="wyfy-hotspot-cert-renew"
API_SERVICE="${API_SERVICE:-api}"

log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$(date -Is)] $*"; }

if [[ -f "$PUSH_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$PUSH_ENV"
fi
: "${HOTSPOT_PUSH_BIND_PORT:=18731}"

# --- the certificate -------------------------------------------------------
MARKER="$(mktemp -u "/tmp/${CERT_NAME}.renewed.XXXXXX")"
trap 'rm -f "$MARKER"' EXIT

certbot_issue() {
  certbot certonly \
    --manual --preferred-challenges dns \
    --manual-auth-hook "${SCRIPT_DIR}/godaddy-dns-auth.sh" \
    --manual-cleanup-hook "${SCRIPT_DIR}/godaddy-dns-cleanup.sh" \
    --non-interactive --agree-tos "$@" \
    --cert-name "$CERT_NAME" \
    -d wifi.wyfyguest.com -d '*.portal.wyfyguest.com' -d portal.wyfyguest.com \
    --deploy-hook "touch $MARKER"
}

case "$MODE" in
  dry-run)
    log "--dry-run: no certbot, no router contact"
    ;;
  push-only)
    # Invoked as certbot's renew_hook, so a renewal performed by the GENERIC
    # certbot.timer still reaches the routers. No certbot here: no lock recursion.
    log "--push-only: invoked as certbot renew_hook -- pushing the freshly renewed cert"
    touch "$MARKER"
    ;;
  renew)
    if [[ "${FORCE_RENEW:-0}" == "1" ]]; then
      log "FORCE_RENEW=1 -- certbot certonly --force-renewal"
      certbot_issue --force-renewal
    elif [[ ! -d "$LIVE_DIR" ]]; then
      # `certbot renew --cert-name X` cannot create a lineage. On the AWS box
      # this lineage was never migrated (README, "Current state"), so the
      # first run is an issuance, not a renewal.
      log "no ${CERT_NAME} lineage on this host -- issuing it (certbot certonly)"
      certbot_issue
    else
      log "running certbot renew --cert-name ${CERT_NAME}"
      certbot renew --cert-name "$CERT_NAME" --non-interactive --deploy-hook "touch $MARKER"
    fi
    if [[ ! -f "$MARKER" ]]; then
      log "no renewal needed this run -- nothing to push to routers"
      exit 0
    fi
    ;;
esac

[[ -f "$FULLCHAIN" ]] || { log "FATAL: ${FULLCHAIN} missing${MODE:+ (mode ${MODE}; for a dry run before first issuance set FULLCHAIN=<some pem>)}"; exit 1; }
if [[ "$MODE" == "dry-run" ]]; then
  PRIVKEY=/dev/null   # a dry run never serves the key; do not even mount it
else
  [[ -f "$PRIVKEY" ]] || { log "FATAL: ${PRIVKEY} missing"; exit 1; }
fi
log "certificate covers: $(openssl x509 -in "$FULLCHAIN" -noout -ext subjectAltName 2>/dev/null \
      | tr ',' '\n' | sed -n 's/.*DNS://p' | tr -d ' ' | tr '\n' ' ')"
log "certificate $(openssl x509 -in "$FULLCHAIN" -noout -enddate)"

# Duplicate-push guard: the timer path and certbot's renew_hook can both fire
# for one renewal; the import/rebind must not run twice back to back.
PUSH_STAMP="/var/lib/wyfy/hotspot-push.stamp"
if [[ "$MODE" != "dry-run" ]]; then
  mkdir -p "$(dirname "$PUSH_STAMP")"
  if [[ -f "$PUSH_STAMP" ]]; then
    AGE=$(( $(date +%s) - $(stat -c %Y "$PUSH_STAMP") ))
    if [[ "$AGE" -lt 600 ]]; then
      log "router push already completed ${AGE}s ago -- skipping duplicate push"
      exit 0
    fi
  fi
fi

# --- PUSH ------------------------------------------------------------------
# push-hotspot-certs.py does the work over the RouterOS API (8728/8729), with
# each router's own stored credential: the router PULLS the two PEMs with
# /tool fetch from a single-use, peer-bound, short-TTL listener, then the
# import / rename / rebind / chain-preserve sequence runs over the same API
# session and is read back before it counts as done (see
# app/domains/router/hotspot_cert_push.py and ephemeral_pem_server.py).
#
# It needs the app's settings and Fernet key (to decrypt router credentials)
# AND an address the routers can reach, which a bridged container does not
# have. So it runs in a throwaway container of the SAME image the api is
# running, with --network host, the api container's exact environment, and
# the two PEM files + this directory mounted read-only. As root (bypassing the
# image entrypoint's privilege drop) because privkey.pem is root-only.
API_CID="$(docker ps --filter "label=com.docker.compose.service=${API_SERVICE}" --format '{{.ID}}' | head -1)"
[[ -n "$API_CID" ]] || { log "FATAL: no running '${API_SERVICE}' container -- is the stack up?"; exit 1; }
API_IMAGE="$(docker inspect --format '{{.Config.Image}}' "$API_CID")"

ENV_FILE="$(mktemp)"; chmod 600 "$ENV_FILE"
trap 'rm -f "$MARKER" "$ENV_FILE"' EXIT
# Same env as the running api. With host networking the compose service name
# `postgres` does not resolve; postgres is published on 127.0.0.1:5432, so
# point the URL there. (An RDS URL has no @postgres: and is left alone.)
docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$API_CID" \
  | grep -v '^PATH=' | grep -v '^$' \
  | sed -E 's#^(CLOUDGUEST_DATABASE_URL=.*@)postgres:#\1127.0.0.1:#' > "$ENV_FILE"

PUSH_ARGS=(--fullchain /run/hotspot/fullchain.pem --privkey /run/hotspot/privkey.pem
           --bind-port "$HOTSPOT_PUSH_BIND_PORT")
if [[ "$MODE" == "dry-run" ]]; then
  # The dry run never opens the listener; the bind host is only parsed.
  PUSH_ARGS+=(--dry-run --bind-host "${HOTSPOT_PUSH_BIND_HOST:-127.0.0.1}")
else
  [[ -n "${HOTSPOT_PUSH_BIND_HOST:-}" ]] || {
    log "FATAL: HOTSPOT_PUSH_BIND_HOST is not set (in ${PUSH_ENV}) -- refusing to guess which address the fleet private key is served on"
    exit 1
  }
  PUSH_ARGS+=(--bind-host "$HOTSPOT_PUSH_BIND_HOST")
fi
[[ -n "${ONLY_ROUTER:-}" ]] && PUSH_ARGS+=(--only "$ONLY_ROUTER")

log "push: image ${API_IMAGE##*/}, mode ${MODE}${ONLY_ROUTER:+, only router $ONLY_ROUTER}"
set +e
docker run --rm --network host --user 0 \
  --env-file "$ENV_FILE" \
  -v "$(readlink -f "$FULLCHAIN"):/run/hotspot/fullchain.pem:ro" \
  -v "$(readlink -f "$PRIVKEY"):/run/hotspot/privkey.pem:ro" \
  -v "${SCRIPT_DIR}:/opt/wyfy-hotspot:ro" \
  --entrypoint python "$API_IMAGE" \
  /opt/wyfy-hotspot/push-hotspot-certs.py "${PUSH_ARGS[@]}" 2>&1 \
  | while IFS= read -r line; do log "$line"; done
RC=${PIPESTATUS[0]}
set -e

if [[ "$RC" -ne 0 ]]; then
  log "FINISHED WITH FAILURES (exit ${RC}) -- failed routers stay on their previous certificate; needs a human"
  exit 1
fi
if [[ "$MODE" == "dry-run" ]]; then
  log "dry run complete -- nothing was changed"
  exit 0
fi
touch "$PUSH_STAMP"
log "push complete: every pushable router verified on the renewed certificate"
