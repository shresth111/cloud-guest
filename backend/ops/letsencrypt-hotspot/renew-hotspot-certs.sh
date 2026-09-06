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
set -euo pipefail

# --push-only: skip certbot entirely and go straight to the router push.
# This is how this script is invoked as certbot's renew_hook, so that a
# renewal performed by the GENERIC certbot.timer (which knows nothing about
# routers) still results in the fleet being updated. Without it, certbot.timer
# would renew this lineage first, this script's own timer would then find
# "no renewal needed", and the routers would silently keep serving the OLD
# cert until it expired. No certbot is invoked here, so there is no lock
# recursion when this runs from inside certbot.
PUSH_ONLY=0
if [[ "${1:-}" == "--push-only" ]]; then
  PUSH_ONLY=1
fi

CERT_NAME="wyfy-hotspot-fleet"
LIVE_DIR="/etc/letsencrypt/live/${CERT_NAME}"
ROUTER_ENV="/etc/wyfy/router-ssh.env"
LOG_TAG="wyfy-hotspot-cert-renew"

log() { logger -t "$LOG_TAG" -- "$*"; echo "[$(date -Is)] $*"; }

# --- Fleet inventory -------------------------------------------------------
# DERIVED FROM THE DATABASE, not hand-written here any more.
#
# This used to be a literal array with one entry and one fleet-wide
# ROUTER_SSH_PASSWORD. Both were wrong for the fleet this platform actually
# provisions, and the note that used to sit here already said so -- "a shared
# password across the whole fleet is a real, known gap, not an oversight".
#
# Measured 2026-08-23, not assumed. The founder's router (10.20.0.72) had
# ZERO certificates on it: it was not in the array, and the shared password
# did not authenticate to it (verified with an explicit SSH attempt). The
# setup-script generator issues every router its own credential and stores it
# encrypted, so the shared password could not reach ANY router the generator
# provisioned. This push had only ever been able to work on the one router
# that predates the generator.
#
# A hand-written list also fails in the direction nobody notices: a venue goes
# live, nobody edits the array, and that venue quietly serves an expiring
# certificate until a guest complains.
#
# fleet-inventory.py emits `name<TAB>address<TAB>credential` on stdout and a
# SKIP line per excluded router on stderr, so a router missing from a push is
# never confusable with a fleet that is fully covered.
#
# TAB-separated, not `|` -- the old array's separator is a perfectly plausible
# character in a generated password and would have split a credential in half
# without a word.
API_SERVICE="${API_SERVICE:-api}"
INVENTORY_SCRIPT="${INVENTORY_SCRIPT:-/opt/wyfy/fleet-inventory.py}"

# COMPOSE_DIR is ASKED OF DOCKER, not written down here.
#
# It used to be `${COMPOSE_DIR:-/home/azureuser/deploy}`, which was true of
# the Azure VM this was written on and became false on 2026-08-27 when
# production moved to AWS (/home/ubuntu/deploy, user `ubuntu`). A `cd` to a
# directory that no longer exists fails this script at the inventory step,
# on a path that runs unattended once every 60 days -- i.e. it would have
# been discovered by a certificate expiring, not by anyone reading a log.
#
# Replacing one stale literal with the next one would rot the same way at
# the next migration. The running api container already knows where it was
# composed from: docker records the project's working directory as a label
# on every container it starts. Reading it back means this script is correct
# on any box that is actually running the stack, and fails loudly on a box
# that is not -- which is the honest answer in that case anyway.
#
# COMPOSE_DIR=... in the environment still wins, for the operator running
# this by hand against a stack that is down.
if [[ -z "${COMPOSE_DIR:-}" ]]; then
  COMPOSE_DIR="$(docker ps --filter "label=com.docker.compose.service=${API_SERVICE}" \
                   --format '{{.ID}}' | head -1 \
                 | xargs -r docker inspect \
                   --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' \
                 2>/dev/null)"
fi
[[ -n "$COMPOSE_DIR" && -d "$COMPOSE_DIR" ]] || {
  log "FATAL: could not locate the compose directory for service '${API_SERVICE}'."
  log "       No running container carries a com.docker.compose.project.working_dir"
  log "       label for it. Is the stack up on this host? Set COMPOSE_DIR= to override."
  exit 1
}

# The cert name bound on every router. One shared certificate across the
# fleet (SANs: wifi.wyfyguest.com, *.portal.wyfyguest.com,
# portal.wyfyguest.com) -- so its private key is on every router, which is a
# real property of this design and the reason the SAN check below matters.
FLEET_CERT_NAME="$CERT_NAME"

# Still sourced, but only as a FALLBACK for routers that predate the
# generator and therefore have no stored per-router credential. Not required:
# on a fleet where every router was provisioned by the generator this file can
# be absent entirely.
if [[ -f "$ROUTER_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$ROUTER_ENV"
fi
: "${ROUTER_SSH_USER:=cloudguest-api}"

MARKER="$(mktemp -u /tmp/${CERT_NAME}.renewed.XXXXXX)"
rm -f "$MARKER"
trap 'rm -f "$MARKER"' EXIT

# --deploy-hook only fires when a cert was ACTUALLY renewed this run (not
# on every timer tick -- certbot renew is a no-op until ~30 days before
# expiry, per this VM's existing renewal.conf convention for its other
# certs). Using a marker file (rather than doing the router push directly
# inside --deploy-hook) keeps this script the single place router-push
# logic lives and is easy to re-run by hand.
#
# FORCE_RENEW=1 ./renew-hotspot-certs.sh bypasses the 30-day window (via
# `certonly --force-renewal` instead of `renew`) -- this is how the
# router-side re-import/rebind path (the part that only exercises on a
# SECOND+ issuance, never the first) got tested for real rather than left
# to be proven the first time it runs unattended in production. Safe to
# use again for an on-demand test; not needed for normal operation.
if [[ "$PUSH_ONLY" == "1" ]]; then
  log "--push-only: invoked as certbot renew_hook -- skipping certbot, pushing freshly renewed cert to routers"
  touch "$MARKER"
elif [[ "${FORCE_RENEW:-0}" == "1" ]]; then
  log "FORCE_RENEW=1 -- running certbot certonly --force-renewal (manual test path)"
  certbot certonly \
    --manual --preferred-challenges dns \
    --manual-auth-hook /opt/wyfy/godaddy-dns-auth.sh \
    --manual-cleanup-hook /opt/wyfy/godaddy-dns-cleanup.sh \
    --non-interactive --agree-tos --force-renewal \
    --cert-name "$CERT_NAME" \
    -d wifi.wyfyguest.com -d '*.portal.wyfyguest.com' -d portal.wyfyguest.com \
    --deploy-hook "touch $MARKER"
else
  log "running certbot renew --cert-name ${CERT_NAME}"
  certbot renew \
    --cert-name "$CERT_NAME" \
    --non-interactive \
    --deploy-hook "touch $MARKER"
fi

if [[ ! -f "$MARKER" ]]; then
  log "no renewal needed this run -- nothing to push to routers"
  exit 0
fi

# Duplicate-push guard.
# There are two legitimate ways the router push can be triggered:
#   a) this script run by wyfy-hotspot-cert-renew.timer (marker via --deploy-hook)
#   b) certbot's own renew_hook calling us with --push-only, which is what makes
#      a renewal performed by the generic certbot.timer still reach the routers
# If certbot ever runs BOTH (i.e. if a CLI --deploy-hook does not fully override
# the renew_hook stored in the renewal conf), the RouterOS import/rebind
# sequence would execute twice back to back. That sequence deletes and re-imports
# the live cert, so running it twice is not something to leave to chance on a
# path that executes unattended once every 60 days. This makes it impossible
# rather than merely unlikely.
PUSH_STAMP="/var/lib/wyfy/hotspot-push.stamp"
mkdir -p "$(dirname "$PUSH_STAMP")"
if [[ -f "$PUSH_STAMP" ]]; then
  AGE=$(( $(date +%s) - $(stat -c %Y "$PUSH_STAMP") ))
  if [[ "$AGE" -lt 600 ]]; then
    log "router push already completed ${AGE}s ago -- skipping duplicate push"
    exit 0
  fi
fi

# --- Who gets it, and does the certificate even match them? ----------------
# The SANs of the PEM about to be pushed. A router is only pushable if the
# hostname its hotspot redirects guests to is one of these. Pushing to a
# router whose `dns-name` is something else installs a certificate that does
# not match the address in the guest's URL bar -- which produces the very
# full-screen browser warning this whole certificate effort exists to remove,
# while looking like a complete success in every log line here.
CERT_SANS="$(openssl x509 -in "${LIVE_DIR}/fullchain.pem" -noout -ext subjectAltName 2>/dev/null \
             | tr ',' '\n' | sed -n 's/.*DNS://p' | tr -d ' ')"
[[ -n "$CERT_SANS" ]] || { log "FATAL: could not read SANs from ${LIVE_DIR}/fullchain.pem"; exit 1; }
log "certificate covers: $(echo "$CERT_SANS" | tr '\n' ' ')"

# `docker compose exec -T` and not `run`: `run` would start a SECOND api
# container against the same database for the sake of one query.
INVENTORY="$(cd "$COMPOSE_DIR" && docker compose exec -T "$API_SERVICE" \
             python "$INVENTORY_SCRIPT" < /dev/null 2> >(logger -t "$LOG_TAG") )" || {
  log "FATAL: could not read the fleet inventory from the api container"
  exit 1
}
ROUTER_COUNT="$(printf '%s' "$INVENTORY" | grep -c . || true)"
[[ "$ROUTER_COUNT" -gt 0 ]] || {
  # NOT a success. A renewal that pushed to nobody is the exact state this
  # rewrite exists to stop being silent.
  log "FATAL: the inventory returned no pushable routers -- nothing was updated"
  exit 1
}

log "cert renewed -- pushing to ${ROUTER_COUNT} router(s)"

FULLCHAIN="${LIVE_DIR}/fullchain.pem"
PRIVKEY="${LIVE_DIR}/privkey.pem"
[[ -f "$FULLCHAIN" && -f "$PRIVKEY" ]] || { log "FATAL: renewed but ${FULLCHAIN}/${PRIVKEY} missing"; exit 1; }

FAIL_COUNT=0
PUSHED_COUNT=0
while IFS=$'\t' read -r RNAME RADDR RPASS; do
  [[ -n "$RNAME" ]] || continue
  RCERTNAME="$FLEET_CERT_NAME"

  # A router with no stored credential is one that predates the generator.
  # Fall back to the shared password if one is configured, and say so -- a
  # silent fallback is how the shared-password gap stayed invisible.
  if [[ -z "$RPASS" ]]; then
    if [[ -n "${ROUTER_SSH_PASSWORD:-}" ]]; then
      log "NOTE: ${RNAME} has no stored credential, using the legacy shared password"
      RPASS="$ROUTER_SSH_PASSWORD"
    else
      log "ERROR: ${RNAME} has no stored credential and no shared fallback is configured, skipping"
      FAIL_COUNT=$((FAIL_COUNT+1)); continue
    fi
  fi

  # THE dns-name CHECK. Read off the router itself, because the only thing
  # that matters is what THIS device redirects guests to -- not what the
  # database, the generator's constant, or this script believes it should be.
  #
  # THIS IS ALSO WHERE THIS SCRIPT CURRENTLY DIES, FLEET-WIDE.
  #
  # Measured from the production app server on 2026-09-06, not assumed: on
  # the only real router in the fleet (10.20.0.17), tcp/22 does not answer.
  # Not "connection refused" (an SSH service that is off) -- it times out,
  # which is a firewall dropping the packet. So do 21, 23, 80, 443 and 8291.
  # The only ports that answer are 8728 and 8729, the RouterOS API and its
  # TLS twin. Every other management path into these devices is shut.
  #
  # This script needs BOTH ssh (this read, and the import/rebind below) and
  # scp (the two PEM uploads). Neither can be made to work over 8728: the
  # RouterOS API protocol has no file-transfer primitive at all, which is
  # exactly why the device gateway (backend/vendor/wyfy-device-gateway)
  # keeps a second, SSH-based transport just for provision_device.
  #
  # Deriving the fleet from the database therefore fixed a real bug but did
  # not make this script able to run: it now correctly identifies who should
  # be pushed to and then cannot reach any of them. Do not read a clean
  # `git log` here as a working renewal. See README.md, "The transport is
  # the blocker", for the /tool fetch + /certificate import route over 8728
  # that would actually work, and what still has to be proven about it.
  RDNS="$(SSHPASS="$RPASS" sshpass -e ssh -n -o StrictHostKeyChecking=accept-new \
          -o ConnectTimeout=15 "${ROUTER_SSH_USER}@${RADDR}" \
          ':put [/ip hotspot profile get [find name=hsprof1] dns-name]' 2>/dev/null | tr -d '\r' | tail -1)"
  if [[ -z "$RDNS" ]]; then
    log "ERROR: ${RNAME} (${RADDR}) -- could not read hsprof1 dns-name over SSH. As of 2026-09-06 the expected cause is that tcp/22 is firewalled shut on these devices and only 8728/8729 answer; check that before assuming a wrong credential or a missing hotspot profile. Skipping."
    FAIL_COUNT=$((FAIL_COUNT+1)); continue
  fi
  if ! printf '%s\n' "$CERT_SANS" | grep -qxF "$RDNS"; then
    log "ERROR: ${RNAME} redirects guests to '${RDNS}', which this certificate does not cover -- skipping rather than installing a certificate that would warn every guest"
    FAIL_COUNT=$((FAIL_COUNT+1)); continue
  fi

  log "pushing to ${RNAME} (${RADDR}), dns-name '${RDNS}', cert name '${RCERTNAME}'"

  UP_FULLCHAIN="${RCERTNAME}.fullchain.pem"
  UP_PRIVKEY="${RCERTNAME}.privkey.pem"

  if ! SSHPASS="$RPASS" sshpass -e scp -o StrictHostKeyChecking=accept-new \
        "$FULLCHAIN" "${ROUTER_SSH_USER}@${RADDR}:${UP_FULLCHAIN}" \
        2>&1 | logger -t "$LOG_TAG"; then
    log "ERROR: scp fullchain to ${RNAME} failed, skipping this router"
    FAIL_COUNT=$((FAIL_COUNT+1)); continue
  fi
  if ! SSHPASS="$RPASS" sshpass -e scp -o StrictHostKeyChecking=accept-new \
        "$PRIVKEY" "${ROUTER_SSH_USER}@${RADDR}:${UP_PRIVKEY}" \
        2>&1 | logger -t "$LOG_TAG"; then
    log "ERROR: scp privkey to ${RNAME} failed, skipping this router"
    FAIL_COUNT=$((FAIL_COUNT+1)); continue
  fi

  # Single combined RouterOS command (one ssh invocation, semicolon-chained)
  # -- splitting the ssl-certificate+login-by rebind across separate `set`
  # calls is what silently no-op'd earlier in this incident, so everything
  # that must land atomically lives in one remote script string:
  #   1. clear any stale intermediate/root artifacts from a PRIOR renewal
  #      (they keep the ephemeral "<file>_1"/"<file>_2" names every import
  #      of the same filename reuses, so they'd collide otherwise), AND any
  #      stale stable "<name>-chain-N" objects from a prior round (step 7)
  #   2. import the fresh fullchain (leaf+intermediate(s), 2-3+ objects,
  #      depending on how many CAs are in Let's Encrypt's current chain --
  #      do not assume exactly 3) + privkey
  #   3. rename+trust the new leaf under a NOT-yet-bound temp name, so the
  #      currently-live cert is never deleted while still referenced
  #   4. rebind hsprof1 to the new leaf (ssl-certificate + login-by together)
  #   5. only now remove the old leaf (safe: nothing references it anymore)
  #   6. rename the new leaf onto the stable name for next round
  #   7. rename EVERY remaining fullchain.pem_N object (the intermediate(s)
  #      -- whatever RouterOS didn't already dedupe against an existing
  #      identical object) onto a stable "<name>-chain-N" name and mark
  #      trusted=yes. This step is the fix for a real incident (2026-08-18):
  #      an earlier version of this script deleted these via the SAME
  #      broad "remove [find name~...fullchain.pem]" sweep now used only in
  #      step 1, but run a second time at the very end -- which, by then,
  #      only matched the still-ephemerally-named intermediate/root objects
  #      (the leaf had already been renamed away in step 3) and deleted
  #      them right after importing them. RouterOS's hotspot TLS server
  #      builds the served chain dynamically from whatever trusted
  #      certificate objects are present in the store and issuer-link
  #      (skid/akid) to the bound leaf -- it does NOT require an explicit
  #      `ca=` field, but it very much requires the intermediate object to
  #      still exist. Losing it meant the router kept serving the leaf
  #      alone: genuinely Let's-Encrypt-issued, chain-of-trust verifiable
  #      offline, but incomplete on the wire -- exactly the shape of gap
  #      strict/embedded TLS clients (no AIA fetching) reject outright while
  #      full desktop browsers often paper over. Confirmed via
  #      `/certificate print detail` (only one object for the new cert, no
  #      matching intermediate, orphaned `akid`) and fixed live by
  #      re-importing just the missing chain certs (RouterOS deduped the
  #      already-present leaf automatically) without ever touching the
  #      already-bound, already-working leaf/hsprof1 binding.
  #   8. final sweep of the ephemeral fullchain.pem_* pattern -- by this
  #      point everything wanted has already been renamed off that pattern
  #      in steps 3 and 7, so this is a true no-op safety net, not a
  #      deletion mechanism (unlike the bug this replaces).
  REMOTE_SCRIPT="/certificate remove [find name~\"${RCERTNAME}.fullchain.pem\"];
/certificate remove [find name~\"${RCERTNAME}-chain-\"];
/certificate import file-name=${UP_FULLCHAIN} passphrase=\"\";
/certificate import file-name=${UP_PRIVKEY} passphrase=\"\";
:delay 1s;
/certificate set [find name=\"${RCERTNAME}.fullchain.pem_0\"] name=\"${RCERTNAME}-new\" trusted=yes;
/ip hotspot profile set [find name=hsprof1] ssl-certificate=\"${RCERTNAME}-new\" login-by=https,http-pap;
:delay 1s;
/certificate remove [find name=\"${RCERTNAME}\"];
/certificate set [find name=\"${RCERTNAME}-new\"] name=\"${RCERTNAME}\";
:local chainIdx 1; :foreach chainCert in=[/certificate find name~\"${RCERTNAME}.fullchain.pem\"] do={ :local newName (\"${RCERTNAME}-chain-\" . \$chainIdx); /certificate set \$chainCert name=\$newName trusted=yes; :set chainIdx (\$chainIdx + 1); }
/certificate remove [find name~\"${RCERTNAME}.fullchain.pem\"]"

  if ! SSHPASS="$RPASS" sshpass -e ssh -n -o StrictHostKeyChecking=accept-new \
        "${ROUTER_SSH_USER}@${RADDR}" "$REMOTE_SCRIPT" 2>&1 | logger -t "$LOG_TAG"; then
    log "ERROR: remote import/rebind on ${RNAME} failed -- router may be left on its PREVIOUS cert (rebind only happens after successful import in the command chain above), needs manual check"
    FAIL_COUNT=$((FAIL_COUNT+1)); continue
  fi

  PUSHED_COUNT=$((PUSHED_COUNT+1))
  log "OK: ${RNAME} rebound to renewed cert"
done <<< "$INVENTORY"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  log "FINISHED WITH ${FAIL_COUNT} FAILURE(S), ${PUSHED_COUNT} pushed -- see above, needs a human"
  exit 1
fi

# A run that reached nobody is a failure even with no per-router error: it
# means the loop never executed, which is what a consumed stdin or an empty
# read would look like. Reporting success there is the shape this rewrite
# exists to remove.
if [[ "$PUSHED_COUNT" -eq 0 ]]; then
  log "FATAL: ${ROUTER_COUNT} router(s) were listed but none was pushed to"
  exit 1
fi

touch "$PUSH_STAMP"
log "all ${PUSHED_COUNT} router(s) updated successfully"
