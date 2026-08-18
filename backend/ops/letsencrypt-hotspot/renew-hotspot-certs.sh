#!/usr/bin/env bash
# Renews the wyfy-hotspot-fleet Let's Encrypt cert (DNS-01 via GoDaddy) and,
# only when a renewal actually happened, re-imports + rebinds it on every
# router listed in ROUTERS below. Meant to run unattended via
# wyfy-hotspot-cert-renew.timer (systemd). See README.md in this directory
# for the full story and how to extend ROUTERS to the rest of the fleet.
set -euo pipefail

CERT_NAME="wyfy-hotspot-fleet"
LIVE_DIR="/etc/letsencrypt/live/${CERT_NAME}"
ROUTER_ENV="/etc/wyfy/router-ssh.env"
LOG_TAG="wyfy-hotspot-cert-renew"

log() { logger -t "$LOG_TAG" -- "$*"; echo "[$(date -Is)] $*"; }

# --- Fleet inventory -------------------------------------------------------
# One line per router: NAME|management-address(WireGuard)|stable RouterOS
# cert name to bind on that router. All routers currently share one cert
# (SANs: wifi.wyfyguest.com, *.portal.wyfyguest.com, portal.wyfyguest.com)
# and one SSH credential (ROUTER_SSH_USER/PASSWORD below) -- see README's
# "Fleet rollout" section for exactly what's still missing to safely add
# cg-04f81868 / cg-c61ae7af / cg-5d3a509e here (per-router dns-name has not
# been confirmed for any of them, and a shared password across the whole
# fleet is a real, known gap, not an oversight).
ROUTERS=(
  "WYFY-GUEST|10.20.0.50|wyfy-hotspot-fleet"
)

[[ -f "$ROUTER_ENV" ]] || { log "FATAL: missing $ROUTER_ENV"; exit 1; }
# shellcheck disable=SC1090
source "$ROUTER_ENV"
: "${ROUTER_SSH_USER:?missing in $ROUTER_ENV}"
: "${ROUTER_SSH_PASSWORD:?missing in $ROUTER_ENV}"

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
if [[ "${FORCE_RENEW:-0}" == "1" ]]; then
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

log "cert renewed -- pushing to ${#ROUTERS[@]} router(s)"

FULLCHAIN="${LIVE_DIR}/fullchain.pem"
PRIVKEY="${LIVE_DIR}/privkey.pem"
[[ -f "$FULLCHAIN" && -f "$PRIVKEY" ]] || { log "FATAL: renewed but ${FULLCHAIN}/${PRIVKEY} missing"; exit 1; }

FAIL_COUNT=0
for entry in "${ROUTERS[@]}"; do
  IFS='|' read -r RNAME RADDR RCERTNAME <<< "$entry"
  log "pushing to ${RNAME} (${RADDR}), cert name '${RCERTNAME}'"

  UP_FULLCHAIN="${RCERTNAME}.fullchain.pem"
  UP_PRIVKEY="${RCERTNAME}.privkey.pem"

  if ! SSHPASS="$ROUTER_SSH_PASSWORD" sshpass -e scp -o StrictHostKeyChecking=accept-new \
        "$FULLCHAIN" "${ROUTER_SSH_USER}@${RADDR}:${UP_FULLCHAIN}" \
        2>&1 | logger -t "$LOG_TAG"; then
    log "ERROR: scp fullchain to ${RNAME} failed, skipping this router"
    FAIL_COUNT=$((FAIL_COUNT+1)); continue
  fi
  if ! SSHPASS="$ROUTER_SSH_PASSWORD" sshpass -e scp -o StrictHostKeyChecking=accept-new \
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

  if ! SSHPASS="$ROUTER_SSH_PASSWORD" sshpass -e ssh -o StrictHostKeyChecking=accept-new \
        "${ROUTER_SSH_USER}@${RADDR}" "$REMOTE_SCRIPT" 2>&1 | logger -t "$LOG_TAG"; then
    log "ERROR: remote import/rebind on ${RNAME} failed -- router may be left on its PREVIOUS cert (rebind only happens after successful import in the command chain above), needs manual check"
    FAIL_COUNT=$((FAIL_COUNT+1)); continue
  fi

  log "OK: ${RNAME} rebound to renewed cert"
done

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  log "FINISHED WITH ${FAIL_COUNT} FAILURE(S) -- see above, needs a human"
  exit 1
fi

log "all routers updated successfully"
