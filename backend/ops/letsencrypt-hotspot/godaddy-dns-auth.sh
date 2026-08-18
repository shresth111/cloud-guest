#!/usr/bin/env bash
# Certbot manual DNS-01 auth hook for wyfyguest.com's GoDaddy-hosted zone.
# certbot invokes this once per SAN in the cert (once per --manual-auth-hook
# call), with CERTBOT_DOMAIN (validation domain -- a wildcard's leading "*."
# is already stripped by certbot before this runs) and CERTBOT_VALIDATION
# (the token to publish) set in the environment.
#
# See ../README.md for the full story. Two things worth knowing before
# touching this file again:
#
# 1. This deliberately uses GoDaddy's PATCH /v1/domains/{domain}/records
#    endpoint (additive) rather than PUT .../records/TXT/{name} (which
#    REPLACES every record at that name). *.portal.wyfyguest.com and
#    portal.wyfyguest.com both validate against the identical record name
#    (_acme-challenge.portal) in the same certbot run -- a PUT from the
#    second auth-hook call would silently clobber the first call's
#    still-pending token and break that domain's validation.
# 2. It polls GoDaddy's own authoritative nameserver (not a public
#    resolver) before returning, so certbot doesn't ask Let's Encrypt to
#    validate before the record is actually live -- a plain "sleep N" would
#    be a guess, this checks the real thing.
set -euo pipefail

ZONE="wyfyguest.com"
ENV_FILE="/etc/wyfy/godaddy-dns.env"
AUTH_NS="ns11.domaincontrol.com"

# shellcheck disable=SC1090
source "$ENV_FILE"
: "${GODADDY_API_KEY:?missing in $ENV_FILE}"
: "${GODADDY_API_SECRET:?missing in $ENV_FILE}"
: "${CERTBOT_DOMAIN:?certbot did not set CERTBOT_DOMAIN}"
: "${CERTBOT_VALIDATION:?certbot did not set CERTBOT_VALIDATION}"

if [[ "$CERTBOT_DOMAIN" == "$ZONE" ]]; then
  RECORD_NAME="_acme-challenge"
else
  SUB="${CERTBOT_DOMAIN%.$ZONE}"
  RECORD_NAME="_acme-challenge.${SUB}"
fi

echo "[godaddy-dns-auth] ${CERTBOT_DOMAIN}: adding TXT ${RECORD_NAME}.${ZONE}" >&2

TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"' EXIT

HTTP_CODE=$(curl -s -o "$TMP_OUT" -w '%{http_code}' \
  -X PATCH "https://api.godaddy.com/v1/domains/${ZONE}/records" \
  -H "Authorization: sso-key ${GODADDY_API_KEY}:${GODADDY_API_SECRET}" \
  -H "Content-Type: application/json" \
  -d "[{\"type\":\"TXT\",\"name\":\"${RECORD_NAME}\",\"data\":\"${CERTBOT_VALIDATION}\",\"ttl\":600}]")

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "[godaddy-dns-auth] GoDaddy API PATCH failed (HTTP ${HTTP_CODE}): $(cat "$TMP_OUT")" >&2
  exit 1
fi

echo "[godaddy-dns-auth] waiting for propagation on ${AUTH_NS}..." >&2
for i in $(seq 1 20); do
  FOUND=$(dig +short TXT "${RECORD_NAME}.${ZONE}" "@${AUTH_NS}" 2>/dev/null | tr -d '"')
  if [[ "$FOUND" == *"$CERTBOT_VALIDATION"* ]]; then
    echo "[godaddy-dns-auth] confirmed live after ~$((i*15))s" >&2
    exit 0
  fi
  sleep 15
done

echo "[godaddy-dns-auth] WARNING: not confirmed on ${AUTH_NS} after 5m, proceeding anyway (Let's Encrypt's own validation attempt is the real check)" >&2
exit 0
