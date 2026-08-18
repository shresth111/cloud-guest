#!/usr/bin/env bash
# Certbot manual DNS-01 cleanup hook -- pairs with godaddy-dns-auth.sh.
# Runs after certbot has finished validating (all auth hooks run first,
# then all validations, then all cleanup hooks, for one certbot invocation
# -- so by the time this runs, nothing still needs the TXT record it's
# about to delete).
set -euo pipefail

ZONE="wyfyguest.com"
ENV_FILE="/etc/wyfy/godaddy-dns.env"

# shellcheck disable=SC1090
source "$ENV_FILE"
: "${GODADDY_API_KEY:?missing in $ENV_FILE}"
: "${GODADDY_API_SECRET:?missing in $ENV_FILE}"
: "${CERTBOT_DOMAIN:?certbot did not set CERTBOT_DOMAIN}"

if [[ "$CERTBOT_DOMAIN" == "$ZONE" ]]; then
  RECORD_NAME="_acme-challenge"
else
  SUB="${CERTBOT_DOMAIN%.$ZONE}"
  RECORD_NAME="_acme-challenge.${SUB}"
fi

echo "[godaddy-dns-cleanup] ${CERTBOT_DOMAIN}: removing TXT ${RECORD_NAME}.${ZONE}" >&2

TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"' EXIT

# DELETE removes every record at this type+name. Safe: nothing else ever
# legitimately owns an _acme-challenge.* name. *.portal.wyfyguest.com and
# portal.wyfyguest.com share this same name -- the second cleanup call for
# it will get a 404 (already deleted by the first), which is expected, not
# an error. This hook never fails the certbot run either way: a leftover
# TXT record is harmless clutter, not worth aborting a successful issuance
# over.
HTTP_CODE=$(curl -s -o "$TMP_OUT" -w '%{http_code}' \
  -X DELETE "https://api.godaddy.com/v1/domains/${ZONE}/records/TXT/${RECORD_NAME}" \
  -H "Authorization: sso-key ${GODADDY_API_KEY}:${GODADDY_API_SECRET}")

if [[ "$HTTP_CODE" != "204" && "$HTTP_CODE" != "404" ]]; then
  echo "[godaddy-dns-cleanup] WARNING: DELETE returned HTTP ${HTTP_CODE}: $(cat "$TMP_OUT") -- leaving stale record, not fatal" >&2
fi
exit 0
