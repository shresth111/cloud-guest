#!/usr/bin/env bash
# FS-4 acceptance checks for the CWMP edge. Read-only: it creates no device,
# credential or task. Run from the LAPTOP (the "not reachable from outside"
# checks only mean something from outside the box).
#
#   ACS_HOST=acs-staging.wyfyguest.com BOX_IP=13.207.123.212 \
#   GOOD_USER=isp-xxxxxxxx GOOD_PASS='...' ./smoke-acs.sh
#
# GOOD_USER/GOOD_PASS: an ACS credential minted on STAGING (Master create or
# GET /isp/tr069/acs). Leave them unset to run only the negative checks.
set -uo pipefail

ACS_HOST="${ACS_HOST:-acs-staging.wyfyguest.com}"
BOX_IP="${BOX_IP:?set BOX_IP to the staging box public IP (aws ec2 describe-instances)}"
fail=0
check() { # check NAME EXPECTED ACTUAL
  if [[ "$2" == "$3" ]]; then echo "PASS  $1 ($3)"; else echo "FAIL  $1: expected $2, got $3"; fail=1; fi
}

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "https://$ACS_HOST/")
check "no credential -> 401" 401 "$code"

hdr=$(curl -s -D - -o /dev/null -X POST "https://$ACS_HOST/" | tr -d '\r' | grep -i '^www-authenticate:' || true)
check "401 carries Basic challenge" 'WWW-Authenticate: Basic realm="wyfy-acs"' "$hdr"

code=$(curl -s -o /dev/null -w '%{http_code}' -u 'isp-00000000:wrong' -X POST "https://$ACS_HOST/")
check "wrong credential -> 401" 401 "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' "https://$ACS_HOST/api/v1/health/live")
check "ACS host never proxies /api" 404 "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' "http://$ACS_HOST/")
check "port 80 -> https" 301 "$code"

if [[ -n "${GOOD_USER:-}" && -n "${GOOD_PASS:-}" ]]; then
  # An empty POST with no session is answered by GenieACS itself (it is not
  # an Inform, so GenieACS replies "Invalid session"); the point is that it is
  # GenieACS answering and not the edge's 401.
  code=$(curl -s -o /dev/null -w '%{http_code}' -u "$GOOD_USER:$GOOD_PASS" -X POST "https://$ACS_HOST/")
  if [[ "$code" != "401" && "$code" != "500" && "$code" != "502" ]]; then
    echo "PASS  good credential reaches GenieACS ($code)"
  else
    echo "FAIL  good credential: got $code (401 = acs-auth rejected; 500 = acs-auth unreachable or gate secret wrong; 502 = cwmp down)"; fail=1
  fi
fi

for port in 7547 7557 7567 27017; do
  if nc -z -G 3 "$BOX_IP" "$port" 2>/dev/null || nc -z -w 3 "$BOX_IP" "$port" 2>/dev/null; then
    echo "FAIL  port $port reachable from outside"; fail=1
  else
    echo "PASS  port $port closed from outside"
  fi
done

exit $fail
