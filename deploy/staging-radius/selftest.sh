#!/bin/bash
# STAGING ONLY. End-to-end self-test of the staging RADIUS hub, no AP needed.
# Run as root on wyfy-staging-server:
#   ~/wyfy-ops/ssm-run-on.sh i-0a6a08bb87c6f0f84 deploy/staging-radius/selftest.sh
#  1. registers a throwaway stanza (127.0.0.1, cg-staging-selftest) through the
#     agent FROM INSIDE deploy-api-1 using the api's own settings -- proves the
#     backend -> agent URL + secret;
#  2. radclient from 127.0.0.1 (host network): Access-Request with
#     Message-Authenticator, the same with a wrong secret, one without
#     Message-Authenticator, and an Accounting-Request Start;
#  3. shows the staging api's /radius/authorize + /radius/accounting log lines;
#  4. removes the stanza and checks it is gone.
# The NAS has no row in the staging DB, so the backend answers 401 and the
# Access-Request ends in Access-Reject: that proves the whole path. An
# Access-Accept needs a registered NAS + guest session (the real AP flow).
set -uo pipefail
NAS=cg-staging-selftest
R=wyfy-staging-radius-radius-1
A=deploy-api-1
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
S=$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)),end="")')
PASS=0; FAIL=0
res() { if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "PASS $2"; else FAIL=$((FAIL+1)); echo "FAIL $2"; fi; }

agent() {  # agent <POST|DELETE>
  docker exec -e T_SECRET="$S" -e T_NAS="$NAS" -e T_METHOD="$1" $A python -c '
import os, httpx
from app.core.config import get_settings
s = get_settings()
body = {"nas_identifier": os.environ["T_NAS"]}
if os.environ["T_METHOD"] == "POST":
    body |= {"address": "127.0.0.1", "secret": os.environ["T_SECRET"], "require_message_authenticator": True}
r = httpx.request(os.environ["T_METHOD"], s.hub_radius_agent_url, headers={"X-Agent-Secret": s.hub_radius_agent_secret}, json=body, timeout=40)
print(r.status_code, r.text)'
}

AUTH='User-Name = "+919999900001"
User-Password = "portal-issued-token"
Calling-Station-Id = "a4c3f0112233"
Service-Type = Login-User
NAS-IP-Address = 192.168.1.23
NAS-Identifier = "wyfy-ap21-selftest"
NAS-Port-Type = Wireless-802.11
Called-Station-Id = "d4e053a21a21"'
ACCT='Acct-Status-Type = Start
User-Name = "+919999900001"
Calling-Station-Id = "a4c3f0112233"
Acct-Session-Id = "SELFTEST-0000A21A"
NAS-IP-Address = 192.168.1.23
NAS-Identifier = "wyfy-ap21-selftest"
NAS-Port-Type = Wireless-802.11
Acct-Input-Octets = 1000
Acct-Output-Octets = 2000
Message-Authenticator = 0x00'
rc() { docker exec -i $R radclient -x -r 1 -t 3 127.0.0.1:$1 $2 "$3" 2>&1; }

echo "== 1. register $NAS @127.0.0.1 via agent, from inside $A"
out=$(agent POST); echo "$out"; [[ "$out" == 200* ]]; res $? "agent POST from api container"
docker exec $R grep -A7 "shortname = $NAS" /etc/freeradius/3.0/clients.conf | sed -E 's/(secret = ).*/\1<redacted>/'
sleep 1

echo "== 2. radclient from 127.0.0.1"
o=$(printf '%s\nMessage-Authenticator = 0x00\n' "$AUTH" | rc 1812 auth "$S"); echo "$o" | grep -E 'Received|No reply'
echo "$o" | grep -q 'Received Access-Reject'; res $? "T1 Access-Request + Message-Authenticator -> Access-Reject (backend 401: NAS not in staging DB)"
o=$(printf '%s\nMessage-Authenticator = 0x00\n' "$AUTH" | rc 1812 auth "${S%?}X"); echo "$o" | grep -E 'Received|No reply'
echo "$o" | grep -q 'No reply'; res $? "T2 wrong secret -> silently dropped"
o=$(printf '%s\n' "$AUTH" | rc 1812 auth "$S"); echo "$o" | grep -E 'Received|No reply'
echo "$o" | grep -q 'No reply'; res $? "T3 no Message-Authenticator -> dropped"
o=$(printf '%s\n' "$ACCT" | rc 1813 acct "$S"); echo "$o" | grep -E 'Received|No reply'
echo "$o" | grep -q 'Received Accounting-Response'; res $? "T4 Accounting-Request Start -> Accounting-Response"

echo "== 3. staging api saw it ($A, since $START)"
L=$(docker logs --since "$START" $A 2>&1 | grep -E '/radius/(authorize|accounting)')
echo "$L" | tail -n 8
echo "$L" | grep -q '/radius/authorize'; res $? "api received POST /radius/authorize"
echo "$L" | grep -q '/radius/accounting'; res $? "api received POST /radius/accounting"
echo "-- freeradius log since start"
docker logs --since "$START" $R 2>&1 | grep -vE '^\s*$' | tail -n 12

echo "== 4. cleanup"
out=$(agent DELETE); echo "$out"; [[ "$out" == 200* ]]; res $? "agent DELETE"
! docker exec $R grep -q "shortname = $NAS" /etc/freeradius/3.0/clients.conf; res $? "stanza gone from clients.conf"
echo "== $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
