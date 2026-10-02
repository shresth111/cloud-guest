#!/bin/bash
# STAGING ONLY. End-to-end self-test of the RadSec (RADIUS/TLS, TCP 2083)
# listener, no AP needed. Run as root on wyfy-staging-server:
#   ~/wyfy-ops/ssm-run-on.sh i-0a6a08bb87c6f0f84 deploy/staging-radius/radsec-selftest.sh
#
#  R1  the listener presents a publicly-trusted chain for staging.wyfyguest.com
#      (what an AP with only a built-in trust store must accept);
#  R2  a client cert from the staging test CA, enrolled as NAS
#      `cg-radsec-selftest`, is used from TWO containers on two different docker
#      networks (two source IPs, neither registered anywhere): Access-Request and
#      Accounting-Request from each reach the staging api, and connections.log
#      shows both sources mapped to the same NAS;
#  R3  unenrolled cert (trusted CA) -> connection refused by
#      New-TLS-Connection, nothing reaches the api;
#  R4  cert from an untrusted CA -> TLS handshake refused;
#  R5  no client cert -> TLS handshake refused;
#  R6  the UDP 1812/1813 listeners are still up (run selftest.sh for the full UDP test).
# The selftest NAS has no row in the staging DB, so the backend answers 401: the
# Access-Request ends in Access-Reject and the accounting snippet still acks.
# That proves listener -> certificate mapping -> rest -> staging api; the header
# VALUES are proven against a header-checking mock in the offline lab
# (STAGING_RADSEC.md), and for real once a RadSec NAS is registered in the DB.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MAPSH="$HERE/radsec-map.sh"
[ -x "$MAPSH" ] || MAPSH=/home/ubuntu/deploy/staging-radius/src/deploy/staging-radius/radsec-map.sh
RD=/home/ubuntu/deploy/staging-radius/radsec
RS=wyfy-staging-radius-radsec-1
A=deploy-api-1
IMG=freeradius/freeradius-server:3.2.8
HOST=${RADSEC_HOST:-staging.wyfyguest.com}
NAS=cg-radsec-selftest
CN=wyfy-radsec-selftest-$(date +%s)
TARGET=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
T=$(mktemp -d /tmp/radsec-selftest.XXXXXX); chmod 0755 "$T"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PASS=0; FAIL=0
res() { if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "PASS $2"; else FAIL=$((FAIL+1)); echo "FAIL $2"; fi; }
cleanup() {
  docker rm -f radsec-st-a radsec-st-b radsec-st-c radsec-st-d >/dev/null 2>&1
  docker network rm radsec-st-net-a radsec-st-net-b >/dev/null 2>&1
  "$MAPSH" del "$CN" >/dev/null 2>&1
  rm -rf "$T"
}
trap cleanup EXIT
echo "target $TARGET:2083 (box private IP; the SG is not involved), selftest CN $CN"

echo "== R1 server certificate as an AP would see it"
o=$(echo | openssl s_client -connect 127.0.0.1:2083 -servername "$HOST" -verify_hostname "$HOST" \
      -verify_return_error -CAfile /etc/ssl/certs/ca-certificates.crt 2>&1)
echo "$o" | grep -E '^ *[0-9] s:|Verify return code|Protocol *:' | sed 's/^/   /'
echo "$o" | grep -q 'Verify return code: 0 (ok)'; res $? "R1 chain + hostname $HOST verify against the public CA bundle"

echo "== certificates for the test"
"$MAPSH" issue "$CN" "$T/good" | sed 's/^/   /'
"$MAPSH" issue "unenrolled-$CN" "$T/unenrolled" | sed 's/^/   /'
( umask 077; mkdir -p "$T/rogue"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -keyout "$T/rogue/ca.key" -out "$T/rogue/ca.pem" -subj "/CN=Rogue CA" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/rogue/client.key" -out "$T/rogue/c.csr" -subj "/O=Wyfy Guest STAGING/CN=$CN" 2>/dev/null
  printf 'extendedKeyUsage=clientAuth\n' > "$T/rogue/ext"
  openssl x509 -req -in "$T/rogue/c.csr" -CA "$T/rogue/ca.pem" -CAkey "$T/rogue/ca.key" -CAcreateserial -days 1 -extfile "$T/rogue/ext" -out "$T/rogue/client.pem" 2>/dev/null )
echo "   rogue: same CN, issued by an untrusted 'Rogue CA'"
chmod -R a+rX "$T"

BSEC=$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)))')
echo "$BSEC" | "$MAPSH" add "$NAS" --cert "$T/good/client.pem" | sed 's/^/   /'

proxy_conf() {  # proxy_conf <dir> <with-cert yes|no>
  cat > "$1/proxy.conf" <<PEOF
proxy server {
	default_fallback = no
}
home_server radsec {
	ipaddr = $TARGET
	port = 2083
	type = auth+acct
	secret = radsec
	proto = tcp
	status_check = none
	response_window = 8
	tls {
$( [ "$2" = yes ] && printf '\t\tprivate_key_file = /c/client.key\n\t\tcertificate_file = /c/client.pem\n' )
		ca_file = /etc/ssl/certs/ca-certificates.crt
		hostname = "$HOST"
		check_cert_cn = "$HOST"
		fragment_size = 8192
		tls_min_version = "1.2"
		tls_max_version = "1.2"
	}
}
home_server_pool radsec {
	type = fail-over
	home_server = radsec
}
realm NULL {
	auth_pool = radsec
	acct_pool = radsec
}
realm DEFAULT {
	auth_pool = radsec
	acct_pool = radsec
}
PEOF
}
client() {  # client <name> <network> <certdir>
  proxy_conf "$3" yes
  docker run -d --name "$1" --network "$2" -v "$3":/c:ro -v "$3/proxy.conf":/etc/freeradius/proxy.conf:ro \
    "$IMG" -f -l stdout >/dev/null
}
ask() {  # ask <container> <auth|acct> <attrs> -> radclient output (proxy on 127.0.0.1 inside the container)
  printf '%s\n' "$3" | docker exec -i "$1" radclient -x -r 1 -t 12 127.0.0.1 "$2" testing123 2>&1
}
UN="+9199999$(shuf -i 10000-99999 -n1)"
AUTH="User-Name = \"$UN\"
User-Password = \"portal-issued-token\"
Calling-Station-Id = \"a4c3f0112233\"
NAS-Identifier = \"wyfy-radsec-selftest\"
Called-Station-Id = \"d4e053a21a21\""
ACCT="Acct-Status-Type = Start
User-Name = \"$UN\"
Calling-Station-Id = \"a4c3f0112233\"
Acct-Session-Id = \"RADSEC-SELFTEST-$$\"
NAS-Identifier = \"wyfy-radsec-selftest\""

docker network create radsec-st-net-a >/dev/null && docker network create radsec-st-net-b >/dev/null
client radsec-st-a radsec-st-net-a "$T/good"
client radsec-st-b radsec-st-net-b "$T/good"
client radsec-st-c radsec-st-net-a "$T/unenrolled"
client radsec-st-d radsec-st-net-b "$T/rogue"
for c in radsec-st-a radsec-st-b radsec-st-c radsec-st-d; do
  for _ in $(seq 1 30); do docker logs "$c" 2>&1 | grep -q 'Ready to process' && break; sleep 1; done
done
for c in a b; do echo "   radsec-st-$c source address: $(docker inspect radsec-st-$c -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"; done

echo "== R2 enrolled cert from two source addresses"
for c in a b; do
  o=$(ask radsec-st-$c auth "$AUTH"); echo "$o" | grep -E 'Received|No reply' | sed "s/^/   [$c] /"
  echo "$o" | grep -q 'Received Access-Reject'; res $? "R2.$c Access-Request over RadSec -> answered (Access-Reject: backend 401, NAS not in staging DB)"
  o=$(ask radsec-st-$c acct "$ACCT"); echo "$o" | grep -E 'Received|No reply' | sed "s/^/   [$c] /"
  echo "$o" | grep -q 'Received Accounting-Response'; res $? "R2.$c Accounting-Request over RadSec -> Accounting-Response"
done
LOG=$(awk -v s="$(date -u -d "$START" '+%Y-%m-%d %H:%M:%S')" '$0 >= s' "$RD/state/connections.log")
echo "$LOG" | sed 's/^/   /'
SRCS=$(echo "$LOG" | grep "verdict=accept nas=$NAS cn=\"$CN\"" | sed -n 's/.* src=\([0-9.]*\):.*/\1/p' | sort -u)
[ "$(echo "$SRCS" | grep -c .)" -ge 2 ]; res $? "R2 two different source IPs ($(echo $SRCS)) both mapped to nas=$NAS"
L=$(docker logs --since "$START" $A 2>&1 | grep -E '"path":"/api/v1/radius/(authorize|accounting)"')
echo "$L" | cut -c1-220 | sed 's/^/   /' | tail -6
[ "$(echo "$L" | grep -c '/radius/authorize')" -ge 2 ]; res $? "R2 staging api received >=2 POST /radius/authorize"
[ "$(echo "$L" | grep -c '/radius/accounting')" -ge 2 ]; res $? "R2 staging api received >=2 POST /radius/accounting"

echo "== R3 trusted CA but not enrolled"
o=$(ask radsec-st-c auth "$AUTH"); echo "$o" | grep -E 'Received|No reply' | sed 's/^/   /'
echo "$LOG$(awk -v s="$(date -u -d "$START" '+%Y-%m-%d %H:%M:%S')" '$0 >= s' "$RD/state/connections.log")" | grep -q "verdict=reject-not-enrolled nas=none cn=\"unenrolled-$CN\""
res $? "R3 connection refused in New-TLS-Connection (verdict=reject-not-enrolled)"

echo "== R4 untrusted CA (same CN as the enrolled cert)"
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ask radsec-st-d auth "$AUTH" | grep -E 'Received|No reply' | sed 's/^/   /'
docker logs --since "$since" $RS 2>&1 | grep -E 'OpenSSL says|Alert' | head -2 | sed 's/^/   /'
docker logs --since "$since" $RS 2>&1 | grep -qE 'unable to get local issuer certificate|unknown CA'; res $? "R4 TLS handshake refused (unknown CA)"

echo "== R5 no client certificate"
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo | timeout 10 openssl s_client -connect 127.0.0.1:2083 -servername "$HOST" -tls1_2 >/dev/null 2>&1
sleep 1
docker logs --since "$since" $RS 2>&1 | grep -E 'Alert|certificate' | head -2 | sed 's/^/   /'
docker logs --since "$since" $RS 2>&1 | grep -qE 'handshake failure|peer did not return a certificate|certificate required'; res $? "R5 handshake refused without a client certificate"

echo "== R6 UDP listeners untouched"
ss -Hlun '( sport = :1812 or sport = :1813 )' | grep -q 1812; res $? "R6 udp/1812 + 1813 still listening (radius container)"
echo "== $PASS passed, $FAIL failed (selftest enrolment is removed on exit)"
[ $FAIL -eq 0 ]
