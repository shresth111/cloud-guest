#!/bin/bash
# STAGING ONLY. Enrol / remove RadSec client certificates on the staging hub.
# Run as root on wyfy-staging-server. Never prints a secret (fingerprints only).
#
#   radsec-map.sh list
#   radsec-map.sh add <nas-shortname> --cert <leaf.pem>          # CN + issuer read from the cert
#   radsec-map.sh add <nas-shortname> --cn <CN> --issuer <DN>    # e.g. from radsec-capture.sh
#   radsec-map.sh del <CN>
#   radsec-map.sh trust-add <name> <ca.pem>    # add a device CA to trust.pem (e.g. Aruba's)
#   radsec-map.sh trust-del <name>
#   radsec-map.sh issue <CN> <outdir>          # client cert from the staging TEST CA (tests only)
#
# `add` reads the backend secret from stdin: it must be the NAS's shared secret
# as stored (encrypted) in the staging DB, i.e. what CurrentNas compares
# X-RADIUS-Shared-Secret against. The device never sees it: over RadSec the
# RADIUS secret on the wire is the fixed string "radsec".
# The DN form is OpenSSL's compat one-line form (`/C=US/O=.../CN=...`), which is
# exactly what FreeRADIUS puts in TLS-Client-Cert-Issuer.
set -euo pipefail
RD=${RD:-/home/ubuntu/deploy/staging-radius/radsec}
MAP=$RD/state/radsec-map
CT=${RADSEC_CONTAINER:-wyfy-staging-radius-radsec-1}
fp() { printf '%s' "$1" | sha256sum | cut -c1-12; }
die() { echo "radsec-map: $*" >&2; exit 1; }
restart() {
  local since; since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker restart "$CT" >/dev/null
  for _ in $(seq 1 40); do docker logs --since "$since" "$CT" 2>&1 | grep -q 'Ready to process requests' && { echo "radsec-map: $CT restarted"; return 0; }; sleep 1; done
  docker logs --since "$since" "$CT" 2>&1 | tail -20; die "$CT did not come back"
}
rebuild_trust() {
  cat "$RD/ca/test-ca.pem" $(ls "$RD"/trust.d/*.pem 2>/dev/null) > "$RD/certs/trust.pem.new"
  chmod 0644 "$RD/certs/trust.pem.new"; mv "$RD/certs/trust.pem.new" "$RD/certs/trust.pem"
}
cert_cn()     { openssl x509 -in "$1" -noout -subject -nameopt compat | sed -n 's#.*/CN=\([^/]*\).*#\1#p'; }
cert_issuer() { openssl x509 -in "$1" -noout -issuer -nameopt compat | sed 's/^issuer=//'; }
[ -e "$MAP" ] || { install -m 0640 -g 101 /dev/null "$MAP"; }

cmd=${1:-list}; shift || true
case "$cmd" in
list)
  echo "CN | nas | backend-secret fp | issuer"
  while IFS='|' read -r cn nas sec iss; do
    [ -n "$cn" ] && echo "$cn | $nas | $(fp "$sec") len=${#sec} | $iss"
  done < "$MAP"
  echo "-- trust.pem: $(grep -c 'BEGIN CERTIFICATE' "$RD/certs/trust.pem") CA(s): test CA + $(ls "$RD"/trust.d/ 2>/dev/null | tr '\n' ' ')"
  ;;
add)
  nas=${1:?nas shortname}; shift
  cn=""; iss=""
  while [ $# -gt 0 ]; do case "$1" in
    --cert) cn=$(cert_cn "$2"); iss=$(cert_issuer "$2"); shift 2;;
    --cn) cn=$2; shift 2;;
    --issuer) iss=$2; shift 2;;
    *) die "unknown arg $1";; esac; done
  [[ "$nas" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "bad nas shortname"
  [ -n "$cn" ] && [ -n "$iss" ] || die "need a CN and an issuer"
  [[ "$cn$iss" != *"|"* && "$cn$iss" != *$'\n'* ]] || die "CN/issuer may not contain | or newline"
  IFS= read -r sec || true
  [[ "$sec" =~ ^[A-Za-z0-9]{16,128}$ ]] || die "backend secret on stdin must be 16-128 alphanumerics"
  tmp=$(mktemp "$MAP.XXXXXX")
  awk -F'|' -v cn="$cn" '$1 != cn' "$MAP" > "$tmp"
  printf '%s|%s|%s|%s\n' "$cn" "$nas" "$sec" "$iss" >> "$tmp"
  chgrp 101 "$tmp"; chmod 0640 "$tmp"; mv "$tmp" "$MAP"
  echo "radsec-map: enrolled cn=\"$cn\" issuer=\"$iss\" -> nas=$nas secret fp=$(fp "$sec") len=${#sec}"
  restart
  ;;
del)
  cn=${1:?CN}
  grep -q "^$(printf '%s' "$cn" | sed 's/[][\.*^$/]/\\&/g')|" "$MAP" || die "not enrolled: $cn"
  tmp=$(mktemp "$MAP.XXXXXX")
  awk -F'|' -v cn="$cn" '$1 != cn' "$MAP" > "$tmp"
  chgrp 101 "$tmp"; chmod 0640 "$tmp"; mv "$tmp" "$MAP"
  echo "radsec-map: removed cn=\"$cn\""
  restart
  ;;
trust-add)
  name=${1:?name}; ca=${2:?ca.pem}
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad name"
  openssl x509 -in "$ca" -noout >/dev/null 2>&1 || die "$ca is not a PEM certificate"
  install -m 0644 "$ca" "$RD/trust.d/$name.pem"; rebuild_trust
  echo "radsec-map: trusted $name: $(openssl x509 -in "$ca" -noout -subject -nameopt compat) sha256=$(openssl x509 -in "$ca" -noout -fingerprint -sha256 | cut -d= -f2)"
  restart
  ;;
trust-del)
  name=${1:?name}; rm -f "$RD/trust.d/$name.pem"; rebuild_trust; echo "radsec-map: untrusted $name"; restart
  ;;
issue)
  cn=${1:?CN}; out=${2:?outdir}; install -d -m 0700 "$out"
  ( umask 077
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$out/client.key" -out "$out/client.csr" -subj "/O=Wyfy Guest STAGING/CN=$cn" 2>/dev/null
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$out/ext"
    openssl x509 -req -in "$out/client.csr" -CA "$RD/ca/test-ca.pem" -CAkey "$RD/ca/test-ca.key" -CAcreateserial \
      -CAserial "$RD/ca/test-ca.srl" -days 30 -extfile "$out/ext" -out "$out/client.pem" 2>/dev/null
    rm -f "$out/client.csr" "$out/ext" )
  echo "radsec-map: issued $out/client.pem cn=\"$(cert_cn "$out/client.pem")\" issuer=\"$(cert_issuer "$out/client.pem")\""
  ;;
*) die "unknown command $cmd";;
esac
