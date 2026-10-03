#!/bin/sh
# STAGING ONLY. Write the shared Aruba listener's client file with a random
# 48-char secret that is never printed, stored or known to anyone: the
# listener (UDP 1912/1913) then drops/rejects every packet until the platform
# sets the real secret (Master > Aruba shared secret > Rotate, which calls the
# agent's POST /radius/shared-client). Usage: aruba-shared-placeholder.sh FILE
set -eu
f="$1"
s=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48)
umask 077
cat > "$f" <<CONF
# PLACEHOLDER: no real secret set yet (radius_agent.py replaces this file).
client wyfy-aruba-shared-v4 {
	ipaddr = 0.0.0.0/0
	secret = $s
	shortname = wyfy-aruba-shared
	backend_secret = $s
	require_message_authenticator = yes
	nas_type = other
}
client wyfy-aruba-shared-v6 {
	ipv6addr = ::/0
	secret = $s
	shortname = wyfy-aruba-shared
	backend_secret = $s
	require_message_authenticator = yes
	nas_type = other
}
CONF
