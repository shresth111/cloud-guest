#!/bin/sh
# Host-level firewall for the Wyfy hub management agents. Defence in depth
# BEHIND wyfy-prod-hub-nsg -- the NSG cannot see traffic that arrives inside
# the WireGuard tunnel (it only sees the encrypted UDP/51820 outer packet),
# so the NSG alone can NOT stop a compromised router from reaching these
# ports over wg0. That is exactly why this file has to exist as well.
#
# Allowed sources for 9091 (wg_agent) and 9092 (radius_agent):
#   - 127.0.0.1        local
#   - 10.30.1.0/24     the app subnet -- the backend is the ONLY real caller
#                      (app/domains/wireguard/router.py and
#                       app/domains/guest/router.py post to these agents)
# Everything else is DROPped, INCLUDING the WireGuard tunnel 10.20.0.0/24.
#
# NOTE this is STRICTER than the old radius-wg-vm, whose
# radius-agent-firewall.sh allowed 10.20.0.0/24. Nothing on a router calls
# these agents (verified by full grep of backend + frontend), so the tunnel
# allowance was unnecessary standing authority for any compromised router to
# add/remove RADIUS clients and WireGuard peers. To revert, add:
#   $IPT -I INPUT 1 -p tcp --dport $p -s 10.20.0.0/24 -j ACCEPT
#
# 9093 (config_agent) is deliberately NOT opened at all -- that bridge was
# retired backend-side (PR #53, commit 3ac8b94) and nothing calls it.
IPT=/usr/sbin/iptables
for p in 9091 9092; do
    $IPT -C INPUT -p tcp --dport $p -s 127.0.0.1 -j ACCEPT 2>/dev/null || \
        $IPT -I INPUT 1 -p tcp --dport $p -s 127.0.0.1 -j ACCEPT
    $IPT -C INPUT -p tcp --dport $p -s 10.30.1.0/24 -j ACCEPT 2>/dev/null || \
        $IPT -I INPUT 1 -p tcp --dport $p -s 10.30.1.0/24 -j ACCEPT
    $IPT -C INPUT -p tcp --dport $p -j DROP 2>/dev/null || \
        $IPT -A INPUT -p tcp --dport $p -j DROP
done
# 9093 stays closed outright.
$IPT -C INPUT -p tcp --dport 9093 -j DROP 2>/dev/null || \
    $IPT -A INPUT -p tcp --dport 9093 -j DROP
