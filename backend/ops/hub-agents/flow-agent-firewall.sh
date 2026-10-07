#!/bin/sh
# Host firewall for the NetFlow collector and flow agent. NOT DEPLOYED.
# Same posture as wyfy-agent-firewall.sh (defence in depth behind the SG,
# which cannot see inside the WireGuard tunnel).
#
#   UDP 2055 (nfacctd)  -- only from router tunnel addresses on wg0.
#   TCP 9094 (flow_agent) -- only from the app server(s) by private /32,
#                            never from the tunnel: a router has no business
#                            reading other venues' flow windows.
#
# Set APP_SOURCES to the app server's private /32 (and the staging server's,
# if staging should read the same hub). Resolve with
# `aws ec2 describe-instances`, never a remembered IP.
IPT=/usr/sbin/iptables
APP_SOURCES="${APP_SOURCES:-172.31.38.118/32}"

$IPT -C INPUT -i wg0 -p udp --dport 2055 -s 10.20.0.0/24 -j ACCEPT 2>/dev/null || \
    $IPT -I INPUT 1 -i wg0 -p udp --dport 2055 -s 10.20.0.0/24 -j ACCEPT
$IPT -C INPUT -p udp --dport 2055 -j DROP 2>/dev/null || \
    $IPT -A INPUT -p udp --dport 2055 -j DROP

for src in 127.0.0.1/32 $APP_SOURCES; do
    $IPT -C INPUT -p tcp --dport 9094 -s "$src" -j ACCEPT 2>/dev/null || \
        $IPT -I INPUT 1 -p tcp --dport 9094 -s "$src" -j ACCEPT
done
$IPT -C INPUT -p tcp --dport 9094 -j DROP 2>/dev/null || \
    $IPT -A INPUT -p tcp --dport 9094 -j DROP
