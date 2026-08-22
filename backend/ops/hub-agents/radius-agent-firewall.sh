#!/bin/sh
# Restrict radius-agent (port 9092) to: WireGuard tunnel (10.20.0.0/24),
# localhost, and cloudguest-vm's public egress IP (20.219.51.94 -- the
# backend hardcodes the hub's public IP rather than its WG tunnel IP for
# this call, confirmed in app/domains/guest/router.py). Everything else
# dropped. Added 2026-08-18: radius-agent.service was found bound to
# 0.0.0.0:9092 with zero host firewall (iptables INPUT policy ACCEPT, no
# rules at all) and was receiving unsolicited scans from random public IPs.
IPT=/usr/sbin/iptables
$IPT -C INPUT -p tcp --dport 9092 -s 127.0.0.1 -j ACCEPT 2>/dev/null || $IPT -I INPUT 1 -p tcp --dport 9092 -s 127.0.0.1 -j ACCEPT
$IPT -C INPUT -p tcp --dport 9092 -s 10.20.0.0/24 -j ACCEPT 2>/dev/null || $IPT -I INPUT 1 -p tcp --dport 9092 -s 10.20.0.0/24 -j ACCEPT
$IPT -C INPUT -p tcp --dport 9092 -s 20.219.51.94/32 -j ACCEPT 2>/dev/null || $IPT -I INPUT 1 -p tcp --dport 9092 -s 20.219.51.94/32 -j ACCEPT
$IPT -C INPUT -p tcp --dport 9092 -j DROP 2>/dev/null || $IPT -A INPUT -p tcp --dport 9092 -j DROP
