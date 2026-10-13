# NetFlow / IPFIX collector (hub) — NOT DEPLOYED

Design, sizing, privacy, legal and the hardware plan: `~/wyfy-ops/netflow/DESIGN.md`.

| File | Goes to (hub) |
|---|---|
| `nfacctd.conf` | `/etc/pmacct/wyfy-nfacctd.conf` (`apt install pmacct`) |
| `../hub-agents/flow_agent.py` | `/usr/local/sbin/flow_agent.py` |
| `../hub-agents/systemd/wyfy-pmacct.sysusers.conf` | `/etc/sysusers.d/wyfy-pmacct.conf`, then `systemd-sysusers`. Debian's pmacct package creates no `pmacct` user and both units run as it |
| `../hub-agents/flow-agent-firewall.sh` | `/usr/local/sbin/flow-agent-firewall.sh` |
| `APP_SOURCES=<app server private /32>` | `/etc/wyfy/flow-agent-firewall.env` (the firewall script refuses to run without it) |
| `../hub-agents/systemd/flow-agent-firewall.service` | `/etc/systemd/system/`, **enabled**: it re-applies the rules at every boot, before the collector and the agent start |
| `../hub-agents/systemd/wyfy-nfacctd.service`, `flow-agent.service` | `/etc/systemd/system/` |
| `FLOW_AGENT_SECRET=<random>` | appended to `/etc/wyfy/hub-agents.env`; the same value goes into the app's `CLOUDGUEST_TRAFFIC_FLOW_AGENT_SECRET` |

The hub serves every venue, so installing this is an owner action. Nothing
here writes to a router. With nfacctd running and no router exporting, it
does nothing.

## Two files per window, and the order to deploy in

`nfacctd.conf` runs two print plugins. `wyfy` writes the rollup rows the app
has always ingested (`<stamp>.json`). `wyfyflows` writes one row per
exported flow record with the router's start and end times and the NAT
translation (`records-<stamp>.json`); the agent serves those as `flow_rows`.

1. **Install the new `flow_agent.py` first** and restart `flow-agent`. With
   the old collector config it behaves exactly as before: no `records-*`
   file exists, so no `flow_rows` key is sent.
2. **Then install the new `nfacctd.conf`**, run the check below, and restart
   `wyfy-nfacctd`. An older agent would neither serve nor prune
   `records-*.json`, which is why the agent goes first.

The app may be upgraded before or after either step. An app that does not
know `flow_rows` ignores it; an app that does falls back to the rollup rows
for any window that has none.

After the restart, on the hub (read-only):

```
head -3 /var/spool/wyfy-flows/records-*.json | tail -3   # timestamp_start != timestamp_end ?
wc -l /var/spool/wyfy-flows/records-*.json               # rows per window, per file
grep -c "Finished cache entries" /var/log/wyfy-nfacctd.log
```

If `timestamp_start` equals `timestamp_end` on every row, pmacct could not
turn the router's uptime-relative times into clock times and wrote the
export time into both: say so before anyone reads the table as "start" and
"end".

## Memory: check before you start it

nfacctd allocates its whole cache at start: `print_cache_entries` * 4048
bytes, used or not. The hub has 2 GB and no swap and carries RADIUS and
WireGuard for every venue. Before the first start, and after any change to
`nfacctd.conf`:

```
python3 check_nfacctd_memory.py /etc/pmacct/wyfy-nfacctd.conf \
    --unit /etc/systemd/system/wyfy-nfacctd.service \
    --agent /usr/local/sbin/flow_agent.py
```

It exits 1 when the start-up total is over 160 MB, when the worst case (every
cache full) is over 60% of the unit's `MemoryMax`, or when the collector's
output keys or file names are not the ones the agent reads.

After the start, the log line `cache entries=... base cache memory=... bytes`
must show the same number for each plugin (66431728 and 33230032). The arithmetic, what happens when the cache fills
(an early purge, not a drop) and how to tell (`Finished cache entries` in the
log) are in the comments of `nfacctd.conf`. The unit sets `MemoryMax=256M` as
a backstop.

`apt install pmacct` may also start the package's own stock daemons; stop,
disable and mask them.

Verify after install:

```
ss -ulpn | grep 2055            # nfacctd on 10.20.0.1 only
curl -s -H "X-Agent-Secret: $S" http://<hub-private-ip>:9094/flows/health
```
