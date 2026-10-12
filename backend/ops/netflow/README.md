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

## Memory: check before you start it

nfacctd allocates its whole cache at start: `print_cache_entries` * 4048
bytes, used or not. The hub has 2 GB and no swap and carries RADIUS and
WireGuard for every venue. Before the first start, and after any change to
`nfacctd.conf`:

```
python3 check_nfacctd_memory.py /etc/pmacct/wyfy-nfacctd.conf   # exits 1 over 100 MB
```

After the start, the log line `cache entries=... base cache memory=... bytes`
must show the same number. The arithmetic, what happens when the cache fills
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
