# NetFlow / IPFIX collector (hub) — NOT DEPLOYED

Design, sizing, privacy, legal and the hardware plan: `~/wyfy-ops/netflow/DESIGN.md`.

| File | Goes to (hub) |
|---|---|
| `nfacctd.conf` | `/etc/pmacct/wyfy-nfacctd.conf` (`apt install pmacct`) |
| `../hub-agents/flow_agent.py` | `/usr/local/sbin/flow_agent.py` |
| `../hub-agents/flow-agent-firewall.sh` | `/usr/local/sbin/flow-agent-firewall.sh` (run once and at boot) |
| `../hub-agents/systemd/wyfy-nfacctd.service`, `flow-agent.service` | `/etc/systemd/system/` |
| `FLOW_AGENT_SECRET=<random>` | appended to `/etc/wyfy/hub-agents.env`; the same value goes into the app's `CLOUDGUEST_TRAFFIC_FLOW_AGENT_SECRET` |

The hub serves every venue, so installing this is an owner action. Nothing
here writes to a router. With nfacctd running and no router exporting, it
does nothing.

Verify after install:

```
ss -ulpn | grep 2055            # nfacctd on 10.20.0.1 only
curl -s -H "X-Agent-Secret: $S" http://172.31.40.230:9094/flows/health
```
