# ISP PPPoE on our RADIUS: X2 virtual server (TEST BOX ONLY)

This is exception X2, approved by the founder in ADDENDUM_02 §5. It adds a new
FreeRADIUS virtual server on its own ports (auth 1912, acct 1913) for PPPoE
subscribers of ISP customers.

What it leaves alone:
- `sites-available/default`
- the existing `rest` module
- `clients.conf` (the radius-agent keeps writing it, and its `client{}`
  stanzas apply to every listener)

**Only on wyfy-isp-test** (13.207.70.7). That box runs its own test-only
FreeRADIUS 3.2.5 (TEST_BOX_RUNBOOK §6). Never apply these files to the prod
hub.

## Files
| repo file | box path |
|---|---|
| `rest_isp_pppoe` | `/etc/freeradius/3.0/mods-available/rest_isp_pppoe`, symlinked from `mods-enabled/` |
| `wyfy-isp-pppoe` | `/etc/freeradius/3.0/sites-available/wyfy-isp-pppoe`, symlinked from `sites-enabled/` |

## Apply (coordinator, in a restart window)
```sh
SECRET=$(openssl rand -hex 24)
sudo install -m 0640 -o root -g freerad rest_isp_pppoe /etc/freeradius/3.0/mods-available/rest_isp_pppoe
sudo sed "s/__PPPOE_REST_SECRET__/$SECRET/" wyfy-isp-pppoe | sudo install -m 0640 -o root -g freerad /dev/stdin /etc/freeradius/3.0/sites-available/wyfy-isp-pppoe
sudo ln -sf ../mods-available/rest_isp_pppoe /etc/freeradius/3.0/mods-enabled/rest_isp_pppoe
sudo ln -sf ../sites-available/wyfy-isp-pppoe /etc/freeradius/3.0/sites-enabled/wyfy-isp-pppoe
sudo radiusd -XC          # must say "Configuration appears to be OK"
# firewall: allow 1912/1913 on wg0 + lo only, the same as 1812/1813.
# Add these to wyfy-test-hub-firewall.service's rules; do not open them in the SG.
sudo iptables -I INPUT -i wg0 -p udp -m multiport --dports 1912,1913 -j ACCEPT
sudo iptables -I INPUT -i lo  -p udp -m multiport --dports 1912,1913 -j ACCEPT
# backend.env
echo "ISP_PPPOE_ENABLED=true" | sudo tee -a /home/ubuntu/deploy/backend.env
echo "ISP_PPPOE_REST_SECRET=$SECRET" | sudo tee -a /home/ubuntu/deploy/backend.env
sudo systemctl restart freeradius
# recreate api + celery-worker so they read the env (same as every deploy)
```
`radiusd -XC` must pass before the restart. If it fails, remove the two
symlinks and restart. The default server is unaffected either way.

## Rollback
```sh
sudo rm -f /etc/freeradius/3.0/sites-enabled/wyfy-isp-pppoe /etc/freeradius/3.0/mods-enabled/rest_isp_pppoe
sudo systemctl restart freeradius
# and set ISP_PPPOE_ENABLED=false in backend.env (routes 404, authorize rejects)
```

## Verify without a real router (throwaway netns, like STAGING_RESULTS 3g2)
1. Create a subscriber, then `PUT /isp/subscribers/{id}/pppoe` to get the
   password, which is shown once.
2. From the e2e router's netns (tunnel IP + NAS secret in
   `/root/hub-verify-*.json`), test the three auth types:
   - `radtest -t pap  <user> <pw> 10.66.0.1:1912 0 <nas-secret>` → Access-Accept with `Mikrotik-Rate-Limit`
   - `radtest -t chap ...` → Accept
   - `radtest -t mschap ...` → Accept
   - a wrong password → Reject
   - `Reply-Message wyfy:<reason>` for each reject case
3. Send `radclient` Accounting Start, Interim and Stop to `:1913`. Each
   should produce or update an `isp_pppoe_sessions` row, and the bytes should
   show under `GET /isp/pppoe/sessions`.
4. The default server must not change: a hotspot authorize on 1812 still
   gives the same answer as before.
