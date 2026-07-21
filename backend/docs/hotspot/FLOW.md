# Hotspot Settings -- Design Notes

## 0. Research: what already exists, what's genuinely missing

Before writing any code, a full-tree grep for "hotspot" across
`app/domains` confirmed no domain renders or pushes real RouterOS
`/ip hotspot` config anywhere in this codebase. Every existing hit was
either the pre-seeded but unclaimed `PermissionModule.HOTSPOT` RBAC key,
or prose in other domains using "hotspot" colloquially (RADIUS/session-
timeout comparisons, `app.domains.analytics`'s own explicit "there is no
separate 'hotspot session' concept -- every guest WiFi connection *is* a
`GuestSession` row" equivalence note).

`app.domains.captive_portal` was confirmed to be scoped entirely to
splash-page **branding/content** (theme, logo, T&Cs, login-method
toggles) -- its own module docstring states outright it "does not
implement guest authentication itself," and it carries zero
session-timeout/walled-garden/bandwidth fields. `app.domains.guest`
carries `GuestSession.session_timeout_minutes`/`data_limit_mb`, but as
values copied per-session at login time from a voucher batch or
portal default -- not a router-wide hotspot profile. Neither domain is
duplicated by this one.

## 1. Scope: `/ip hotspot user profile` + walled-garden, not the server bind

RouterOS's own `/ip hotspot` feature set spans several sub-menus: a
*server* (bound to an interface + address pool), a *server profile*
(login page/method), a *user profile* (session-timeout/idle-timeout/
rate-limit), and *walled-garden* entries (allowed hosts). This domain
models only the user-profile/walled-garden slice -- the part fully
described by real, storable fields -- rather than fabricate an
interface/address-pool binding this table has no data for (that binding
concern is the same one `app.domains.dhcp.models.DhcpPool` already
covers for DHCP pools, not duplicated here).

`HotspotProfile` therefore has no FK to `app.domains.captive_portal
.CaptivePortalConfig` -- a splash-page binding was considered and
deliberately left out of this pass to keep scope tight; the two domains
compose independently for now.

## 2. `upload_limit_kbps`/`download_limit_kbps`: mirroring an existing convention

RouterOS's `/ip hotspot user profile`'s own `rate-limit` field is
`rx-rate/tx-rate`, where `rx` is traffic *received by the router* (the
client's upload) and `tx` is traffic *transmitted to the client* (the
client's download). `app.domains.queue_management.service
.format_mikrotik_rate_limit` already establishes this exact rx=upload/
tx=download convention for its own `QueueProfile.upload_rate_kbps`/
`download_rate_kbps` fields -- `HotspotProfile.upload_limit_kbps`/
`download_limit_kbps` mirror that identical ordering, so
`app.domains.network_config`'s renderer can format a `rate-limit` value
the same way, without inventing a second, differently-ordered
convention.

## 3. RBAC: zero new permission keys, one display-name upgrade

`PermissionModule.HOTSPOT` was already seeded (`CREATE`/`READ`/`UPDATE`/
`DELETE`/`MANAGE`/`EXECUTE` actions, `ScopeType.ROUTER`) with no domain
claiming it yet -- mirroring the same "pre-seeded ahead of any real
domain" posture `PermissionModule.DHCP`/`FIREWALL` had before
`app.domains.dhcp`/`app.domains.port_forwarding` filled them in. This
domain reuses it entirely, only upgrading the generic `"Hotspot"`
display name to `"Hotspot Settings"` (mirroring the identical DHCP
precedent). No `seed.py` structural change was needed -- the pre-existing
"Network Administrator" role already grants `FULL` access and "Location
Manager" already grants `READ`.

This domain's own router only uses `CREATE`/`READ`/`UPDATE`/`DELETE` --
`EXECUTE`/`MANAGE` are left for `app.domains.network_config`'s own
push/rollback actions (which gate on `network_config.execute`, a
separate permission key), not reused here.

## 4. Composed by Network Configuration Management in the same pass

Unlike `app.domains.dhcp`/`app.domains.vlan`/`app.domains
.port_forwarding` (all built before Network Configuration Management
existed, each independently deferring real device provisioning to a
"not-yet-built" domain), Hotspot Settings is composed into that pipeline
immediately: `app.domains.network_config` gained a fourth
`HotspotLookupProtocol`/`render_hotspot_profile` category composing this
domain's own `list_profiles_for_router` -- see that domain's own
`FLOW.md` for the render/push details (RouterOS `/ip hotspot user
profile` + `/ip hotspot walled-garden` entries).
