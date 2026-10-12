"""Traffic flow domain: MikroTik NetFlow v9 / IPFIX export, ingested as
5-minute per-router rollups for the Master console.

Design, sizing, privacy and the hardware plan: ``~/wyfy-ops/netflow/DESIGN.md``.

## What this is

* ``routeros.py`` -- the ONE place the desired ``/ip traffic-flow`` state is
  built. The script generator (``network_config.renderers``) and the device
  writer (``MikroTikAdapter.apply_traffic_flow``) both consume it, so the two
  config paths cannot drift.
* ``ingest.py`` -- pure reduction of the hub collector's aggregated rows into
  per-router top talkers / top destinations / service buckets, plus
  guest-session attribution.
* ``summary.py`` -- pure assembly of the venue summary from stored rows.
* ``geo.py`` / ``geo_service.py`` / ``geo_router.py`` -- Geo Location: client
  traffic by country and network (AS), from DB-IP Lite files that are fetched
  at image build and may be absent (``geo_available: false``). ``mmdb.py``
  reads them.
* ``tasks.py`` -- the pull sweep from the hub's ``flow_agent.py``.
* ``router.py`` -- Master console only, every route pinned to
  ``ScopeType.GLOBAL`` under the GLOBAL-only ``traffic_flows`` permission.

## What this is not

* **Not per-application accounting.** IPFIX carries addresses and ports; there
  is no DPI. Nothing here names an application.
* **Not the per-guest byte source of truth.** RADIUS accounting is.
* **Not a legal record.** No raw flow and no NAT translation is stored; see
  DESIGN.md §6 for the archive that would be, and why it needs legal sign-off.
* **Not a guest browsing history.** No stored row links a guest or a device
  to a destination or to a service. The one pairing that is stored is
  venue-level and has no device in it: outside address by service, in
  ``traffic_flow_dest_buckets`` (``destination_buckets.py``).
  Countries and networks (``geo.py``) are a further independent list with no
  address in it.

Everything is gated by ``Settings.traffic_flow_enabled`` (default False).
Which routers export is the per-router switch in
``router_traffic_flow_export``, set by a Master apply -- not a setting.
"""
