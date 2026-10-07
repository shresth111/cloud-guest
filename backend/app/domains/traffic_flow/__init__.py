"""Traffic flow domain: MikroTik NetFlow v9 / IPFIX export, ingested as
5-minute per-router rollups for the Master console.

Design, sizing, privacy and the hardware plan: ``~/wyfy-ops/netflow/DESIGN.md``.

## What this is

* ``routeros.py`` -- the ONE place the desired ``/ip traffic-flow`` state is
  built. The script generator (``network_config.renderers``) and the device
  writer (``MikroTikAdapter.apply_traffic_flow``) both consume it, so the two
  config paths cannot drift.
* ``ingest.py`` -- pure reduction of the hub collector's aggregated rows into
  per-router top talkers / top destinations, plus guest-session attribution.
* ``tasks.py`` -- the pull sweep from the hub's ``flow_agent.py``.
* ``router.py`` -- Master console only, every route pinned to
  ``ScopeType.GLOBAL`` under the GLOBAL-only ``traffic_flows`` permission.

## What this is not

* **Not per-application accounting.** IPFIX carries addresses and ports; there
  is no DPI. Nothing here names an application.
* **Not the per-guest byte source of truth.** RADIUS accounting is.
* **Not a legal record.** No raw flow and no NAT translation is stored; see
  DESIGN.md §6 for the archive that would be, and why it needs legal sign-off.
* **Not a guest browsing history.** Talkers and destinations are stored as
  two independent lists; no stored row links a guest to a destination.

Everything is gated by ``Settings.traffic_flow_enabled`` (default False) and
``Settings.traffic_flow_router_ids`` (default empty).
"""
