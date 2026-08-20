# Router fleet ops — live venue adoption

Operator scripts for Wave 1 **live venue adoption** (see
`backend/docs/router_fleet/LIVE_VENUE_ADOPTION.md`).

## Phase A — snapshot-only discovery

`phase_a_discover.py` runs read-only discovery (`POST /api/v1/routers/{id}/discover?trigger=manual`)
for every router id listed in a manifest. **No WAN apply, no plan approve.**

### Prerequisites

- Wave 1 backend deployed with discovery APIs live
- Master Console bearer token with `routers.manage`
- Router ids for the live venues (from Master Console fleet or DB)

### Usage

```bash
export CLOUDGUEST_API_BASE_URL="https://api.example.com/api/v1"
export CLOUDGUEST_BEARER_TOKEN="..."   # Master Console session JWT

# Dry-run (lists manifest only)
python backend/ops/router-fleet/phase_a_discover.py \
  --manifest backend/ops/router-fleet/live_venues.template.json \
  --dry-run

# Run Phase A discover for each router
python backend/ops/router-fleet/phase_a_discover.py \
  --manifest backend/ops/router-fleet/live_venues.template.json
```

Copy `live_venues.template.json` to a local file (do not commit real ids) and fill in
`router_id`, `venue_name`, and optional `organization_id` for each live site.

Output is a CSV-style table: router id, snapshot status, compatibility overall, snapshot id.

Stop after Phase A per venue — do not proceed to WAN apply or plan approval until Phase C.
