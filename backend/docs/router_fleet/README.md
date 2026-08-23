# Router Fleet — Wave 1 Operator Docs

Wave 1 replaces the client-side MikroTik script generator with a **server-driven
provisioning wizard** (Master Console) backed by read-only discovery, WAN profiles,
a deterministic configuration planner, and a gateway push pipeline over the existing
WireGuard tunnel.

These documents are written for **operators and field engineers** deploying or
migrating routers — not as API reference (use OpenAPI at `/docs` for that).

| Document | Audience | Purpose |
|---|---|---|
| [`PROVISIONING_RUNBOOK.md`](./PROVISIONING_RUNBOOK.md) | Field / NOC | End-to-end procedure for a **new** router from bootstrap through fleet online |
| [`LIVE_VENUE_ADOPTION.md`](./LIVE_VENUE_ADOPTION.md) | Platform / account owners | Safe adoption of the **~12 existing live venues** without touching production config until explicitly approved |

## Related backend docs

| Topic | Location |
|---|---|
| Router device record, check-in, heartbeat | [`docs/router/README.md`](../router/README.md) |
| Config versions, apply, rollback machinery | [`docs/router_provisioning/README.md`](../router_provisioning/README.md) |
| WAN profile renderers (`wan/basic/*`) | [`docs/network_config/README.md`](../network_config/README.md) |
| ISP link model (physical/routing split, PPPoE) | [`docs/isp/README.md`](../isp/README.md) |
| Legacy provisioning jobs (day-2, templates) | [`docs/provisioning_engine/README.md`](../provisioning_engine/README.md) |
| Device gateway package (vendored) | [`vendor/wyfy-device-gateway/README.md`](../../vendor/wyfy-device-gateway/README.md) |

## Frontend entry points (`cloudguest-foundation`)

| Surface | Route / location |
|---|---|
| **Provisioning wizard** (primary) | Master Console → Router Fleet → **Wizard** → `/master/routers/setup/$routerId` |
| Fleet browse drawer | `/master/routers` (`?open=<id>` deep link) |
| Legacy expert script (advanced) | `/master/routers?advanced=<id>` (legacy alias `?setup=<id>`) |

## Wave 1 API map (under `/api/v1`)

All router-scoped Wave 1 endpoints live on the router domain router
(`app/domains/router/router.py`). Permission keys are typically `routers.read`
(read-only steps) and `routers.manage` (mutating steps).

```text
GET    /routers/{id}/bootstrap/preview          # Step 0 bootstrap script (pending routers)
POST   /routers/{id}/discover
GET    /routers/{id}/snapshots[/{snapshot_id}]
GET    /routers/{id}/compatibility
POST   /routers/{id}/verify/wan
GET    /routers/{id}/verify/wan/gate
GET    /routers/{id}/guest/interfaces/availability
POST   /routers/{id}/plans
GET    /routers/{id}/plans/{plan_id}
POST   /routers/{id}/plans/{plan_id}/approve
POST   /routers/{id}/plans/{plan_id}/render
POST   /routers/{id}/plans/{plan_id}/prepare
POST   /routers/{id}/plans/{plan_id}/apply
POST   /routers/{id}/plans/{plan_id}/verify/final

GET    /network-config/routers/{id}/wan/basic/preview   # network_config domain
POST   /network-config/routers/{id}/wan/basic/apply
```

> The `/network-config` prefix on those last two is load-bearing and is
> not shown on the others because they really do live under `/routers`.
> This table previously omitted it, and the frontend's
> `router-fleet-wizard.service.ts` was written to match the table rather
> than the router — so the wizard's WAN Apply step 404'd from the day it
> shipped, and the server-side WAN renderer it calls went four frontend
> PRs stale without anyone noticing, because nothing was consuming it.

Implementation plan and architecture grounding:
`~/wyfy-specs/router-fleet-implementation-plan.md`,
`~/wyfy-specs/router-fleet-current-architecture.md`,
`~/wyfy-specs/router-provisioning-spec.md`.
