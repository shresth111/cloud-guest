"""Queue Management Engine: CloudGuest's vendor-agnostic bandwidth/QoS
orchestrator.

Dashboard -> Queue Management Engine -> {Policy Service, Router Service,
Guest Service, Voucher Service, Guest Teams Service} -> Queue Adapter ->
{MikroTik Queue Adapter, Cisco/Aruba/UniFi QoS Adapter (future)}.

Controls bandwidth at every level the brief names -- User (``Guest``),
Guest Group (``GuestTeam``), Voucher, Device (``GuestDevice``), Session
(``GuestSession``), Location, Organization, Router -- via a single,
polymorphic :class:`~.models.QueueAssignment` (mirrors
``app.domains.policy.models.PolicyAssignment``'s own ``scope_type``/
``scope_id`` shape) resolved against real, reusable
:class:`~.models.QueueProfile` rate/burst/priority definitions. Never talks
to a device directly -- every device-side operation goes through
:class:`~.device_adapters.BaseQueueAdapter`, real for MikroTik today
(``librouteros``-backed ``/queue simple``/``/queue tree``/PCQ commands),
pluggable for Cisco/Aruba/UniFi later without touching this module's own
core engine. See ``docs/queue_management/FLOW.md`` for the full design
write-up.
"""
