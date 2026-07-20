"""Provisioning Engine domain: the automation orchestrator that drives a
router through its full provisioning lifecycle -- discover, validate,
generate configuration, push, verify, health-check, register monitoring --
end to end, tracked as a real, resumable, retryable, rollback-able job.

This is a genuinely new orchestration layer sitting *above*
``app.domains.router_provisioning`` (config template/version/job-queue
workflow), ``app.domains.router`` (the device record), ``app.domains
.policy`` (session/authN policy resolution feeding configuration
generation), ``app.domains.guest`` (NAS registration), and
``app.domains.monitoring`` (post-provision health registration) -- it
composes all of them, never duplicates their logic. See ``service.py``'s
own module docstring for the full architectural write-up, and
``docs/provisioning_engine/FLOW.md`` for the end-to-end job/step lifecycle.

Real device I/O (RouterOS API + SSH) lives in ``device_adapters.py`` --
see that module's own docstring for the honest "real client code, never
exercised against a live device in this sandbox" scope note.
"""
