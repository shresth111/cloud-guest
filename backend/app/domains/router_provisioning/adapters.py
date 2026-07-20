"""Vendor provisioning adapters -- the Strategy/Adapter seam this module's
own workflow (config templates/versions/profiles, the durable job queue) is
built to compose with, so a new device vendor can plug in without any
change to that workflow's own code.

See ``docs/router_provisioning/PROVISIONING_ENGINE.md`` for the full design
write-up. The short version:

## What this seam is, and what it deliberately is not

This module (and ``app.domains.router_agent``) never executes a vendor
command against a live device -- see ``service.py``'s own module docstring:
there is no live device in this sandbox, and the real device-side
translation of a rendered config into vendor-specific API/CLI calls is
performed by an external agent process outside this codebase (the same
"platform builds the real workflow/wire-contract, an external process does
the actual device call" split ``app.domains.guest``'s FreeRADIUS `rlm_rest`
integration already establishes for RADIUS).

``ProvisioningAdapterProtocol`` is therefore **not** a "connect to a device
and run commands" interface -- there is nothing in this codebase that could
honestly implement that without a live device to test against. It is the
real, useful thing that *can* exist without one:

1. **Template/router vendor-compatibility validation** -- a real,
   previously-unenforced gap (any :class:`~.models.ConfigTemplate` could be
   assigned to any router regardless of vendor). ``validate_template
   _compatibility`` closes it.
2. **Vendor-aware job payload shaping** -- real, meaningful metadata a
   device-side agent would need to know how to dispatch a job correctly
   (e.g. MikroTik's RouterOS scripts are applied via `/import`; a
   hypothetical OPNsense agent would need a different content-type/apply
   mechanism entirely). ``build_job_payload`` adds this to
   :class:`~.models.ProvisioningJob`'s existing ``payload`` JSONB column --
   the column and the job/queue mechanics around it are completely
   unchanged.
3. **Capability introspection** -- a real, static description of what a
   vendor's agent is expected to support, consumed by
   ``GET /router-provisioning/vendors`` for dashboard/admin visibility.

## Plugging in a new vendor

Implement :class:`ProvisioningAdapterProtocol` and add one entry to
``_ADAPTERS`` below. Nothing else in ``router_provisioning`` or
``router_agent`` needs to change -- both already move config content and
job payloads as opaque text/JSONB, never inspecting vendor-specific syntax
themselves (confirmed by this extension's own gap analysis: zero hardcoded
RouterOS -- or any vendor's -- command strings exist anywhere in either
module prior to this file).
"""

from __future__ import annotations

from typing import Protocol

from .constants import ProvisioningJobType
from .exceptions import TemplateVendorMismatchError, UnsupportedVendorError


class ProvisioningAdapterProtocol(Protocol):
    """What a vendor plugs into the existing provisioning workflow by
    implementing. See module docstring for the full "what this is and is
    not" write-up."""

    vendor: str

    def validate_template_compatibility(self, *, template_vendor: str) -> None:
        """Raises :class:`TemplateVendorMismatchError` if ``template_vendor``
        is incompatible with this adapter's own ``vendor`` -- called by
        ``RouterProvisioningService.assign_profile`` before a template is
        ever assigned to a router."""
        ...

    def build_job_payload(
        self, *, job_type: str, base_payload: dict[str, object]
    ) -> dict[str, object]:
        """Returns ``base_payload`` enriched with real, vendor-specific
        dispatch metadata a device-side agent needs to know how to apply
        this job correctly -- never the job's actual device-facing
        execution (see module docstring). Called by
        ``RouterProvisioningService._enqueue_job`` for every job type
        (``initial_config``/``config_push``/``backup``/``restore``/
        ``factory_reset``)."""
        ...

    def describe_capabilities(self) -> dict[str, object]:
        """A real, static description of what this vendor's real device
        agent is expected to support -- consumed by
        ``GET /router-provisioning/vendors``."""
        ...


class MikroTikProvisioningAdapter:
    """The one vendor every ``Router``/``ConfigTemplate`` in this codebase
    is, today. Config content is a RouterOS script
    (``/import``-applied) -- see ``ConfigTemplate.template_content``'s own
    "flat text substitution" design (``service.render_template``)."""

    vendor = "mikrotik"

    def validate_template_compatibility(self, *, template_vendor: str) -> None:
        if template_vendor != self.vendor:
            raise TemplateVendorMismatchError(template_vendor, self.vendor)

    def build_job_payload(
        self, *, job_type: str, base_payload: dict[str, object]
    ) -> dict[str, object]:
        return {
            **base_payload,
            "vendor": self.vendor,
            "content_type": "routeros_script",
            "apply_mechanism": "import",
        }

    def describe_capabilities(self) -> dict[str, object]:
        return {
            "vendor": self.vendor,
            "config_format": "routeros_script",
            "apply_mechanism": "import",
            "supported_job_types": [job_type.value for job_type in ProvisioningJobType],
            "supports_diff": True,
            "supports_rollback": True,
            "supports_health_snapshots": True,
        }


# The registry: one entry per real, plugged-in vendor. Adding a new vendor is
# exactly "implement ProvisioningAdapterProtocol, add one entry here" -- see
# module docstring.
_ADAPTERS: dict[str, ProvisioningAdapterProtocol] = {
    "mikrotik": MikroTikProvisioningAdapter(),
}


def get_provisioning_adapter(vendor: str) -> ProvisioningAdapterProtocol:
    """Raises :class:`UnsupportedVendorError` if no adapter is registered
    for ``vendor``."""
    adapter = _ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedVendorError(vendor)
    return adapter


def list_supported_vendors() -> list[str]:
    return sorted(_ADAPTERS)


__all__ = [
    "ProvisioningAdapterProtocol",
    "MikroTikProvisioningAdapter",
    "get_provisioning_adapter",
    "list_supported_vendors",
]
