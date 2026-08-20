"""Router discovery / snapshot / compatibility planner (Wave 1).

Read-only discovery of a MikroTik via
``wyfy_device_gateway.ReadOnlyDeviceReader``, persistence of sanitized
``RouterSnapshot`` rows, and a deterministic compatibility evaluator
used by the fleet wizard before any apply step.

This package deliberately does **not** push WAN config, generate
planner rules, or touch live venues / agent credentials /
``config_versions`` semantics -- those are later waves.
"""

from __future__ import annotations

from .models import RouterSnapshot

__all__ = ["RouterSnapshot"]
