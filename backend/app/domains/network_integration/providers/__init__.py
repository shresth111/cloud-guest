"""Provider registry for the Network Integration domain.

``get_network_provider(kind)`` is the single lookup ``service.py`` uses.
One dictionary, one function -- the same registry pattern
``app.domains.connected_devices.device_adapters
.get_connected_device_adapter`` and ``app.domains.isp.device_adapters
.get_isp_health_adapter`` already establish in this codebase, rather than
a seventh reinvention of it with different semantics.

## Why the registry is lazy

``providers.omada`` is imported on first use, not at module import time.
The Omada provider's own module docstring explains why *it* imports the
gateway lazily; this is the outer half of the same decision. A module-level
``{OMADA: OmadaProvider()}`` would make importing this package import
``providers.omada``, and while that module's gateway import is itself
deferred, keeping the registry lazy means a provider module that later
grows a genuinely eager third-party import cannot take the whole domain
down with it. The cost is one dictionary lookup and one cached import per
process.

The instance is cached: providers are stateless by construction (see
``base.ProviderConnectionConfig``), so one instance per process is correct
and there is nothing for two tenants to share.
"""

from __future__ import annotations

from .base import (
    NetworkProvider,
    ProviderAuthorizationResult,
    ProviderClient,
    ProviderConnectionConfig,
    ProviderControllerInfo,
    ProviderDevice,
    ProviderPortalContext,
    ProviderSite,
    ProviderSsid,
)

__all__ = [
    "NetworkProvider",
    "ProviderAuthorizationResult",
    "ProviderClient",
    "ProviderConnectionConfig",
    "ProviderControllerInfo",
    "ProviderDevice",
    "ProviderPortalContext",
    "ProviderSite",
    "ProviderSsid",
    "get_network_provider",
    "list_supported_providers",
]

_INSTANCES: dict[str, NetworkProvider] = {}

# kind -> "module:attribute". Strings rather than imported classes, so this
# table can be read (and this package imported) without importing any
# provider module at all.
_PROVIDER_PATHS: dict[str, tuple[str, str]] = {
    "omada": ("app.domains.network_integration.providers.omada", "OmadaProvider"),
}


def get_network_provider(kind: str) -> NetworkProvider:
    """The provider registered for ``kind``.

    Raises :class:`~app.domains.network_integration.exceptions
    .UnsupportedNetworkProviderError` for an unregistered kind -- a
    domain exception with a real HTTP status, not a ``KeyError``, because
    ``provider`` arrives from a request body and an unknown value is a 400
    rather than a 500.
    """
    from ..exceptions import UnsupportedNetworkProviderError

    cached = _INSTANCES.get(kind)
    if cached is not None:
        return cached

    path = _PROVIDER_PATHS.get(kind)
    if path is None:
        raise UnsupportedNetworkProviderError(kind)

    import importlib

    module_name, attribute = path
    module = importlib.import_module(module_name)
    instance = getattr(module, attribute)()
    _INSTANCES[kind] = instance
    return instance


def list_supported_providers() -> list[str]:
    return sorted(_PROVIDER_PATHS)
