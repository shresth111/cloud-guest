"""Server-side WAN profile renderers (Wave 1 Step 5).

Ports the client ``buildRouterSetupScriptChunks`` WAN sections to pure
Python functions that emit RouterOS script text for push via the
existing ``router_provisioning`` apply pipeline.
"""

from .assembler import render_basic_wan_config
from .context import WanRenderContext, WanRenderLink

__all__ = [
    "WanRenderContext",
    "WanRenderLink",
    "render_basic_wan_config",
]
