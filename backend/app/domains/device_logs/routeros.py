"""RouterOS remote logging: the ONE description of what a router should hold.

Two paths put this onto a router, and both are built from
:func:`desired_config` so they cannot drift (the failure class in the
``network_config`` renderers' history, where the device writer and the
script generator disagreed silently):

* the device writer (``wyfy_device_gateway.mikrotik_remote_logging``, over
  the 8728 API) converges to ``desired_config(...).as_rows()`` and reads back;
* the paste script (:func:`render_script`), shown in the Master console.

Deliberately NOT added to ``network_config.render_network_config``: that
push ships over SFTP/port 22, which is filtered on the fleet, so a third
copy there would never reach a router.

Shape on the device: one ``/system logging action`` (name is its unique
key) and one ``/system logging`` rule per topic. Rules have no unique key,
so they are keyed on ``action=`` and *replaced*, never appended -- an
``add`` with no key duplicates on every apply.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass

from .constants import (
    ROUTEROS_ACTION_NAME,
    ROUTEROS_SYSLOG_FACILITY,
    ROUTEROS_TOPICS,
    TAG_HEX_LENGTH,
    TAG_PREFIX,
)


def router_tag(router_id: uuid.UUID) -> str:
    """The 8-hex tag carried in every message's prefix. Cross-check only --
    attribution is by tunnel IP (DESIGN §5.3)."""
    return router_id.hex[:TAG_HEX_LENGTH]


def hub_tunnel_address(tunnel_network_cidr: str) -> str:
    """The hub's tunnel address: the first usable host of the hub's tunnel
    network -- the same convention the WireGuard renderer uses for the
    router's ``allowed-address=<hub>/32``, which is the only destination a
    router can reach through the tunnel."""
    network = ipaddress.ip_network(tunnel_network_cidr, strict=False)
    return str(next(network.hosts()))


@dataclass(frozen=True)
class RemoteLoggingConfig:
    remote_host: str
    remote_port: int
    src_address: str
    tag: str

    def __post_init__(self) -> None:
        # Validated here, before any renderer or writer sees it: these values
        # are interpolated into a RouterOS command line, so anything that is
        # not exactly an IP/port/hex tag is refused rather than quoted.
        ipaddress.ip_address(self.remote_host)
        ipaddress.ip_address(self.src_address)
        if not 1 <= int(self.remote_port) <= 65535:
            raise ValueError(f"remote_port out of range: {self.remote_port}")
        if len(self.tag) != TAG_HEX_LENGTH or any(
            c not in "0123456789abcdef" for c in self.tag
        ):
            raise ValueError(f"tag must be {TAG_HEX_LENGTH} lowercase hex chars")

    @property
    def prefix(self) -> str:
        return f"{TAG_PREFIX}{self.tag}"

    def action_row(self) -> dict[str, str]:
        """The ``/system logging action`` row, in API field names."""
        return {
            "name": ROUTEROS_ACTION_NAME,
            "target": "remote",
            "remote": self.remote_host,
            "remote-port": str(self.remote_port),
            "src-address": self.src_address,
            "bsd-syslog": "yes",
            "syslog-facility": ROUTEROS_SYSLOG_FACILITY,
            "syslog-severity": "auto",
        }

    def rule_rows(self) -> list[dict[str, str]]:
        """One ``/system logging`` row per topic, in API field names."""
        return [
            {"action": ROUTEROS_ACTION_NAME, "topics": topic, "prefix": self.prefix}
            for topic in ROUTEROS_TOPICS
        ]


def desired_config(
    *, router_id: uuid.UUID, tunnel_ip: str, remote_host: str, remote_port: int
) -> RemoteLoggingConfig:
    return RemoteLoggingConfig(
        remote_host=remote_host,
        remote_port=remote_port,
        src_address=tunnel_ip,
        tag=router_tag(router_id),
    )


def _args(row: dict[str, str]) -> str:
    return " ".join(f"{key}={value}" for key, value in row.items())


def render_removal() -> list[str]:
    """Remove every rule pointing at our action, then the action.

    Wrapped in ``:do {} on-error={}`` because on a router that never had the
    action, ``find action=<name>`` can itself fail to resolve the name --
    which is the desired end state, not an error."""
    return [
        f":do {{ /system logging remove [find action={ROUTEROS_ACTION_NAME}] }} "
        "on-error={}",
        f":do {{ /system logging action remove [find name={ROUTEROS_ACTION_NAME}] }} "
        "on-error={}",
    ]


def render_script(config: RemoteLoggingConfig) -> list[str]:
    """Paste script: remove-then-add (idempotent by replacement), then print
    what the router now holds so the operator sees the read-back.

    The ``add`` lines are NOT wrapped in ``on-error``: a rejected parameter
    (e.g. an older RouterOS without ``src-address``) must stop the paste
    loudly instead of leaving a half-configured router that looks done."""
    lines = render_removal()
    lines.append(f"/system logging action add {_args(config.action_row())}")
    lines.extend(f"/system logging add {_args(row)}" for row in config.rule_rows())
    lines.append(
        f':put ("Wyfy remote logging: " . [:len [/system logging find '
        f'action={ROUTEROS_ACTION_NAME}]] . " rules, expected '
        f'{len(ROUTEROS_TOPICS)}")'
    )
    return lines


__all__ = [
    "RemoteLoggingConfig",
    "desired_config",
    "hub_tunnel_address",
    "render_removal",
    "render_script",
    "router_tag",
]
