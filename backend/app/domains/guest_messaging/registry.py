"""The provider registry for guest login codes: one adapter per vendor.

Every adapter is described by an :class:`AdapterSpec`. The spec is the single
source of truth for

* which fields the venue (or the Wyfy team, from Master) must enter -- the
  dashboard renders its form from :meth:`AdapterSpec.as_schema`, so there is
  no per-vendor form in the frontend;
* which of those fields are secret (encrypted at rest, write-only: the API
  returns ``{"set": true, "hint": "…a1b2"}`` and never the value);
* how to build the sender (``factory``) and any extra validation.

Adding a vendor is: write the adapter class in :mod:`.adapters`, add one
``AdapterSpec`` there, and it appears in the form. "Verify" is the same for
every adapter (:mod:`.service`): send a code to a number the operator types,
and mark the account verified only when they type that code back.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

CHANNELS = ("whatsapp", "sms")

# Field kinds the frontend knows how to render.
KIND_TEXT = "text"
KIND_SECRET = "secret"
KIND_SELECT = "select"
KIND_TEXTAREA = "textarea"
KIND_BOOLEAN = "boolean"
KIND_HEADERS = "headers"  # [{name, value, secret}]; secret values write-only

HINT_MIN_LENGTH = 12


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str
    kind: str = KIND_TEXT
    required: bool = True
    help: str = ""
    placeholder: str = ""
    options: tuple[str, ...] = ()
    pattern: str | None = None
    pattern_message: str = ""
    default: Any = None
    max_length: int = 2048

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "kind": self.kind,
            "required": self.required,
            "help": self.help,
            "placeholder": self.placeholder,
            "options": list(self.options),
            "pattern": self.pattern,
            "default": self.default,
            "max_length": self.max_length,
        }


@dataclass(frozen=True)
class OtpMessage:
    """One login code to one phone. ``text`` is the platform's composed
    message; adapters that send free text (SMS without a vendor-side
    template) use the venue's own ``message_template`` instead, because DLT
    carriers drop any body that does not match the registered template."""

    phone_e164: str
    code: str
    text: str

    @property
    def phone_digits(self) -> str:
        return self.phone_e164.lstrip("+")

    @property
    def phone_10(self) -> str:
        return self.phone_digits[-10:]


@dataclass(frozen=True)
class SendResult:
    provider: str
    message_id: str | None


class ProviderSendError(Exception):
    """A vendor refused or failed a send. ``auth`` marks a credential or
    account error (HTTP 401/403, Meta 190, "invalid API key")."""

    def __init__(self, code: str, message: str, *, auth: bool = False) -> None:
        self.code = code
        self.message = str(message)[:500]
        self.auth = auth
        super().__init__(f"{code}: {self.message}")


class OtpAdapter(Protocol):
    provider: str

    async def send_otp(self, message: OtpMessage) -> SendResult: ...


@dataclass(frozen=True)
class AdapterContext:
    """What a factory may need besides the config: test seams."""

    transport: Any | None = None  # httpx.AsyncBaseTransport, tests only
    resolver: Any | None = None  # DNS resolver for the SSRF guard
    settings: Any | None = None


Factory = Callable[[dict[str, Any], AdapterContext], OtpAdapter]
Validator = Callable[[dict[str, Any]], dict[str, str]]


@dataclass(frozen=True)
class AdapterSpec:
    key: str
    channel: str
    display_name: str
    docs_url: str
    fields: tuple[FieldSpec, ...]
    factory: Factory
    validate: Validator | None = None
    # The non-secret field shown as "sends as ..." on the card.
    sender_field: str | None = None
    notes: str = ""

    @property
    def secret_fields(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.kind == KIND_SECRET)

    def field(self, name: str) -> FieldSpec | None:
        return next((f for f in self.fields if f.name == name), None)

    def as_schema(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "channel": self.channel,
            "display_name": self.display_name,
            "docs_url": self.docs_url,
            "notes": self.notes,
            "sender_field": self.sender_field,
            "fields": [f.as_dict() for f in self.fields],
        }


@dataclass
class Registry:
    specs: dict[tuple[str, str], AdapterSpec] = field(default_factory=dict)

    def register(self, spec: AdapterSpec) -> AdapterSpec:
        if spec.channel not in CHANNELS:
            raise ValueError(f"unknown channel {spec.channel!r}")
        key = (spec.channel, spec.key)
        if key in self.specs:
            raise ValueError(f"adapter {key!r} registered twice")
        names = [f.name for f in spec.fields]
        if len(names) != len(set(names)):
            raise ValueError(f"adapter {key!r} has duplicate field names")
        self.specs[key] = spec
        return spec

    def get(self, channel: str, key: str) -> AdapterSpec | None:
        return self.specs.get((channel, key))

    def for_channel(self, channel: str) -> list[AdapterSpec]:
        return [s for (c, _), s in self.specs.items() if c == channel]

    def schema(self) -> dict[str, list[dict[str, Any]]]:
        return {c: [s.as_schema() for s in self.for_channel(c)] for c in CHANNELS}


# ---------------------------------------------------------------------------
# Config validation, display and merge (generic over every spec)
# ---------------------------------------------------------------------------


class ConfigError(ValueError):
    def __init__(self, fields: dict[str, str]) -> None:
        self.fields = fields
        super().__init__("; ".join(f"{k}: {v}" for k, v in fields.items()))


_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")


def _normalize_headers(
    value: Any, stored: list[dict[str, Any]] | None
) -> tuple[list[dict[str, Any]], str | None]:
    if value in (None, ""):
        return [], None
    if not isinstance(value, list):
        return [], "must be a list of {name, value, secret}"
    previous = {
        str(h.get("name", "")).lower(): h for h in (stored or []) if isinstance(h, dict)
    }
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value[:20]:
        if not isinstance(item, dict):
            return [], "each header must be {name, value, secret}"
        name = str(item.get("name") or "").strip()
        if not _HEADER_NAME.match(name):
            return [], f"'{name}' is not a valid header name"
        if name.lower() in (
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
        ):
            return [], f"'{name}' cannot be set"
        if name.lower() in seen:
            return [], f"'{name}' is listed twice"
        seen.add(name.lower())
        secret = bool(item.get("secret"))
        raw = item.get("value")
        if raw in (None, "") and secret:
            # Write-only: an omitted secret value keeps the stored one.
            kept = previous.get(name.lower())
            raw = kept.get("value") if kept and kept.get("secret") else None
            if raw in (None, ""):
                return [], f"'{name}' needs a value"
        raw = "" if raw is None else str(raw)
        if "\r" in raw or "\n" in raw or len(raw) > 4096:
            return [], f"'{name}' has an invalid value"
        out.append({"name": name, "value": raw, "secret": secret})
    return out, None


def normalize_config(
    spec: AdapterSpec,
    config: dict[str, Any],
    *,
    stored: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a config for ``spec``. ``stored`` is the decrypted config of
    the same provider type: an omitted or empty secret keeps its stored
    value (write-only secrets are never sent back to be re-submitted)."""
    stored = stored or {}
    errors: dict[str, str] = {}
    for name in sorted(set(config) - {f.name for f in spec.fields}):
        errors[name] = "unknown field for this provider"
    out: dict[str, Any] = {}
    for f in spec.fields:
        value = config.get(f.name)
        if f.kind == KIND_HEADERS:
            headers, error = _normalize_headers(value, stored.get(f.name))
            if error:
                errors[f.name] = error
            elif headers:
                out[f.name] = headers
            elif f.required:
                errors[f.name] = "required"
            continue
        if f.kind == KIND_BOOLEAN:
            if value is None:
                value = stored.get(f.name, f.default)
            if value is None:
                continue
            if not isinstance(value, bool):
                errors[f.name] = "must be true or false"
                continue
            out[f.name] = value
            continue
        if isinstance(value, str):
            value = value.strip()
        if f.kind == KIND_SECRET and value in (None, ""):
            value = stored.get(f.name)
        if value in (None, ""):
            value = f.default
        if value in (None, ""):
            if f.required:
                errors[f.name] = "required"
            continue
        if not isinstance(value, str | int):
            errors[f.name] = "must be text"
            continue
        value = str(value)
        if len(value) > f.max_length:
            errors[f.name] = "too long"
            continue
        if f.options and value not in f.options:
            errors[f.name] = "must be one of " + ", ".join(f.options)
            continue
        if f.pattern and not re.fullmatch(f.pattern, value):
            errors[f.name] = f.pattern_message or "has the wrong format"
            continue
        out[f.name] = value
    if not errors and spec.validate is not None:
        errors.update(spec.validate(out))
    if errors:
        raise ConfigError(errors)
    return out


def secret_hint(value: str | None) -> str:
    if not value or len(value) < HINT_MIN_LENGTH:
        return "…"
    return "…" + value[-4:]


def build_display(spec: AdapterSpec, config: dict[str, Any]) -> dict[str, Any]:
    """The ONLY view of a config any API returns."""
    display: dict[str, Any] = {}
    for f in spec.fields:
        if f.kind == KIND_SECRET:
            value = config.get(f.name)
            display[f.name] = {"set": bool(value), "hint": secret_hint(value)}
        elif f.kind == KIND_HEADERS:
            display[f.name] = [
                {
                    "name": h["name"],
                    "secret": True,
                    "set": bool(h.get("value")),
                    "hint": secret_hint(h.get("value")),
                }
                if h.get("secret")
                else {"name": h["name"], "secret": False, "value": h.get("value", "")}
                for h in config.get(f.name) or []
            ]
        elif f.name in config:
            display[f.name] = config[f.name]
    return display


def secret_values(spec: AdapterSpec, config: dict[str, Any]) -> list[str]:
    values = [config.get(name) for name in spec.secret_fields]
    for f in spec.fields:
        if f.kind == KIND_HEADERS:
            values.extend(
                h.get("value") for h in config.get(f.name) or [] if h.get("secret")
            )
    return [v for v in values if isinstance(v, str) and v]


def scrub(message: str | None, config: dict[str, Any]) -> str | None:
    """Remove every configured value that could be a credential from vendor
    text before it is stored or returned (some vendors echo keys back)."""
    if message is None:
        return None
    text = str(message)
    candidates: list[str] = []
    for value in config.values():
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, list):
            candidates.extend(
                str(h.get("value"))
                for h in value
                if isinstance(h, dict) and h.get("value")
            )
    for value in sorted(candidates, key=len, reverse=True):
        if len(value) >= 6:
            text = text.replace(value, "***")
    return text[:500]


__all__ = [
    "AdapterContext",
    "AdapterSpec",
    "CHANNELS",
    "ConfigError",
    "FieldSpec",
    "OtpAdapter",
    "OtpMessage",
    "ProviderSendError",
    "Registry",
    "SendResult",
    "build_display",
    "normalize_config",
    "scrub",
    "secret_hint",
    "secret_values",
]
