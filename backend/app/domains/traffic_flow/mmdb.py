"""A small read-only reader for MaxMind DB (``.mmdb``) files, standard
library only.

Why not the ``maxminddb`` package: the two things read here are a country
code and an AS number, the format is public and short
(https://maxmind.github.io/MaxMind-DB/), and a new runtime dependency for
that is not worth the lock-file churn. The file is memory-mapped, so several
worker processes share one copy in the page cache.

The file is data fetched from the internet at image build time. It is never
trusted: every offset is bounds-checked by the slicing below, nesting and
pointer chains are depth-limited, and any decoding error surfaces as
``MMDBError`` (at open) or as "no answer" (at lookup) -- never as a crash in
the ingest sweep.
"""

from __future__ import annotations

import ipaddress
import mmap
import struct
from pathlib import Path
from typing import Any

__all__ = ["MMDBError", "MMDBReader"]

_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
_DATA_SEPARATOR = 16
_MAX_DEPTH = 32

_T_POINTER = 1
_T_STRING = 2
_T_DOUBLE = 3
_T_BYTES = 4
_T_UINT16 = 5
_T_UINT32 = 6
_T_MAP = 7
_T_INT32 = 8
_T_UINT64 = 9
_T_UINT128 = 10
_T_ARRAY = 11
_T_BOOLEAN = 14
_T_FLOAT = 15


class MMDBError(ValueError):
    """The file is not a MaxMind DB this reader can use."""


class MMDBReader:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        with self.path.open("rb") as handle:
            try:
                self._buf = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError as exc:  # empty file
                raise MMDBError(f"{self.path.name}: empty file") from exc
        try:
            marker = self._buf.rfind(_METADATA_MARKER)
            if marker < 0:
                raise MMDBError(f"{self.path.name}: no MaxMind DB metadata marker")
            metadata_start = marker + len(_METADATA_MARKER)
            metadata, _ = self._decode(metadata_start, metadata_start, 0)
            if not isinstance(metadata, dict):
                raise MMDBError(f"{self.path.name}: metadata is not a map")
            self.metadata: dict[str, Any] = metadata
            self.node_count = int(metadata["node_count"])
            self.record_size = int(metadata["record_size"])
            self.ip_version = int(metadata["ip_version"])
            if self.record_size not in (24, 28, 32) or self.ip_version not in (4, 6):
                raise MMDBError(f"{self.path.name}: unsupported tree layout")
            self._node_bytes = self.record_size // 4
            self._tree_size = self.node_count * self._node_bytes
            self._data_start = self._tree_size + _DATA_SEPARATOR
            if self._data_start > marker:
                raise MMDBError(f"{self.path.name}: search tree is larger than file")
            self._ipv4_start = self._find_ipv4_start()
        except MMDBError:
            self.close()
            raise
        except (KeyError, TypeError, ValueError, IndexError, struct.error) as exc:
            self.close()
            raise MMDBError(f"{self.path.name}: unreadable metadata ({exc})") from exc

    # -- public -----------------------------------------------------------
    @property
    def build_epoch(self) -> int | None:
        value = self.metadata.get("build_epoch")
        return int(value) if isinstance(value, int) else None

    @property
    def database_type(self) -> str:
        return str(self.metadata.get("database_type") or "")

    def close(self) -> None:
        buf = getattr(self, "_buf", None)
        if buf is not None and not buf.closed:
            buf.close()

    def get(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Any | None:
        """The record for ``address``, or ``None`` when the database has
        none (or the record cannot be decoded)."""
        try:
            return self._get(address)
        except (MMDBError, IndexError, ValueError, struct.error, RecursionError):
            return None

    # -- search tree ------------------------------------------------------
    def _read_node(self, node: int, right: bool) -> int:
        base = node * self._node_bytes
        chunk = self._buf[base : base + self._node_bytes]
        if len(chunk) != self._node_bytes:
            raise MMDBError("node outside the search tree")
        if self.record_size == 24:
            part = chunk[3:6] if right else chunk[0:3]
            return int.from_bytes(part, "big")
        if self.record_size == 28:
            if right:
                return ((chunk[3] & 0x0F) << 24) | int.from_bytes(chunk[4:7], "big")
            return ((chunk[3] & 0xF0) << 20) | int.from_bytes(chunk[0:3], "big")
        part = chunk[4:8] if right else chunk[0:4]
        return int.from_bytes(part, "big")

    def _find_ipv4_start(self) -> int:
        """In an IPv6 tree, IPv4 addresses live under ``::/96``."""
        if self.ip_version == 4:
            return 0
        node = 0
        for _ in range(96):
            if node >= self.node_count:
                break
            node = self._read_node(node, right=False)
        return node

    def _get(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Any:
        packed = address.packed
        if len(packed) == 4:
            node = self._ipv4_start
        elif self.ip_version == 4:
            return None  # an IPv6 address in an IPv4-only database
        else:
            node = 0
        for byte in packed:
            for shift in range(7, -1, -1):
                if node >= self.node_count:
                    break
                node = self._read_node(node, right=bool((byte >> shift) & 1))
        if node <= self.node_count:
            # == node_count: "no data". < node_count: ran out of bits.
            return None
        offset = node - self.node_count + self._tree_size
        value, _ = self._decode(offset, self._data_start, 0)
        return value

    # -- data section -----------------------------------------------------
    def _take(self, offset: int, size: int) -> bytes:
        chunk = self._buf[offset : offset + size]
        if offset < 0 or len(chunk) != size:
            raise MMDBError("read past the end of the file")
        return chunk

    def _decode(self, offset: int, base: int, depth: int) -> tuple[Any, int]:
        """Decode one value at ``offset``. Pointers are relative to ``base``
        (the data section, or the metadata block). Returns the value and the
        offset just after it."""
        if depth > _MAX_DEPTH:
            raise MMDBError("data nested too deeply")
        control = self._take(offset, 1)[0]
        offset += 1
        kind = control >> 5
        if kind == _T_POINTER:
            width = (control >> 3) & 0x3
            raw = self._take(offset, width + 1)
            offset += width + 1
            if width == 0:
                pointer = ((control & 0x7) << 8) | raw[0]
            elif width == 1:
                pointer = 2048 + (((control & 0x7) << 16) | int.from_bytes(raw, "big"))
            elif width == 2:
                pointer = 526336 + (
                    ((control & 0x7) << 24) | int.from_bytes(raw, "big")
                )
            else:
                pointer = int.from_bytes(raw, "big")
            value, _ = self._decode(base + pointer, base, depth + 1)
            return value, offset
        if kind == 0:
            kind = 7 + self._take(offset, 1)[0]
            offset += 1
        size = control & 0x1F
        if size == 29:
            size = 29 + self._take(offset, 1)[0]
            offset += 1
        elif size == 30:
            size = 285 + int.from_bytes(self._take(offset, 2), "big")
            offset += 2
        elif size == 31:
            size = 65821 + int.from_bytes(self._take(offset, 3), "big")
            offset += 3

        if kind == _T_MAP:
            result: dict[str, Any] = {}
            for _ in range(size):
                key, offset = self._decode(offset, base, depth + 1)
                value, offset = self._decode(offset, base, depth + 1)
                result[str(key)] = value
            return result, offset
        if kind == _T_ARRAY:
            items = []
            for _ in range(size):
                item, offset = self._decode(offset, base, depth + 1)
                items.append(item)
            return items, offset
        if kind == _T_BOOLEAN:
            return bool(size), offset
        raw = self._take(offset, size)
        offset += size
        if kind == _T_STRING:
            return raw.decode("utf-8", errors="replace"), offset
        if kind in (_T_UINT16, _T_UINT32, _T_UINT64, _T_UINT128):
            return int.from_bytes(raw, "big"), offset
        if kind == _T_INT32:
            return int.from_bytes(raw, "big", signed=True), offset
        if kind == _T_DOUBLE and size == 8:
            return struct.unpack(">d", raw)[0], offset
        if kind == _T_FLOAT and size == 4:
            return struct.unpack(">f", raw)[0], offset
        if kind == _T_BYTES:
            return raw, offset
        raise MMDBError(f"unsupported data type {kind}")
