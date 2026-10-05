"""Incremental JSON encoding with a hard byte budget."""

from __future__ import annotations

import dataclasses
import enum
import json
from pathlib import PurePath
from typing import Any

from pydantic import BaseModel

# Leaves 77 UTF-8 JSON string bytes for a useful diagnostic after the v3 error
# envelope and newline framing; smaller requests are rejected before app execution.
MIN_PROTOCOL_OUTPUT_BYTES = 128


def bounded_json_bytes(value: Any, *, max_bytes: int, field: str) -> bytes:  # noqa: PLR0915
    """Encode supported response values incrementally, without dumping full models."""
    output = bytearray()
    active: set[int] = set()
    scalar_encoder = json.JSONEncoder(separators=(",", ":"), allow_nan=False)

    def append(encoded: bytes) -> None:
        if len(output) + len(encoded) > max_bytes:
            raise ValueError(f"{field} exceeded the serialized output limit")
        output.extend(encoded)

    def write_string(value: str) -> None:
        append(b'"')
        escapes = {
            '"': b'\\"',
            "\\": b"\\\\",
            "\b": b"\\b",
            "\f": b"\\f",
            "\n": b"\\n",
            "\r": b"\\r",
            "\t": b"\\t",
        }
        for character in value:
            escaped = escapes.get(character)
            if escaped is not None:
                append(escaped)
            elif ord(character) < 0x20:
                append(f"\\u{ord(character):04x}".encode("ascii"))
            else:
                append(character.encode("utf-8"))
        append(b'"')

    def write_pairs(pairs: Any, depth: int) -> None:
        append(b"{")
        for index, (key, child) in enumerate(pairs):
            if not isinstance(key, str):
                raise TypeError(f"{field} mapping keys must be strings")
            if index:
                append(b",")
            write_string(key)
            append(b":")
            write(child, depth + 1)
        append(b"}")

    def write(item: Any, depth: int = 0) -> None:  # noqa: PLR0911, PLR0912, PLR0915
        if depth > 128:
            raise ValueError(f"{field} contains excessive JSON nesting")
        if isinstance(item, enum.Enum):
            write(item.value, depth + 1)
            return
        if isinstance(item, PurePath):
            write_string(str(item))
            return
        if isinstance(item, BaseModel):
            identity = id(item)
            if identity in active:
                raise ValueError(f"{field} contains a cyclic model")
            active.add(identity)
            try:
                write_pairs(
                    ((name, getattr(item, name)) for name in type(item).model_fields), depth + 1
                )
            finally:
                active.remove(identity)
            return
        if dataclasses.is_dataclass(item) and not isinstance(item, type):
            identity = id(item)
            if identity in active:
                raise ValueError(f"{field} contains a cyclic dataclass")
            active.add(identity)
            try:
                write_pairs(
                    (
                        (field_info.name, getattr(item, field_info.name))
                        for field_info in dataclasses.fields(item)
                    ),
                    depth + 1,
                )
            finally:
                active.remove(identity)
            return
        if isinstance(item, dict):
            identity = id(item)
            if identity in active:
                raise ValueError(f"{field} contains a cyclic mapping")
            active.add(identity)
            try:
                write_pairs(iter(item.items()), depth + 1)
            finally:
                active.remove(identity)
            return
        if isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active:
                raise ValueError(f"{field} contains a cyclic sequence")
            active.add(identity)
            try:
                append(b"[")
                for index, child in enumerate(item):
                    if index:
                        append(b",")
                    write(child, depth + 1)
                append(b"]")
            finally:
                active.remove(identity)
            return
        if isinstance(item, str):
            write_string(item)
            return
        if item is None or isinstance(item, (bool, int, float)):
            if (
                isinstance(item, int)
                and not isinstance(item, bool)
                and item.bit_length() > int(max_bytes * 3.322) + 1
            ):
                raise ValueError(f"{field} exceeded the serialized output limit")
            for chunk in scalar_encoder.iterencode(item):
                append(chunk.encode("utf-8"))
            return
        raise TypeError(f"{field} contains unsupported value {type(item).__name__}")

    write(value)
    return bytes(output)
