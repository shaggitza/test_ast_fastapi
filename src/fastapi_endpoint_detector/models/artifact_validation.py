"""Strict JSON primitives shared by installed product and benchmark tooling."""

from __future__ import annotations

import json
import math
from typing import Any


class BenchmarkSchemaError(ValueError):
    """A benchmark artifact is malformed or ambiguous."""


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise BenchmarkSchemaError(f"duplicate JSON member {name!r}")
        result[name] = value
    return result


def _reject_non_finite(token: str) -> None:
    raise BenchmarkSchemaError(f"non-finite JSON number {token!r}")


def strict_json_loads(content: str, source: str) -> Any:
    """Decode JSON while rejecting duplicate object members and non-finite numbers."""
    try:
        return json.loads(
            content,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_non_finite,
        )
    except (json.JSONDecodeError, BenchmarkSchemaError) as error:
        raise BenchmarkSchemaError(f"invalid JSON in {source}: {error}") from error


def finite_nonnegative(value: object, field: str) -> float:
    """Return a finite non-negative timing value, rejecting bool-as-int."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BenchmarkSchemaError(f"{field} must be a finite non-negative number")
    if not math.isfinite(value) or value < 0:
        raise BenchmarkSchemaError(f"{field} must be a finite non-negative number")
    return float(value)
