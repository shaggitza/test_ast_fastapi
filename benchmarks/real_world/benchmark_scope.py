"""Explicit benchmark scopes for framework-specific evaluation."""

from __future__ import annotations

from typing import Any

from benchmarks.real_world.semantic_normalization import parse_claims

SCOPES = ("all", "fastapi", "out-of-scope")


def is_fastapi_entrypoint(item: dict[str, Any]) -> bool:
    """Return whether an entrypoint is addressable by the FastAPI adapter."""
    return any(
        not claim.opaque and claim.family in {"http", "websocket"} for claim in parse_claims(item)
    )


def entrypoint_in_scope(item: dict[str, Any], scope: str) -> bool:
    if scope == "all":
        return True
    if scope == "fastapi":
        return is_fastapi_entrypoint(item)
    if scope == "out-of-scope":
        return not is_fastapi_entrypoint(item)
    raise ValueError(f"unknown benchmark scope: {scope}")


def filter_record(record: dict[str, Any], scope: str) -> dict[str, Any]:
    """Copy a record with only entrypoints belonging to ``scope``."""
    filtered = dict(record)
    for field in ("affected_entrypoints", "candidate_entrypoints"):
        if field in record:
            filtered[field] = [
                item for item in record.get(field, []) if entrypoint_in_scope(item, scope)
            ]
    return filtered
