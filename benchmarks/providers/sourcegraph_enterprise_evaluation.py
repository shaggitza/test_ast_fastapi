"""Offline validation helpers for a Sourcegraph Enterprise + SCIP evaluation.

This module deliberately performs no network I/O. It validates normalized evidence
exported by a separately authorized evaluator and refuses to promote incomplete
or mismatched evidence into benchmark claims.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Literal, cast

EvidenceKind = Literal["changed_symbol", "reverse_reference", "call_chain", "cross_repo_consumer"]
_KINDS = {"changed_symbol", "reverse_reference", "call_chain", "cross_repo_consumer"}
_BINDING = {
    "repository",
    "revision",
    "path",
    "start_line",
    "end_line",
    "index_fingerprint",
    "tool_fingerprint",
    "config_fingerprint",
}


class EvidenceError(ValueError):
    """Evidence is missing, malformed, or does not support its claim."""


@dataclass(frozen=True)
class EvaluationStatus:
    status: Literal["evaluable", "not_evaluable"]
    reasons: tuple[str, ...]


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise EvidenceError(f"{field} must be a lowercase sha256 fingerprint")
    return value


def build_request(
    *, kind: EvidenceKind, repository: str, revision: str, path: str, symbol: str
) -> dict[str, str]:
    """Build a transport-neutral request description; never sends it anywhere."""
    if kind not in _KINDS:
        raise EvidenceError("unsupported evidence kind")
    for name, value in (
        ("repository", repository),
        ("revision", revision),
        ("path", path),
        ("symbol", symbol),
    ):
        if not value or "\n" in value:
            raise EvidenceError(f"{name} must be a non-empty single-line string")
    return {
        "kind": kind,
        "repository": repository,
        "revision": revision,
        "path": path,
        "symbol": symbol,
    }


def validate_response(response: object, *, request: dict[str, str]) -> dict[str, Any]:
    """Validate one normalized response and return a detached, safe-to-score value."""
    if not isinstance(response, dict) or set(response) != {
        "kind",
        "binding",
        "evidence",
        "receipt",
    }:
        raise EvidenceError("response must contain exactly kind, binding, evidence, receipt")
    kind = response["kind"]
    if kind != request["kind"] or kind not in _KINDS:
        raise EvidenceError("response kind does not match request")
    binding = response["binding"]
    if not isinstance(binding, dict) or set(binding) != _BINDING:
        raise EvidenceError("binding is incomplete or has unsupported fields")
    for key in ("repository", "revision", "path"):
        if binding[key] != request[key]:
            raise EvidenceError(f"binding {key} does not match requested source")
    if (
        type(binding["start_line"]) is not int
        or binding["start_line"] < 1
        or type(binding["end_line"]) is not int
        or binding["end_line"] < binding["start_line"]
    ):
        raise EvidenceError("binding source range is invalid")
    for key in ("index_fingerprint", "tool_fingerprint", "config_fingerprint"):
        _sha(binding[key], key)
    receipt = response["receipt"]
    if not isinstance(receipt, dict) or set(receipt) != {
        "source",
        "query_fingerprint",
        "result_fingerprint",
    }:
        raise EvidenceError("receipt is incomplete")
    if not isinstance(receipt["source"], str) or not receipt["source"].strip():
        raise EvidenceError("receipt source is required")
    _sha(receipt["query_fingerprint"], "query_fingerprint")
    _sha(receipt["result_fingerprint"], "result_fingerprint")
    evidence = response["evidence"]
    if kind == "changed_symbol":
        _validate_changed_symbol(evidence)
    elif kind in {"reverse_reference", "cross_repo_consumer"}:
        _validate_references(
            evidence, cross_repo=kind == "cross_repo_consumer", repository=request["repository"]
        )
    else:
        _validate_call_chain(evidence, request["repository"], request["revision"])
    # Deep copy through JSON prevents callers retaining mutable unvalidated references.
    return cast("dict[str, Any]", json.loads(json.dumps(response, allow_nan=False)))


def _validate_changed_symbol(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"symbol", "before", "after", "change"}:
        raise EvidenceError("changed-symbol evidence must include symbol, before, after, change")
    if not all(
        isinstance(value[key], str) and value[key]
        for key in ("symbol", "before", "after", "change")
    ):
        raise EvidenceError("changed-symbol identities and change are required")
    if value["before"] == value["after"]:
        raise EvidenceError("changed-symbol evidence must distinguish before and after identities")


def _validate_references(value: object, *, cross_repo: bool, repository: str) -> None:
    if not isinstance(value, list) or not value:
        raise EvidenceError("reference evidence must be a non-empty list")
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "repository",
            "revision",
            "path",
            "start_line",
            "end_line",
            "symbol",
        }:
            raise EvidenceError("reference is missing source identity or range")
        if not all(
            isinstance(item[k], str) and item[k]
            for k in ("repository", "revision", "path", "symbol")
        ):
            raise EvidenceError("reference identity fields must be non-empty strings")
        if (
            type(item["start_line"]) is not int
            or item["start_line"] < 1
            or type(item["end_line"]) is not int
            or item["end_line"] < item["start_line"]
        ):
            raise EvidenceError("reference range is invalid")
        if cross_repo and item["repository"] == repository:
            raise EvidenceError("cross-repository consumer must name another repository")


def _validate_call_chain(value: object, repository: str, revision: str) -> None:
    if not isinstance(value, list) or len(value) < 2:
        raise EvidenceError("call-chain evidence requires at least two ordered hops")
    for hop in value:
        if not isinstance(hop, dict) or set(hop) != {
            "repository",
            "revision",
            "path",
            "start_line",
            "end_line",
            "symbol",
            "edge",
        }:
            raise EvidenceError("call-chain hop is incomplete")
        if (
            hop["repository"] != repository
            or hop["revision"] != revision
            or not all(
                isinstance(hop[k], str) and hop[k] for k in ("revision", "path", "symbol", "edge")
            )
        ):
            raise EvidenceError("call-chain hop has invalid repository or identity")
        if (
            type(hop["start_line"]) is not int
            or hop["start_line"] < 1
            or type(hop["end_line"]) is not int
            or hop["end_line"] < hop["start_line"]
        ):
            raise EvidenceError("call-chain hop range is invalid")


def evaluation_status(
    *,
    authenticated: bool,
    indexed_repositories: set[str],
    required_repositories: set[str],
    complete_coverage: bool,
    provenance_verified: bool,
) -> EvaluationStatus:
    reasons = []
    if not authenticated:
        reasons.append("missing_credentials")
    if not required_repositories <= indexed_repositories:
        reasons.append("missing_index")
    if not complete_coverage:
        reasons.append("incomplete_coverage")
    if not provenance_verified:
        reasons.append("missing_provenance")
    return EvaluationStatus("not_evaluable" if reasons else "evaluable", tuple(reasons))


def fingerprint(value: object) -> str:
    """Stable fingerprint helper for non-secret request/config metadata."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def three_year_tco(
    *,
    annual_license: float,
    annual_compute: float,
    annual_storage: float,
    setup_hours: float,
    hourly_rate: float,
    annual_operations_hours: float,
) -> dict[str, float]:
    """Parametric USD estimate; license quote remains an explicit caller input."""
    numbers = (
        annual_license,
        annual_compute,
        annual_storage,
        setup_hours,
        hourly_rate,
        annual_operations_hours,
    )
    if any(
        isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0
        for v in numbers
    ):
        raise ValueError("all TCO inputs must be finite non-negative numbers")
    setup = setup_hours * hourly_rate
    operations = annual_operations_hours * hourly_rate * 3
    license_cost = annual_license * 3
    infrastructure = (annual_compute + annual_storage) * 3
    return {
        "license_usd": license_cost,
        "infrastructure_usd": infrastructure,
        "setup_labor_usd": setup,
        "operations_labor_usd": operations,
        "total_usd": license_cost + infrastructure + setup + operations,
    }
