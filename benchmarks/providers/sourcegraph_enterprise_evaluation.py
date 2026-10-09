"""Offline schema validation for a Sourcegraph Enterprise + SCIP evaluation.

This module performs no network I/O and authenticates no provider. Its output is
schema-validated supplied evidence, never trusted runtime authorization or proof.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Literal, cast

EvidenceKind = Literal["changed_symbol", "reverse_reference", "call_chain", "cross_repo_consumer"]
_KINDS = {"changed_symbol", "reverse_reference", "call_chain", "cross_repo_consumer"}
_FINGERPRINTS = ("index_fingerprint", "tool_fingerprint", "config_fingerprint")
_BINDING = {"repository", "revision", "path", "start_line", "end_line", *_FINGERPRINTS}
_REFERENCE_FIELDS = {
    "repository",
    "revision",
    "path",
    "start_line",
    "end_line",
    "symbol",
    *_FINGERPRINTS,
}
_CALL_EDGE_FIELDS = {
    "relation",
    "from_symbol",
    "to_symbol",
    "repository",
    "revision",
    "path",
    "start_line",
    "end_line",
    "call_expression",
    *_FINGERPRINTS,
}


class EvidenceError(ValueError):
    """Evidence is missing, malformed, mismatched, or uses unsupported semantics."""


@dataclass(frozen=True)
class ReadinessStatus:
    """Descriptive operator-reported prerequisites; never grants authorization."""

    status: Literal["ready_to_attempt", "not_ready"]
    reasons: tuple[str, ...]


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise EvidenceError(f"{field} must be a lowercase sha256 fingerprint")
    return value


def build_request(
    *,
    kind: EvidenceKind,
    repository: str,
    revision: str,
    path: str,
    symbol: str,
    index_fingerprint: str,
    tool_fingerprint: str,
    config_fingerprint: str,
    consumer_indexes: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build deterministic transport-neutral request metadata; never sends it."""
    if not isinstance(kind, str) or kind not in _KINDS:
        raise EvidenceError("unsupported evidence kind")
    for name, value in (
        ("repository", repository),
        ("revision", revision),
        ("path", path),
        ("symbol", symbol),
    ):
        _single_line(value, name)
    for name, value in zip(
        _FINGERPRINTS, (index_fingerprint, tool_fingerprint, config_fingerprint), strict=True
    ):
        _sha(value, name)
    consumers = {} if consumer_indexes is None else consumer_indexes
    if not isinstance(consumers, dict):
        raise EvidenceError("consumer indexes must be a repository-to-identity object")
    for repo, identity in consumers.items():
        if (
            not isinstance(repo, str)
            or not repo
            or "\n" in repo
            or "\r" in repo
            or repo == repository
        ):
            raise EvidenceError("consumer indexes must name distinct repositories")
        if not isinstance(identity, dict) or set(identity) != {"revision", *_FINGERPRINTS}:
            raise EvidenceError(
                "each consumer index must bind revision and tool/config fingerprints"
            )
        _single_line(identity["revision"], "consumer index revision")
        for name in _FINGERPRINTS:
            _sha(identity[name], f"consumer.{name}")
    if kind == "cross_repo_consumer" and not consumers:
        raise EvidenceError("cross-repository requests require explicit consumer index identities")
    if kind != "cross_repo_consumer" and consumers:
        raise EvidenceError("consumer revisions are only valid for cross-repository requests")
    return {
        "kind": kind,
        "repository": repository,
        "revision": revision,
        "path": path,
        "symbol": symbol,
        "index_fingerprint": index_fingerprint,
        "tool_fingerprint": tool_fingerprint,
        "config_fingerprint": config_fingerprint,
        "consumer_indexes": {repo: consumers[repo] for repo in sorted(consumers)},
    }


def validate_response(  # noqa: PLR0912
    response: object, *, request: dict[str, Any]
) -> dict[str, Any]:
    """Validate hash binding and schema; result remains untrusted and non-authoritative."""
    request = _validate_request(request)
    if not isinstance(response, dict) or set(response) != {
        "kind",
        "binding",
        "evidence",
        "receipt",
    }:
        raise EvidenceError("response must contain exactly kind, binding, evidence, receipt")
    kind = response["kind"]
    if not isinstance(kind, str) or kind != request["kind"] or kind not in _KINDS:
        raise EvidenceError("response kind does not match request")
    binding = response["binding"]
    if not isinstance(binding, dict) or set(binding) != _BINDING:
        raise EvidenceError("binding is incomplete or has unsupported fields")
    for key in ("repository", "revision", "path"):
        if binding[key] != request[key]:
            raise EvidenceError(f"binding {key} does not match requested source")
    for key in _FINGERPRINTS:
        if binding[key] != request[key]:
            raise EvidenceError(f"binding {key} does not match the requested index identity")
    _validate_range(binding, "binding")
    for key in _FINGERPRINTS:
        _sha(binding[key], key)

    evidence = response["evidence"]
    if kind == "changed_symbol":
        _validate_changed_symbol(evidence, request["symbol"])
    elif kind in {"reverse_reference", "cross_repo_consumer"}:
        _validate_references(evidence, kind=kind, request=request, binding=binding)
    else:
        _validate_call_chain(evidence, request=request, binding=binding)

    receipt = response["receipt"]
    if not isinstance(receipt, dict) or set(receipt) != {
        "source",
        "query_fingerprint",
        "result_fingerprint",
    }:
        raise EvidenceError("receipt is incomplete")
    if not isinstance(receipt["source"], str) or not receipt["source"].strip():
        raise EvidenceError("receipt source is required as descriptive metadata")
    query_hash = _sha(receipt["query_fingerprint"], "query_fingerprint")
    result_hash = _sha(receipt["result_fingerprint"], "result_fingerprint")
    if query_hash != fingerprint(request):
        raise EvidenceError("query fingerprint does not match canonical request")
    if result_hash != fingerprint(_result_payload(response)):
        raise EvidenceError("result fingerprint does not match canonical binding and evidence")

    # Receipt strings are caller-supplied metadata; no provider signature or identity is checked.
    validated = cast("dict[str, Any]", json.loads(json.dumps(response, allow_nan=False)))
    validated["validation"] = {
        "status": "schema_validated_supplied_evidence",
        "provider_authenticated": False,
        "scorable": False,
    }
    return validated


def _single_line(value: object, field: str) -> None:
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        raise EvidenceError(f"{field} must be a non-empty single-line string")


def _validate_request(request: object) -> dict[str, Any]:
    """Reject malformed request metadata before it can shape response validation."""
    fields = {
        "kind",
        "repository",
        "revision",
        "path",
        "symbol",
        *_FINGERPRINTS,
        "consumer_indexes",
    }
    if not isinstance(request, dict) or set(request) != fields:
        raise EvidenceError("request must contain exactly the canonical request fields")
    kind = request["kind"]
    if not isinstance(kind, str) or kind not in _KINDS:
        raise EvidenceError("request kind is unsupported")
    for name in ("repository", "revision", "path", "symbol"):
        _single_line(request[name], name)
    for name in _FINGERPRINTS:
        _sha(request[name], name)
    consumers = request["consumer_indexes"]
    if not isinstance(consumers, dict):
        raise EvidenceError("request consumer indexes must be an object")
    if (kind == "cross_repo_consumer") != bool(consumers):
        raise EvidenceError("request consumer indexes do not match evidence kind")
    for repo, identity in consumers.items():
        _single_line(repo, "consumer repository")
        if repo == request["repository"]:
            raise EvidenceError("consumer index must name a distinct repository")
        if not isinstance(identity, dict) or set(identity) != {"revision", *_FINGERPRINTS}:
            raise EvidenceError("consumer index identity is incomplete")
        _single_line(identity["revision"], "consumer revision")
        for name in _FINGERPRINTS:
            _sha(identity[name], f"consumer.{name}")
    return request


def _result_payload(response: dict[str, Any]) -> dict[str, Any]:
    return {key: response[key] for key in ("kind", "binding", "evidence")}


def _validate_range(value: dict[str, Any], label: str) -> None:
    if (
        type(value.get("start_line")) is not int
        or value["start_line"] < 1
        or type(value.get("end_line")) is not int
        or value["end_line"] < value["start_line"]
    ):
        raise EvidenceError(f"{label} source range is invalid")


def _validate_changed_symbol(value: object, requested_symbol: str) -> None:
    if not isinstance(value, dict) or set(value) != {"symbol", "before", "after", "change"}:
        raise EvidenceError("changed-symbol evidence must include symbol, before, after, change")
    if not all(
        isinstance(value[key], str) and value[key]
        for key in ("symbol", "before", "after", "change")
    ):
        raise EvidenceError("changed-symbol identities and change are required")
    if value["symbol"] != requested_symbol:
        raise EvidenceError("changed-symbol evidence does not match requested symbol")
    if value["before"] == value["after"]:
        raise EvidenceError("changed-symbol evidence must distinguish before and after identities")


def _validate_references(  # noqa: PLR0912
    value: object, *, kind: str, request: dict[str, Any], binding: dict[str, Any]
) -> None:
    if not isinstance(value, list) or not value:
        raise EvidenceError("reference evidence must be a non-empty list")
    consumer_indexes = request["consumer_indexes"]
    seen_identities: set[tuple[str, str, str, int, int, str]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != _REFERENCE_FIELDS:
            raise EvidenceError("reference lacks exact source identity, range, or fingerprints")
        if not all(
            isinstance(item[key], str) and item[key]
            for key in ("repository", "revision", "path", "symbol")
        ):
            raise EvidenceError("reference identity fields must be non-empty strings")
        _validate_range(item, "reference")
        if item["symbol"] != request["symbol"]:
            raise EvidenceError("reference symbol does not match requested symbol")
        identity = (
            item["repository"],
            item["revision"],
            item["path"],
            item["start_line"],
            item["end_line"],
            item["symbol"],
        )
        if identity in seen_identities:
            raise EvidenceError("duplicate reference identity")
        seen_identities.add(identity)
        if kind == "reverse_reference":
            if item["repository"] != request["repository"]:
                raise EvidenceError("reverse reference must be in the queried repository")
            if item["revision"] != request["revision"]:
                raise EvidenceError("reverse reference revision does not match queried revision")
        else:
            expected_index = consumer_indexes.get(item["repository"])
            if expected_index is None or item["revision"] != expected_index["revision"]:
                raise EvidenceError("consumer repository/revision is not in the explicit request")
        for key in _FINGERPRINTS:
            _sha(item[key], f"reference.{key}")
        expected_fingerprints = (
            {key: binding[key] for key in _FINGERPRINTS}
            if item["repository"] == request["repository"]
            else expected_index
        )
        if any(item[key] != expected_fingerprints[key] for key in _FINGERPRINTS):
            raise EvidenceError("reference fingerprints differ from the requested index identity")


def _validate_call_chain(
    value: object, *, request: dict[str, Any], binding: dict[str, Any]
) -> None:
    if not isinstance(value, list) or not value:
        raise EvidenceError("call-chain evidence requires at least one direct-call edge")
    expected_source = request["symbol"]
    for edge in value:
        if not isinstance(edge, dict) or set(edge) != _CALL_EDGE_FIELDS:
            raise EvidenceError("call-chain edge lacks explicit direct-call evidence or provenance")
        if edge["relation"] != "calls":
            raise EvidenceError(
                "unsupported call-chain relationship; only direct calls are supported"
            )
        if edge["from_symbol"] != expected_source or not all(
            isinstance(edge[key], str) and edge[key]
            for key in ("to_symbol", "repository", "revision", "path", "call_expression")
        ):
            raise EvidenceError("call-chain edges must form an ordered direct-call path")
        if edge["repository"] != request["repository"] or edge["revision"] != request["revision"]:
            raise EvidenceError("call-chain edge is not bound to the queried repository revision")
        _validate_range(edge, "call-chain edge")
        for key in _FINGERPRINTS:
            _sha(edge[key], f"call-chain.{key}")
            if edge[key] != binding[key]:
                raise EvidenceError("call-chain edge fingerprints differ from queried index")
        expression = edge["call_expression"].strip()
        callee_name = edge["to_symbol"].rsplit(".", 1)[-1]
        if not re.search(rf"(?:^|[^\w]){re.escape(callee_name)}\s*\(", expression):
            raise EvidenceError("call edge lacks source text for the declared direct callee")
        expected_source = edge["to_symbol"]


def readiness_status(
    *,
    credentials_reported_available: bool,
    indexed_repositories_reported: set[str],
    required_repositories: set[str],
    coverage_reported_complete: bool,
    provenance_reported_available: bool,
) -> ReadinessStatus:
    """Summarize operator-reported prerequisites; this is not auth or runtime policy."""
    reasons = []
    if not credentials_reported_available:
        reasons.append("credentials_not_reported_available")
    if not required_repositories:
        reasons.append("required_coverage_empty")
    elif not required_repositories <= indexed_repositories_reported:
        reasons.append("required_indexes_not_reported_available")
    if not coverage_reported_complete:
        reasons.append("coverage_not_reported_complete")
    if not provenance_reported_available:
        reasons.append("provenance_not_reported_available")
    return ReadinessStatus("not_ready" if reasons else "ready_to_attempt", tuple(reasons))


def fingerprint(value: object) -> str:
    """Canonical SHA-256 over JSON-compatible, non-secret request/result metadata."""
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as error:
        raise EvidenceError("fingerprint input must be finite JSON-compatible data") from error
    return hashlib.sha256(encoded).hexdigest()


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
    normalized: list[float] = []
    for value in numbers:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ValueError("all TCO inputs must be finite non-negative numbers")
        try:
            numeric = float(value)
        except (OverflowError, ValueError) as error:
            raise ValueError("all TCO inputs must be finite non-negative numbers") from error
        if not math.isfinite(numeric):
            raise ValueError("all TCO inputs must be finite non-negative numbers")
        normalized.append(numeric)
    (
        annual_license,
        annual_compute,
        annual_storage,
        setup_hours,
        hourly_rate,
        annual_operations_hours,
    ) = normalized
    setup = setup_hours * hourly_rate
    operations = annual_operations_hours * hourly_rate * 3
    license_cost = annual_license * 3
    infrastructure = (annual_compute + annual_storage) * 3
    costs = {
        "license_usd": license_cost,
        "infrastructure_usd": infrastructure,
        "setup_labor_usd": setup,
        "operations_labor_usd": operations,
    }
    if any(not math.isfinite(value) for value in costs.values()):
        raise ValueError("derived TCO component exceeds finite numeric range")
    try:
        total = math.fsum(costs.values())
    except OverflowError as error:
        raise ValueError("derived TCO total exceeds finite numeric range") from error
    if not math.isfinite(total):
        raise ValueError("derived TCO total exceeds finite numeric range")
    return {**costs, "total_usd": total}
