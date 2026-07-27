"""Strict, backwards-compatible validation for benchmark JSON artifacts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from pathlib import Path

RecordKind = Literal["ground_truth", "prediction"]
_ALLOWED_CONFIDENCE = {"high", "medium", "low"}
_ALLOWED_TRUTH_STATUS = {"adjudicated", "not_evaluable", "unknown"}
_ALLOWED_PREDICTION_STATUS = {"completed", "partial", "unresolved"}
_V3_PREDICTION_FIELDS = {
    "schema_version",
    "repository",
    "pr",
    "candidate",
    "adapter",
    "status",
    "affected_entrypoints",
    "candidate_entrypoints",
    "unresolved",
    "timing_seconds",
}
_HTTP_ENTRYPOINT = re.compile(r"HTTP (?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|TRACE|CUSTOM) /.*")
_WEBSOCKET_ENTRYPOINT = re.compile(r"WEBSOCKET /.*")


class BenchmarkSchemaError(ValueError):
    """A benchmark artifact is malformed or ambiguous."""


@dataclass(frozen=True)
class PrimaryArtifact:
    """One immutable byte snapshot and the records parsed from it."""

    path: Path
    content: bytes
    sha256: str
    records: list[dict[str, Any]]


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


def _record_identity(record: dict[str, Any], location: str) -> tuple[str, int]:
    repository = record.get("repository")
    pr = record.get("pr")
    if not isinstance(repository, str) or not repository.strip():
        raise BenchmarkSchemaError(f"{location}: repository must be a non-empty string")
    if type(pr) is not int or pr < 1:
        raise BenchmarkSchemaError(f"{location}: pr must be a positive integer")
    return repository, pr


def _validate_entrypoints(
    value: object,
    field: str,
    location: str,
    *,
    ranked: bool,
) -> None:
    if not isinstance(value, list):
        raise BenchmarkSchemaError(f"{location}: {field} must be a list")
    identifiers: set[str] = set()
    for index, item in enumerate(value):
        item_location = f"{location}: {field}[{index}]"
        if not isinstance(item, dict):
            raise BenchmarkSchemaError(f"{item_location} must be an object")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            raise BenchmarkSchemaError(f"{item_location}.id must be a non-empty string")
        if identifier in identifiers:
            raise BenchmarkSchemaError(f"{location}: duplicate {field} id {identifier!r}")
        identifiers.add(identifier)
        kind = item.get("kind")
        if kind is not None and (not isinstance(kind, str) or not kind.strip()):
            raise BenchmarkSchemaError(f"{item_location}.kind must be a non-empty string")
        if ranked:
            confidence = item.get("confidence")
            if confidence not in _ALLOWED_CONFIDENCE:
                raise BenchmarkSchemaError(
                    f"{item_location}.confidence must be high, medium, or low"
                )


def _validate_truth_record(record: dict[str, Any], location: str) -> None:
    if record.get("status") not in _ALLOWED_TRUTH_STATUS:
        raise BenchmarkSchemaError(
            f"{location}: status must be adjudicated, not_evaluable, or unknown"
        )
    if "reachability_only_entrypoints" in record:
        _validate_entrypoints(
            record["reachability_only_entrypoints"],
            "reachability_only_entrypoints",
            location,
            ranked=False,
        )


def _validate_timing(record: dict[str, Any], location: str) -> None:
    for field in ("index_seconds", "incremental_seconds", "analyzer_seconds"):
        if field in record:
            finite_nonnegative(record[field], f"{location}: {field}")
    timing = record.get("timing_seconds")
    if timing is None:
        return
    if not isinstance(timing, dict) or any(
        not isinstance(name, str) or not name.strip() for name in timing
    ):
        raise BenchmarkSchemaError(f"{location}: timing_seconds must be an object")
    for name, value in timing.items():
        finite_nonnegative(value, f"{location}: timing_seconds.{name}")


def _validate_v3_entrypoint(item: dict[str, Any], field: str, location: str) -> None:
    expected = (
        {"id", "kind", "confidence", "effect_evidence"}
        if field == "candidate_entrypoints"
        else {"id", "kind", "evidence"}
    )
    if set(item) != expected:
        raise BenchmarkSchemaError(f"{location}: schema 3 {field} has unknown or missing fields")
    evidence_field = "effect_evidence" if field == "candidate_entrypoints" else "evidence"
    if not isinstance(item[evidence_field], list):
        raise BenchmarkSchemaError(f"{location}: {evidence_field} must be a list")
    identifier = item["id"]
    kind = item["kind"]
    if _HTTP_ENTRYPOINT.fullmatch(identifier):
        if kind != "http":
            raise BenchmarkSchemaError(f"{location}: HTTP entrypoint kind must be http")
    elif _WEBSOCKET_ENTRYPOINT.fullmatch(identifier):
        if kind != "event":
            raise BenchmarkSchemaError(f"{location}: WebSocket entrypoint kind must be event")
    else:
        raise BenchmarkSchemaError(f"{location}: entrypoint is not emitted by fastapi-adapter-v1")


def _validate_v3_prediction(record: dict[str, Any], unresolved: list[str], location: str) -> None:
    if set(record) != _V3_PREDICTION_FIELDS:
        raise BenchmarkSchemaError(f"{location}: schema 3 prediction has unknown or missing fields")
    candidate = record.get("candidate")
    if not isinstance(candidate, str) or not candidate.strip():
        raise BenchmarkSchemaError(f"{location}: schema 3 requires candidate")
    if record.get("adapter") != "fastapi-adapter-v1":
        raise BenchmarkSchemaError(f"{location}: schema 3 requires fastapi-adapter-v1")
    for field in ("affected_entrypoints", "candidate_entrypoints"):
        for index, item in enumerate(record[field]):
            _validate_v3_entrypoint(item, field, f"{location}: {field}[{index}]")
    status = record.get("status")
    if status not in _ALLOWED_PREDICTION_STATUS:
        raise BenchmarkSchemaError(
            f"{location}: schema 3 status must be completed, partial, or unresolved"
        )
    if (status == "completed") != (not unresolved):
        raise BenchmarkSchemaError(
            f"{location}: schema 3 status and unresolved diagnostics disagree"
        )
    if "index_seconds" in record or "incremental_seconds" in record:
        raise BenchmarkSchemaError(
            f"{location}: schema 3 forbids legacy index/incremental timing fields"
        )


def _validate_prediction_record(
    record: dict[str, Any], location: str, schema_version: object
) -> None:
    candidate = record.get("candidate")
    if not isinstance(candidate, str) or not candidate.strip():
        raise BenchmarkSchemaError(f"{location}: candidate must be a non-empty string")
    if "candidate_entrypoints" in record:
        _validate_entrypoints(
            record["candidate_entrypoints"],
            "candidate_entrypoints",
            location,
            ranked=True,
        )
    for index, item in enumerate(record["affected_entrypoints"]):
        confidence = item.get("confidence")
        if confidence is not None and confidence not in _ALLOWED_CONFIDENCE:
            raise BenchmarkSchemaError(
                f"{location}: affected_entrypoints[{index}].confidence is invalid"
            )
    unresolved = record.get("unresolved", [])
    if not isinstance(unresolved, list) or any(
        not isinstance(item, str) or not item.strip() for item in unresolved
    ):
        raise BenchmarkSchemaError(f"{location}: unresolved must contain non-empty strings")
    _validate_timing(record, location)
    if schema_version == 3:
        _validate_v3_prediction(record, unresolved, location)


def _validate_record(record: dict[str, Any], kind: RecordKind, location: str) -> None:
    schema_version = record.get("schema_version")
    if schema_version is not None and type(schema_version) is not int:
        raise BenchmarkSchemaError(f"{location}: schema_version must be an integer")
    if schema_version not in {None, 2, 3}:
        raise BenchmarkSchemaError(f"{location}: unsupported schema_version {schema_version!r}")
    _record_identity(record, location)
    _validate_entrypoints(
        record.get("affected_entrypoints"),
        "affected_entrypoints",
        location,
        ranked=False,
    )
    if kind == "ground_truth":
        _validate_truth_record(record, location)
    else:
        _validate_prediction_record(record, location, schema_version)


def read_primary_artifact(path: Path, kind: RecordKind) -> PrimaryArtifact:
    """Read one immutable byte snapshot and validate every primary JSONL record."""
    try:
        content = path.read_bytes()
        text = content.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise BenchmarkSchemaError(f"could not read {path}: {error}") from error
    records: list[dict[str, Any]] = []
    seen: dict[tuple[str, int], int] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        location = f"{path}: line {line_number}"
        value = strict_json_loads(line, location)
        if not isinstance(value, dict):
            raise BenchmarkSchemaError(f"{location}: record must be an object")
        _validate_record(value, kind, location)
        identity = _record_identity(value, location)
        previous = seen.get(identity)
        if previous is not None:
            raise BenchmarkSchemaError(
                f"{location}: duplicate record {identity}; first seen on line {previous}"
            )
        seen[identity] = line_number
        records.append(value)
    if not records:
        raise BenchmarkSchemaError(f"{path}: artifact has no records")
    if kind == "prediction":
        candidates = {
            record["candidate"] for record in records if isinstance(record.get("candidate"), str)
        }
        candidate_rows = sum(1 for record in records if isinstance(record.get("candidate"), str))
        if len(candidates) != 1 or candidate_rows != len(records):
            raise BenchmarkSchemaError(
                f"{path}: prediction records have missing or inconsistent candidate identities"
            )
    return PrimaryArtifact(
        path=path,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        records=records,
    )


def read_primary_jsonl(path: Path, kind: RecordKind) -> list[dict[str, Any]]:
    """Compatibility wrapper returning records from one validated byte snapshot."""
    return read_primary_artifact(path, kind).records
