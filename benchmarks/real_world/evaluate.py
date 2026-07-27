#!/usr/bin/env python3
"""Evaluate impact-analysis predictions against adjudicated PR labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world.benchmark_schema import (
    BenchmarkSchemaError,
    PrimaryArtifact,
    finite_nonnegative,
    read_primary_artifact,
    strict_json_loads,
)
from benchmarks.real_world.benchmark_scope import (
    SCOPES,
    filter_entrypoint_items,
    filter_record,
)
from benchmarks.real_world.semantic_normalization import (
    ALIAS_VERSION,
    claims,
    match_claims,
    split_ranked_claims,
)


def key(record: dict[str, Any]) -> tuple[str, int]:
    return record["repository"], int(record["pr"])


def entrypoints(record: dict[str, Any]) -> set[str]:
    return {item["id"] for item in record.get("affected_entrypoints", [])}


def entrypoints_by_kind(record: dict[str, Any]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    for item in record.get("affected_entrypoints", []):
        identifier = item["id"]
        kind = item.get("kind")
        if not isinstance(kind, str):
            kind = "http" if identifier.startswith("HTTP ") else "unknown"
        grouped[kind.lower()].add(identifier)
    return grouped


def ranked_entrypoints(record: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Return selected and LOW exact IDs after strongest-tier deduplication."""
    rank = {"low": 0, "medium": 1, "high": 2}
    items = record.get("candidate_entrypoints")
    if items is None:
        items = record.get("affected_entrypoints", [])
    strongest: dict[str, int] = {}
    for item in items:
        identifier = item["id"]
        item_rank = rank.get(str(item.get("confidence", "medium")).lower(), 1)
        strongest[identifier] = max(strongest.get(identifier, -1), item_rank)
    return (
        {identifier for identifier, item_rank in strongest.items() if item_rank >= 1},
        {identifier for identifier, item_rank in strongest.items() if item_rank == 0},
    )


def low_diagnostics(
    expected: set[str],
    selected: set[str],
    low: set[str],
    reachability_only: set[str] | None = None,
) -> dict[str, int]:
    unmatched_expected = expected - selected
    low_matches = unmatched_expected & low
    low_fp = low - expected
    reachability_matches = low_fp & (reachability_only or set())
    return {
        "low_tp": len(low_matches),
        "low_fp": len(low_fp),
        "low_candidates": len(low),
        "low_supported_reachability": len(reachability_matches),
        "low_unmatched": len(low_fp - reachability_matches),
        "fn_with_low_candidate": len(low_matches),
        "fn_with_no_candidate": len(unmatched_expected - low_matches),
    }


def predicted_ids_by_kind(record: dict[str, Any], identifiers: set[str]) -> dict[str, set[str]]:
    rank = {"low": 0, "medium": 1, "high": 2}
    items = record.get("candidate_entrypoints")
    if items is None:
        items = record.get("affected_entrypoints", [])
    strongest: dict[str, tuple[int, str]] = {}
    for item in items:
        identifier = item["id"]
        if identifier not in identifiers:
            continue
        item_rank = rank.get(str(item.get("confidence", "medium")).lower(), 1)
        kind = str(item.get("kind", "unknown")).lower()
        if identifier not in strongest or item_rank > strongest[identifier][0]:
            strongest[identifier] = (item_rank, kind)
    grouped: dict[str, set[str]] = defaultdict(set)
    for identifier, (_item_rank, kind) in strongest.items():
        grouped[kind].add(identifier)
    return grouped


def read_verification_selection(
    path: Path,
) -> tuple[dict[str, Any], str, set[tuple[str, int]], str]:
    """Load and validate a versioned PR-level verification selection."""
    content = path.read_bytes()
    manifest = strict_json_loads(content.decode("utf-8"), str(path))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("verification set must use schema_version 1")
    identifier = manifest.get("id")
    base_scope = manifest.get("base_scope")
    selection = manifest.get("selection", "exclude")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("verification set must have a non-empty id")
    if not isinstance(base_scope, str) or not base_scope.strip():
        raise ValueError("verification set must have a non-empty base_scope")
    if selection not in {"include", "exclude"}:
        raise ValueError("verification set selection must be include or exclude")
    field = "included" if selection == "include" else "excluded"
    raw_items = manifest.get(field)
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError(f"verification set {field} must be a non-empty list")
    selected: set[tuple[str, int]] = set()
    for item in raw_items:
        repository = item.get("repository") if isinstance(item, dict) else None
        if not isinstance(repository, str) or not repository.strip():
            raise ValueError(f"malformed verification-set {field} entry")
        pr = item.get("pr")
        if type(pr) is not int:
            raise ValueError("verification-set PR must be an integer")
        record_key = (repository, pr)
        if record_key in selected:
            raise ValueError(f"duplicate verification-set {field} entry: {record_key}")
        selected.add(record_key)
    return manifest, selection, selected, hashlib.sha256(content).hexdigest()


def _validate_census_entrypoint(item: object, side_name: str, record_key: tuple[str, int]) -> None:
    if not isinstance(item, dict):
        raise ValueError(f"route census has malformed {side_name} entrypoint for {record_key}")
    identifier = item.get("id")
    kind = item.get("kind")
    occurrences = item.get("occurrences")
    if (
        not isinstance(identifier, str)
        or not identifier.strip()
        or not isinstance(kind, str)
        or kind not in {"http", "event"}
        or not isinstance(occurrences, list)
        or not occurrences
    ):
        raise ValueError(f"route census has malformed {side_name} entrypoint for {record_key}")
    for occurrence in occurrences:
        if not isinstance(occurrence, dict):
            raise ValueError(f"route census has malformed occurrence for {record_key}")
        file_name = occurrence.get("file")
        line = occurrence.get("line")
        end_line = occurrence.get("end_line")
        discovery_status = occurrence.get("discovery_status", "established")
        conditions = occurrence.get("discovery_conditions", [])
        if (
            not isinstance(file_name, str)
            or not file_name
            or Path(file_name).is_absolute()
            or ".." in Path(file_name).parts
            or type(line) is not int
            or line < 1
            or (end_line is not None and (type(end_line) is not int or end_line < line))
            or not isinstance(occurrence.get("handler"), str)
            or not occurrence["handler"]
            or not isinstance(occurrence.get("module"), str)
            or not occurrence["module"]
            or not isinstance(occurrence.get("root"), str)
            or not occurrence["root"]
            or discovery_status not in {"established", "conditional"}
            or not isinstance(conditions, list)
            or (discovery_status == "conditional") != bool(conditions)
        ):
            raise ValueError(f"route census has malformed occurrence for {record_key}")
        for condition in conditions:
            if not isinstance(condition, dict):
                raise ValueError(f"route census has malformed occurrence for {record_key}")
            source = condition.get("source")
            source_line = condition.get("line")
            reason = condition.get("reason")
            if (
                not isinstance(source, str)
                or not source
                or Path(source).is_absolute()
                or ".." in Path(source).parts
                or type(source_line) is not int
                or source_line < 1
                or not isinstance(reason, str)
                or not reason.strip()
            ):
                raise ValueError(f"route census has malformed occurrence for {record_key}")


def read_route_census(  # noqa: PLR0912, PLR0915
    path: Path,
    selected_truth_keys: set[tuple[str, int]],
    all_truth_keys: set[tuple[str, int]],
    scope: str,
) -> tuple[dict[tuple[str, int], dict[str, Any]], str]:
    """Load route-census v1/v2 without feeding it into primary scoring."""
    content = path.read_bytes()
    records: dict[tuple[str, int], dict[str, Any]] = {}
    for line_number, line in enumerate(content.decode().splitlines(), start=1):
        if not line.strip():
            continue
        item = strict_json_loads(line, f"{path}: line {line_number}")
        schema_version = item.get("schema_version") if isinstance(item, dict) else None
        if not isinstance(item, dict) or schema_version not in {1, 2}:
            raise ValueError(f"route census line {line_number} must use schema_version 1 or 2")
        record_key = key(item)
        if record_key in records:
            raise ValueError(f"duplicate route-census record: {record_key}")
        if record_key not in all_truth_keys:
            raise ValueError(f"route-census key absent from ground truth: {record_key}")
        status = item.get("status")
        complete = item.get("complete")
        if status not in {"completed", "partial", "unresolved"} or type(complete) is not bool:
            raise ValueError(f"route census has invalid status for {record_key}")
        filtered = dict(item)
        for side_name in ("target", "baseline"):
            side = item.get(side_name)
            if not isinstance(side, dict):
                raise ValueError(f"route census is missing {side_name} for {record_key}")
            side_status = side.get("status")
            entrypoint_items = side.get("entrypoints")
            unresolved = side.get("unresolved")
            if (
                side_status not in {"completed", "partial", "unresolved"}
                or not isinstance(entrypoint_items, list)
                or not isinstance(unresolved, list)
                or any(not isinstance(item, str) or not item.strip() for item in unresolved)
            ):
                raise ValueError(f"route census has malformed {side_name} for {record_key}")
            for entrypoint_item in entrypoint_items:
                _validate_census_entrypoint(entrypoint_item, side_name, record_key)
            if schema_version == 2:
                inventory_status = side.get("inventory_status")
                limitations = side.get("inventory_limitations")
                if inventory_status not in {"established", "conditional", "unavailable"}:
                    raise ValueError(
                        f"route census has invalid inventory strength for {record_key}"
                    )
                if not isinstance(limitations, list):
                    raise ValueError(
                        f"route census has invalid inventory limitations for {record_key}"
                    )
                expected_side_status = {
                    "established": "completed",
                    "conditional": "partial",
                    "unavailable": "unresolved",
                }[inventory_status]
                if side_status != expected_side_status and not (
                    inventory_status == "established" and side_status == "partial" and unresolved
                ):
                    raise ValueError(f"route census inventory/status mismatch for {record_key}")
                if inventory_status == "established" and limitations:
                    raise ValueError(
                        f"route census established inventory has limitations for {record_key}"
                    )
                if inventory_status == "conditional" and not limitations:
                    raise ValueError(
                        f"route census conditional inventory lacks limitations for {record_key}"
                    )
                if inventory_status == "unavailable" and not limitations and not unresolved:
                    raise ValueError(
                        "route census unavailable inventory lacks limitations or "
                        f"an operational error for {record_key}"
                    )
                if inventory_status == "unavailable" and any(
                    occurrence.get("discovery_status", "established") == "established"
                    for entrypoint_item in entrypoint_items
                    for occurrence in entrypoint_item["occurrences"]
                ):
                    raise ValueError(
                        "route census unavailable inventory has established "
                        f"occurrences for {record_key}"
                    )
                for limitation in limitations:
                    if not isinstance(limitation, dict):
                        raise ValueError(
                            f"route census has malformed inventory limitation for {record_key}"
                        )
                    source = limitation.get("source")
                    source_line = limitation.get("line")
                    reason = limitation.get("reason")
                    if (
                        not isinstance(source, str)
                        or not source
                        or Path(source).is_absolute()
                        or ".." in Path(source).parts
                        or type(source_line) is not int
                        or source_line < 1
                        or not isinstance(reason, str)
                        or not reason.strip()
                    ):
                        raise ValueError(
                            f"route census has malformed inventory limitation for {record_key}"
                        )
            else:
                has_conditional = any(
                    occurrence.get("discovery_status", "established") == "conditional"
                    for entrypoint_item in entrypoint_items
                    for occurrence in entrypoint_item["occurrences"]
                )
                inventory_status = (
                    "conditional"
                    if side_status == "completed" and has_conditional
                    else "established"
                    if side_status == "completed"
                    else "unavailable"
                )
                limitations = []
                side_status = {
                    "established": "completed",
                    "conditional": "partial",
                    "unavailable": "unresolved",
                }[inventory_status]
            filtered[side_name] = {
                **side,
                "status": side_status,
                "inventory_status": inventory_status,
                "inventory_limitations": limitations,
                "entrypoints": filter_entrypoint_items(entrypoint_items, scope),
            }
        side_statuses = {filtered[side_name]["status"] for side_name in ("target", "baseline")}
        if side_statuses == {"completed"}:
            derived_status = "completed"
        elif side_statuses == {"unresolved"}:
            derived_status = "unresolved"
        else:
            derived_status = "partial"
        if schema_version == 2 and (
            status != derived_status or complete != (derived_status == "completed")
        ):
            raise ValueError(f"route census complete/status mismatch for {record_key}")
        filtered["status"] = derived_status
        filtered["complete"] = derived_status == "completed"
        records[record_key] = filtered
    missing = selected_truth_keys - set(records)
    if missing:
        raise ValueError(f"route census is missing selected truth keys: {sorted(missing)}")
    return records, hashlib.sha256(content).hexdigest()


def _inventory_items_by_strength(
    record: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split route IDs by strongest physical occurrence across both snapshots."""
    grouped: dict[str, dict[str, Any]] = {}
    if record is not None:
        for side_name in ("target", "baseline"):
            for item in record[side_name]["entrypoints"]:
                current = grouped.setdefault(item["id"], {**item, "occurrences": []})
                current["occurrences"].extend(item["occurrences"])
    established: list[dict[str, Any]] = []
    conditional: list[dict[str, Any]] = []
    for item in grouped.values():
        if any(
            occurrence.get("discovery_status", "established") == "established"
            for occurrence in item["occurrences"]
        ):
            established.append(item)
        else:
            conditional.append(item)
    return established, conditional


def _stage_counts(
    observation: int, propagation: int, discovery: int, unavailable: int
) -> dict[str, int]:
    return {
        "observation_missing": observation,
        "propagation_missing": propagation,
        "discovery_missing": discovery,
        "inventory_unavailable": unavailable,
    }


def ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def _macro_result(
    sums: dict[str, float], samples: dict[str, int]
) -> dict[str, float | dict[str, int]]:
    return {
        "precision": ratio(sums["precision"], samples["precision"]),
        "recall": ratio(sums["recall"], samples["recall"]),
        "f1": ratio(sums["f1"], samples["f1"]),
        "sample_prs": dict(samples),
    }


def _timing_summary(values: list[float]) -> dict[str, int | float]:
    """Return nearest-rank p50/p95 plus mean/max for one timing protocol."""
    ordered = sorted(values)

    def percentile(fraction: float) -> float:
        if not ordered:
            return 0.0
        return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]

    return {
        "samples": len(ordered),
        "mean": ratio(sum(ordered), len(ordered)),
        "p50": percentile(0.50),
        "p95": percentile(0.95),
        "max": max(ordered, default=0.0),
    }


_RUNNER_MANIFEST_FIELDS = {
    "schema_version",
    "prediction_schema_version",
    "created_at",
    "candidate",
    "git",
    "prediction_output",
    "selected_keys",
    "python",
    "platform",
    "corpus",
    "root_config",
    "app_entry_config",
    "bootstrap_entry_config",
    "configuration",
    "selection_count",
    "prs",
    "timing",
}
_CANDIDATE_FIELDS = {
    "id",
    "name",
    "version",
    "adapter",
    "git_sha",
    "config_hash",
    "dirty",
    "dirty_sha256",
    "uv_lock_sha256",
    "uv_version",
    "command",
    "performance_protocol",
}


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkSchemaError(f"prediction manifest {field} must be a non-empty string")
    return value


def _validate_hash(value: object, field: str, length: int) -> str:
    text = _nonempty_string(value, field)
    if len(text) != length or any(character not in "0123456789abcdef" for character in text):
        raise BenchmarkSchemaError(f"prediction manifest {field} is not a valid digest")
    return text


def _validate_timestamp(value: object, field: str) -> str:
    text = _nonempty_string(value, field)
    try:
        timestamp = datetime.fromisoformat(text)
    except ValueError as error:
        raise BenchmarkSchemaError(f"prediction manifest {field} is not ISO-8601") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise BenchmarkSchemaError(f"prediction manifest {field} lacks a timezone")
    return text


def _validate_manifest_candidate(candidate: object) -> dict[str, Any]:
    if not isinstance(candidate, dict) or set(candidate) != _CANDIDATE_FIELDS:
        raise BenchmarkSchemaError("prediction manifest candidate fields are invalid")
    for field in ("id", "name", "version", "uv_version", "command"):
        _nonempty_string(candidate[field], f"candidate.{field}")
    if candidate["name"] != "fastapi-endpoint-detector" or candidate["command"] != (
        "uv run --frozen fastapi-endpoint-detector analyze --no-cache"
    ):
        raise BenchmarkSchemaError("prediction manifest candidate command is invalid")
    _validate_hash(candidate["git_sha"], "candidate.git_sha", 40)
    _validate_hash(candidate["config_hash"], "candidate.config_hash", 12)
    if candidate["adapter"] != "fastapi-adapter-v1":
        raise BenchmarkSchemaError("prediction manifest candidate adapter is invalid")
    if type(candidate["dirty"]) is not bool:
        raise BenchmarkSchemaError("prediction manifest candidate dirty flag is invalid")
    if candidate["dirty"]:
        _validate_hash(candidate["dirty_sha256"], "candidate.dirty_sha256", 64)
    elif candidate["dirty_sha256"] is not None:
        raise BenchmarkSchemaError("clean candidate must not have a dirty digest")
    _validate_hash(candidate["uv_lock_sha256"], "candidate.uv_lock_sha256", 64)
    protocol = candidate["performance_protocol"]
    if protocol != {
        "id": "cold-no-cache-analyzer-wall-v1",
        "cache_enabled": False,
        "incremental_valid": False,
    }:
        raise BenchmarkSchemaError("prediction manifest performance protocol is invalid")
    return candidate


def _validate_string_map(value: object, field: str) -> None:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str) or not key.strip() or not item.strip()
        for key, item in value.items()
    ):
        raise BenchmarkSchemaError(f"prediction manifest {field} must be a string map")


def _validate_manifest_configuration(manifest: dict[str, Any]) -> None:
    root = manifest["root_config"]
    if not isinstance(root, dict) or set(root) != {"default", "repositories"}:
        raise BenchmarkSchemaError("prediction manifest root_config is invalid")
    _nonempty_string(root["default"], "root_config.default")
    _validate_string_map(root["repositories"], "root_config.repositories")
    _validate_string_map(manifest["app_entry_config"], "app_entry_config")
    _validate_string_map(manifest["bootstrap_entry_config"], "bootstrap_entry_config")
    configuration = manifest["configuration"]
    expected = {
        "cache",
        "output",
        "manifest",
        "timeout_seconds",
        "dry_run",
        "allow_upstream_execution",
        "use_scip",
        "filters",
    }
    if not isinstance(configuration, dict) or set(configuration) != expected:
        raise BenchmarkSchemaError("prediction manifest configuration fields are invalid")
    for field in ("cache", "output", "manifest"):
        _nonempty_string(configuration[field], f"configuration.{field}")
    timeout = finite_nonnegative(
        configuration["timeout_seconds"], "prediction manifest configuration.timeout_seconds"
    )
    if timeout == 0:
        raise BenchmarkSchemaError("prediction manifest timeout must be positive")
    for field in ("dry_run", "allow_upstream_execution", "use_scip"):
        if type(configuration[field]) is not bool:
            raise BenchmarkSchemaError(
                f"prediction manifest configuration.{field} must be a boolean"
            )
    filters = configuration["filters"]
    if not isinstance(filters, dict) or set(filters) != {"limit", "repositories", "prs"}:
        raise BenchmarkSchemaError("prediction manifest filters are invalid")
    if filters["limit"] is not None and (type(filters["limit"]) is not int or filters["limit"] < 0):
        raise BenchmarkSchemaError("prediction manifest filter limit is invalid")
    if not isinstance(filters["repositories"], list) or any(
        not isinstance(item, str) or not item for item in filters["repositories"]
    ):
        raise BenchmarkSchemaError("prediction manifest repository filters are invalid")
    if not isinstance(filters["prs"], list) or any(
        type(item) is not int or item < 1 for item in filters["prs"]
    ):
        raise BenchmarkSchemaError("prediction manifest PR filters are invalid")


def _validate_manifest_prs(  # noqa: PLR0912 - fail-closed PR schema checks are explicit
    value: object, prediction_count: int
) -> None:
    required = {
        "repository",
        "pr",
        "configured_app_root",
        "configured_app_entry",
        "configured_bootstrap_entry",
        "merge_sha",
        "base_sha",
        "status",
        "timing_seconds",
    }
    optional = {
        "reason",
        "candidate_endpoint_count",
        "candidate_confidence_counts",
        "effect_evidence_count",
    }
    if not isinstance(value, list) or len(value) != prediction_count:
        raise BenchmarkSchemaError("prediction manifest PR records are invalid")
    for item in value:
        if not isinstance(item, dict) or not required <= set(item) <= required | optional:
            raise BenchmarkSchemaError("prediction manifest PR record fields are invalid")
        _nonempty_string(item["repository"], "prs.repository")
        if type(item["pr"]) is not int or item["pr"] < 1:
            raise BenchmarkSchemaError("prediction manifest PR identity is invalid")
        _nonempty_string(item["configured_app_root"], "prs.configured_app_root")
        for field in ("configured_app_entry", "configured_bootstrap_entry"):
            if item[field] is not None:
                _nonempty_string(item[field], f"prs.{field}")
        for field in ("merge_sha", "base_sha"):
            if item[field] is not None:
                _validate_hash(item[field], f"prs.{field}", 40)
        if item["status"] not in {"completed", "completed_with_unresolved", "unresolved"}:
            raise BenchmarkSchemaError("prediction manifest PR status is invalid")
        if item["status"] != "unresolved" and (
            item["merge_sha"] is None or item["base_sha"] is None
        ):
            raise BenchmarkSchemaError("completed prediction manifest PR lacks source SHAs")
        timing = item["timing_seconds"]
        if not isinstance(timing, dict):
            raise BenchmarkSchemaError("prediction manifest PR timing is invalid")
        for name, timing_value in timing.items():
            finite_nonnegative(timing_value, f"prediction manifest prs.timing_seconds.{name}")
        if item["status"] == "unresolved":
            _nonempty_string(item.get("reason"), "prs.reason")
        for field in ("candidate_endpoint_count", "effect_evidence_count"):
            if field in item and (type(item[field]) is not int or item[field] < 0):
                raise BenchmarkSchemaError(f"prediction manifest prs.{field} is invalid")
        if "candidate_confidence_counts" in item:
            counts = item["candidate_confidence_counts"]
            if (
                not isinstance(counts, dict)
                or set(counts) != {"high", "medium", "low"}
                or any(type(count) is not int or count < 0 for count in counts.values())
            ):
                raise BenchmarkSchemaError(
                    "prediction manifest PR candidate confidence counts are invalid"
                )


def _validate_manifest_shape(manifest: object, prediction_count: int) -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) != _RUNNER_MANIFEST_FIELDS:
        raise BenchmarkSchemaError("prediction manifest has unknown or missing fields")
    if manifest["schema_version"] != 3 or type(manifest["schema_version"]) is not int:
        raise BenchmarkSchemaError("prediction manifest must use schema_version 3")
    if (
        manifest["prediction_schema_version"] != 3
        or type(manifest["prediction_schema_version"]) is not int
    ):
        raise BenchmarkSchemaError("prediction manifest must bind prediction schema 3")
    _validate_timestamp(manifest["created_at"], "created_at")
    for field in ("python", "platform"):
        _nonempty_string(manifest[field], field)
    _validate_manifest_candidate(manifest["candidate"])
    if (
        type(manifest["selection_count"]) is not int
        or manifest["selection_count"] != prediction_count
    ):
        raise BenchmarkSchemaError("prediction manifest selection count mismatch")
    for field in ("git", "corpus"):
        if not isinstance(manifest[field], dict):
            raise BenchmarkSchemaError(f"prediction manifest {field} must be an object")
    _validate_manifest_configuration(manifest)
    _validate_manifest_prs(manifest["prs"], prediction_count)
    timing = manifest["timing"]
    if not isinstance(timing, dict) or set(timing) != {
        "started_at",
        "finished_at",
        "total_seconds",
        "protocol",
        "incremental_valid",
        "not_measured",
    }:
        raise BenchmarkSchemaError("prediction manifest timing fields are invalid")
    _validate_timestamp(timing["started_at"], "timing.started_at")
    _validate_timestamp(timing["finished_at"], "timing.finished_at")
    finite_nonnegative(timing["total_seconds"], "prediction manifest timing.total_seconds")
    if (
        timing["protocol"] != "cold-no-cache-analyzer-wall-v1"
        or timing["incremental_valid"] is not False
        or not isinstance(timing["not_measured"], list)
        or any(not isinstance(item, str) or not item for item in timing["not_measured"])
    ):
        raise BenchmarkSchemaError("prediction manifest timing protocol is invalid")
    return manifest


def read_prediction_manifest(  # noqa: PLR0912 - cross-artifact bindings stay explicit
    path: Path,
    predictions: PrimaryArtifact,
) -> dict[str, Any]:
    """Validate a schema-v3 runner manifest against exact prediction bytes and rows."""
    raw = path.read_bytes()
    manifest = _validate_manifest_shape(
        strict_json_loads(raw.decode("utf-8"), str(path)), len(predictions.records)
    )
    output = manifest["prediction_output"]
    if not isinstance(output, dict) or set(output) != {"path", "sha256", "records"}:
        raise BenchmarkSchemaError("prediction manifest output fields are invalid")
    _nonempty_string(output["path"], "prediction_output.path")
    if Path(output["path"]).resolve() != predictions.path.resolve():
        raise BenchmarkSchemaError("prediction manifest output path does not match predictions")
    configuration = manifest["configuration"]
    if (
        Path(configuration["output"]).resolve() != predictions.path.resolve()
        or Path(configuration["manifest"]).resolve() != path.resolve()
    ):
        raise BenchmarkSchemaError("prediction manifest configured artifact paths mismatch")
    expected_sha = predictions.sha256
    if (
        output.get("sha256") != expected_sha
        or type(output.get("records")) is not int
        or output.get("records") != len(predictions.records)
    ):
        raise BenchmarkSchemaError("prediction manifest output hash or record count mismatch")
    raw_keys = manifest["selected_keys"]
    if not isinstance(raw_keys, list) or len(raw_keys) != len(predictions.records):
        raise BenchmarkSchemaError("prediction manifest selected_keys are invalid")
    manifest_keys: set[tuple[str, int]] = set()
    for item in raw_keys:
        if (
            not isinstance(item, dict)
            or set(item) != {"repository", "pr"}
            or not isinstance(item.get("repository"), str)
            or type(item.get("pr")) is not int
        ):
            raise BenchmarkSchemaError("prediction manifest contains malformed selected key")
        item_key = (item["repository"], item["pr"])
        if item_key in manifest_keys:
            raise BenchmarkSchemaError(f"duplicate prediction manifest key: {item_key}")
        manifest_keys.add(item_key)
    prediction_keys = {key(item) for item in predictions.records}
    if manifest_keys != prediction_keys:
        raise BenchmarkSchemaError("prediction manifest selected keys do not match predictions")
    pr_keys = {
        (item.get("repository"), item.get("pr"))
        for item in manifest["prs"]
        if isinstance(item, dict)
    }
    if pr_keys != prediction_keys:
        raise BenchmarkSchemaError("prediction manifest PR records do not match predictions")
    candidate = manifest["candidate"]
    if manifest["git"] != {"candidate_sha": candidate["git_sha"]}:
        raise BenchmarkSchemaError("prediction manifest Git binding is invalid")
    corpus = manifest["corpus"]
    if set(corpus) != {"path", "sha256"}:
        raise BenchmarkSchemaError("prediction manifest corpus binding is invalid")
    _nonempty_string(corpus["path"], "corpus.path")
    _validate_hash(corpus["sha256"], "corpus.sha256", 64)
    candidate_id = candidate.get("id") if isinstance(candidate, dict) else None
    record_candidates = {item.get("candidate") for item in predictions.records}
    record_adapters = {item.get("adapter") for item in predictions.records}
    if record_candidates != {candidate_id} or record_adapters != {candidate["adapter"]}:
        raise BenchmarkSchemaError("prediction manifest candidate does not match predictions")
    ineligibility_reasons = []
    if configuration["dry_run"]:
        ineligibility_reasons.append("dry_run")
    if configuration["allow_upstream_execution"]:
        ineligibility_reasons.append("upstream_execution")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "prediction_sha256": expected_sha,
        "candidate": candidate_id,
        "adapter": candidate["adapter"],
        "runner_provenance_validated": True,
        "secure_execution_eligible": not ineligibility_reasons,
        "execution_ineligibility_reasons": ineligibility_reasons,
    }


def main() -> None:  # noqa: PLR0912, PLR0915 - raw and normalized metrics share one pass
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--scope", choices=SCOPES, default="all")
    parser.add_argument("--verification-set", type=Path)
    parser.add_argument("--route-census", type=Path)
    parser.add_argument(
        "--prediction-manifest",
        type=Path,
        help="schema-v3 runner manifest that authenticates prediction bytes and selection",
    )
    args = parser.parse_args()

    scope_id = {
        "all": "all-surfaces",
        "fastapi": "fastapi-adapter-v1",
        "out-of-scope": "out-of-scope-v1",
    }[args.scope]
    verification_manifest: dict[str, Any] | None = None
    verification_selection: str | None = None
    verification_keys: set[tuple[str, int]] = set()
    verification_sha256: str | None = None
    if args.verification_set is not None:
        (
            verification_manifest,
            verification_selection,
            verification_keys,
            verification_sha256,
        ) = read_verification_selection(args.verification_set)
        if verification_manifest["base_scope"] != scope_id:
            raise ValueError(
                f"verification set requires scope {verification_manifest['base_scope']!r}, "
                f"not {scope_id!r}"
            )

    truth_artifact = read_primary_artifact(args.ground_truth, "ground_truth")
    truth_records = truth_artifact.records
    truth_keys = {key(item) for item in truth_records}
    unmatched = verification_keys - truth_keys
    if unmatched:
        raise ValueError(f"verification-set keys absent from ground truth: {sorted(unmatched)}")
    truth = {
        key(item): filter_record(item, args.scope)
        for item in truth_records
        if verification_selection is None
        or (verification_selection == "include" and key(item) in verification_keys)
        or (verification_selection == "exclude" and key(item) not in verification_keys)
    }
    prediction_artifact = read_primary_artifact(args.predictions, "prediction")
    prediction_records = prediction_artifact.records
    prediction_integrity = (
        read_prediction_manifest(args.prediction_manifest, prediction_artifact)
        if args.prediction_manifest is not None
        else None
    )
    prediction_keys = {key(item) for item in prediction_records}
    unknown_prediction_keys = prediction_keys - truth_keys
    if unknown_prediction_keys:
        raise ValueError(
            f"prediction keys absent from ground truth: {sorted(unknown_prediction_keys)}"
        )
    predictions = {key(item): filter_record(item, args.scope) for item in prediction_records}
    adjudicated_keys = {
        record_key for record_key, record in truth.items() if record.get("status") == "adjudicated"
    }
    unknown_label_prs = sum(1 for record in truth.values() if record.get("status") == "unknown")
    not_evaluable_prs = sum(
        1 for record in truth.values() if record.get("status") == "not_evaluable"
    )
    missing_prediction_keys = adjudicated_keys - prediction_keys
    if missing_prediction_keys:
        raise ValueError(
            f"predictions are missing selected adjudicated keys: {sorted(missing_prediction_keys)}"
        )
    census: dict[tuple[str, int], dict[str, Any]] | None = None
    census_sha256: str | None = None
    if args.route_census is not None:
        census, census_sha256 = read_route_census(
            args.route_census, set(truth), truth_keys, args.scope
        )
    totals: dict[str, int] = defaultdict(int)
    macro_sums: dict[str, float] = defaultdict(float)
    macro_samples: dict[str, int] = defaultdict(int)
    evaluated = 0
    completed_prediction_records = 0
    timing_samples: dict[str, list[float]] = defaultdict(list)
    kind_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_totals: dict[str, int] = defaultdict(int)
    normalized_macro_sums: dict[str, float] = defaultdict(float)
    normalized_macro_samples: dict[str, int] = defaultdict(int)
    normalized_kinds: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_rules: dict[str, int] = defaultdict(int)
    low_rules: dict[str, int] = defaultdict(int)
    ranked_totals: dict[str, int] = defaultdict(int)
    ranked_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_ranked_totals: dict[str, int] = defaultdict(int)
    normalized_ranked_repositories: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    repository_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    truth_positive_prs = 0
    negative_controls_with_fp = 0
    negative_controls_with_low_fp = 0
    completed_negative_controls = 0
    clean_completed_negative_controls = 0
    exact_stage_totals: dict[str, int] = defaultdict(int)
    normalized_stage_totals: dict[str, int] = defaultdict(int)
    exact_stage_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_stage_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    exact_stage_prs: dict[tuple[str, int], dict[str, int]] = {}
    normalized_stage_prs: dict[tuple[str, int], dict[str, int]] = {}

    for record_key, expected_record in truth.items():
        if expected_record.get("status", "adjudicated") != "adjudicated":
            continue
        evaluated += 1
        expected = entrypoints(expected_record)
        reachability_only = {
            item["id"] for item in expected_record.get("reachability_only_entrypoints", [])
        }
        predicted_record = predictions[record_key]
        predicted, low_predicted = ranked_entrypoints(predicted_record)
        unresolved = predicted_record.get("unresolved", [])
        if not unresolved:
            completed_prediction_records += 1
        tp = len(expected & predicted)
        fp = len(predicted - expected)
        fn = len(expected - predicted)
        totals["tp"] += tp
        totals["fp"] += fp
        totals["fn"] += fn
        repository_totals[record_key[0]]["tp"] += tp
        repository_totals[record_key[0]]["fp"] += fp
        repository_totals[record_key[0]]["fn"] += fn
        exact_low = low_diagnostics(expected, predicted, low_predicted, reachability_only)
        for metric, count in exact_low.items():
            ranked_totals[metric] += count
            ranked_repositories[record_key[0]][metric] += count
        census_record = census.get(record_key) if census is not None else None
        if census is not None:
            exact_observation_ids = (expected - predicted) & low_predicted
            exact_after_low = (expected - predicted) - exact_observation_ids
            established_items, conditional_items = _inventory_items_by_strength(census_record)
            established_ids = {item["id"] for item in established_items}
            conditional_ids = {item["id"] for item in conditional_items}
            exact_propagation_ids = exact_after_low & established_ids
            exact_after_established = exact_after_low - exact_propagation_ids
            exact_conditional_ids = exact_after_established & conditional_ids
            exact_after_inventory = exact_after_established - exact_conditional_ids
            inventory_complete = census_record is not None and census_record["complete"]
            exact_stage = _stage_counts(
                len(exact_observation_ids),
                len(exact_propagation_ids),
                len(exact_after_inventory) if inventory_complete else 0,
                len(exact_conditional_ids)
                + (len(exact_after_inventory) if not inventory_complete else 0),
            )
            if sum(exact_stage.values()) != fn:
                raise AssertionError(f"exact FN-stage partition failed for {record_key}")
            exact_stage_prs[record_key] = exact_stage
            for metric, count in exact_stage.items():
                exact_stage_totals[metric] += count
                exact_stage_repositories[record_key[0]][metric] += count
        if expected:
            truth_positive_prs += 1
        else:
            if predicted:
                negative_controls_with_fp += 1
            if low_predicted:
                negative_controls_with_low_fp += 1
            if not unresolved:
                completed_negative_controls += 1
                if not predicted:
                    clean_completed_negative_controls += 1
        totals["unresolved"] += len(unresolved)
        expected_kinds = entrypoints_by_kind(expected_record)
        predicted_kinds = predicted_ids_by_kind(predicted_record, predicted)
        for kind in expected_kinds.keys() | predicted_kinds.keys():
            expected_kind = expected_kinds.get(kind, set())
            predicted_kind = predicted_kinds.get(kind, set())
            kind_totals[kind]["tp"] += len(expected_kind & predicted_kind)
            kind_totals[kind]["fp"] += len(predicted_kind - expected_kind)
            kind_totals[kind]["fn"] += len(expected_kind - predicted_kind)
        expected_claims = claims(expected_record)
        selected_claims, low_claims = split_ranked_claims(record_key[0], predicted_record)
        normalized = match_claims(record_key[0], expected_claims, selected_claims)
        residual_expected = [
            claim
            for index, claim in enumerate(normalized["expected_claims"])
            if index not in normalized["_matched_expected"]
        ]
        normalized_low = match_claims(record_key[0], residual_expected, low_claims)
        unmatched_low_claims = [
            claim
            for index, claim in enumerate(normalized_low["predicted_claims"])
            if index not in normalized_low["_matched_predicted"]
        ]
        reachability_record = {
            "affected_entrypoints": expected_record.get("reachability_only_entrypoints", [])
        }
        normalized_reachability = match_claims(
            record_key[0], claims(reachability_record), unmatched_low_claims
        )
        for metric in ("tp", "fp", "fn", "expected_atoms", "predicted_atoms"):
            normalized_totals[metric] += normalized[metric]
        normalized_low_counts = {
            "low_tp": normalized_low["tp"],
            "low_fp": normalized_low["fp"],
            "low_candidates": normalized_low["predicted_atoms"],
            "low_supported_reachability": normalized_reachability["tp"],
            "low_unmatched": normalized_reachability["fp"],
            "fn_with_low_candidate": normalized_low["tp"],
            "fn_with_no_candidate": normalized_low["fn"],
        }
        for metric, count in normalized_low_counts.items():
            normalized_ranked_totals[metric] += count
            normalized_ranked_repositories[record_key[0]][metric] += count
        if census is not None:
            normalized_after_low = [
                claim
                for index, claim in enumerate(normalized_low["expected_claims"])
                if index not in normalized_low["_matched_expected"]
            ]
            established_items, conditional_items = _inventory_items_by_strength(census_record)
            inventory_match = match_claims(
                record_key[0],
                normalized_after_low,
                claims({"affected_entrypoints": established_items}),
            )
            after_established = [
                claim
                for index, claim in enumerate(inventory_match["expected_claims"])
                if index not in inventory_match["_matched_expected"]
            ]
            conditional_match = match_claims(
                record_key[0],
                after_established,
                claims({"affected_entrypoints": conditional_items}),
            )
            normalized_remaining = conditional_match["fn"]
            inventory_complete = census_record is not None and census_record["complete"]
            normalized_stage = _stage_counts(
                normalized_low["tp"],
                inventory_match["tp"],
                normalized_remaining if inventory_complete else 0,
                conditional_match["tp"] + (normalized_remaining if not inventory_complete else 0),
            )
            if sum(normalized_stage.values()) != normalized["fn"]:
                raise AssertionError(f"normalized FN-stage partition failed for {record_key}")
            normalized_stage_prs[record_key] = normalized_stage
            for metric, count in normalized_stage.items():
                normalized_stage_totals[metric] += count
                normalized_stage_repositories[record_key[0]][metric] += count
        for rule, count in normalized_low["matches_by_rule"].items():
            low_rules[rule] += count
        for metric in ("tp", "fp", "fn"):
            normalized_repositories[record_key[0]][metric] += normalized[metric]
        for rule, count in normalized["matches_by_rule"].items():
            normalized_rules[rule] += count
        for match in normalized["matches"]:
            normalized_kinds[match["kind"]]["tp"] += 1
        for index, claim in enumerate(normalized["expected_claims"]):
            if index not in normalized["_matched_expected"]:
                normalized_kinds[claim.kind]["fn"] += 1
        for index, claim in enumerate(normalized["predicted_claims"]):
            if index not in normalized["_matched_predicted"]:
                normalized_kinds[claim.kind]["fp"] += 1
        normalized_precision = ratio(normalized["tp"], normalized["tp"] + normalized["fp"])
        normalized_recall = ratio(normalized["tp"], normalized["tp"] + normalized["fn"])
        normalized_f1 = ratio(
            2 * normalized_precision * normalized_recall,
            normalized_precision + normalized_recall,
        )
        if normalized["expected_atoms"]:
            normalized_macro_sums["precision"] += normalized_precision
            normalized_macro_sums["recall"] += normalized_recall
            normalized_macro_sums["f1"] += normalized_f1
            for metric in ("precision", "recall", "f1"):
                normalized_macro_samples[metric] += 1

        precision = ratio(tp, tp + fp)
        recall = ratio(tp, tp + fn)
        f1 = ratio(2 * precision * recall, precision + recall)
        if expected:
            macro_sums["precision"] += precision
            macro_sums["recall"] += recall
            macro_sums["f1"] += f1
            for metric in ("precision", "recall", "f1"):
                macro_samples[metric] += 1
        for name, value in predicted_record.get("timing_seconds", {}).items():
            protocol = (
                name if predicted_record.get("schema_version") == 3 else f"legacy_unattested_{name}"
            )
            timing_samples[protocol].append(float(value))
        if "analyzer_seconds" in predicted_record:
            timing_samples["legacy_analyzer_wall"].append(
                float(predicted_record["analyzer_seconds"])
            )
        if "incremental_seconds" in predicted_record:
            timing_samples["legacy_reported_incremental_unattested"].append(
                float(predicted_record["incremental_seconds"])
            )

    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)

    def metrics(counts: dict[str, int]) -> dict[str, int | float]:
        item_precision = ratio(counts["tp"], counts["tp"] + counts["fp"])
        item_recall = ratio(counts["tp"], counts["tp"] + counts["fn"])
        return {
            "precision": item_precision,
            "recall": item_recall,
            "f1": ratio(2 * item_precision * item_recall, item_precision + item_recall),
            "tp": counts["tp"],
            "fp": counts["fp"],
            "fn": counts["fn"],
        }

    def confidence_diagnostics(
        primary: dict[str, int], low_counts: dict[str, int]
    ) -> dict[str, Any]:
        low_tp = low_counts["low_tp"]
        low_fp = low_counts["low_fp"]
        ceiling = {
            "tp": primary["tp"] + low_tp,
            "fp": primary["fp"] + low_fp,
            "fn": low_counts["fn_with_no_candidate"],
        }
        return {
            "policy": "HIGH and MEDIUM are primary; LOW is diagnostic only",
            "low": {
                **dict(low_counts),
                "diagnostic_precision": ratio(low_tp, low_tp + low_fp),
                "supported_precision": ratio(
                    low_tp + low_counts["low_supported_reachability"],
                    low_counts["low_candidates"],
                ),
            },
            "candidate_ceiling": metrics(ceiling),
        }

    negative_control_prs = evaluated - truth_positive_prs
    inventory_completed = (
        sum(1 for record_key in adjudicated_keys if census[record_key]["complete"])
        if census is not None
        else 0
    )
    timing_results = {
        name: {
            **_timing_summary(values),
            "incremental_valid": False,
            "definition": (
                "historical field; timing protocol was not attested"
                if name.startswith("legacy_")
                else "runner-declared timing protocol"
            ),
        }
        for name, values in sorted(timing_samples.items())
    }
    result = {
        "schema_version": 2,
        "scope": scope_id,
        "integrity": {
            "ground_truth": {
                "path": str(args.ground_truth),
                "sha256": truth_artifact.sha256,
                "records": len(truth_records),
            },
            "predictions": {
                "path": str(args.predictions),
                "sha256": prediction_artifact.sha256,
                "records": len(prediction_records),
            },
            "prediction_manifest": prediction_integrity,
            "prediction_bytes_attested": prediction_integrity is not None,
            "runner_provenance_validated": prediction_integrity is not None,
            "secure_execution_eligible": bool(
                prediction_integrity and prediction_integrity["secure_execution_eligible"]
            ),
            "truth_selection_attested": False,
            "source_inventory_attested": False,
            "fully_attested": False,
            "official_scoring_eligible": False,
            "limitations": [
                "ground-truth completeness is not yet bound to a corpus selection manifest",
                "candidate source inventory is not yet bound into the runner manifest",
                "incremental backend reuse is not measured or attested",
            ],
        },
        "verification_set": (
            {
                "id": verification_manifest["id"],
                "path": str(args.verification_set),
                "selection": verification_selection,
                "selected_keys": [
                    {"repository": repository, "pr": pr}
                    for repository, pr in sorted(verification_keys)
                ],
                "matched_prs": len(verification_keys),
                "sha256": verification_sha256,
            }
            if verification_manifest is not None
            else None
        ),
        "adjudicated_prs": evaluated,
        "unknown_label_prs": unknown_label_prs,
        "not_evaluable_prs": not_evaluable_prs,
        "prediction_coverage": ratio(len(adjudicated_keys & set(predictions)), evaluated),
        "coverage": {
            "record": {
                "numerator": len(adjudicated_keys & set(predictions)),
                "denominator": evaluated,
                "rate": ratio(len(adjudicated_keys & set(predictions)), evaluated),
            },
            "completed": {
                "numerator": completed_prediction_records,
                "denominator": evaluated,
                "rate": ratio(completed_prediction_records, evaluated),
                "definition": "prediction rows with no unresolved diagnostics",
            },
            "inventory": {
                "available": census is not None,
                "numerator": inventory_completed if census is not None else None,
                "denominator": evaluated if census is not None else None,
                "rate": ratio(inventory_completed, evaluated) if census is not None else None,
            },
            "changed_symbols": {"available": False, "rate": None},
            "unresolved_hunks": {"available": False, "rate": None},
        },
        "truth_positive_prs": truth_positive_prs,
        "negative_control_prs": negative_control_prs,
        "negative_controls_with_fp": negative_controls_with_fp,
        "negative_controls_with_low_fp": negative_controls_with_low_fp,
        "negative_control_specificity": {
            "completed_controls": completed_negative_controls,
            "all_controls": negative_control_prs,
            "clean_completed_controls": clean_completed_negative_controls,
            "completed_control_coverage": ratio(completed_negative_controls, negative_control_prs),
            "specificity": ratio(clean_completed_negative_controls, completed_negative_controls),
            "conservative_specificity": ratio(
                clean_completed_negative_controls, negative_control_prs
            ),
        },
        "micro": {
            "precision": precision,
            "recall": recall,
            "f1": ratio(2 * precision * recall, precision + recall),
            "tp": tp,
            "fp": fp,
            "fn": fn,
        },
        "confidence": {
            **confidence_diagnostics(totals, ranked_totals),
            "by_repository": {
                repository: confidence_diagnostics(repository_totals[repository], counts)
                for repository, counts in sorted(ranked_repositories.items())
            },
        },
        "macro": _macro_result(macro_sums, macro_samples),
        "by_repository": {
            repository: metrics(counts) for repository, counts in sorted(repository_totals.items())
        },
        "by_kind": {
            kind: {
                "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
                "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
                "f1": ratio(
                    2
                    * ratio(counts["tp"], counts["tp"] + counts["fp"])
                    * ratio(counts["tp"], counts["tp"] + counts["fn"]),
                    ratio(counts["tp"], counts["tp"] + counts["fp"])
                    + ratio(counts["tp"], counts["tp"] + counts["fn"]),
                ),
                **dict(counts),
            }
            for kind, counts in sorted(kind_totals.items())
        },
        "normalized": {
            "alias_version": ALIAS_VERSION,
            "micro": metrics(normalized_totals),
            "macro": _macro_result(normalized_macro_sums, normalized_macro_samples),
            "by_repository": {
                repository: metrics(counts)
                for repository, counts in sorted(normalized_repositories.items())
            },
            "by_kind": {kind: metrics(counts) for kind, counts in sorted(normalized_kinds.items())},
            "expected_atoms": normalized_totals["expected_atoms"],
            "predicted_atoms": normalized_totals["predicted_atoms"],
            "matches_by_rule": dict(sorted(normalized_rules.items())),
            "low_matches_by_rule": dict(sorted(low_rules.items())),
            "confidence": {
                **confidence_diagnostics(normalized_totals, normalized_ranked_totals),
                "by_repository": {
                    repository: confidence_diagnostics(normalized_repositories[repository], counts)
                    for repository, counts in sorted(normalized_ranked_repositories.items())
                },
            },
            "rules": [
                "raw exact",
                "composite HTTP method expansion",
                "template parameter-name normalization with converter preservation",
                "case-insensitive WebSocket family",
                "unique generic/qualified relaxation",
                "frozen repository-scoped explicit aliases",
            ],
        },
        "unresolved_items": totals["unresolved"],
        "performance": {
            "percentile_method": "nearest-rank",
            "protocols": timing_results,
            "incremental_gate_eligible": False,
            "reason": "no backend currently attests incremental index reuse",
        },
    }
    if census is not None:
        if sum(exact_stage_totals.values()) != totals["fn"]:
            raise AssertionError("global exact FN-stage partition failed")
        if sum(normalized_stage_totals.values()) != normalized_totals["fn"]:
            raise AssertionError("global normalized FN-stage partition failed")
        result["fn_stages"] = {
            "schema_version": 1,
            "route_census": {
                "path": str(args.route_census),
                "sha256": census_sha256,
            },
            "definitions": {
                "observation_missing": (
                    "Primary FN matched only by a LOW candidate; this is operational, "
                    "not a causal diagnosis."
                ),
                "propagation_missing": (
                    "Primary FN absent from LOW but present in target or baseline "
                    "static route inventory."
                ),
                "discovery_missing": (
                    "Primary FN absent from both sides of a complete configured static inventory."
                ),
                "inventory_unavailable": (
                    "Primary FN could not be classified because inventory was missing "
                    "or incomplete."
                ),
            },
            "exact": {
                "totals": dict(exact_stage_totals),
                "by_repository": {
                    repository: dict(counts)
                    for repository, counts in sorted(exact_stage_repositories.items())
                },
                "by_pr": [
                    {"repository": repository, "pr": pr, **counts}
                    for (repository, pr), counts in sorted(exact_stage_prs.items())
                ],
            },
            "normalized": {
                "totals": dict(normalized_stage_totals),
                "by_repository": {
                    repository: dict(counts)
                    for repository, counts in sorted(normalized_stage_repositories.items())
                },
                "by_pr": [
                    {"repository": repository, "pr": pr, **counts}
                    for (repository, pr), counts in sorted(normalized_stage_prs.items())
                ],
            },
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
