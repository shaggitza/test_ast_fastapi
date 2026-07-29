#!/usr/bin/env python3
"""Compare paired secure/runtime artifacts without treating runtime as truth."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world._secure_publish import SecurePathError, publish_exclusive_bytes
from benchmarks.real_world.benchmark_schema import (
    BenchmarkSchemaError,
    finite_nonnegative,
    strict_json_loads,
)

_FAILURE_PHASES = {
    "dependency",
    "import",
    "app_resolution",
    "extraction",
    "timeout",
    "unavailable",
}
_PARAMETER = re.compile(r"\{[^{}]+\}")
_LOCK_HASH = re.compile(r"(?:sha256:)?[0-9a-f]{64}", re.IGNORECASE)
_ENTRY_CONFIGURATION_FIELDS = {
    "app_entry",
    "bootstrap_entry",
    "app_variable",
    "backend",
}
_RUNTIME_ROLE = "positive_observation_comparator_not_truth"


class ComparisonError(ValueError):
    """A paired record is invalid or configured inequitably."""


def _load(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ComparisonError(f"could not read {path}: {error}") from error
    try:
        value = strict_json_loads(raw.decode("utf-8"), str(path))
    except (BenchmarkSchemaError, UnicodeError) as exc:
        raise ComparisonError(str(exc)) from exc
    if not isinstance(value, dict):
        raise ComparisonError(f"record {path} must be an object")
    return value, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _validate_configuration(configuration: object, *, require_lock: bool) -> dict[str, Any]:
    if not isinstance(configuration, dict):
        raise ComparisonError("configuration must be an object")
    missing = _ENTRY_CONFIGURATION_FIELDS - set(configuration)
    if missing:
        raise ComparisonError(f"configuration is missing entry fields: {sorted(missing)}")
    for field in ("app_entry", "bootstrap_entry"):
        value = configuration[field]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ComparisonError(f"configuration.{field} must be null or a non-empty string")
    for field in ("app_variable", "backend"):
        value = configuration[field]
        if not isinstance(value, str) or not value.strip():
            raise ComparisonError(f"configuration.{field} must be a non-empty string")
    if require_lock:
        lock_hash = configuration.get("dependency_lock_sha256")
        if not isinstance(lock_hash, str) or not _LOCK_HASH.fullmatch(lock_hash):
            raise ComparisonError(
                "target/baseline comparison requires configuration.dependency_lock_sha256"
            )
    return configuration


def _validate_failure(failure: object) -> None:
    if not isinstance(failure, dict) or set(failure) != {"phase", "message"}:
        raise ComparisonError("failed records require exact phase/message metadata")
    if failure["phase"] not in _FAILURE_PHASES:
        raise ComparisonError("failed records require a recognized failure phase")
    if not isinstance(failure["message"], str) or not failure["message"].strip():
        raise ComparisonError("failure.message must be a non-empty string")


def _validate(record: dict[str, Any], expected_mode: str) -> None:  # noqa: PLR0912
    required = {
        "schema_version",
        "mode",
        "snapshot",
        "status",
        "configuration",
        "timing",
    }
    if set(record) - {
        *required,
        "failure",
        "inventory",
        "impact",
        "provenance",
    }:
        raise ComparisonError("record contains unknown top-level fields")
    if required - set(record):
        raise ComparisonError("record is missing required fields")
    if record["schema_version"] != 1 or record["mode"] != expected_mode:
        raise ComparisonError(f"expected schema v1 {expected_mode} record")
    if record["snapshot"] not in {"target", "baseline"}:
        raise ComparisonError("snapshot must be target or baseline")
    if record["status"] not in {"success", "failure"}:
        raise ComparisonError("status must be success or failure")
    if record["status"] == "success":
        inventory = record.get("inventory")
        if not isinstance(inventory, dict) or not isinstance(record.get("impact"), dict):
            raise ComparisonError("successful records require inventory and impact")
        inventory_status = inventory.get("inventory_status")
        if not isinstance(inventory_status, str) or not inventory_status.strip():
            raise ComparisonError("successful inventory requires inventory_status")
        if record.get("failure") is not None:
            raise ComparisonError("successful records forbid failure metadata")
    else:
        _validate_failure(record.get("failure"))
        if record.get("inventory") is not None or record.get("impact") is not None:
            raise ComparisonError("failed records forbid partial inventory/impact claims")
    _validate_configuration(record["configuration"], require_lock=False)
    timing = record["timing"]
    if not isinstance(timing, dict) or not timing:
        raise ComparisonError("timing values must be finite non-negative numbers")
    try:
        for name, value in timing.items():
            if not isinstance(name, str) or not name:
                raise ComparisonError("timing names must be non-empty strings")
            finite_nonnegative(value, f"timing.{name}")
    except BenchmarkSchemaError as error:
        raise ComparisonError("timing values must be finite non-negative numbers") from error


def _endpoint_id(endpoint: dict[str, Any]) -> str:
    surface = endpoint.get("surface")
    if isinstance(surface, dict):
        kind = surface.get("surface_kind")
        identity = surface.get("surface_id")
        if not isinstance(kind, str) or not kind or not isinstance(identity, str) or not identity:
            raise ComparisonError("surface endpoints require string kind and identity")
        return f"{kind.upper()} {identity}"
    if surface is not None:
        raise ComparisonError("endpoint surface must be an object or null")
    methods = endpoint.get("methods")
    path = endpoint.get("path")
    if (
        not isinstance(methods, list)
        or not methods
        or not all(isinstance(item, str) and item for item in methods)
    ):
        raise ComparisonError("endpoint methods must be non-empty strings")
    if not isinstance(path, str) or not path:
        raise ComparisonError("endpoint path must be a non-empty string")
    return f"{','.join(sorted(methods))} {path}"


def _inventory_ids(payload: dict[str, Any]) -> set[str]:
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list):
        raise ComparisonError("inventory endpoints must be an array")
    identities: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            raise ComparisonError("inventory endpoint entries must be objects")
        identity = _endpoint_id(endpoint)
        if identity in identities:
            raise ComparisonError(f"duplicate inventory endpoint: {identity}")
        identities.add(identity)
    return identities


def _impact_ids(payload: dict[str, Any]) -> set[str]:
    candidates = payload.get("candidate_endpoints")
    if not isinstance(candidates, list):
        raise ComparisonError("impact candidate_endpoints must be an array")
    identities: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict) or not isinstance(candidate.get("endpoint"), dict):
            raise ComparisonError("impact candidates require endpoint objects")
        identity = _endpoint_id(candidate["endpoint"])
        if identity in identities:
            raise ComparisonError(f"duplicate impact endpoint: {identity}")
        identities.add(identity)
    return identities


def _normalized(identity: str) -> str:
    return _PARAMETER.sub("{}", identity)


def _set_metrics(secure: set[str], runtime: set[str]) -> dict[str, Any]:
    intersection = secure & runtime
    union = secure | runtime
    has_disagreement = secure != runtime
    return {
        "secure_count": len(secure),
        "runtime_count": len(runtime),
        "intersection_count": len(intersection),
        "secure_only": sorted(secure - runtime),
        "runtime_only": sorted(runtime - secure),
        "jaccard": len(intersection) / len(union) if union else 1.0,
        "has_disagreement": has_disagreement,
        "interpretation": "requires_source_adjudication" if has_disagreement else "agreement",
    }


def _compare_loaded(
    secure: dict[str, Any],
    runtime: dict[str, Any],
    *,
    secure_hash: str,
    runtime_hash: str,
) -> dict[str, Any]:
    if secure["snapshot"] != runtime["snapshot"]:
        raise ComparisonError("paired records must use the same snapshot")
    if secure["configuration"] != runtime["configuration"]:
        raise ComparisonError("paired records must use identical entry/backend configuration")
    result: dict[str, Any] = {
        "schema_version": 1,
        "runtime_role": _RUNTIME_ROLE,
        "snapshot": secure["snapshot"],
        "paired_success": secure["status"] == runtime["status"] == "success",
        "status": {"secure": secure["status"], "runtime": runtime["status"]},
        "failure": {"secure": secure.get("failure"), "runtime": runtime.get("failure")},
        "configuration": secure["configuration"],
        "timing": {"secure": secure["timing"], "runtime": runtime["timing"]},
        "input_hashes": {"secure": secure_hash, "runtime": runtime_hash},
        "inventory_strength": {
            "secure": secure.get("inventory", {}).get("inventory_status")
            if secure["status"] == "success"
            else None,
            "runtime": runtime.get("inventory", {}).get("inventory_status")
            if runtime["status"] == "success"
            else None,
        },
    }
    if not result["paired_success"]:
        result["inventory"] = None
        result["impact_exact"] = None
        result["impact_normalized"] = None
        return result
    secure_inventory = _inventory_ids(secure["inventory"])
    runtime_inventory = _inventory_ids(runtime["inventory"])
    secure_impact = _impact_ids(secure["impact"])
    runtime_impact = _impact_ids(runtime["impact"])
    result["inventory"] = _set_metrics(secure_inventory, runtime_inventory)
    result["impact_exact"] = _set_metrics(secure_impact, runtime_impact)
    result["impact_normalized"] = _set_metrics(
        {_normalized(item) for item in secure_impact},
        {_normalized(item) for item in runtime_impact},
    )
    return result


def compare(secure_path: Path, runtime_path: Path) -> dict[str, Any]:
    """Compare one snapshot pair while keeping failures in the operational result."""
    secure, secure_hash = _load(secure_path)
    runtime, runtime_hash = _load(runtime_path)
    _validate(secure, "secure")
    _validate(runtime, "runtime")
    return _compare_loaded(
        secure,
        runtime,
        secure_hash=secure_hash,
        runtime_hash=runtime_hash,
    )


def _lifecycle(target: set[str], baseline: set[str]) -> dict[str, Any]:
    return {
        "target_count": len(target),
        "baseline_count": len(baseline),
        "added": sorted(target - baseline),
        "removed": sorted(baseline - target),
        "unchanged_count": len(target & baseline),
    }


def _mode_lifecycle(target: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any] | None:
    if target["status"] != "success" or baseline["status"] != "success":
        return None
    target_inventory = _inventory_ids(target["inventory"])
    baseline_inventory = _inventory_ids(baseline["inventory"])
    target_impact = _impact_ids(target["impact"])
    baseline_impact = _impact_ids(baseline["impact"])
    return {
        "inventory": _lifecycle(target_inventory, baseline_inventory),
        "impact_exact": _lifecycle(target_impact, baseline_impact),
        "impact_normalized": _lifecycle(
            {_normalized(item) for item in target_impact},
            {_normalized(item) for item in baseline_impact},
        ),
    }


def _operational_summary(records: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
    success_count = {"secure": 0, "runtime": 0}
    failure_phases: dict[str, dict[str, int]] = {"secure": {}, "runtime": {}}
    inventory_strength: dict[str, dict[str, str | None]] = {
        "target": {},
        "baseline": {},
    }
    timing: dict[str, dict[str, dict[str, Any]]] = {"target": {}, "baseline": {}}
    peak_rss_mib: dict[str, float | int | None] = {"secure": None, "runtime": None}
    for (snapshot, mode), record in records.items():
        timing[snapshot][mode] = record["timing"]
        if record["status"] == "success":
            success_count[mode] += 1
            inventory_strength[snapshot][mode] = record["inventory"]["inventory_status"]
        else:
            inventory_strength[snapshot][mode] = None
            phase = record["failure"]["phase"]
            failure_phases[mode][phase] = failure_phases[mode].get(phase, 0) + 1
        rss = record["timing"].get("rss_mib")
        if isinstance(rss, (int, float)) and not isinstance(rss, bool):
            current = peak_rss_mib[mode]
            peak_rss_mib[mode] = rss if current is None else max(current, rss)
    return {
        "artifact_count": len(records),
        "success_count": success_count,
        "abstention_count": {mode: 2 - count for mode, count in success_count.items()},
        "failure_phase_counts": failure_phases,
        "inventory_strength": inventory_strength,
        "timing": timing,
        "peak_rss_mib": peak_rss_mib,
    }


def compare_target_baseline(
    *,
    secure_target_path: Path,
    runtime_target_path: Path,
    secure_baseline_path: Path,
    runtime_baseline_path: Path,
) -> dict[str, Any]:
    """Compare secure/runtime on both snapshots with one pinned configuration."""
    paths = {
        ("target", "secure"): secure_target_path,
        ("target", "runtime"): runtime_target_path,
        ("baseline", "secure"): secure_baseline_path,
        ("baseline", "runtime"): runtime_baseline_path,
    }
    records: dict[tuple[str, str], dict[str, Any]] = {}
    hashes: dict[tuple[str, str], str] = {}
    for (snapshot, mode), path in paths.items():
        record, digest = _load(path)
        _validate(record, mode)
        if record["snapshot"] != snapshot:
            raise ComparisonError(f"{mode} {snapshot} artifact declares {record['snapshot']}")
        records[(snapshot, mode)] = record
        hashes[(snapshot, mode)] = digest

    configurations = [record["configuration"] for record in records.values()]
    if any(configuration != configurations[0] for configuration in configurations[1:]):
        raise ComparisonError(
            "target/baseline secure/runtime records must use identical entry/backend configuration"
        )
    configuration = _validate_configuration(configurations[0], require_lock=True)

    pairs: dict[str, dict[str, Any]] = {}
    for snapshot in ("target", "baseline"):
        pairs[snapshot] = _compare_loaded(
            records[(snapshot, "secure")],
            records[(snapshot, "runtime")],
            secure_hash=hashes[(snapshot, "secure")],
            runtime_hash=hashes[(snapshot, "runtime")],
        )
    eligible_snapshots = [
        snapshot for snapshot in ("target", "baseline") if pairs[snapshot]["paired_success"]
    ]
    quality = {
        snapshot: {
            "inventory": pairs[snapshot]["inventory"],
            "impact_exact": pairs[snapshot]["impact_exact"],
            "impact_normalized": pairs[snapshot]["impact_normalized"],
        }
        for snapshot in eligible_snapshots
    }
    return {
        "schema_version": 1,
        "protocol": "secure-runtime-target-baseline-v1",
        "runtime_role": _RUNTIME_ROLE,
        "configuration": configuration,
        "operational": _operational_summary(records),
        "snapshot_pairs": pairs,
        "paired_success_quality": {
            "eligible_snapshots": eligible_snapshots,
            "metrics": quality,
        },
        "lifecycle": {
            "secure": _mode_lifecycle(
                records[("target", "secure")], records[("baseline", "secure")]
            ),
            "runtime": _mode_lifecycle(
                records[("target", "runtime")], records[("baseline", "runtime")]
            ),
        },
        "input_hashes": {
            snapshot: {mode: hashes[(snapshot, mode)] for mode in ("secure", "runtime")}
            for snapshot in ("target", "baseline")
        },
    }


def _write_output(
    path: Path,
    result: dict[str, Any],
    *,
    input_paths: tuple[Path, ...],
) -> None:
    try:
        content = (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
            "utf-8"
        )
        publish_exclusive_bytes(path, content, forbidden_files=input_paths)
    except (SecurePathError, TypeError, ValueError) as error:
        raise ComparisonError(f"could not write {path}: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secure", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--secure-target", type=Path)
    parser.add_argument("--runtime-target", type=Path)
    parser.add_argument("--secure-baseline", type=Path)
    parser.add_argument("--runtime-baseline", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    legacy = (args.secure, args.runtime)
    matrix = (
        args.secure_target,
        args.runtime_target,
        args.secure_baseline,
        args.runtime_baseline,
    )
    input_paths: tuple[Path, ...]
    try:
        if all(value is not None for value in legacy) and all(value is None for value in matrix):
            result = compare(args.secure, args.runtime)
            input_paths = (args.secure, args.runtime)
        elif all(value is None for value in legacy) and all(value is not None for value in matrix):
            result = compare_target_baseline(
                secure_target_path=args.secure_target,
                runtime_target_path=args.runtime_target,
                secure_baseline_path=args.secure_baseline,
                runtime_baseline_path=args.runtime_baseline,
            )
            input_paths = matrix
        else:
            parser.error(
                "pass either --secure/--runtime or all four target/baseline artifact arguments"
            )
        _write_output(args.output, result, input_paths=input_paths)
    except ComparisonError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
