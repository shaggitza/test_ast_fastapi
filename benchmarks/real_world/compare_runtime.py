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

from benchmarks.real_world._secure_publish import (
    SecurePathError,
    ensure_publishable,
    publish_exclusive_bytes,
)
from benchmarks.real_world.benchmark_schema import (
    BenchmarkSchemaError,
    finite_nonnegative,
    strict_json_loads,
)

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parents[1]
_FROZEN_FILES = (
    HERE / "corpus.json",
    HERE / "adjudicated.jsonl",
    HERE / "review-a.jsonl",
    HERE / "review-b.jsonl",
)
_FROZEN_ROOTS = (PROJECT_ROOT / "benchmarks" / "results",)
_FAILURE_PHASES = {
    "dependency",
    "import",
    "app_resolution",
    "extraction",
    "timeout",
    "unavailable",
}
_PARAMETER = re.compile(r"\{[^{}]+\}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE_DIGEST = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_ENTRY_CONFIGURATION_FIELDS = {
    "app_entry",
    "bootstrap_entry",
    "app_variable",
    "backend",
}
_TIMING_FIELDS = {"list", "impact"}
_RESOURCE_FIELDS = {"peak_rss_bytes"}
_SECURE_INVENTORY_STATES = {"established", "conditional", "unavailable"}
_RUNTIME_INVENTORY_STATES = {
    "runtime_observed",
    "runtime_conditional",
    "runtime_unavailable",
}
_COMMON_PROVENANCE_FIELDS = {
    "source_sha256",
    "tool_sha256",
    "effective_invocation_sha256",
    "dependency_lock_sha256",
    "runtime_image_digest",
    "runtime_sbom_sha256",
}
_RUNTIME_PROVENANCE_FIELDS = {
    *_COMMON_PROVENANCE_FIELDS,
    "runtime_seccomp_sha256",
    "runtime_policy_sha256",
}
_ENVIRONMENT_PROVENANCE_FIELDS = {
    "source_sha256",
    "tool_sha256",
    "dependency_lock_sha256",
    "runtime_image_digest",
    "runtime_sbom_sha256",
}
_RUNTIME_ROLE = "positive_observation_comparator_not_truth"


class ComparisonError(ValueError):
    """A paired record is invalid or configured inequitably."""


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


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


def _validate_configuration(configuration: object) -> dict[str, Any]:
    if not isinstance(configuration, dict):
        raise ComparisonError("configuration must be an object")
    expected = {*_ENTRY_CONFIGURATION_FIELDS, "dependency_lock_sha256"}
    if set(configuration) != expected:
        raise ComparisonError(
            "configuration requires exact app/bootstrap/app-variable/backend/lock fields"
        )
    for field in ("app_entry", "bootstrap_entry"):
        value = configuration[field]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ComparisonError(f"configuration.{field} must be null or a non-empty string")
    for field in ("app_variable", "backend"):
        value = configuration[field]
        if not isinstance(value, str) or not value.strip():
            raise ComparisonError(f"configuration.{field} must be a non-empty string")
    lock_hash = configuration["dependency_lock_sha256"]
    if not isinstance(lock_hash, str) or not _SHA256.fullmatch(lock_hash):
        raise ComparisonError("configuration.dependency_lock_sha256 must be a sha256 digest")
    return configuration


def _validate_failure(failure: object) -> None:
    if not isinstance(failure, dict) or set(failure) != {"phase", "message"}:
        raise ComparisonError("failed records require exact phase/message metadata")
    if failure["phase"] not in _FAILURE_PHASES:
        raise ComparisonError("failed records require a recognized failure phase")
    if not isinstance(failure["message"], str) or not failure["message"].strip():
        raise ComparisonError("failure.message must be a non-empty string")


def _validate_measurement(value: object, *, field: str, unit: str) -> None:
    if not isinstance(value, dict):
        raise ComparisonError(f"{field} measurement state must be an object")
    if value.get("status") == "measured":
        if set(value) != {"status", unit}:
            raise ComparisonError(f"{field} measured state requires only {unit}")
        try:
            finite_nonnegative(value[unit], f"{field}.{unit}")
        except BenchmarkSchemaError as error:
            raise ComparisonError(f"{field}.{unit} must be finite and non-negative") from error
    elif value.get("status") == "not_measured":
        if (
            set(value) != {"status", "reason"}
            or not isinstance(value.get("reason"), str)
            or not value["reason"].strip()
        ):
            raise ComparisonError(f"{field} not_measured state requires only a reason")
    else:
        raise ComparisonError(f"{field} status must be measured or not_measured")


def _validate_telemetry(record: dict[str, Any]) -> None:
    timing = record["timing"]
    resources = record["resources"]
    if not isinstance(timing, dict) or set(timing) != _TIMING_FIELDS:
        raise ComparisonError("timing requires exact list and impact states")
    if not isinstance(resources, dict) or set(resources) != _RESOURCE_FIELDS:
        raise ComparisonError("resources requires exact peak_rss_bytes state")
    for name in sorted(_TIMING_FIELDS):
        _validate_measurement(timing[name], field=f"timing.{name}", unit="seconds")
    _validate_measurement(
        resources["peak_rss_bytes"],
        field="resources.peak_rss_bytes",
        unit="bytes",
    )


def _validate_provenance(value: object, mode: str) -> dict[str, str]:
    expected = _RUNTIME_PROVENANCE_FIELDS if mode == "runtime" else _COMMON_PROVENANCE_FIELDS
    if not isinstance(value, dict) or set(value) != expected:
        raise ComparisonError(f"{mode} provenance requires exact mode-specific fields")
    for field in expected - {"runtime_image_digest"}:
        digest = value[field]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ComparisonError(f"provenance.{field} must be a lowercase sha256 digest")
    image = value["runtime_image_digest"]
    if not isinstance(image, str) or not _IMAGE_DIGEST.fullmatch(image):
        raise ComparisonError("provenance.runtime_image_digest must be an immutable image digest")
    return value


def _validate(record: dict[str, Any], expected_mode: str) -> None:  # noqa: PLR0912
    required = {
        "schema_version",
        "mode",
        "snapshot",
        "status",
        "configuration",
        "timing",
        "resources",
        "provenance",
    }
    allowed = {*required, "failure", "inventory", "impact"}
    if set(record) - allowed:
        raise ComparisonError("record contains unknown top-level fields")
    if required - set(record):
        raise ComparisonError("record is missing required fields")
    if record["schema_version"] != 1 or record["mode"] != expected_mode:
        raise ComparisonError(f"expected schema v1 {expected_mode} record")
    if record["snapshot"] not in {"target", "baseline"}:
        raise ComparisonError("snapshot must be target or baseline")
    if record["status"] not in {"success", "failure"}:
        raise ComparisonError("status must be success or failure")
    configuration = _validate_configuration(record["configuration"])
    if expected_mode == "runtime" and any(
        configuration[field] is not None for field in ("app_entry", "bootstrap_entry")
    ):
        raise ComparisonError(
            "runtime records do not support non-null app_entry or bootstrap_entry"
        )
    provenance = _validate_provenance(record["provenance"], expected_mode)
    if provenance["dependency_lock_sha256"] != configuration["dependency_lock_sha256"]:
        raise ComparisonError("provenance dependency lock does not match configuration")
    _validate_telemetry(record)
    if record["status"] == "success":
        inventory = record.get("inventory")
        impact = record.get("impact")
        if not isinstance(inventory, dict) or not isinstance(impact, dict):
            raise ComparisonError("successful records require inventory and impact")
        inventory_status = inventory.get("inventory_status")
        allowed_inventory = (
            _SECURE_INVENTORY_STATES if expected_mode == "secure" else _RUNTIME_INVENTORY_STATES
        )
        if inventory_status not in allowed_inventory:
            raise ComparisonError(f"successful {expected_mode} inventory status is invalid")
        _inventory_ids(inventory)
        _impact_ids(impact)
        if record.get("failure") is not None:
            raise ComparisonError("successful records forbid failure metadata")
    else:
        _validate_failure(record.get("failure"))
        if record.get("inventory") is not None or record.get("impact") is not None:
            raise ComparisonError("failed records forbid partial inventory/impact claims")


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


def _paired_attestations_measured(secure: dict[str, Any], runtime: dict[str, Any]) -> bool:
    for record in (secure, runtime):
        if any(record["timing"][name]["status"] != "measured" for name in _TIMING_FIELDS):
            return False
        if record["resources"]["peak_rss_bytes"]["status"] != "measured":
            return False
    return True


def _validate_pair_equivalence(secure: dict[str, Any], runtime: dict[str, Any]) -> None:
    if secure["snapshot"] != runtime["snapshot"]:
        raise ComparisonError("paired records must use the same snapshot")
    if secure["configuration"] != runtime["configuration"]:
        raise ComparisonError("paired records must use identical snapshot configuration")
    for field in _ENVIRONMENT_PROVENANCE_FIELDS:
        if secure["provenance"][field] != runtime["provenance"][field]:
            raise ComparisonError(f"paired records have mismatched provenance.{field}")


def _compare_loaded(
    secure: dict[str, Any],
    runtime: dict[str, Any],
    *,
    secure_hash: str,
    runtime_hash: str,
) -> dict[str, Any]:
    _validate_pair_equivalence(secure, runtime)
    paired_success = secure["status"] == runtime["status"] == "success"
    quality_eligible = paired_success and _paired_attestations_measured(secure, runtime)
    result: dict[str, Any] = {
        "schema_version": 1,
        "runtime_role": _RUNTIME_ROLE,
        "snapshot": secure["snapshot"],
        "paired_success": paired_success,
        "quality_eligible": quality_eligible,
        "status": {"secure": secure["status"], "runtime": runtime["status"]},
        "failure": {"secure": secure.get("failure"), "runtime": runtime.get("failure")},
        "configuration": secure["configuration"],
        "timing": {"secure": secure["timing"], "runtime": runtime["timing"]},
        "resources": {"secure": secure["resources"], "runtime": runtime["resources"]},
        "input_hashes": {"secure": secure_hash, "runtime": runtime_hash},
        "provenance_digests": {
            "secure": _canonical_digest(secure["provenance"]),
            "runtime": _canonical_digest(runtime["provenance"]),
        },
        "inventory_strength": {
            "secure": secure.get("inventory", {}).get("inventory_status")
            if secure["status"] == "success"
            else None,
            "runtime": runtime.get("inventory", {}).get("inventory_status")
            if runtime["status"] == "success"
            else None,
        },
    }
    if not quality_eligible:
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


def _aggregate_peak_rss(
    records: dict[tuple[str, str], dict[str, Any]], mode: str
) -> dict[str, Any]:
    states = [
        records[(snapshot, mode)]["resources"]["peak_rss_bytes"]
        for snapshot in ("target", "baseline")
    ]
    if all(state["status"] == "measured" for state in states):
        return {"status": "measured", "bytes": max(state["bytes"] for state in states)}
    return {"status": "not_measured", "reason": "one_or_more_snapshot_rss_not_measured"}


def _operational_summary(records: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
    success_count = {"secure": 0, "runtime": 0}
    failure_phases: dict[str, dict[str, int]] = {"secure": {}, "runtime": {}}
    inventory_strength: dict[str, dict[str, str | None]] = {"target": {}, "baseline": {}}
    timing: dict[str, dict[str, dict[str, Any]]] = {"target": {}, "baseline": {}}
    resources: dict[str, dict[str, dict[str, Any]]] = {"target": {}, "baseline": {}}
    for (snapshot, mode), record in records.items():
        timing[snapshot][mode] = record["timing"]
        resources[snapshot][mode] = record["resources"]
        if record["status"] == "success":
            success_count[mode] += 1
            inventory_strength[snapshot][mode] = record["inventory"]["inventory_status"]
        else:
            inventory_strength[snapshot][mode] = None
            phase = record["failure"]["phase"]
            failure_phases[mode][phase] = failure_phases[mode].get(phase, 0) + 1
    return {
        "artifact_count": len(records),
        "success_count": success_count,
        "abstention_count": {mode: 2 - count for mode, count in success_count.items()},
        "failure_phase_counts": failure_phases,
        "inventory_strength": inventory_strength,
        "timing": timing,
        "resources": resources,
        "peak_rss_bytes": {
            mode: _aggregate_peak_rss(records, mode) for mode in ("secure", "runtime")
        },
    }


def compare_target_baseline(
    *,
    secure_target_path: Path,
    runtime_target_path: Path,
    secure_baseline_path: Path,
    runtime_baseline_path: Path,
) -> dict[str, Any]:
    """Compare secure/runtime pairs while permitting snapshot-specific environments."""
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

    for snapshot in ("target", "baseline"):
        _validate_pair_equivalence(records[(snapshot, "secure")], records[(snapshot, "runtime")])
    entry_configuration = {
        field: records[("target", "secure")]["configuration"][field]
        for field in sorted(_ENTRY_CONFIGURATION_FIELDS)
    }
    for record in records.values():
        if any(
            record["configuration"][field] != value for field, value in entry_configuration.items()
        ):
            raise ComparisonError(
                "target/baseline records must use identical entry/backend configuration"
            )

    pairs = {
        snapshot: _compare_loaded(
            records[(snapshot, "secure")],
            records[(snapshot, "runtime")],
            secure_hash=hashes[(snapshot, "secure")],
            runtime_hash=hashes[(snapshot, "runtime")],
        )
        for snapshot in ("target", "baseline")
    }
    eligible_snapshots = [
        snapshot for snapshot in ("target", "baseline") if pairs[snapshot]["quality_eligible"]
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
        "configuration": {
            "entry": entry_configuration,
            "snapshots": {
                snapshot: records[(snapshot, "secure")]["configuration"]
                for snapshot in ("target", "baseline")
            },
        },
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
        "provenance_digests": {
            snapshot: {
                mode: _canonical_digest(records[(snapshot, mode)]["provenance"])
                for mode in ("secure", "runtime")
            }
            for snapshot in ("target", "baseline")
        },
    }


def _write_output(
    path: Path,
    result: dict[str, Any],
    *,
    input_paths: tuple[Path, ...],
) -> None:
    forbidden_files = (*_FROZEN_FILES, *input_paths)
    try:
        absolute = path.expanduser().absolute()
        if absolute in {item.expanduser().absolute() for item in forbidden_files} or any(
            absolute == root.expanduser().absolute()
            or absolute.is_relative_to(root.expanduser().absolute())
            for root in _FROZEN_ROOTS
        ):
            raise SecurePathError(f"refusing to target frozen benchmark artifact: {path}")
        ensure_publishable(
            path,
            forbidden_files=forbidden_files,
            forbidden_roots=_FROZEN_ROOTS,
        )
        content = (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
            "utf-8"
        )
        publish_exclusive_bytes(
            path,
            content,
            forbidden_files=forbidden_files,
            forbidden_roots=_FROZEN_ROOTS,
        )
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
