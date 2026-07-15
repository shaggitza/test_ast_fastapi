#!/usr/bin/env python3
"""Compare paired secure/runtime artifacts without treating runtime as truth."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

_FAILURE_PHASES = {
    "dependency",
    "import",
    "app_resolution",
    "extraction",
    "timeout",
    "unavailable",
}
_PARAMETER = re.compile(r"\{[^{}]+\}")


class ComparisonError(ValueError):
    """A paired record is invalid or configured inequitably."""


def _load(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ComparisonError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ComparisonError(f"record {path} must be an object")
    return value, f"sha256:{hashlib.sha256(raw).hexdigest()}"


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
        if not isinstance(record.get("inventory"), dict) or not isinstance(
            record.get("impact"), dict
        ):
            raise ComparisonError("successful records require inventory and impact")
        if record.get("failure") is not None:
            raise ComparisonError("successful records forbid failure metadata")
    else:
        failure = record.get("failure")
        if not isinstance(failure, dict) or failure.get("phase") not in _FAILURE_PHASES:
            raise ComparisonError("failed records require a recognized failure phase")
        if record.get("inventory") is not None or record.get("impact") is not None:
            raise ComparisonError("failed records forbid partial inventory/impact claims")
    if not isinstance(record["configuration"], dict):
        raise ComparisonError("configuration must be an object")
    timing = record["timing"]
    if not isinstance(timing, dict) or any(
        not isinstance(value, (int, float)) or value < 0 for value in timing.values()
    ):
        raise ComparisonError("timing values must be non-negative numbers")


def _endpoint_id(endpoint: dict[str, Any]) -> str:
    surface = endpoint.get("surface")
    if isinstance(surface, dict):
        return f"{surface['surface_kind'].upper()} {surface['surface_id']}"
    methods = endpoint.get("methods")
    path = endpoint.get("path")
    if not isinstance(methods, list) or not all(isinstance(item, str) for item in methods):
        raise ComparisonError("endpoint methods must be strings")
    if not isinstance(path, str):
        raise ComparisonError("endpoint path must be a string")
    return f"{','.join(sorted(methods))} {path}"


def _inventory_ids(payload: dict[str, Any]) -> set[str]:
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list):
        raise ComparisonError("inventory endpoints must be an array")
    return {_endpoint_id(item) for item in endpoints if isinstance(item, dict)}


def _impact_ids(payload: dict[str, Any]) -> set[str]:
    candidates = payload.get("candidate_endpoints")
    if not isinstance(candidates, list):
        raise ComparisonError("impact candidate_endpoints must be an array")
    return {
        _endpoint_id(item["endpoint"])
        for item in candidates
        if isinstance(item, dict) and isinstance(item.get("endpoint"), dict)
    }


def _normalized(identity: str) -> str:
    return _PARAMETER.sub("{}", identity)


def _set_metrics(secure: set[str], runtime: set[str]) -> dict[str, Any]:
    intersection = secure & runtime
    union = secure | runtime
    return {
        "secure_count": len(secure),
        "runtime_count": len(runtime),
        "intersection_count": len(intersection),
        "secure_only": sorted(secure - runtime),
        "runtime_only": sorted(runtime - secure),
        "jaccard": len(intersection) / len(union) if union else 1.0,
    }


def compare(secure_path: Path, runtime_path: Path) -> dict[str, Any]:
    secure, secure_hash = _load(secure_path)
    runtime, runtime_hash = _load(runtime_path)
    _validate(secure, "secure")
    _validate(runtime, "runtime")
    if secure["snapshot"] != runtime["snapshot"]:
        raise ComparisonError("paired records must use the same snapshot")
    if secure["configuration"] != runtime["configuration"]:
        raise ComparisonError("paired records must use identical entry/backend configuration")
    result: dict[str, Any] = {
        "schema_version": 1,
        "snapshot": secure["snapshot"],
        "paired_success": secure["status"] == runtime["status"] == "success",
        "status": {"secure": secure["status"], "runtime": runtime["status"]},
        "failure": {"secure": secure.get("failure"), "runtime": runtime.get("failure")},
        "configuration": secure["configuration"],
        "timing": {"secure": secure["timing"], "runtime": runtime["timing"]},
        "input_hashes": {"secure": secure_hash, "runtime": runtime_hash},
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secure", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.secure, args.runtime)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
