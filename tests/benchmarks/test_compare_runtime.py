"""Frozen secure/runtime comparison protocol tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from benchmarks.real_world.compare_runtime import (
    ComparisonError,
    compare,
    compare_target_baseline,
    main,
)

if TYPE_CHECKING:
    from pathlib import Path

LOCK_HASH = "a" * 64


def _record(
    mode: str,
    *,
    snapshot: str = "target",
    dependency_lock: bool = False,
) -> dict[str, Any]:
    inventory = {
        "inventory_status": "established" if mode == "secure" else "runtime_observed",
        "endpoints": [
            {"methods": ["GET"], "path": "/users/{user_id}", "surface": None},
            {"methods": ["POST"], "path": "/jobs", "surface": None},
        ],
    }
    impact = {
        "candidate_endpoints": [
            {
                "endpoint": {
                    "methods": ["GET"],
                    "path": "/users/{user_id}" if mode == "secure" else "/users/{id}",
                    "surface": None,
                }
            }
        ]
    }
    configuration: dict[str, object] = {
        "app_entry": "main:app",
        "bootstrap_entry": None,
        "app_variable": "app",
        "backend": "mypy",
    }
    if dependency_lock:
        configuration["dependency_lock_sha256"] = LOCK_HASH
    return {
        "schema_version": 1,
        "mode": mode,
        "snapshot": snapshot,
        "status": "success",
        "configuration": configuration,
        "timing": {"list_seconds": 1.0, "impact_seconds": 2.0, "rss_mib": 100},
        "failure": None,
        "inventory": inventory,
        "impact": impact,
        "provenance": {"artifact": mode},
    }


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _matrix_paths(tmp_path: Path) -> dict[tuple[str, str], Path]:
    paths: dict[tuple[str, str], Path] = {}
    for snapshot in ("target", "baseline"):
        for mode in ("secure", "runtime"):
            path = tmp_path / f"{mode}-{snapshot}.json"
            _write(
                path,
                _record(mode, snapshot=snapshot, dependency_lock=True),
            )
            paths[(snapshot, mode)] = path
    return paths


def _compare_matrix(paths: dict[tuple[str, str], Path]) -> dict[str, Any]:
    return compare_target_baseline(
        secure_target_path=paths[("target", "secure")],
        runtime_target_path=paths[("target", "runtime")],
        secure_baseline_path=paths[("baseline", "secure")],
        runtime_baseline_path=paths[("baseline", "runtime")],
    )


def test_paired_success_preserves_exact_and_normalized_metrics(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    runtime_record = _record("runtime")
    runtime_record["inventory"]["endpoints"].append(
        {"methods": ["DELETE"], "path": "/runtime-only", "surface": None}
    )
    _write(runtime, runtime_record)

    result = compare(secure, runtime)

    assert result["runtime_role"] == "positive_observation_comparator_not_truth"
    assert result["paired_success"] is True
    assert result["inventory"]["runtime_only"] == ["DELETE /runtime-only"]
    assert result["inventory"]["interpretation"] == "requires_source_adjudication"
    assert result["impact_exact"]["intersection_count"] == 0
    assert result["impact_normalized"]["intersection_count"] == 1
    assert result["inventory_strength"] == {
        "secure": "established",
        "runtime": "runtime_observed",
    }
    assert result["input_hashes"]["secure"].startswith("sha256:")


def test_failure_phase_abstains_from_quality_metrics(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    failed = _record("runtime")
    failed.update(
        status="failure",
        failure={"phase": "import", "message": "missing dependency"},
        inventory=None,
        impact=None,
    )
    _write(runtime, failed)

    result = compare(secure, runtime)

    assert result["paired_success"] is False
    assert result["inventory"] is None
    assert result["failure"]["runtime"]["phase"] == "import"
    assert result["inventory_strength"]["runtime"] is None


def test_configuration_mismatch_fails_closed(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    runtime_record = _record("runtime")
    runtime_record["configuration"]["app_entry"] = "other:app"
    _write(runtime, runtime_record)

    with pytest.raises(ComparisonError, match="identical"):
        compare(secure, runtime)


@pytest.mark.parametrize(
    "phase",
    ["dependency", "import", "app_resolution", "extraction", "timeout", "unavailable"],
)
def test_all_failure_phases_are_versioned(tmp_path: Path, phase: str) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    first = _record("secure")
    second = _record("runtime")
    for record in (first, second):
        record.update(
            status="failure",
            failure={"phase": phase, "message": "abstain"},
            inventory=None,
            impact=None,
        )
    _write(secure, first)
    _write(runtime, second)

    assert compare(secure, runtime)["paired_success"] is False


@pytest.mark.parametrize("invalid", [True, float("nan"), float("inf"), -1.0])
def test_timing_rejects_bool_non_finite_and_negative_values(
    tmp_path: Path, invalid: object
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    secure_record["timing"] = {"impact_seconds": invalid}
    _write(secure, secure_record)
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError):
        compare(secure, runtime)


def test_comparison_rejects_duplicate_json_members(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError, match="duplicate JSON member"):
        compare(secure, runtime)


def test_target_baseline_matrix_separates_operational_and_quality_results(
    tmp_path: Path,
) -> None:
    paths = _matrix_paths(tmp_path)
    secure_target = _record("secure", snapshot="target", dependency_lock=True)
    secure_target["inventory"]["endpoints"].append(
        {"methods": ["PATCH"], "path": "/target-only", "surface": None}
    )
    _write(paths[("target", "secure")], secure_target)

    result = _compare_matrix(paths)

    assert result["protocol"] == "secure-runtime-target-baseline-v1"
    assert result["runtime_role"] == "positive_observation_comparator_not_truth"
    assert result["operational"]["artifact_count"] == 4
    assert result["operational"]["success_count"] == {"secure": 2, "runtime": 2}
    assert result["operational"]["abstention_count"] == {"secure": 0, "runtime": 0}
    assert result["operational"]["peak_rss_mib"] == {"secure": 100, "runtime": 100}
    assert result["paired_success_quality"]["eligible_snapshots"] == ["target", "baseline"]
    assert result["lifecycle"]["secure"]["inventory"]["added"] == ["PATCH /target-only"]
    assert result["lifecycle"]["runtime"]["inventory"]["added"] == []
    assert set(result["input_hashes"]) == {"target", "baseline"}


def test_matrix_keeps_failures_operational_and_excludes_them_from_quality(
    tmp_path: Path,
) -> None:
    paths = _matrix_paths(tmp_path)
    failed = _record("runtime", snapshot="baseline", dependency_lock=True)
    failed.update(
        status="failure",
        failure={"phase": "dependency", "message": "lock install failed"},
        inventory=None,
        impact=None,
    )
    _write(paths[("baseline", "runtime")], failed)

    result = _compare_matrix(paths)

    assert result["operational"]["success_count"] == {"secure": 2, "runtime": 1}
    assert result["operational"]["failure_phase_counts"]["runtime"] == {"dependency": 1}
    assert result["paired_success_quality"]["eligible_snapshots"] == ["target"]
    assert result["snapshot_pairs"]["baseline"]["inventory"] is None
    assert result["lifecycle"]["runtime"] is None
    assert result["lifecycle"]["secure"] is not None


@pytest.mark.parametrize("lock_hash", [None, "abc", "g" * 64, True])
def test_matrix_requires_a_pinned_dependency_lock(tmp_path: Path, lock_hash: object) -> None:
    paths = _matrix_paths(tmp_path)
    record = _record("runtime", snapshot="target", dependency_lock=True)
    if lock_hash is None:
        record["configuration"].pop("dependency_lock_sha256")
    else:
        record["configuration"]["dependency_lock_sha256"] = lock_hash
    _write(paths[("target", "runtime")], record)

    with pytest.raises(ComparisonError, match=r"dependency_lock_sha256|identical"):
        _compare_matrix(paths)


def test_matrix_rejects_snapshot_or_cross_snapshot_configuration_mismatch(
    tmp_path: Path,
) -> None:
    paths = _matrix_paths(tmp_path)
    record = _record("secure", snapshot="target", dependency_lock=True)
    _write(paths[("baseline", "secure")], record)
    with pytest.raises(ComparisonError, match="declares target"):
        _compare_matrix(paths)

    record = _record("secure", snapshot="baseline", dependency_lock=True)
    record["configuration"]["app_variable"] = "application"
    _write(paths[("baseline", "secure")], record)
    with pytest.raises(ComparisonError, match="identical"):
        _compare_matrix(paths)


def test_duplicate_or_malformed_endpoint_rows_fail_closed(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    secure_record["inventory"]["endpoints"].append(
        {"methods": ["GET"], "path": "/users/{user_id}", "surface": None}
    )
    _write(secure, secure_record)
    _write(runtime, _record("runtime"))
    with pytest.raises(ComparisonError, match="duplicate inventory"):
        compare(secure, runtime)

    secure_record = _record("secure")
    secure_record["impact"]["candidate_endpoints"] = ["bad"]
    _write(secure, secure_record)
    with pytest.raises(ComparisonError, match="endpoint objects"):
        compare(secure, runtime)


def test_cli_matrix_is_no_clobber(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)
    output = tmp_path / "comparison.json"
    arguments = [
        "--secure-target",
        str(paths[("target", "secure")]),
        "--runtime-target",
        str(paths[("target", "runtime")]),
        "--secure-baseline",
        str(paths[("baseline", "secure")]),
        "--runtime-baseline",
        str(paths[("baseline", "runtime")]),
        "--output",
        str(output),
    ]

    assert main(arguments) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["runtime_role"] == "positive_observation_comparator_not_truth"
    with pytest.raises(SystemExit) as raised:
        main(arguments)
    assert raised.value.code == 2
