"""Frozen secure/runtime comparison protocol tests."""

import json
from pathlib import Path

import pytest
from benchmarks.real_world.compare_runtime import ComparisonError, compare


def _record(mode: str) -> dict[str, object]:
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
    return {
        "schema_version": 1,
        "mode": mode,
        "snapshot": "target",
        "status": "success",
        "configuration": {
            "app_entry": "main:app",
            "bootstrap_entry": None,
            "app_variable": "app",
            "backend": "mypy",
        },
        "timing": {"list_seconds": 1.0, "impact_seconds": 2.0, "rss_mib": 100},
        "failure": None,
        "inventory": inventory,
        "impact": impact,
        "provenance": {"artifact": mode},
    }


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_paired_success_preserves_exact_and_normalized_metrics(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    runtime_record = _record("runtime")
    runtime_record["inventory"]["endpoints"].append(  # type: ignore[index]
        {"methods": ["DELETE"], "path": "/runtime-only", "surface": None}
    )
    _write(runtime, runtime_record)

    result = compare(secure, runtime)

    assert result["paired_success"] is True
    assert result["inventory"]["runtime_only"] == ["DELETE /runtime-only"]
    assert result["impact_exact"]["intersection_count"] == 0
    assert result["impact_normalized"]["intersection_count"] == 1
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


def test_configuration_mismatch_fails_closed(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    runtime_record = _record("runtime")
    runtime_record["configuration"]["app_entry"] = "other:app"  # type: ignore[index]
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
