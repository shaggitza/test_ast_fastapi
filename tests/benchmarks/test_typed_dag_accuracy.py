"""Fail-closed tests for the generated GH283 typed-DAG accuracy gate."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import typed_dag_accuracy as gate

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper


def _record(case: gate.Case, *, supported: bool) -> dict[str, Any]:
    expected = list(gate.oracle(case.symbol))
    actual = (
        [{"endpoint": endpoint, "confidence": "low"} for endpoint in expected] if supported else []
    )
    tp = len(expected) if supported else 0
    return {
        "case_id": case.case_id,
        "symbol": case.symbol,
        "supported": supported,
        "control": case.control,
        "status": "passed" if supported else "unsupported",
        "expected": expected,
        "actual": actual,
        "tp": tp,
        "fp": 0,
        "fn": 0,
        "precision": 1.0 if supported else None,
        "recall": 1.0 if supported else None,
        "input_material": {"source": case.case_id},
        "input_hashes": {"source": gate.sha(case.case_id)},
    }


def _passing_document() -> dict[str, Any]:
    cases: list[dict[str, Any]] = [_record(case, supported=case.supported) for case in gate.CASES]
    runtime = {
        "python": "test",
        "mypy": "test",
        "fastapi": "test",
        "pydantic": "test",
        "ruff": "test",
    }
    configuration = {"backend": "mypy", "secure_ast": True, "transitive": True, "cache": False}
    return {
        "schema": gate.SCHEMA,
        "gate_status": "passed",
        "cases": cases,
        "revision": "test-revision",
        "tool_revision_hash": gate.sha("test-revision"),
        "runtime": runtime,
        "dependency_versions": runtime,
        "dependency_version_hash": gate.sha(json.dumps(runtime, sort_keys=True)),
        "configuration": configuration,
        "configuration_hash": gate.sha(json.dumps(configuration, sort_keys=True)),
        "harness_sha256": "sha256:" + hashlib.sha256(Path(gate.__file__).read_bytes()).hexdigest(),
        "metrics": {
            "tp": sum(case["tp"] for case in cases if case["supported"]),
            "fp": 0,
            "fn": 0,
            "precision": 1.0,
            "recall": 1.0,
            "high_medium_control_candidates": 0,
        },
    }


def test_oracle_is_graph_spec_derived_and_exercises_shared_paths() -> None:
    assert gate.oracle("leaf_alias") == ("GET /one", "GET /two")
    assert gate.oracle("shared_live") == ("GET /one", "GET /two")
    assert gate.oracle("direct_one") == ("GET /one",)
    for control in (
        "literal_false_dead",
        "post_return_dead",
        "deferred_closure_dead",
        "deferred_lambda_dead",
        "unawaited_coroutine_dead",
        "unrelated_dead",
    ):
        assert gate.oracle(control) == ()


def test_validator_accepts_a_derived_pass() -> None:
    gate.validate(_passing_document())


def test_validator_rejects_duplicate_or_missing_cases() -> None:
    document = _passing_document()
    document["cases"] = document["cases"][:-1]
    with pytest.raises(ValueError, match="duplicate, missing"):
        gate.validate(document)


def test_validator_rejects_tampered_input_hash() -> None:
    document = _passing_document()
    document["cases"][0]["input_hashes"]["source"] = "sha256:bad"
    with pytest.raises(ValueError, match="tampered/missing"):
        gate.validate(document)


def test_validator_rejects_inconsistent_metrics_even_when_marked_passed() -> None:
    document = _passing_document()
    document["cases"][0]["fp"] = 1
    with pytest.raises(ValueError, match="inconsistent metrics"):
        gate.validate(document)


def test_validator_rejects_nonfinite_metrics() -> None:
    document = _passing_document()
    document["cases"][0]["precision"] = math.nan
    with pytest.raises(ValueError, match="non-finite"):
        gate.validate(document)


def test_validator_rejects_false_pass_with_failed_supported_case() -> None:
    document = _passing_document()
    document["cases"][0]["status"] = "failed"
    with pytest.raises(ValueError, match="gate status"):
        gate.validate(document)


def test_checked_in_analyzer_result_is_a_valid_failed_baseline() -> None:
    evidence = gate.RESULTS / "current-main.json"
    document = json.loads(evidence.read_text(encoding="utf-8"))
    gate.validate(document)
    assert document["gate_status"] == "failed"
    assert document["metrics"]["fp"] == 1
    assert document["metrics"]["high_medium_control_candidates"] == 1


def test_real_cli_change_mapper_on_secure_generated_project(tmp_path: Path) -> None:
    """One real analyzer path protects against a generator-only false green."""
    case = gate.CASES[0]
    result = gate.execute_case(case, tmp_path)
    assert result["supported"] is True
    assert result["source_discovery"] == "secure_ast"
    assert result["expected"] == ["GET /one", "GET /two"]
    assert result["status"] == "passed", result


def test_real_change_mapper_public_api_on_secure_generated_project(tmp_path: Path) -> None:
    """The supported ChangeMapper API reports candidates from generated source."""
    case = gate.CASES[1]
    original = gate.sources(case.symbol, "return 1")
    modified = gate.sources(case.symbol, "return 2")
    target = tmp_path / "target"
    for relative, source in modified.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    diff = tmp_path / "direct.diff"
    changed = "app/service.py"
    diff.write_text(gate.make_diff(changed, original[changed], modified[changed]), encoding="utf-8")
    report = ChangeMapper(target / "app", secure_ast=True, use_cache=False).analyze_diff(diff)
    actual = {
        f"{item.endpoint.methods[0].value} {item.endpoint.path}"
        for item in report.candidate_endpoints
    }
    assert actual == {"GET /one"}
