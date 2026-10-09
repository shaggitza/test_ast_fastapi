"""Fail-closed tests for the generated GH283 typed-DAG accuracy gate."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import typed_dag_accuracy as gate

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper


def _synthetic_validation_document() -> dict[str, Any]:
    """Build in-memory validator probes, never analyzer result evidence."""
    cases: list[dict[str, Any]] = []
    for declared in gate.CASES:
        material = gate.case_inputs(declared)
        expected = list(gate.oracle(declared.symbol))
        fn = len(expected) if declared.supported else 0
        cases.append(
            {
                "case_id": declared.case_id,
                "symbol": declared.symbol,
                "source_symbol": declared.source_symbol,
                "control": declared.control,
                "supported": declared.supported,
                "change_kind": declared.change_kind,
                "status": "failed" if declared.supported else "unsupported",
                "expected": expected,
                "actual": [],
                "tp": 0,
                "fp": 0,
                "fn": fn,
                "precision": (0.0 if fn else 1.0) if declared.supported else None,
                "recall": (0.0 if fn else 1.0) if declared.supported else None,
                "source_discovery": "secure_ast" if declared.supported else "unsupported",
                "inventory_status": None,
                "inventory_limitations": [],
                "total_endpoints": None,
                "analyzer_errors": ["synthetic validation probe; CLI not invoked"]
                if declared.supported
                else [],
                "analyzer_warnings": [],
                "input_material": material,
                "input_hashes": {key: gate.sha(value) for key, value in material.items()},
            }
        )
    supported = [case for case in cases if case["supported"]]
    tp, fp, fn = (sum(case[key] for case in supported) for key in ("tp", "fp", "fn"))
    metrics = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else (1.0 if not fn else 0.0),
        "recall": tp / (tp + fn) if tp + fn else 1.0,
        "high_medium_control_candidates": 0,
        "high_medium": gate._tier_metrics(supported, {"high", "medium"}),
        "low_report_only": gate._tier_metrics(supported, {"low"}),
    }
    runtime = {"python": "synthetic", "mypy": "not-run"}
    revision = "synthetic-validation-only"
    configuration = {"backend": "mypy", "secure_ast": True, "transitive": True, "cache": False}
    harness_hash = "sha256:" + hashlib.sha256(Path(gate.__file__).read_bytes()).hexdigest()
    return {
        "schema": gate.SCHEMA,
        "evidence_kind": "synthetic_validation_only",
        "gate_status": "failed",
        "revision": revision,
        "tool_revision_hash": gate.sha(revision),
        "harness_sha256": harness_hash,
        "dependency_versions": runtime,
        "dependency_version_hash": gate.sha(json.dumps(runtime, sort_keys=True)),
        "runtime": runtime,
        "configuration": configuration,
        "configuration_hash": gate.sha(json.dumps(configuration, sort_keys=True)),
        "case_coverage": {
            "declared": len(gate.CASES),
            "recorded": len(cases),
            "supported": sum(case.supported for case in gate.CASES),
            "unsupported": sum(not case.supported for case in gate.CASES),
        },
        "metrics": metrics,
        "cases": cases,
    }


def test_oracle_and_source_guards_cover_live_and_dead_paths() -> None:
    assert gate.oracle("leaf_alias") == ("GET /one", "GET /two")
    assert gate.oracle("shared_live") == ("GET /one", "GET /two")
    assert gate.oracle("direct_one") == ("GET /one",)
    for dead_site in (
        "literal_false_site",
        "post_return_site",
        "deferred_closure_site",
        "deferred_lambda_site",
        "unawaited_coroutine_site",
    ):
        assert gate.oracle(dead_site) == ()
    for live_site in (
        "literal_true_live",
        "post_return_live",
        "invoked_closure_live",
        "invoked_lambda_live",
    ):
        assert gate.oracle(live_site) == ("GET /one",)
    for case in gate.CASES:
        gate.validate_generated_fixture(case, gate.case_inputs(case))


def test_synthetic_validation_probe_is_explicitly_not_cli_evidence() -> None:
    document = _synthetic_validation_document()
    gate.validate(document)
    assert document["gate_status"] == "failed"
    assert document["evidence_kind"] == "synthetic_validation_only"
    assert document["case_coverage"]["recorded"] == len(gate.CASES)


def test_validator_rejects_duplicate_or_missing_cases() -> None:
    document = _synthetic_validation_document()
    document["cases"] = document["cases"][:-1]
    with pytest.raises(ValueError, match="duplicate, missing"):
        gate.validate(document)
    document = _synthetic_validation_document()
    document["cases"][-1] = copy.deepcopy(document["cases"][0])
    with pytest.raises(ValueError, match="duplicate, missing"):
        gate.validate(document)


def test_validator_rejects_tampered_input_hash() -> None:
    document = _synthetic_validation_document()
    document["cases"][0]["input_hashes"]["baseline"] = "sha256:bad"
    with pytest.raises(ValueError, match="tampered/missing input hashes"):
        gate.validate(document)


def test_validator_rejects_rehashed_but_forged_fixture_material() -> None:
    document = _synthetic_validation_document()
    case = document["cases"][0]
    case["input_material"] = {"source": case["case_id"]}
    case["input_hashes"] = {"source": gate.sha(case["case_id"])}
    with pytest.raises(ValueError, match="source/diff/config do not match generator"):
        gate.validate(document)


def test_validator_rejects_incomplete_inventory_and_analyzer_errors() -> None:
    document = _synthetic_validation_document()
    case = document["cases"][0]
    case["inventory_status"] = "incomplete"
    case["total_endpoints"] = 0
    case["analyzer_errors"] = ["build failed"]
    case["status"] = "passed"
    with pytest.raises(ValueError, match="passing case lacks real CLI evidence"):
        gate.validate(document)


def test_validator_rejects_control_metadata_tampering() -> None:
    document = _synthetic_validation_document()
    control = next(item for item in document["cases"] if item["control"])
    control["control"] = False
    with pytest.raises(ValueError, match="case metadata differs"):
        gate.validate(document)


def test_validator_rejects_forged_case_coverage() -> None:
    document = _synthetic_validation_document()
    document["case_coverage"] = {"declared": 999, "recorded": 1, "supported": 0, "unsupported": 0}
    with pytest.raises(ValueError, match="case coverage"):
        gate.validate(document)


def test_validator_rejects_metrics_and_false_pass_tampering() -> None:
    document = _synthetic_validation_document()
    document["cases"][0]["precision"] = math.nan
    with pytest.raises(ValueError, match="non-finite"):
        gate.validate(document)
    document = _synthetic_validation_document()
    document["gate_status"] = "passed"
    with pytest.raises(ValueError, match="gate status"):
        gate.validate(document)


def test_synthetic_probe_cannot_claim_a_pass() -> None:
    document = _synthetic_validation_document()
    document["gate_status"] = "passed"
    with pytest.raises(ValueError, match="gate status"):
        gate.validate(document)


def test_real_cli_change_mapper_on_secure_generated_project(tmp_path: Path) -> None:
    case = gate.CASES[0]
    result = gate.execute_case(case, tmp_path)
    assert result["supported"] is True
    assert result["source_discovery"] == "secure_ast"
    assert result["expected"] == ["GET /one", "GET /two"]
    assert result["cli_evidence"]["exit_code"] == 0


def test_real_change_mapper_public_api_on_secure_generated_project(tmp_path: Path) -> None:
    case = gate.CASES[1]
    material = gate.case_inputs(case)
    target_sources = json.loads(material["target"])
    target = tmp_path / "target"
    for relative, source in target_sources.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    diff = tmp_path / "direct.diff"
    diff.write_text(material["diff"], encoding="utf-8")
    report = ChangeMapper(target / "app", secure_ast=True, use_cache=False).analyze_diff(diff)
    actual = {
        f"{item.endpoint.methods[0].value} {item.endpoint.path}"
        for item in report.candidate_endpoints
    }
    assert actual == {"GET /one"}
