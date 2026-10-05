"""Unit and schema checks for the paired GH283 analyzer CLI gate."""

from __future__ import annotations

import copy
import json
import math
from typing import TYPE_CHECKING, Any

import pytest
from benchmarks.real_world import typed_dag_paired_cli_accuracy as gate

if TYPE_CHECKING:
    from pathlib import Path


def _synthetic_validation_only() -> dict[str, Any]:
    """In-memory schema probes; never CLI evidence and never eligible to pass."""
    cases = []
    for declared in gate.CASES:
        expected = list(gate.expected_for(declared))
        material = gate.case_inputs(declared)
        metrics = gate._metrics(expected, [])
        cases.append(
            {
                "case_id": declared.case_id,
                "symbol": declared.symbol,
                "source_symbol": declared.source_symbol,
                "control": declared.control,
                "change_kind": declared.change_kind,
                "capability_probe": declared.capability_probe,
                "supported": not declared.capability_probe,
                "status": "failed",
                "error": "synthetic validation probe; analyzer CLI was not invoked",
                "expected": expected,
                "actual": [],
                **metrics,
                "input_material": material,
                "input_hashes": {key: gate.sha_text(value) for key, value in material.items()},
                "cli_evidence": None,
            }
        )
    supported = [case for case in cases if case["supported"]]
    tp = sum(case["tp"] for case in supported)
    fp = sum(case["fp"] for case in supported)
    fn = sum(case["fn"] for case in supported)
    return {
        "schema": gate.SCHEMA,
        "evidence_kind": "synthetic_validation_only",
        "gate_status": "failed",
        "case_coverage": {
            "declared": len(gate.CASES),
            "recorded": len(cases),
            "supported": len(supported),
            "unsupported": 0,
            "failed": len(cases),
        },
        "metrics": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else (1.0 if not fn else 0.0),
            "recall": tp / (tp + fn) if tp + fn else 1.0,
            "high_medium_control_candidates": 0,
            "high_medium": gate._tier_metrics(supported, {"high", "medium"}),
            "low_report_only": gate._tier_metrics(supported, {"low"}),
        },
        "cases": cases,
    }


def test_all_cases_have_exact_paired_baseline_target_inputs() -> None:
    assert len(gate.CASES) == 18
    assert len({case.case_id for case in gate.CASES}) == 18
    assert sum(case.capability_probe for case in gate.CASES) == 3
    for case in gate.CASES:
        material = gate.case_inputs(case)
        gate.validate_generated_fixture(case, material)
        config = json.loads(material["config"])
        assert config["paired_baseline_target"] is True
        assert set(json.loads(material["baseline"]))
        assert set(json.loads(material["target"]))
        assert material["diff"]


def test_oracle_keeps_connected_dead_controls_out_and_live_paths_in() -> None:
    for case_id in (
        "literal_false_control",
        "post_return_control",
        "deferred_closure_control",
        "deferred_lambda_control",
        "unawaited_coroutine_control",
        "unrelated_disconnected_control",
    ):
        case = next(case for case in gate.CASES if case.case_id == case_id)
        assert gate.expected_for(case) == ()
    assert gate.expected_for(
        next(case for case in gate.CASES if case.case_id == "live_invoked_lambda_counterpart")
    ) == ("GET /one",)


def test_paired_capability_probes_are_oracle_reachable_on_the_correct_side() -> None:
    for kind, endpoint in (
        ("addition", "GET /one"),
        ("deletion", "GET /one"),
        ("rename", "GET /one"),
    ):
        case = next(case for case in gate.CASES if case.change_kind == kind)
        assert gate.expected_for(case) == (endpoint,)


def test_source_hashes_are_bound_to_analyzer_commit_files(tmp_path: Path) -> None:
    document = _synthetic_validation_only()
    gate.validate(document, tmp_path)
    assert document["gate_status"] == "failed"


def test_synthetic_probe_rejects_tampered_input_hash_and_case_metadata() -> None:
    document = _synthetic_validation_only()
    document["cases"][0]["input_hashes"]["baseline"] = "sha256:tampered"
    with pytest.raises(ValueError, match="input hashes mismatch"):
        gate.validate(document)
    document = _synthetic_validation_only()
    next(case for case in document["cases"] if case["control"])["control"] = False
    with pytest.raises(ValueError, match="synthetic case metadata mismatch"):
        gate.validate(document)


def test_synthetic_probe_rejects_duplicate_missing_nonfinite_and_forged_pass() -> None:
    document = _synthetic_validation_only()
    document["cases"][-1] = copy.deepcopy(document["cases"][0])
    with pytest.raises(ValueError, match="duplicate, missing"):
        gate.validate(document)
    document = _synthetic_validation_only()
    document["cases"][0]["precision"] = math.nan
    with pytest.raises(ValueError, match="synthetic metrics mismatch"):
        gate.validate(document)
    document = _synthetic_validation_only()
    document["gate_status"] = "passed"
    with pytest.raises(ValueError, match="cannot claim a passing gate"):
        gate.validate(document)


def test_non_finite_case_metrics_are_not_accepted() -> None:
    metrics = gate._metrics(["GET /one"], [])
    assert metrics == {"tp": 0, "fp": 0, "fn": 1, "precision": 0.0, "recall": 0.0}
    assert all(math.isfinite(value) for value in metrics.values() if isinstance(value, float))
