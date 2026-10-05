"""Unit and schema checks for the paired GH283 analyzer CLI gate."""

from __future__ import annotations

import copy
import json
import math
import subprocess
import sys
import time
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


def test_unsupported_capability_probe_cannot_satisfy_gate() -> None:
    cases = [
        {"supported": True, "status": "passed"},
        {"supported": False, "status": "unsupported"},
    ]
    coverage = {"unsupported": 1, "failed": 0}
    metrics = {"precision": 1.0, "recall": 1.0, "high_medium_control_candidates": 0}
    assert not gate._gate_passed(cases, coverage, metrics)


def test_source_identity_snapshot_detects_changes_between_cases(tmp_path: Path) -> None:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "accuracy@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Accuracy Harness"],
        check=True,
    )
    source = tmp_path / "src" / "analyzer.py"
    source.parent.mkdir()
    source.write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/analyzer.py"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "pin"], check=True, capture_output=True
    )
    pinned = {"src/analyzer.py": gate.sha_bytes(source.read_bytes())}
    before = gate._source_identity_snapshot(tmp_path, pinned)
    assert before["worktree_clean"] is True
    source.write_text("VALUE = 2\n", encoding="utf-8")
    after = gate._source_identity_snapshot(tmp_path, pinned)
    assert after["worktree_clean"] is False
    assert after["source_tree_hash"] != before["source_tree_hash"]


def test_self_consistent_fabricated_cli_document_requires_runtime_receipt() -> None:
    artifact = gate.RESULTS / "paired-run-88365f0-analyzer-8ccd5d3.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    target = next(
        case for case in document["cases"] if case["case_id"] == "deferred_lambda_control"
    )
    evidence = target["cli_evidence"]
    report = evidence["report"]
    assert report["candidate_endpoints"]
    report["candidate_endpoints"] = []
    target["actual"] = []
    target.update(gate._metrics(target["expected"], []))
    target["status"] = "passed"
    target["error"] = None
    evidence["stdout"] = json.dumps(report)
    evidence["stdout_sha256"] = gate.sha_text(evidence["stdout"])
    evidence["report_hash"] = gate.sha_text(gate._canonical_json(report))
    evidence["execution_receipt"] = "forged-self-consistent-receipt"
    supported = [case for case in document["cases"] if case["supported"]]
    tp = sum(case["tp"] for case in supported)
    fp = sum(case["fp"] for case in supported)
    fn = sum(case["fn"] for case in supported)
    document["metrics"] = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp),
        "recall": tp / (tp + fn),
        "high_medium_control_candidates": 0,
        "high_medium": gate._tier_metrics(supported, {"high", "medium"}),
        "low_report_only": gate._tier_metrics(supported, {"low"}),
    }
    document["case_coverage"]["failed"] = 0
    document["gate_status"] = "passed"
    document["run_validity"] = "valid"
    document["integrity_errors"] = []
    document["final_source_identity"] = {
        "worktree_clean": True,
        "source_tree_hash": document["analyzer_provenance"]["source_tree_hash"],
    }
    assert document["metrics"]["precision"] == document["metrics"]["recall"] == 1.0
    with pytest.raises(ValueError, match="in-memory subprocess execution context"):
        gate.validate(document)


def test_cli_output_is_bounded_while_reading(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(gate, "CLI_OUTPUT_LIMIT_BYTES", 1024)
    result = gate._run_bounded_cli(
        [sys.executable, "-c", "print('x' * 200_000)"], tmp_path, timeout_seconds=10
    )
    assert result.output_limit_exceeded
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 1024


def test_cli_deadline_covers_descendants_holding_pipes_open(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-c",
        "import subprocess,sys; subprocess.Popen([sys.executable,'-c',"
        "'import time; time.sleep(30)']); print('parent exited')",
    ]
    started = time.perf_counter()
    result = gate._run_bounded_cli(command, tmp_path, timeout_seconds=1)
    elapsed = time.perf_counter() - started
    assert result.timed_out
    assert elapsed < 3
