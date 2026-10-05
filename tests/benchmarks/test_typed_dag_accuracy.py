"""Fail-closed tests for the generated GH283 typed-DAG accuracy gate."""

from __future__ import annotations

import copy
import json
import math
from typing import TYPE_CHECKING, Any, cast

import pytest
from benchmarks.real_world import typed_dag_accuracy as gate

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper

if TYPE_CHECKING:
    from pathlib import Path


def _evidence() -> dict[str, Any]:
    return cast(
        "dict[str, Any]",
        json.loads((gate.RESULTS / "current-main.json").read_text(encoding="utf-8")),
    )


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


def test_checked_in_cli_run_is_valid_but_fails_the_gate() -> None:
    document = _evidence()
    gate.validate(document)
    assert document["gate_status"] == "failed"
    assert document["case_coverage"]["recorded"] == len(gate.CASES)


def test_validator_rejects_duplicate_or_missing_cases() -> None:
    document = _evidence()
    document["cases"] = document["cases"][:-1]
    with pytest.raises(ValueError, match="duplicate, missing"):
        gate.validate(document)
    document = _evidence()
    document["cases"][-1] = copy.deepcopy(document["cases"][0])
    with pytest.raises(ValueError, match="duplicate, missing"):
        gate.validate(document)


def test_validator_rejects_tampered_input_hash() -> None:
    document = _evidence()
    document["cases"][0]["input_hashes"]["baseline"] = "sha256:bad"
    with pytest.raises(ValueError, match="tampered/missing input hashes"):
        gate.validate(document)


def test_validator_rejects_rehashed_but_forged_fixture_material() -> None:
    document = _evidence()
    case = document["cases"][0]
    case["input_material"] = {"source": case["case_id"]}
    case["input_hashes"] = {"source": gate.sha(case["case_id"])}
    with pytest.raises(ValueError, match="source/diff/config do not match generator"):
        gate.validate(document)


def test_validator_rejects_incomplete_inventory_and_analyzer_errors() -> None:
    document = _evidence()
    case = document["cases"][0]
    case["inventory_status"] = "incomplete"
    case["total_endpoints"] = 0
    case["analyzer_errors"] = ["build failed"]
    with pytest.raises(ValueError, match=r"diagnostics differ|endpoint inventory differs"):
        gate.validate(document)


def test_validator_rejects_control_metadata_tampering() -> None:
    document = _evidence()
    control = next(item for item in document["cases"] if item["control"])
    control["control"] = False
    with pytest.raises(ValueError, match="case metadata differs"):
        gate.validate(document)


def test_validator_rejects_forged_case_coverage() -> None:
    document = _evidence()
    document["case_coverage"] = {"declared": 999, "recorded": 1, "supported": 0, "unsupported": 0}
    with pytest.raises(ValueError, match="case coverage"):
        gate.validate(document)


def test_validator_rejects_metrics_and_false_pass_tampering() -> None:
    document = _evidence()
    document["cases"][0]["precision"] = math.nan
    with pytest.raises(ValueError, match="non-finite"):
        gate.validate(document)
    document = _evidence()
    document["gate_status"] = "passed"
    with pytest.raises(ValueError, match="gate status"):
        gate.validate(document)


def test_validator_rejects_candidate_rows_that_disagree_with_cli_report() -> None:
    document = _evidence()
    document["cases"][0]["actual"] = []
    with pytest.raises(ValueError, match="candidate rows differ"):
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
