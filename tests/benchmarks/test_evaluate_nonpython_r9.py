"""R9 project-adapter selection, provenance, and observation controls."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from benchmarks.real_world import evaluate_nonpython_r9 as evaluator

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parents[2]


def _case_input() -> dict[str, Any]:
    source = "fetch('/api/items?q=1')\n"
    return {
        "expected_selected_paths": ["client.ts"],
        "client_patterns": ["client.ts"],
        "deployment_patterns": [],
        "source_text_lengths": {"client.ts": len(source)},
        "source_text_snapshots": {"client.ts": source},
    }


def _snapshot() -> dict[str, Any]:
    source = _case_input()["source_text_snapshots"]["client.ts"]
    return {
        "schema_version": 1,
        "scope": "bounded_source_observations_only",
        "root": "<verified-temporary-case-source>",
        "expected_selected_paths": ["client.ts"],
        "source_selection": {
            "client_include_patterns": ["client.ts"],
            "deployment_include_patterns": [],
        },
        "budgets": {"max_files": 10000, "max_file_bytes": 2000000},
        "trusted_surface_ids": [],
        "trusted_server_origins": {},
        "surface_matches": [],
        "complete": True,
        "scanned_files": 1,
        "selection_file_count_matches": True,
        "client_observations": [
            {
                "source_path": "client.ts",
                "line": 1,
                "start_offset": 0,
                "end_offset": len(source.rstrip("\n")),
                "certainty": "exact",
                "protocol": "http",
                "method": "GET",
                "literal_url": "/api/items?q=1",
                "origin": None,
                "route_path": "/api/items",
                "query": "q=1",
            }
        ],
        "client_uncertainties": [],
        "deployment_observations": [],
        "issues": [],
        "limitations": [],
    }


def test_r9_project_adapter_preserves_provisional_denominator_and_source_proof() -> None:
    result = evaluator.build_result(repo_root=ROOT)
    assert result["schema"] == "gh108-adapter-evaluation-r9-v1"
    assert result["truth_status"] == "reviewed_historical_atoms_provisional_not_canonical_truth"
    assert result["scope_units"] == {
        "audited_pr_count": 6,
        "client_route_atom_count": 8,
        "conditional_deployment_atom_count": 1,
        "total_audited_nonpython_atom_count": 9,
    }
    assert result["acceptance_claim"].endswith("GH108 full acceptance remains open")
    assert result["established_surface_join_count"] == 0
    assert result["scanner"]["project_source_sha256"] == evaluator.PROJECT_SCANNER_SHA256
    proof = result["executed_scanner_sources"][
        "fastapi_endpoint_detector.analyzer.project_observations"
    ]
    assert proof == {
        "path": evaluator.PROJECT_SCANNER_PATH.removeprefix("src/"),
        "sha256": evaluator.PROJECT_SCANNER_SHA256,
    }
    spec = evaluator.strict_json(evaluator.FIXTURE / "evaluation_cases.json")
    manifests = evaluator.strict_json(evaluator.FIXTURE / "source_manifest.json")
    assert len(result["cases"]) == 6
    by_id = {case["case_id"]: case for case in spec["cases"]}
    for case in result["cases"]:
        declared = by_id[case["case_id"]]
        source_record = next(
            value
            for value in manifests["cases"].values()
            if value["repository"] == declared["repository"]
            and value["merge_snapshot"] == declared["merge_snapshot"]
        )
        paths = {item["path"] for item in source_record["files"]}
        clients, deployment, selected = evaluator._selected_case_paths(declared, paths)
        scan = case["source_scan"]
        assert scan["source_selection"] == {
            "client_include_patterns": list(clients),
            "deployment_include_patterns": list(deployment),
        }
        assert scan["expected_selected_paths"] == list(selected)
        assert scan["budgets"] == {"max_files": 10000, "max_file_bytes": 2000000}
        assert scan["selection_file_count_matches"] is (scan["scanned_files"] == len(selected))
        assert scan["selection_complete"] is (
            scan["complete"] and scan["selection_file_count_matches"]
        )
        assert scan["selection_complete"] is True
        assert case["explicit_established_surface_joins"] == []
        if declared.get("subprocess_file"):
            assert declared["subprocess_file"] in selected
            assert scan["subprocess_file_status"] == "selected_and_scanned"
        else:
            assert scan["subprocess_file_status"] == "not_present_in_audited_selection"
        assert scan["subprocess_observation_count"] == len(case["raw_subprocess_observations"])
        for atom in case["atoms"]:
            if case["mode"] != "docker_env_subprocess":
                assert "query_evidence" in atom
                assert atom["normalized_route_identity"] == f"{atom['method']} {atom['path']}"


def test_selected_paths_include_python_and_explicit_subprocess_inputs() -> None:
    clients, deployment, selected = evaluator._selected_case_paths(
        {
            "client_files": ["web/client.ts"],
            "deployment_files": ["Dockerfile"],
            "subprocess_file": "tools/run.py",
        },
        {"web/client.ts", "Dockerfile", "tools/run.py", "src/helper.py", "note.txt"},
    )
    assert clients == ("web/client.ts",)
    assert deployment == ("Dockerfile", "src/helper.py", "tools/run.py")
    assert selected == ("Dockerfile", "src/helper.py", "tools/run.py", "web/client.ts")


@pytest.mark.parametrize(
    ("case", "paths"),
    [
        ({"client_files": ["missing.ts"]}, {"present.ts"}),
        ({"client_files": ["../escape.ts"]}, {"../escape.ts"}),
        ({"client_files": ["src/*.ts"]}, {"src/*.ts"}),
        ({"client_files": ["same.ts", "same.ts"]}, {"same.ts"}),
        ({"deployment_files": ["Dockerfile", "Dockerfile"]}, {"Dockerfile"}),
        ({"client_files": "client.ts"}, {"client.ts"}),
    ],
)
def test_selected_paths_reject_missing_or_ambiguous_selection(
    case: dict[str, Any], paths: set[str]
) -> None:
    with pytest.raises(evaluator.NonPythonFixtureError):
        evaluator._selected_case_paths(case, paths)


def test_case_scan_preserves_an_absent_query_as_null() -> None:
    value = _snapshot()
    value["client_observations"][0]["query"] = None
    assert (
        evaluator._validate_case_scan(value, _case_input())["client_observations"][0]["query"]
        is None
    )


def test_case_scan_accepts_source_bound_observation_and_separate_query() -> None:
    result = evaluator._validate_case_scan(_snapshot(), _case_input())
    observation = result["client_observations"][0]
    assert observation["route_path"] == "/api/items"
    assert observation["query"] == "q=1"
    assert result["trusted_server_origins"] == {}
    assert result["surface_matches"] == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda value: value.update(surface_matches=[{"surface_id": "untrusted"}]),
            "pinned selection",
        ),
        (
            lambda value: value.update(trusted_server_origins={"fake": "https://example.test"}),
            "pinned selection",
        ),
        (
            lambda value: value["client_observations"][0].update(source_path="other.ts"),
            "outside the selected source",
        ),
        (lambda value: value["client_observations"][0].update(line=2), "physical source line"),
        (
            lambda value: value["client_observations"][0].update(start_offset=-1),
            "invalid source span",
        ),
        (
            lambda value: value["client_observations"][0].update(end_offset=1000),
            "invalid source span",
        ),
        (lambda value: value.update(scanned_files=0), "pinned selection"),
        (lambda value: value.update(schema_version=True), "pinned selection"),
        (
            lambda value: value["source_selection"]["client_include_patterns"].append("*.ts"),
            "pinned selection",
        ),
    ],
)
def test_case_scan_rejects_join_span_and_count_disagreement(
    change: Callable[[dict[str, Any]], None], message: str
) -> None:
    value = copy.deepcopy(_snapshot())
    change(value)
    with pytest.raises(evaluator.NonPythonFixtureError, match=message):
        evaluator._validate_case_scan(value, _case_input())


def test_case_scan_retains_incomplete_selection_without_promoting_it() -> None:
    value = _snapshot()
    value.update(
        complete=False,
        scanned_files=0,
        selection_file_count_matches=False,
        client_observations=[],
        issues=[{"source_path": "client.ts", "reason": "budget"}],
    )
    result = evaluator._validate_case_scan(value, _case_input())
    assert result["complete"] is False
    assert result["selection_file_count_matches"] is False
    assert result["client_observations"] == []


def test_case_scan_keeps_uncertain_observations_explicit() -> None:
    value = _snapshot()
    value["client_observations"] = []
    value["client_uncertainties"] = [
        {
            "source_path": "client.ts",
            "line": 1,
            "start_offset": 0,
            "end_offset": 5,
            "certainty": "uncertain",
            "reason": "dynamic URL",
        }
    ]
    result = evaluator._validate_case_scan(value, _case_input())
    assert result["client_observations"] == []
    assert result["client_uncertainties"][0]["certainty"] == "uncertain"


def test_modified_verified_source_is_rejected_before_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = tmp_path / "fixture"
    shutil.copytree(evaluator.FIXTURE, fixture)
    manifest = json.loads((fixture / "source_manifest.json").read_text(encoding="utf-8"))
    case_key, record = next(iter(manifest["cases"].items()))
    stored = fixture / "source" / case_key / record["files"][0]["storage_path"]
    stored.write_bytes(stored.read_bytes() + b"\n")

    def forbidden_scan(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("changed source reached the adapter before custody validation")

    monkeypatch.setattr(evaluator, "_run_worker", forbidden_scan)
    with pytest.raises(evaluator.NonPythonFixtureError, match="source SHA-256 mismatch"):
        evaluator.build_result(fixture=fixture, repo_root=ROOT)


@pytest.mark.parametrize("suffix, query", [("?q=1", "q=1"), ("", None)])
def test_synthetic_absolute_client_has_no_unattested_origin_join(
    suffix: str,
    query: str | None,
) -> None:
    scan = evaluator.scan_literal_case(
        repo_root=ROOT,
        scanner_commit=evaluator.SCANNER_COMMIT,
        source_path="client.ts",
        source_text=f"fetch('https://service.example/api/items{suffix}')\n",
    )
    assert scan["complete"] is True
    assert scan["scanned_files"] == 1
    assert scan["selection_file_count_matches"] is True
    assert scan["trusted_server_origins"] == {}
    assert scan["surface_matches"] == []
    assert len(scan["client_observations"]) == 1
    observation = scan["client_observations"][0]
    assert observation["route_path"] == "/api/items"
    assert observation["query"] == query
    assert observation["origin"] == "https://service.example"
    assert (
        scan["executed_scanner_sources"]["fastapi_endpoint_detector.analyzer.project_observations"][
            "sha256"
        ]
        == evaluator.PROJECT_SCANNER_SHA256
    )
