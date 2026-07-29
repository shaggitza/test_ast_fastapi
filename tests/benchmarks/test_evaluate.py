from __future__ import annotations

import hashlib
import json
import sys
from typing import TYPE_CHECKING

import pytest
from benchmarks.real_world import evaluate, semantic_normalization
from benchmarks.real_world.benchmark_schema import read_primary_artifact, read_primary_jsonl

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def test_ranked_kind_preserves_declared_non_http_kind() -> None:
    record = {"candidate_entrypoints": [{"id": "CLI sync", "kind": "cli", "confidence": "medium"}]}

    assert evaluate.predicted_ids_by_kind(record, {"CLI sync"}) == {"cli": {"CLI sync"}}


def test_stratifies_metrics_by_entrypoint_kind(tmp_path: Path, monkeypatch, capsys) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    truth.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "status": "adjudicated",
                "affected_entrypoints": [
                    {"id": "HTTP GET /items", "kind": "http"},
                    {"id": "WEBSOCKET /events", "kind": "event"},
                ],
            }
        )
        + "\n"
    )
    predictions.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "candidate": "test-candidate",
                "affected_entrypoints": [
                    {"id": "HTTP GET /items", "kind": "http"},
                    {"id": "HTTP GET /wrong", "kind": "http"},
                ],
            }
        )
        + "\n"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["evaluate.py", "--ground-truth", str(truth), "--predictions", str(predictions)],
    )

    evaluate.main()

    result = json.loads(capsys.readouterr().out)
    assert result["micro"] == {
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "tp": 1,
        "fp": 1,
        "fn": 1,
    }
    assert result["by_kind"]["http"] == {
        "precision": 0.5,
        "recall": 1.0,
        "f1": 2 / 3,
        "tp": 1,
        "fp": 1,
        "fn": 0,
    }
    assert result["by_kind"]["event"]["fn"] == 1


def test_fastapi_scope_keeps_http_and_websocket_but_excludes_generic_events(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    truth.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "status": "adjudicated",
                "affected_entrypoints": [
                    {"id": "HTTP GET /items", "kind": "http"},
                    {"id": "WEBSOCKET /events", "kind": "event"},
                    {"id": "Socket.IO connect event", "kind": "event"},
                    {"id": "Web UI settings", "kind": "other"},
                ],
            }
        )
        + "\n"
    )
    predictions.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "candidate": "test-candidate",
                "affected_entrypoints": [
                    {"id": "HTTP GET /items", "kind": "http"},
                    {"id": "WebSocket /events", "kind": "event"},
                    {"id": "Socket.IO connect event", "kind": "event"},
                ],
            }
        )
        + "\n"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluate.py",
            "--ground-truth",
            str(truth),
            "--predictions",
            str(predictions),
            "--scope",
            "fastapi",
        ],
    )

    evaluate.main()

    result = json.loads(capsys.readouterr().out)
    assert result["scope"] == "fastapi-adapter-v1"
    assert result["micro"] == {
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "tp": 1,
        "fp": 1,
        "fn": 1,
    }
    assert result["normalized"]["micro"]["tp"] == 2
    assert result["normalized"]["micro"]["fp"] == 0
    assert result["normalized"]["micro"]["fn"] == 0


def test_low_confidence_is_diagnostic_and_splits_primary_false_negatives(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    truth.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "status": "adjudicated",
                "affected_entrypoints": [
                    {"id": "HTTP GET /a", "kind": "http"},
                    {"id": "HTTP GET /b", "kind": "http"},
                    {"id": "HTTP GET /c", "kind": "http"},
                ],
                "reachability_only_entrypoints": [{"id": "HTTP GET /low-fp", "kind": "http"}],
            }
        )
        + "\n"
    )
    predictions.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "candidate": "test-candidate",
                "affected_entrypoints": [
                    {"id": "HTTP GET /a", "kind": "http"},
                    {"id": "HTTP GET /selected-fp", "kind": "http"},
                ],
                "candidate_entrypoints": [
                    {"id": "HTTP GET /a", "kind": "http", "confidence": "high"},
                    {
                        "id": "HTTP GET /selected-fp",
                        "kind": "http",
                        "confidence": "medium",
                    },
                    {"id": "HTTP GET /b", "kind": "http", "confidence": "low"},
                    {"id": "HTTP GET /low-fp", "kind": "http", "confidence": "low"},
                ],
            }
        )
        + "\n"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["evaluate.py", "--ground-truth", str(truth), "--predictions", str(predictions)],
    )

    evaluate.main()

    result = json.loads(capsys.readouterr().out)
    assert result["micro"] == {
        "precision": 0.5,
        "recall": 1 / 3,
        "f1": 0.4,
        "tp": 1,
        "fp": 1,
        "fn": 2,
    }
    assert result["confidence"]["low"] == {
        "low_tp": 1,
        "low_fp": 1,
        "low_candidates": 2,
        "low_supported_reachability": 1,
        "low_unmatched": 0,
        "fn_with_low_candidate": 1,
        "fn_with_no_candidate": 1,
        "diagnostic_precision": 0.5,
        "supported_precision": 1.0,
    }
    assert result["by_kind"]["http"] == result["micro"]
    assert result["confidence"]["candidate_ceiling"]["tp"] == 2
    assert result["confidence"]["candidate_ceiling"]["fn"] == 1


def test_normalized_composite_matches_selected_before_low(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    truth.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "status": "adjudicated",
                "affected_entrypoints": [{"id": "HTTP GET|POST /items", "kind": "http"}],
            }
        )
        + "\n"
    )
    predictions.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "candidate": "test-candidate",
                "affected_entrypoints": [{"id": "HTTP GET /items", "kind": "http"}],
                "candidate_entrypoints": [
                    {"id": "HTTP GET /items", "kind": "http", "confidence": "high"},
                    {"id": "HTTP POST /items", "kind": "http", "confidence": "low"},
                    {"id": "HTTP DELETE /items", "kind": "http", "confidence": "low"},
                ],
            }
        )
        + "\n"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["evaluate.py", "--ground-truth", str(truth), "--predictions", str(predictions)],
    )

    evaluate.main()

    normalized = json.loads(capsys.readouterr().out)["normalized"]
    assert normalized["micro"]["tp"] == 1
    assert normalized["micro"]["fn"] == 1
    assert normalized["confidence"]["low"]["low_tp"] == 1
    assert normalized["confidence"]["low"]["low_fp"] == 1
    assert normalized["confidence"]["low"]["fn_with_no_candidate"] == 0


def test_prediction_coverage_excludes_not_evaluable_truth(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    truth.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "repository": "owner/repo",
                        "pr": 1,
                        "status": "adjudicated",
                        "affected_entrypoints": [],
                    }
                ),
                json.dumps(
                    {
                        "repository": "owner/repo",
                        "pr": 2,
                        "status": "not_evaluable",
                        "affected_entrypoints": [],
                    }
                ),
                json.dumps(
                    {
                        "repository": "owner/repo",
                        "pr": 3,
                        "status": "unknown",
                        "affected_entrypoints": [{"id": "HTTP GET /partial", "kind": "http"}],
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    predictions.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "repository": "owner/repo",
                        "pr": 1,
                        "candidate": "test-candidate",
                        "affected_entrypoints": [],
                    }
                ),
                json.dumps(
                    {
                        "repository": "owner/repo",
                        "pr": 2,
                        "candidate": "test-candidate",
                        "affected_entrypoints": [],
                    }
                ),
                json.dumps(
                    {
                        "repository": "owner/repo",
                        "pr": 3,
                        "candidate": "test-candidate",
                        "affected_entrypoints": [],
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["evaluate.py", "--ground-truth", str(truth), "--predictions", str(predictions)],
    )

    evaluate.main()

    result = json.loads(capsys.readouterr().out)
    assert result["adjudicated_prs"] == 1
    assert result["not_evaluable_prs"] == 1
    assert result["unknown_label_prs"] == 1
    assert result["prediction_coverage"] == 1.0


@pytest.mark.parametrize(
    "manifest",
    [
        {
            "schema_version": 1,
            "id": "",
            "base_scope": "all-surfaces",
            "excluded": [{"repository": "owner/repo", "pr": 1}],
        },
        {
            "schema_version": 1,
            "id": "test",
            "base_scope": "all-surfaces",
            "excluded": [
                {"repository": "owner/repo", "pr": 1},
                {"repository": "owner/repo", "pr": 1},
            ],
        },
    ],
)
def test_verification_set_rejects_malformed_or_duplicate_entries(
    tmp_path: Path, manifest: dict
) -> None:
    path = tmp_path / "verification.json"
    path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError):
        evaluate.read_verification_selection(path)


def test_route_census_partitions_fn_without_changing_metrics(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    census = tmp_path / "census.jsonl"
    truth.write_text(
        "".join(
            json.dumps(
                {
                    "repository": "owner/repo",
                    "pr": pr,
                    "status": "adjudicated",
                    "affected_entrypoints": [{"id": f"HTTP GET /{pr}", "kind": "http"}],
                }
            )
            + "\n"
            for pr in range(1, 5)
        )
    )
    predictions.write_text(
        "".join(
            json.dumps(
                {
                    "repository": "owner/repo",
                    "pr": pr,
                    "candidate": "test-candidate",
                    "candidate_entrypoints": (
                        [
                            {
                                "id": "HTTP GET /1",
                                "kind": "http",
                                "confidence": "low",
                            }
                        ]
                        if pr == 1
                        else []
                    ),
                    "affected_entrypoints": [],
                }
            )
            + "\n"
            for pr in range(1, 5)
        )
    )

    def side(items: list[dict], status: str = "completed") -> dict:
        return {"status": status, "entrypoints": items, "unresolved": []}

    census_records = []
    for pr in range(1, 5):
        item = {
            "id": f"HTTP GET /{pr}",
            "kind": "http",
            "occurrences": [
                {
                    "file": "main.py",
                    "line": pr,
                    "end_line": pr,
                    "handler": f"route_{pr}",
                    "module": "main",
                    "root": ".",
                }
            ],
        }
        target = side([item] if pr == 2 else [], "partial" if pr == 4 else "completed")
        baseline = side([], "completed")
        status = "partial" if pr == 4 else "completed"
        census_records.append(
            {
                "schema_version": 1,
                "repository": "owner/repo",
                "pr": pr,
                "status": status,
                "complete": status == "completed",
                "target": target,
                "baseline": baseline,
            }
        )
    census.write_text("".join(json.dumps(item) + "\n" for item in census_records))

    base_argv = [
        "evaluate.py",
        "--ground-truth",
        str(truth),
        "--predictions",
        str(predictions),
        "--scope",
        "fastapi",
    ]
    monkeypatch.setattr(sys, "argv", base_argv)
    evaluate.main()
    without_census = json.loads(capsys.readouterr().out)
    monkeypatch.setattr(sys, "argv", [*base_argv, "--route-census", str(census)])
    evaluate.main()
    with_census = json.loads(capsys.readouterr().out)

    diagnostics = with_census.pop("fn_stages")
    inventory_coverage = with_census["coverage"].pop("inventory")
    without_census["coverage"].pop("inventory")
    assert with_census == without_census
    assert inventory_coverage == {
        "available": True,
        "numerator": 3,
        "denominator": 4,
        "rate": 0.75,
    }
    assert diagnostics["exact"]["totals"] == {
        "observation_missing": 1,
        "propagation_missing": 1,
        "discovery_missing": 1,
        "inventory_unavailable": 1,
    }
    assert diagnostics["normalized"]["totals"] == diagnostics["exact"]["totals"]
    assert sum(diagnostics["normalized"]["totals"].values()) == 4
    assert with_census["normalized"]["micro"]["tp"] == 0
    assert with_census["normalized"]["confidence"]["candidate_ceiling"]["tp"] == 1


def test_route_census_v2_uses_occurrence_and_inventory_strength(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    census = tmp_path / "census.jsonl"
    truth.write_text(
        "".join(
            json.dumps(
                {
                    "repository": "owner/repo",
                    "pr": pr,
                    "status": "adjudicated",
                    "affected_entrypoints": [{"id": f"HTTP GET /{pr}", "kind": "http"}],
                }
            )
            + "\n"
            for pr in range(1, 5)
        )
    )
    predictions.write_text(
        "".join(
            json.dumps(
                {
                    "repository": "owner/repo",
                    "pr": pr,
                    "candidate": "test-candidate",
                    "affected_entrypoints": [],
                }
            )
            + "\n"
            for pr in range(1, 5)
        )
    )

    limitation = {"source": "main.py", "line": 1, "reason": "unknown helper"}

    def occurrence(pr: int, status: str) -> dict:
        result = {
            "file": "main.py",
            "line": pr,
            "end_line": pr,
            "handler": f"route_{pr}",
            "module": "main",
            "root": ".",
            "discovery_status": status,
            "discovery_conditions": [],
        }
        if status == "conditional":
            result["discovery_conditions"] = [limitation]
        return result

    def side(status: str, entrypoints: list[dict]) -> dict:
        return {
            "status": {"established": "completed", "conditional": "partial"}[status],
            "inventory_status": status,
            "inventory_limitations": [] if status == "established" else [limitation],
            "entrypoints": entrypoints,
            "unresolved": [],
        }

    records = []
    for pr in range(1, 5):
        route = {
            "id": f"HTTP GET /{pr}",
            "kind": "http",
            "occurrences": [occurrence(pr, "conditional")],
        }
        target = side("conditional", [route] if pr in {1, 2} else [])
        baseline = side("conditional", [])
        if pr == 2:
            route["occurrences"].append(occurrence(pr, "established"))
            target = side("established", [route])
            baseline = side("established", [])
        elif pr == 4:
            target = side("established", [])
            baseline = side("established", [])
        records.append(
            {
                "schema_version": 2,
                "repository": "owner/repo",
                "pr": pr,
                "status": (
                    "completed"
                    if target["status"] == baseline["status"] == "completed"
                    else "partial"
                ),
                "complete": target["status"] == baseline["status"] == "completed",
                "target": target,
                "baseline": baseline,
            }
        )
    census.write_text("".join(json.dumps(record) + "\n" for record in records))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluate.py",
            "--ground-truth",
            str(truth),
            "--predictions",
            str(predictions),
            "--scope",
            "fastapi",
            "--route-census",
            str(census),
        ],
    )

    evaluate.main()

    result = json.loads(capsys.readouterr().out)
    expected = {
        "observation_missing": 0,
        "propagation_missing": 1,
        "discovery_missing": 1,
        "inventory_unavailable": 2,
    }
    assert result["fn_stages"]["exact"]["totals"] == expected
    assert result["fn_stages"]["normalized"]["totals"] == expected
    assert result["micro"] == result["normalized"]["micro"]
    assert result["micro"]["fn"] == sum(expected.values())


def test_route_census_v2_rejects_malformed_operational_unavailable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "census.jsonl"
    unavailable = {
        "status": "unresolved",
        "inventory_status": "unavailable",
        "inventory_limitations": [],
        "entrypoints": [],
        "unresolved": [""],
    }
    record = {
        "schema_version": 2,
        "repository": "owner/repo",
        "pr": 1,
        "status": "unresolved",
        "complete": False,
        "target": unavailable,
        "baseline": {**unavailable, "unresolved": ["tool failed"]},
    }
    path.write_text(json.dumps(record) + "\n")

    with pytest.raises(ValueError, match="malformed target"):
        evaluate.read_route_census(path, {("owner/repo", 1)}, {("owner/repo", 1)}, "fastapi")


def test_route_census_rejects_duplicate_and_missing_selected_keys(tmp_path: Path) -> None:
    path = tmp_path / "census.jsonl"
    record = {
        "schema_version": 1,
        "repository": "owner/repo",
        "pr": 1,
        "status": "completed",
        "complete": True,
        "target": {"status": "completed", "entrypoints": [], "unresolved": []},
        "baseline": {"status": "completed", "entrypoints": [], "unresolved": []},
    }
    path.write_text(json.dumps(record) + "\n" + json.dumps(record) + "\n")
    with pytest.raises(ValueError, match="duplicate"):
        evaluate.read_route_census(path, {("owner/repo", 1)}, {("owner/repo", 1)}, "fastapi")
    path.write_text(json.dumps(record) + "\n")
    with pytest.raises(ValueError, match="missing selected"):
        evaluate.read_route_census(
            path,
            {("owner/repo", 1), ("owner/repo", 2)},
            {("owner/repo", 1), ("owner/repo", 2)},
            "fastapi",
        )


def test_route_census_rejects_unknown_key_and_malformed_occurrence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "census.jsonl"
    malformed = {
        "schema_version": 1,
        "repository": "owner/repo",
        "pr": 1,
        "status": "completed",
        "complete": True,
        "target": {
            "status": "completed",
            "entrypoints": [
                {
                    "id": "HTTP GET /items",
                    "kind": "http",
                    "occurrences": [{"file": "../escape.py", "line": 0}],
                }
            ],
            "unresolved": [],
        },
        "baseline": {"status": "completed", "entrypoints": [], "unresolved": []},
    }
    path.write_text(json.dumps(malformed) + "\n")
    with pytest.raises(ValueError, match="malformed occurrence"):
        evaluate.read_route_census(path, {("owner/repo", 1)}, {("owner/repo", 1)}, "fastapi")

    malformed["target"]["entrypoints"] = []
    malformed["pr"] = 9
    path.write_text(json.dumps(malformed) + "\n")
    with pytest.raises(ValueError, match="absent from ground truth"):
        evaluate.read_route_census(path, {("owner/repo", 9)}, {("owner/repo", 1)}, "fastapi")


def test_verification_set_excludes_pr_without_deleting_truth(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    verification = tmp_path / "verification.json"
    truth.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "repository": "owner/repo",
                        "pr": pr,
                        "status": "adjudicated",
                        "affected_entrypoints": [{"id": f"HTTP GET /{pr}", "kind": "http"}],
                    }
                )
                for pr in (1, 2)
            ]
        )
        + "\n"
    )
    predictions.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "repository": "owner/repo",
                        "pr": pr,
                        "candidate": "test-candidate",
                        "affected_entrypoints": [{"id": f"HTTP GET /{pr}", "kind": "http"}],
                    }
                )
                for pr in (1, 2)
            ]
        )
        + "\n"
    )
    verification.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "id": "verification-v1",
                "base_scope": "all-surfaces",
                "selection": "exclude",
                "excluded": [{"repository": "owner/repo", "pr": 2}],
            }
        )
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluate.py",
            "--ground-truth",
            str(truth),
            "--predictions",
            str(predictions),
            "--verification-set",
            str(verification),
        ],
    )

    evaluate.main()

    result = json.loads(capsys.readouterr().out)
    assert result["adjudicated_prs"] == 1
    assert result["micro"]["tp"] == 1
    assert result["verification_set"]["id"] == "verification-v1"
    assert result["verification_set"]["path"] == str(verification)
    assert result["verification_set"]["selection"] == "exclude"
    assert result["verification_set"]["selected_keys"] == [{"repository": "owner/repo", "pr": 2}]
    assert result["verification_set"]["matched_prs"] == 1
    assert len(result["verification_set"]["sha256"]) == 64


def test_primary_reader_rejects_duplicate_rows_members_and_non_finite_numbers(
    tmp_path: Path,
) -> None:
    valid = {
        "repository": "owner/repo",
        "pr": 1,
        "status": "adjudicated",
        "affected_entrypoints": [],
    }
    path = tmp_path / "records.jsonl"
    path.write_text(json.dumps(valid) + "\n" + json.dumps(valid) + "\n")
    with pytest.raises(ValueError, match="duplicate record"):
        read_primary_jsonl(path, "ground_truth")

    path.write_text(
        '{"repository":"owner/repo","repository":"other/repo","pr":1,'
        '"status":"adjudicated","affected_entrypoints":[]}\n'
    )
    with pytest.raises(ValueError, match="duplicate JSON member"):
        read_primary_jsonl(path, "ground_truth")

    path.write_text(
        '{"repository":"owner/repo","pr":1,"affected_entrypoints":[],"incremental_seconds":NaN}\n'
    )
    with pytest.raises(ValueError, match="non-finite"):
        read_primary_jsonl(path, "prediction")


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda _row: None, "candidate must be a non-empty string"),
        (lambda row: row.update(candidate=7), "candidate must be a non-empty string"),
        (lambda row: row.update(candidate="   "), "candidate must be a non-empty string"),
        (
            lambda row: row.update(
                candidate="test-candidate",
                affected_entrypoints=[
                    {"id": "HTTP GET /x", "kind": "http", "confidence": "certain"}
                ],
            ),
            "affected_entrypoints.*confidence",
        ),
        (
            lambda row: row.update(
                candidate="test-candidate",
                candidate_entrypoints=[
                    {"id": "HTTP GET /x", "kind": "http", "confidence": "certain"}
                ],
            ),
            "confidence",
        ),
        (
            lambda row: row.update(
                candidate="test-candidate",
                candidate_entrypoints=[
                    {"id": "HTTP GET /x", "kind": "http", "confidence": "high"},
                    {"id": "HTTP GET /x", "kind": "http", "confidence": "low"},
                ],
            ),
            "duplicate candidate_entrypoints",
        ),
        (
            lambda row: row.update(candidate="test-candidate", incremental_seconds=-1),
            "finite non-negative",
        ),
        (
            lambda row: row.update(candidate="test-candidate", pr=True),
            "positive integer",
        ),
    ],
)
def test_prediction_reader_rejects_malformed_scoring_inputs(
    tmp_path: Path,
    mutate: Callable[[dict[str, object]], None],
    message: str,
) -> None:
    row: dict[str, object] = {
        "repository": "owner/repo",
        "pr": 1,
        "affected_entrypoints": [],
    }
    mutate(row)
    path = tmp_path / "predictions.jsonl"
    path.write_text(json.dumps(row) + "\n")

    with pytest.raises(ValueError, match=message):
        read_primary_jsonl(path, "prediction")


def test_schema_v3_rejects_unknown_fields_float_versions_and_malformed_adapter_claims(
    tmp_path: Path,
) -> None:
    base = {
        "schema_version": 3,
        "repository": "owner/repo",
        "pr": 1,
        "candidate": "candidate/v1",
        "adapter": "fastapi-adapter-v1",
        "status": "completed",
        "affected_entrypoints": [],
        "candidate_entrypoints": [],
        "unresolved": [],
        "timing_seconds": {},
    }
    cases = []
    unknown = dict(base, unexpected=True)
    cases.append((unknown, "unknown or missing fields"))
    float_version = dict(base, schema_version=3.0)
    cases.append((float_version, "schema_version must be an integer"))
    malformed_claim = dict(
        base,
        candidate_entrypoints=[
            {
                "id": "not an endpoint",
                "kind": "http",
                "confidence": "medium",
                "effect_evidence": [],
            }
        ],
    )
    cases.append((malformed_claim, "not emitted by fastapi-adapter-v1"))
    path = tmp_path / "predictions.jsonl"
    for record, message in cases:
        path.write_text(json.dumps(record) + "\n")
        with pytest.raises(ValueError, match=message):
            read_primary_jsonl(path, "prediction")


@pytest.mark.parametrize(
    ("state", "message"),
    [
        ({"status": "measured"}, "requires only seconds"),
        (
            {"status": "not_measured", "reason": "missing", "seconds": 1.0},
            "forbids samples",
        ),
        ({"status": "measured", "seconds": float("nan")}, "finite non-negative"),
        ({"status": "unknown"}, "status is invalid"),
    ],
)
def test_schema_v4_phase_states_reject_malformed_measured_statuses(
    state: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        evaluate._validate_measurement_state(state, "prs.phase_telemetry.cold_build")


def test_schema_v4_aggregate_rejects_mixed_or_dropped_measured_samples() -> None:
    with pytest.raises(ValueError, match="drops measured PR telemetry"):
        evaluate._validate_aggregate_phase_state(
            {"status": "not_measured", "reason": "missing"},
            [1.0],
            "timing.phases.cold_build",
        )
    with pytest.raises(ValueError, match="do not match PR telemetry"):
        evaluate._validate_aggregate_phase_state(
            {"status": "measured", "samples": [2.0]},
            [1.0],
            "timing.phases.cold_build",
        )
    with pytest.raises(ValueError, match="forbids samples"):
        evaluate._validate_aggregate_phase_state(
            {"status": "not_measured", "reason": "missing", "samples": []},
            [],
            "timing.phases.warm_no_change",
        )


def test_explicit_empty_candidate_list_does_not_fall_back_to_affected() -> None:
    record = {
        "affected_entrypoints": [{"id": "HTTP GET /selected", "kind": "http"}],
        "candidate_entrypoints": [],
    }

    assert evaluate.ranked_entrypoints(record) == (set(), set())
    assert semantic_normalization.split_ranked_claims("owner/repo", record) == ([], [])


def test_evaluator_requires_exact_selected_prediction_coverage(tmp_path: Path, monkeypatch) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    truth.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 1,
                "status": "adjudicated",
                "affected_entrypoints": [],
            }
        )
        + "\n"
    )
    predictions.write_text(
        json.dumps(
            {
                "repository": "owner/repo",
                "pr": 2,
                "candidate": "test-candidate",
                "affected_entrypoints": [],
            }
        )
        + "\n"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["evaluate.py", "--ground-truth", str(truth), "--predictions", str(predictions)],
    )

    with pytest.raises(ValueError, match="absent from ground truth"):
        evaluate.main()

    predictions.write_text("")
    with pytest.raises(ValueError, match="no records"):
        evaluate.main()


def test_macro_specificity_coverage_and_timing_protocols_are_separate(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    truth = tmp_path / "truth.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    truth_rows = [
        {
            "repository": "owner/repo",
            "pr": 1,
            "status": "adjudicated",
            "affected_entrypoints": [{"id": "HTTP GET /x", "kind": "http"}],
        },
        {
            "repository": "owner/repo",
            "pr": 2,
            "status": "adjudicated",
            "affected_entrypoints": [],
        },
        {
            "repository": "owner/repo",
            "pr": 3,
            "status": "adjudicated",
            "affected_entrypoints": [],
        },
        {
            "repository": "owner/repo",
            "pr": 4,
            "status": "adjudicated",
            "affected_entrypoints": [{"id": "HTTP GET /missed", "kind": "http"}],
        },
    ]
    prediction_rows = [
        {
            "schema_version": 3,
            "repository": "owner/repo",
            "pr": 1,
            "candidate": "candidate/v1",
            "adapter": "fastapi-adapter-v1",
            "status": "completed",
            "affected_entrypoints": [{"id": "HTTP GET /x", "kind": "http", "evidence": []}],
            "candidate_entrypoints": [
                {
                    "id": "HTTP GET /x",
                    "kind": "http",
                    "confidence": "medium",
                    "effect_evidence": [],
                }
            ],
            "unresolved": [],
            "timing_seconds": {"cold_no_cache_analyzer_wall": 1.0},
        },
        {
            "schema_version": 3,
            "repository": "owner/repo",
            "pr": 2,
            "candidate": "candidate/v1",
            "adapter": "fastapi-adapter-v1",
            "status": "completed",
            "affected_entrypoints": [],
            "candidate_entrypoints": [],
            "unresolved": [],
            "timing_seconds": {"cold_no_cache_analyzer_wall": 2.0},
        },
        {
            "schema_version": 3,
            "repository": "owner/repo",
            "pr": 3,
            "candidate": "candidate/v1",
            "adapter": "fastapi-adapter-v1",
            "status": "partial",
            "affected_entrypoints": [{"id": "HTTP GET /fp", "kind": "http", "evidence": []}],
            "candidate_entrypoints": [
                {
                    "id": "HTTP GET /fp",
                    "kind": "http",
                    "confidence": "medium",
                    "effect_evidence": [],
                }
            ],
            "unresolved": ["analysis incomplete"],
            "timing_seconds": {"cold_no_cache_analyzer_wall": 3.0},
        },
        {
            "schema_version": 3,
            "repository": "owner/repo",
            "pr": 4,
            "candidate": "candidate/v1",
            "adapter": "fastapi-adapter-v1",
            "status": "completed",
            "affected_entrypoints": [],
            "candidate_entrypoints": [],
            "unresolved": [],
            "timing_seconds": {"cold_no_cache_analyzer_wall": 4.0},
        },
    ]
    truth.write_text("".join(json.dumps(row) + "\n" for row in truth_rows))
    predictions.write_text("".join(json.dumps(row) + "\n" for row in prediction_rows))
    monkeypatch.setattr(
        sys,
        "argv",
        ["evaluate.py", "--ground-truth", str(truth), "--predictions", str(predictions)],
    )

    evaluate.main()

    result = json.loads(capsys.readouterr().out)
    assert result["macro"]["sample_prs"] == {"precision": 2, "recall": 2, "f1": 2}
    assert result["macro"]["precision"] == 0.5
    assert result["macro"]["recall"] == 0.5
    assert result["negative_control_specificity"] == {
        "completed_controls": 1,
        "all_controls": 2,
        "clean_completed_controls": 1,
        "completed_control_coverage": 0.5,
        "specificity": 1.0,
        "conservative_specificity": 0.5,
    }
    assert result["coverage"]["completed"]["rate"] == 3 / 4
    timing = result["performance"]["protocols"]["cold_no_cache_analyzer_wall"]
    assert timing["samples"] == 4
    assert timing["p50"] == 2.0
    assert timing["p95"] == 4.0
    assert result["performance"]["incremental_gate_eligible"] is False


def test_prediction_manifest_authenticates_exact_bytes_and_candidate(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.jsonl"
    row = {
        "schema_version": 3,
        "repository": "owner/repo",
        "pr": 1,
        "candidate": "candidate/v1",
        "adapter": "fastapi-adapter-v1",
        "status": "completed",
        "affected_entrypoints": [],
        "candidate_entrypoints": [],
        "unresolved": [],
        "timing_seconds": {"cold_no_cache_analyzer_wall": 1.0},
    }
    content = json.dumps(row) + "\n"
    predictions.write_text(content)
    manifest = tmp_path / "manifest.json"
    manifest_content = json.dumps(
        {
            "schema_version": 3,
            "prediction_schema_version": 3,
            "created_at": "2026-01-01T00:00:00+00:00",
            "candidate": {
                "id": "candidate/v1",
                "name": "fastapi-endpoint-detector",
                "version": "test",
                "adapter": "fastapi-adapter-v1",
                "git_sha": "a" * 40,
                "config_hash": "d" * 12,
                "dirty": False,
                "dirty_sha256": None,
                "uv_lock_sha256": "b" * 64,
                "uv_version": "uv test",
                "command": "uv run --frozen fastapi-endpoint-detector analyze --no-cache",
                "performance_protocol": {
                    "id": "cold-no-cache-analyzer-wall-v1",
                    "cache_enabled": False,
                    "incremental_valid": False,
                },
            },
            "git": {"candidate_sha": "a" * 40},
            "prediction_output": {
                "path": str(predictions),
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "records": 1,
            },
            "selected_keys": [{"repository": "owner/repo", "pr": 1}],
            "python": "Python test",
            "platform": "test-platform",
            "corpus": {"path": "corpus.json", "sha256": "c" * 64},
            "root_config": {"default": ".", "repositories": {}},
            "app_entry_config": {},
            "bootstrap_entry_config": {},
            "configuration": {
                "cache": "/tmp/cache",
                "output": str(predictions),
                "manifest": str(manifest),
                "timeout_seconds": 60.0,
                "dry_run": False,
                "allow_upstream_execution": False,
                "use_scip": False,
                "filters": {"limit": None, "repositories": [], "prs": []},
            },
            "selection_count": 1,
            "prs": [
                {
                    "repository": "owner/repo",
                    "pr": 1,
                    "configured_app_root": ".",
                    "configured_app_entry": None,
                    "configured_bootstrap_entry": None,
                    "merge_sha": "a" * 40,
                    "base_sha": "e" * 40,
                    "status": "completed",
                    "timing_seconds": {"analyzer": 1.0, "total": 1.0},
                }
            ],
            "timing": {
                "started_at": "2026-01-01T00:00:00+00:00",
                "finished_at": "2026-01-01T00:00:01+00:00",
                "total_seconds": 1.0,
                "protocol": "cold-no-cache-analyzer-wall-v1",
                "incremental_valid": False,
                "not_measured": ["warm_no_change"],
            },
        }
    )
    manifest.write_text(manifest_content)
    artifact = read_primary_artifact(predictions, "prediction")

    result = evaluate.read_prediction_manifest(manifest, artifact)

    assert result["candidate"] == "candidate/v1"
    assert result["prediction_sha256"] == artifact.sha256
    assert result["runner_provenance_validated"] is True
    assert result["secure_execution_eligible"] is True
    unsafe_manifest = json.loads(manifest_content)
    unsafe_manifest["configuration"]["allow_upstream_execution"] = True
    manifest.write_text(json.dumps(unsafe_manifest))
    unsafe_result = evaluate.read_prediction_manifest(manifest, artifact)
    assert unsafe_result["secure_execution_eligible"] is False
    assert unsafe_result["execution_ineligibility_reasons"] == ["upstream_execution"]
    invalid_hash_manifest = json.loads(manifest_content)
    invalid_hash_manifest["candidate"]["git_sha"] = "not-a-sha"
    invalid_hash_manifest["git"]["candidate_sha"] = "not-a-sha"
    manifest.write_text(json.dumps(invalid_hash_manifest))
    with pytest.raises(ValueError, match="valid digest"):
        evaluate.read_prediction_manifest(manifest, artifact)
    malformed_manifest = json.loads(manifest_content)
    malformed_manifest["unexpected"] = True
    manifest.write_text(json.dumps(malformed_manifest))
    with pytest.raises(ValueError, match="unknown or missing fields"):
        evaluate.read_prediction_manifest(manifest, artifact)
    manifest.write_text(manifest_content)
    predictions.write_text(content + "\n")
    assert evaluate.read_prediction_manifest(manifest, artifact) == result
