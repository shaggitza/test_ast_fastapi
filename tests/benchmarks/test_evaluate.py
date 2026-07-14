from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

import pytest
from benchmarks.real_world import evaluate

if TYPE_CHECKING:
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
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    predictions.write_text(
        "\n".join(
            [
                json.dumps({"repository": "owner/repo", "pr": 1, "affected_entrypoints": []}),
                json.dumps({"repository": "owner/repo", "pr": 2, "affected_entrypoints": []}),
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
    assert with_census == without_census
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
