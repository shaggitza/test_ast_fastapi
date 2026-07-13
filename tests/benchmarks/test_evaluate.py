from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from benchmarks.real_world import evaluate

if TYPE_CHECKING:
    from pathlib import Path


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
