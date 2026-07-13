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
