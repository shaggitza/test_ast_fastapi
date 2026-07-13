from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from benchmarks.real_world import evaluate

if TYPE_CHECKING:
    from pathlib import Path


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
