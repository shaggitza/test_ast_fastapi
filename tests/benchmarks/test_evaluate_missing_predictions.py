"""Missing predictions retain truth denominators without producing confusion scores."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from benchmarks.real_world import evaluate


@pytest.mark.parametrize("include_completed_prediction", [False, True])
def test_missing_positive_negative_and_unknown_truth_remain_explicit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    include_completed_prediction: bool,
) -> None:
    truth_records = [
        {
            "repository": "owner/repo",
            "pr": 1,
            "status": "adjudicated",
            "affected_entrypoints": [{"id": "HTTP GET /positive", "kind": "http"}],
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
            "status": "unknown",
            "affected_entrypoints": [{"id": "HTTP GET /unknown", "kind": "http"}],
        },
    ]
    predictions = []
    if include_completed_prediction:
        truth_records.append(
            {
                "repository": "owner/repo",
                "pr": 4,
                "status": "adjudicated",
                "affected_entrypoints": [{"id": "HTTP GET /completed", "kind": "http"}],
            }
        )
        predictions.append(
            {
                "repository": "owner/repo",
                "pr": 4,
                "affected_entrypoints": [{"id": "HTTP GET /completed", "kind": "http"}],
            }
        )
    args = SimpleNamespace(
        ground_truth="truth-memory.jsonl",
        predictions="predictions-memory.jsonl",
        scope="all",
        verification_set=None,
        route_census=None,
        prediction_manifest=None,
    )
    monkeypatch.setattr(evaluate.argparse.ArgumentParser, "parse_args", lambda _self: args)

    def read_in_memory(_path: object, kind: str) -> SimpleNamespace:
        return SimpleNamespace(
            records=truth_records if kind == "ground_truth" else predictions,
            sha256=("a" if kind == "ground_truth" else "b") * 64,
            content=b"in-memory",
        )

    monkeypatch.setattr(evaluate, "read_primary_artifact", read_in_memory)
    evaluate.main()
    result = json.loads(capsys.readouterr().out)
    den = result["terminal_denominators"]
    completed = int(include_completed_prediction)
    assert (den["total"], den["terminal"], den["evaluable"]) == (
        3 + completed,
        3 + completed,
        2 + completed,
    )
    assert (den["positive"], den["negative"], den["unknown"], den["not_evaluable"]) == (
        1 + completed,
        1,
        1,
        0,
    )
    assert den["missing_prediction"] == 3
    rows = {(row["repository"], row["pr"]): row for row in result["comparison_evidence"]["per_pr"]}
    for pr, polarity in ((1, True), (2, False)):
        row = rows[("owner/repo", pr)]
        assert row["truth_positive"] is polarity
        assert row["terminal_status"] == "evaluable"
        assert row["prediction_status"] == "missing"
        assert row["unresolved_count"] is None
        assert row["raw"] is None and row["normalized"] is None
    assert rows[("owner/repo", 3)]["terminal_status"] == "unknown"
    assert rows[("owner/repo", 3)]["truth_positive"] is None
    assert result["micro"]["tp"] == completed
    assert result["micro"]["fp"] == result["micro"]["fn"] == 0
    assert result["prediction_coverage"] == pytest.approx(completed / (2 + completed))
    assert result["comparison_evidence"]["attested"] is False
