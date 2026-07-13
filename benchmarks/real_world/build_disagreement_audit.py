#!/usr/bin/env python3
"""Build per-backend/per-PR normalized disagreement packets for source audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world.semantic_normalization import match_records


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def record_key(record: dict[str, Any]) -> tuple[str, int]:
    return str(record["repository"]), int(record["pr"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    truth = {
        record_key(record): record
        for record in read_jsonl(args.ground_truth)
        if record.get("status") == "adjudicated"
    }
    args.output.mkdir(parents=True, exist_ok=True)
    index: list[dict[str, Any]] = []
    for prediction in read_jsonl(args.predictions):
        key = record_key(prediction)
        expected = truth.get(key)
        if expected is None or not prediction.get("affected_entrypoints"):
            continue
        matched = match_records(key[0], expected, prediction)
        packet = {
            "backend": args.backend,
            "repository": key[0],
            "pr": key[1],
            "truth": expected.get("affected_entrypoints", []),
            "predictions": prediction.get("affected_entrypoints", []),
            "normalized_matches": matched["matches"],
            "unmatched_predictions": matched["unmatched_predicted"],
            "unmatched_truth": matched["unmatched_expected"],
        }
        name = f"{key[0].replace('/', '--')}-pr-{key[1]}.json"
        (args.output / name).write_text(json.dumps(packet, indent=2) + "\n")
        index.append(
            {
                "file": name,
                "repository": key[0],
                "pr": key[1],
                "unmatched_predictions": len(matched["unmatched_predicted"]),
                "unmatched_truth": len(matched["unmatched_expected"]),
            }
        )
    (args.output / "index.json").write_text(json.dumps(index, indent=2) + "\n")


if __name__ == "__main__":
    main()
