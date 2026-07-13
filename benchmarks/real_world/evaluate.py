#!/usr/bin/env python3
"""Evaluate impact-analysis predictions against adjudicated PR labels."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def key(record: dict[str, Any]) -> tuple[str, int]:
    return record["repository"], int(record["pr"])


def entrypoints(record: dict[str, Any]) -> set[str]:
    return {item["id"] for item in record.get("affected_entrypoints", [])}


def entrypoints_by_kind(record: dict[str, Any]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    for item in record.get("affected_entrypoints", []):
        identifier = item["id"]
        kind = item.get("kind")
        if not isinstance(kind, str):
            kind = "http" if identifier.startswith("HTTP ") else "unknown"
        grouped[kind.lower()].add(identifier)
    return grouped


def ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    args = parser.parse_args()

    truth = {key(item): item for item in read_jsonl(args.ground_truth)}
    predictions = {key(item): item for item in read_jsonl(args.predictions)}
    totals: dict[str, int] = defaultdict(int)
    macro: dict[str, float] = defaultdict(float)
    evaluated = 0
    latencies: list[float] = []
    kind_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for record_key, expected_record in truth.items():
        if expected_record.get("status", "adjudicated") != "adjudicated":
            continue
        evaluated += 1
        expected = entrypoints(expected_record)
        predicted_record = predictions.get(record_key, {})
        predicted = entrypoints(predicted_record)
        tp = len(expected & predicted)
        fp = len(predicted - expected)
        fn = len(expected - predicted)
        totals["tp"] += tp
        totals["fp"] += fp
        totals["fn"] += fn
        totals["unresolved"] += len(predicted_record.get("unresolved", []))
        expected_kinds = entrypoints_by_kind(expected_record)
        predicted_kinds = entrypoints_by_kind(predicted_record)
        for kind in expected_kinds.keys() | predicted_kinds.keys():
            expected_kind = expected_kinds.get(kind, set())
            predicted_kind = predicted_kinds.get(kind, set())
            kind_totals[kind]["tp"] += len(expected_kind & predicted_kind)
            kind_totals[kind]["fp"] += len(predicted_kind - expected_kind)
            kind_totals[kind]["fn"] += len(expected_kind - predicted_kind)
        precision = ratio(tp, tp + fp)
        recall = ratio(tp, tp + fn)
        macro["precision"] += precision
        macro["recall"] += recall
        macro["f1"] += ratio(2 * precision * recall, precision + recall)
        if "incremental_seconds" in predicted_record:
            latencies.append(float(predicted_record["incremental_seconds"]))

    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    adjudicated_keys = {
        record_key
        for record_key, record in truth.items()
        if record.get("status", "adjudicated") == "adjudicated"
    }
    result = {
        "adjudicated_prs": evaluated,
        "prediction_coverage": ratio(len(adjudicated_keys & set(predictions)), evaluated),
        "micro": {
            "precision": precision,
            "recall": recall,
            "f1": ratio(2 * precision * recall, precision + recall),
            "tp": tp,
            "fp": fp,
            "fn": fn,
        },
        "macro": {name: ratio(value, evaluated) for name, value in macro.items()},
        "by_kind": {
            kind: {
                "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
                "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
                "f1": ratio(
                    2
                    * ratio(counts["tp"], counts["tp"] + counts["fp"])
                    * ratio(counts["tp"], counts["tp"] + counts["fn"]),
                    ratio(counts["tp"], counts["tp"] + counts["fp"])
                    + ratio(counts["tp"], counts["tp"] + counts["fn"]),
                ),
                **dict(counts),
            }
            for kind, counts in sorted(kind_totals.items())
        },
        "unresolved_items": totals["unresolved"],
        "latency_seconds": {
            "samples": len(latencies),
            "mean": ratio(sum(latencies), len(latencies)),
            "max": max(latencies, default=0.0),
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
