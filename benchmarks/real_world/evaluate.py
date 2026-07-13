#!/usr/bin/env python3
"""Evaluate impact-analysis predictions against adjudicated PR labels."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world.semantic_normalization import (
    ALIAS_VERSION,
    match_records,
)


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


def main() -> None:  # noqa: PLR0915 - raw and normalized metrics share one pass
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
    normalized_totals: dict[str, int] = defaultdict(int)
    normalized_macro: dict[str, float] = defaultdict(float)
    normalized_kinds: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_rules: dict[str, int] = defaultdict(int)

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
        normalized = match_records(record_key[0], expected_record, predicted_record)
        for metric in ("tp", "fp", "fn", "expected_atoms", "predicted_atoms"):
            normalized_totals[metric] += normalized[metric]
        for rule, count in normalized["matches_by_rule"].items():
            normalized_rules[rule] += count
        for match in normalized["matches"]:
            normalized_kinds[match["kind"]]["tp"] += 1
        for index, claim in enumerate(normalized["expected_claims"]):
            if index not in normalized["_matched_expected"]:
                normalized_kinds[claim.kind]["fn"] += 1
        for index, claim in enumerate(normalized["predicted_claims"]):
            if index not in normalized["_matched_predicted"]:
                normalized_kinds[claim.kind]["fp"] += 1
        normalized_precision = ratio(normalized["tp"], normalized["tp"] + normalized["fp"])
        normalized_recall = ratio(normalized["tp"], normalized["tp"] + normalized["fn"])
        normalized_macro["precision"] += normalized_precision
        normalized_macro["recall"] += normalized_recall
        normalized_macro["f1"] += ratio(
            2 * normalized_precision * normalized_recall,
            normalized_precision + normalized_recall,
        )

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

    def metrics(counts: dict[str, int]) -> dict[str, int | float]:
        item_precision = ratio(counts["tp"], counts["tp"] + counts["fp"])
        item_recall = ratio(counts["tp"], counts["tp"] + counts["fn"])
        return {
            "precision": item_precision,
            "recall": item_recall,
            "f1": ratio(2 * item_precision * item_recall, item_precision + item_recall),
            "tp": counts["tp"],
            "fp": counts["fp"],
            "fn": counts["fn"],
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
        "normalized": {
            "alias_version": ALIAS_VERSION,
            "micro": metrics(normalized_totals),
            "macro": {name: ratio(value, evaluated) for name, value in normalized_macro.items()},
            "by_kind": {kind: metrics(counts) for kind, counts in sorted(normalized_kinds.items())},
            "expected_atoms": normalized_totals["expected_atoms"],
            "predicted_atoms": normalized_totals["predicted_atoms"],
            "matches_by_rule": dict(sorted(normalized_rules.items())),
            "rules": [
                "raw exact",
                "composite HTTP method expansion",
                "template parameter-name normalization with converter preservation",
                "case-insensitive WebSocket family",
                "unique generic/qualified relaxation",
                "frozen repository-scoped explicit aliases",
            ],
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
