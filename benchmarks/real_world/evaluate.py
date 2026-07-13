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

from benchmarks.real_world.benchmark_scope import SCOPES, filter_record
from benchmarks.real_world.semantic_normalization import (
    ALIAS_VERSION,
    claims,
    match_claims,
    split_ranked_claims,
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


def ranked_entrypoints(record: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Return selected and LOW exact IDs after strongest-tier deduplication."""
    rank = {"low": 0, "medium": 1, "high": 2}
    items = record.get("candidate_entrypoints")
    if not items:
        items = record.get("affected_entrypoints", [])
    strongest: dict[str, int] = {}
    for item in items:
        identifier = item["id"]
        item_rank = rank.get(str(item.get("confidence", "medium")).lower(), 1)
        strongest[identifier] = max(strongest.get(identifier, -1), item_rank)
    return (
        {identifier for identifier, item_rank in strongest.items() if item_rank >= 1},
        {identifier for identifier, item_rank in strongest.items() if item_rank == 0},
    )


def low_diagnostics(
    expected: set[str],
    selected: set[str],
    low: set[str],
    reachability_only: set[str] | None = None,
) -> dict[str, int]:
    unmatched_expected = expected - selected
    low_matches = unmatched_expected & low
    low_fp = low - expected
    reachability_matches = low_fp & (reachability_only or set())
    return {
        "low_tp": len(low_matches),
        "low_fp": len(low_fp),
        "low_candidates": len(low),
        "low_supported_reachability": len(reachability_matches),
        "low_unmatched": len(low_fp - reachability_matches),
        "fn_with_low_candidate": len(low_matches),
        "fn_with_no_candidate": len(unmatched_expected - low_matches),
    }


def predicted_ids_by_kind(identifiers: set[str]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    for identifier in identifiers:
        kind = "http" if identifier.startswith("HTTP ") else "event"
        grouped[kind].add(identifier)
    return grouped


def ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> None:  # noqa: PLR0912, PLR0915 - raw and normalized metrics share one pass
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--scope", choices=SCOPES, default="all")
    args = parser.parse_args()

    truth = {key(item): filter_record(item, args.scope) for item in read_jsonl(args.ground_truth)}
    predictions = {
        key(item): filter_record(item, args.scope) for item in read_jsonl(args.predictions)
    }
    totals: dict[str, int] = defaultdict(int)
    macro: dict[str, float] = defaultdict(float)
    evaluated = 0
    latencies: list[float] = []
    kind_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_totals: dict[str, int] = defaultdict(int)
    normalized_macro: dict[str, float] = defaultdict(float)
    normalized_kinds: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_rules: dict[str, int] = defaultdict(int)
    low_rules: dict[str, int] = defaultdict(int)
    ranked_totals: dict[str, int] = defaultdict(int)
    ranked_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_ranked_totals: dict[str, int] = defaultdict(int)
    normalized_ranked_repositories: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    repository_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    truth_positive_prs = 0
    negative_controls_with_fp = 0
    negative_controls_with_low_fp = 0

    for record_key, expected_record in truth.items():
        if expected_record.get("status", "adjudicated") != "adjudicated":
            continue
        evaluated += 1
        expected = entrypoints(expected_record)
        reachability_only = {
            item["id"] for item in expected_record.get("reachability_only_entrypoints", [])
        }
        predicted_record = predictions.get(record_key, {})
        predicted, low_predicted = ranked_entrypoints(predicted_record)
        tp = len(expected & predicted)
        fp = len(predicted - expected)
        fn = len(expected - predicted)
        totals["tp"] += tp
        totals["fp"] += fp
        totals["fn"] += fn
        repository_totals[record_key[0]]["tp"] += tp
        repository_totals[record_key[0]]["fp"] += fp
        repository_totals[record_key[0]]["fn"] += fn
        exact_low = low_diagnostics(expected, predicted, low_predicted, reachability_only)
        for metric, count in exact_low.items():
            ranked_totals[metric] += count
            ranked_repositories[record_key[0]][metric] += count
        if expected:
            truth_positive_prs += 1
        elif predicted:
            negative_controls_with_fp += 1
        if not expected and low_predicted:
            negative_controls_with_low_fp += 1
        totals["unresolved"] += len(predicted_record.get("unresolved", []))
        expected_kinds = entrypoints_by_kind(expected_record)
        predicted_kinds = predicted_ids_by_kind(predicted)
        for kind in expected_kinds.keys() | predicted_kinds.keys():
            expected_kind = expected_kinds.get(kind, set())
            predicted_kind = predicted_kinds.get(kind, set())
            kind_totals[kind]["tp"] += len(expected_kind & predicted_kind)
            kind_totals[kind]["fp"] += len(predicted_kind - expected_kind)
            kind_totals[kind]["fn"] += len(expected_kind - predicted_kind)
        expected_claims = claims(expected_record)
        selected_claims, low_claims = split_ranked_claims(record_key[0], predicted_record)
        normalized = match_claims(record_key[0], expected_claims, selected_claims)
        residual_expected = [
            claim
            for index, claim in enumerate(normalized["expected_claims"])
            if index not in normalized["_matched_expected"]
        ]
        normalized_low = match_claims(record_key[0], residual_expected, low_claims)
        unmatched_low_claims = [
            claim
            for index, claim in enumerate(normalized_low["predicted_claims"])
            if index not in normalized_low["_matched_predicted"]
        ]
        reachability_record = {
            "affected_entrypoints": expected_record.get("reachability_only_entrypoints", [])
        }
        normalized_reachability = match_claims(
            record_key[0], claims(reachability_record), unmatched_low_claims
        )
        for metric in ("tp", "fp", "fn", "expected_atoms", "predicted_atoms"):
            normalized_totals[metric] += normalized[metric]
        normalized_low_counts = {
            "low_tp": normalized_low["tp"],
            "low_fp": normalized_low["fp"],
            "low_candidates": normalized_low["predicted_atoms"],
            "low_supported_reachability": normalized_reachability["tp"],
            "low_unmatched": normalized_reachability["fp"],
            "fn_with_low_candidate": normalized_low["tp"],
            "fn_with_no_candidate": normalized_low["fn"],
        }
        for metric, count in normalized_low_counts.items():
            normalized_ranked_totals[metric] += count
            normalized_ranked_repositories[record_key[0]][metric] += count
        for rule, count in normalized_low["matches_by_rule"].items():
            low_rules[rule] += count
        for metric in ("tp", "fp", "fn"):
            normalized_repositories[record_key[0]][metric] += normalized[metric]
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

    def confidence_diagnostics(
        primary: dict[str, int], low_counts: dict[str, int]
    ) -> dict[str, Any]:
        low_tp = low_counts["low_tp"]
        low_fp = low_counts["low_fp"]
        ceiling = {
            "tp": primary["tp"] + low_tp,
            "fp": primary["fp"] + low_fp,
            "fn": low_counts["fn_with_no_candidate"],
        }
        return {
            "policy": "HIGH and MEDIUM are primary; LOW is diagnostic only",
            "low": {
                **dict(low_counts),
                "diagnostic_precision": ratio(low_tp, low_tp + low_fp),
                "supported_precision": ratio(
                    low_tp + low_counts["low_supported_reachability"],
                    low_counts["low_candidates"],
                ),
            },
            "candidate_ceiling": metrics(ceiling),
        }

    result = {
        "scope": {
            "all": "all-surfaces",
            "fastapi": "fastapi-adapter-v1",
            "out-of-scope": "out-of-scope-v1",
        }[args.scope],
        "adjudicated_prs": evaluated,
        "prediction_coverage": ratio(len(adjudicated_keys & set(predictions)), evaluated),
        "truth_positive_prs": truth_positive_prs,
        "negative_control_prs": evaluated - truth_positive_prs,
        "negative_controls_with_fp": negative_controls_with_fp,
        "negative_controls_with_low_fp": negative_controls_with_low_fp,
        "micro": {
            "precision": precision,
            "recall": recall,
            "f1": ratio(2 * precision * recall, precision + recall),
            "tp": tp,
            "fp": fp,
            "fn": fn,
        },
        "confidence": {
            **confidence_diagnostics(totals, ranked_totals),
            "by_repository": {
                repository: confidence_diagnostics(repository_totals[repository], counts)
                for repository, counts in sorted(ranked_repositories.items())
            },
        },
        "macro": {name: ratio(value, evaluated) for name, value in macro.items()},
        "by_repository": {
            repository: metrics(counts) for repository, counts in sorted(repository_totals.items())
        },
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
            "by_repository": {
                repository: metrics(counts)
                for repository, counts in sorted(normalized_repositories.items())
            },
            "by_kind": {kind: metrics(counts) for kind, counts in sorted(normalized_kinds.items())},
            "expected_atoms": normalized_totals["expected_atoms"],
            "predicted_atoms": normalized_totals["predicted_atoms"],
            "matches_by_rule": dict(sorted(normalized_rules.items())),
            "low_matches_by_rule": dict(sorted(low_rules.items())),
            "confidence": {
                **confidence_diagnostics(normalized_totals, normalized_ranked_totals),
                "by_repository": {
                    repository: confidence_diagnostics(normalized_repositories[repository], counts)
                    for repository, counts in sorted(normalized_ranked_repositories.items())
                },
            },
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
